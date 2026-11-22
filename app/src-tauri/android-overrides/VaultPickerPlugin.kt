// Bộ chọn file kho cho Android (workflow ghép dòng `package …` của MainActivity lên đầu file này).
//
// Bộ chọn của plugin dialog dùng ACTION_GET_CONTENT: quyền đọc file chỉ là TẠM THỜI và mất khi Android
// đóng tiến trình app — lần mở sau app không đọc được file trên Drive / Dropbox nữa ("Permission
// Denial … StorageBackendContentProvider") và phải dùng bản đã lưu. Ở đây dùng ACTION_OPEN_DOCUMENT
// và xin quyền đọc LÂU DÀI (takePersistableUriPermission): còn nguyên sau khi app bị đóng hay điện
// thoại khởi động lại. Chỉ xin quyền ĐỌC.

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Intent
import androidx.activity.result.ActivityResult
import app.tauri.annotation.ActivityCallback
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin

@InvokeArg
class PickVaultArgs {
  /** "documents" (mặc định): trình chọn tài liệu của hệ thống; "apps": chọn qua app Drive/Dropbox. */
  var mode: String? = null
}

@TauriPlugin
class VaultPickerPlugin(private val activity: Activity) : Plugin(activity) {
  /** Trình chọn vừa được mở (để báo lại khi có lỗi). */
  private var lastPicker: String = ""

  @Command
  fun pickVault(invoke: Invoke) {
    val mode = try {
      invoke.parseArgs(PickVaultArgs::class.java).mode
    } catch (_: Exception) {
      null
    }
    try {
      if (mode == "apps") {
        // Dự phòng: y hệt bộ chọn của plugin dialog (danh sách app Drive, Dropbox…), không thêm cờ gì.
        val intent = Intent(Intent.ACTION_GET_CONTENT)
        intent.addCategory(Intent.CATEGORY_OPENABLE)
        intent.type = "*/*"
        lastPicker = "GET_CONTENT"
        startActivityForResult(invoke, intent, "pickVaultResult")
        return
      }
      // Một số bản Android của hãng (ColorOS, MIUI…) thay trình chọn tài liệu bằng trình quản lý file
      // riêng chỉ hiện bộ nhớ máy. Thử trình chọn chuẩn của hệ thống trước (có Google Drive / Dropbox
      // trong menu ☰). Trên ColorOS bản của Google tuy mở được nhưng KHÔNG cấp được quyền đọc (không
      // phải trình chọn chính thức của máy) nên để sau cùng; không có gì thì dùng trình chọn mặc định.
      for (pkg in listOf("com.android.documentsui", "com.google.android.documentsui", null)) {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT)
        intent.addCategory(Intent.CATEGORY_OPENABLE)
        // Không lọc theo kiểu file: dịch vụ đồng bộ báo `.pwv` là application/octet-stream hoặc lạ hơn.
        intent.type = "*/*"
        intent.addFlags(
          Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION
        )
        if (pkg != null) intent.setPackage(pkg)
        try {
          lastPicker = pkg ?: "OPEN_DOCUMENT (mặc định)"
          startActivityForResult(invoke, intent, "pickVaultResult")
          return
        } catch (_: ActivityNotFoundException) {
          // thử trình chọn kế tiếp
        }
      }
      invoke.reject("Không tìm thấy trình chọn file trên máy")
    } catch (ex: Exception) {
      invoke.reject(ex.message ?: "Không mở được bộ chọn file")
    }
  }

  @ActivityCallback
  fun pickVaultResult(invoke: Invoke, result: ActivityResult) {
    val data = result.data
    // Một số app trả file trong ClipData thay vì `data`.
    val uri = data?.data ?: data?.clipData?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.uri
    val ret = JSObject()
    ret.put("picker", lastPicker)
    if (result.resultCode != Activity.RESULT_OK || uri == null) {
      // Người dùng huỷ: không có `uri`.
      ret.put("persisted", false)
      ret.put("readable", false)
      invoke.resolve(ret)
      return
    }
    var persisted = false
    try {
      activity.contentResolver.takePersistableUriPermission(
        uri,
        Intent.FLAG_GRANT_READ_URI_PERMISSION
      )
      persisted = true
    } catch (_: Exception) {
      // Nhà cung cấp không cho giữ quyền lâu dài: vẫn đọc được trong lần chạy này.
    }
    // Đọc thử ngay (lúc quyền chắc chắn còn): nếu không đọc được thì báo nguyên văn lỗi.
    var readable = false
    var readError: String? = null
    try {
      activity.contentResolver.openInputStream(uri)?.use { it.read() }
      readable = true
    } catch (ex: Exception) {
      readError = ex.javaClass.simpleName + ": " + (ex.message ?: "")
    }
    ret.put("uri", uri.toString())
    ret.put("persisted", persisted)
    ret.put("readable", readable)
    if (readError != null) ret.put("readError", readError.take(400))
    invoke.resolve(ret)
  }
}
