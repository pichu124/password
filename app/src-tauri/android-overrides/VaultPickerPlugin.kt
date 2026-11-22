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
  @Command
  fun pickVault(invoke: Invoke) {
    val mode = try {
      invoke.parseArgs(PickVaultArgs::class.java).mode
    } catch (_: Exception) {
      null
    }
    try {
      if (mode == "apps") {
        // Dự phòng: danh sách app (Drive, Dropbox…) như bộ chọn cũ. Vẫn xin quyền lâu dài; app nào
        // không cho thì quyền chỉ còn trong lần chạy này.
        startActivityForResult(invoke, baseIntent(Intent.ACTION_GET_CONTENT), "pickVaultResult")
        return
      }
      // Một số bản Android của hãng (ColorOS, MIUI…) thay trình chọn tài liệu bằng trình quản lý file
      // riêng chỉ hiện bộ nhớ máy. Ưu tiên trình chọn chuẩn (có Google Drive / Dropbox trong menu ☰);
      // không có thì dùng trình chọn mặc định của máy.
      for (pkg in listOf("com.google.android.documentsui", "com.android.documentsui", null)) {
        val intent = baseIntent(Intent.ACTION_OPEN_DOCUMENT)
        if (pkg != null) intent.setPackage(pkg)
        try {
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

  private fun baseIntent(action: String): Intent {
    val intent = Intent(action)
    intent.addCategory(Intent.CATEGORY_OPENABLE)
    // Không lọc theo kiểu file: dịch vụ đồng bộ báo `.pwv` là application/octet-stream hoặc lạ hơn.
    intent.type = "*/*"
    intent.addFlags(
      Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION
    )
    return intent
  }

  @ActivityCallback
  fun pickVaultResult(invoke: Invoke, result: ActivityResult) {
    val uri = result.data?.data
    val ret = JSObject()
    if (result.resultCode != Activity.RESULT_OK || uri == null) {
      // Người dùng huỷ: không có `uri`.
      ret.put("persisted", false)
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
    } catch (_: SecurityException) {
      // Nhà cung cấp không cho giữ quyền lâu dài: vẫn đọc được trong lần chạy này.
    }
    ret.put("uri", uri.toString())
    ret.put("persisted", persisted)
    invoke.resolve(ret)
  }
}
