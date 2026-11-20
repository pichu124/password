// Bản thay thế cho MainActivity do `tauri android init` sinh ra (dòng `package …` được workflow
// giữ lại từ file gốc và ghép lên đầu file này).

import android.os.Build
import android.os.Bundle
import android.view.View
import android.view.WindowManager
import android.webkit.WebView
import androidx.activity.enableEdgeToEdge

class MainActivity : TauriActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    // Không cho chụp/quay màn hình và không hiện nội dung trong màn hình "Ứng dụng gần đây":
    // mật khẩu, mã 2FA đang hiện không lọt vào ảnh chụp tự đồng bộ lên cloud.
    window.setFlags(
      WindowManager.LayoutParams.FLAG_SECURE,
      WindowManager.LayoutParams.FLAG_SECURE
    )
    enableEdgeToEdge()
    super.onCreate(savedInstanceState)
  }

  override fun onWebViewCreate(webView: WebView) {
    super.onWebViewCreate(webView)
    // Không để dịch vụ tự điền (Google, bàn phím) đề nghị lưu master password.
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
      webView.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
    }
  }
}
