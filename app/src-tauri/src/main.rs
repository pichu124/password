// Không mở cửa sổ console trên Windows khi chạy bản release.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    pwv_app_lib::run()
}
