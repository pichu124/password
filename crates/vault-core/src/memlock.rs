//! Khoá vùng nhớ chứa khoá giải mã để hệ điều hành không ghi nó xuống pagefile/swap.
//! Đây là biện pháp "cố gắng hết sức": nếu hệ điều hành từ chối thì vẫn chạy bình thường.
//!
//! Mỗi [`LockedKey`] nằm trên MỘT TRANG BỘ NHỚ RIÊNG. `mlock`/`VirtualLock` làm việc theo trang và
//! không đếm số lần khoá: nếu hai khoá dùng chung một trang (như khi mỗi khoá là một `Box` 32 byte),
//! thì việc huỷ khoá CŨ sau khi đổi mật khẩu sẽ mở khoá luôn trang đang chứa khoá HIỆN TẠI, trong
//! khi `is_locked()` vẫn báo là đang khoá.

use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::ptr::NonNull;

use zeroize::Zeroize;

use crate::crypto::Key;

/// Khoá 32 byte nằm một mình trên một trang bộ nhớ (địa chỉ cố định), trang đó được khoá trong RAM.
pub struct LockedKey {
    /// Trỏ tới đầu một vùng `layout` (đúng một trang, căn theo trang) do `new` cấp phát; ở đầu vùng
    /// là một `Key` đã được khởi tạo. Chỉ `LockedKey` này sở hữu vùng đó.
    ptr: NonNull<Key>,
    layout: Layout,
    locked: bool,
}

// SAFETY: `LockedKey` sở hữu độc quyền vùng nhớ mà `ptr` trỏ tới (giống `Box<Key>`): không có bản
// sao nào của con trỏ, không có tính khả biến nội tại, và chỉ đọc được qua `&self` (Deref). `Key`
// (`Zeroizing<[u8; 32]>`) là Send + Sync, nên chuyển/chia sẻ `LockedKey` giữa các luồng an toàn như
// chuyển/chia sẻ một `Box<Key>`. mlock/VirtualLock gắn với tiến trình, không gắn với luồng.
unsafe impl Send for LockedKey {}
// SAFETY: xem ở trên.
unsafe impl Sync for LockedKey {}

/// Kích thước trang của hệ điều hành (Android có thể dùng trang 16 KiB).
fn page_size() -> usize {
    #[cfg(unix)]
    {
        // SAFETY: sysconf không có điều kiện tiên quyết; trả về -1 nếu không biết.
        let n = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if n >= std::mem::size_of::<Key>() as libc::c_long && (n as usize).is_power_of_two() {
            return n as usize;
        }
    }
    4096
}

impl LockedKey {
    pub fn new(key: Key) -> Self {
        let page = page_size();
        let layout = Layout::from_size_align(page, page)
            .expect("kích thước trang là luỹ thừa của 2 và đủ chứa khoá");
        // SAFETY: `layout` có kích thước khác 0.
        let raw = unsafe { alloc_zeroed(layout) }.cast::<Key>();
        let Some(ptr) = NonNull::new(raw) else {
            std::alloc::handle_alloc_error(layout);
        };
        // SAFETY: vùng nhớ vừa cấp phát, căn theo trang (≥ căn của `Key`) và dài một trang
        // (≥ kích thước của `Key`), chưa được khởi tạo thành `Key` ⇒ `write` (không drop gì cũ).
        // Ghi một khoá toàn 0 rồi CHÉP byte vào, để bản `key` truyền vào được drop (và tự xoá) ở đây
        // thay vì bị "chuyển" đi và để lại bản sao trên stack.
        unsafe {
            ptr.as_ptr().write(Key::new([0u8; crate::crypto::KEY_LEN]));
            (*ptr.as_ptr()).copy_from_slice(&key[..]);
        }
        drop(key);
        // SAFETY: `ptr` trỏ tới đầu một vùng dài `page` byte do ta sở hữu.
        let locked = unsafe { lock(ptr.as_ptr().cast::<u8>(), page) };
        LockedKey {
            ptr,
            layout,
            locked,
        }
    }

    pub fn is_locked(&self) -> bool {
        self.locked
    }
}

impl std::ops::Deref for LockedKey {
    type Target = Key;
    fn deref(&self) -> &Key {
        // SAFETY: `ptr` trỏ tới một `Key` đã khởi tạo, sống tới khi `self` bị drop; chỉ cho mượn
        // không khả biến, gắn với thời gian sống của `&self`.
        unsafe { self.ptr.as_ref() }
    }
}

impl Drop for LockedKey {
    fn drop(&mut self) {
        let p = self.ptr.as_ptr();
        // SAFETY: `p` trỏ tới `Key` đã khởi tạo do ta sở hữu, không còn ai mượn (`&mut self`). Xoá
        // trước, mở khoá sau, rồi mới trả vùng nhớ đúng với `layout` đã dùng khi cấp phát.
        unsafe {
            (*p).zeroize();
            std::ptr::drop_in_place(p); // Zeroizing xoá thêm lần nữa — không hại.
            if self.locked {
                unlock(p.cast::<u8>(), self.layout.size());
            }
            dealloc(p.cast::<u8>(), self.layout);
        }
    }
}

#[cfg(unix)]
unsafe fn lock(p: *const u8, len: usize) -> bool {
    libc::mlock(p.cast(), len) == 0
}
#[cfg(unix)]
unsafe fn unlock(p: *const u8, len: usize) {
    libc::munlock(p.cast(), len);
}

#[cfg(windows)]
unsafe fn lock(p: *const u8, len: usize) -> bool {
    windows_sys::Win32::System::Memory::VirtualLock(p as _, len) != 0
}
#[cfg(windows)]
unsafe fn unlock(p: *const u8, len: usize) {
    windows_sys::Win32::System::Memory::VirtualUnlock(p as _, len);
}

#[cfg(not(any(unix, windows)))]
unsafe fn lock(_: *const u8, _: usize) -> bool {
    false
}
#[cfg(not(any(unix, windows)))]
unsafe fn unlock(_: *const u8, _: usize) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(k: &LockedKey) -> usize {
        (&**k as *const Key) as usize
    }

    #[test]
    fn locked_key_derefs_to_same_bytes() {
        let k = crate::crypto::random_key();
        let copy = *k;
        let l = LockedKey::new(k);
        assert_eq!(**l, copy);
        // Trong container/CI mlock có thể bị giới hạn; chỉ in ra, không bắt buộc.
        eprintln!("memory locked: {}", l.is_locked());
    }

    /// Rà soát H5: hai khoá dùng chung một trang ⇒ drop khoá cũ (sau khi đổi mật khẩu) mở khoá luôn
    /// trang của khoá hiện tại.
    #[test]
    fn every_key_has_its_own_page_and_dropping_one_leaves_the_other_intact() {
        let page = page_size();
        let (ka, kb) = (crate::crypto::random_key(), crate::crypto::random_key());
        let (ca, cb) = (*ka, *kb);
        let a = LockedKey::new(ka);
        let b = LockedKey::new(kb);
        assert_eq!(addr(&a) % page, 0, "căn theo trang");
        assert_eq!(addr(&b) % page, 0);
        assert_ne!(addr(&a) / page, addr(&b) / page, "hai trang khác nhau");
        assert_eq!((**a, **b), (ca, cb));
        let survivor = addr(&b);
        drop(a);
        assert_eq!(**b, cb, "khoá còn lại vẫn đọc được");

        // Linux: đọc /proc/self/smaps xem trang của khoá còn lại có còn bị khoá không.
        #[cfg(target_os = "linux")]
        if b.is_locked() {
            match locked_kb_of(survivor) {
                Some(kb) => assert!(kb > 0, "trang của khoá hiện tại đã bị mở khoá"),
                None => eprintln!("không đọc được /proc/self/smaps — bỏ qua"),
            }
        } else {
            eprintln!("mlock không được phép ở đây — bỏ qua phần kiểm tra smaps");
        }
        let _ = survivor;
    }

    /// Số kB "Locked" của vùng nhớ (VMA) chứa địa chỉ `a`, theo /proc/self/smaps.
    #[cfg(target_os = "linux")]
    fn locked_kb_of(a: usize) -> Option<u64> {
        let s = std::fs::read_to_string("/proc/self/smaps").ok()?;
        let mut inside = false;
        for line in s.lines() {
            let first = line.split_whitespace().next().unwrap_or("");
            if let Some((lo, hi)) = first.split_once('-') {
                if let (Ok(lo), Ok(hi)) =
                    (usize::from_str_radix(lo, 16), usize::from_str_radix(hi, 16))
                {
                    inside = lo <= a && a < hi;
                    continue;
                }
            }
            if inside {
                if let Some(rest) = line.strip_prefix("Locked:") {
                    return rest.split_whitespace().next()?.parse().ok();
                }
            }
        }
        None
    }
}
