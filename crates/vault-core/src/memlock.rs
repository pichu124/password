//! Khoá vùng nhớ chứa khoá giải mã để hệ điều hành không ghi nó xuống pagefile/swap.
//! Đây là biện pháp "cố gắng hết sức": nếu hệ điều hành từ chối thì vẫn chạy bình thường.

use crate::crypto::{Key, KEY_LEN};

/// Khoá 32 byte nằm trên heap (địa chỉ cố định) và được khoá trong RAM.
pub struct LockedKey {
    inner: Box<Key>,
    locked: bool,
}

impl LockedKey {
    pub fn new(key: Key) -> Self {
        let inner = Box::new(key);
        let locked = unsafe { lock(inner.as_ptr(), KEY_LEN) };
        LockedKey { inner, locked }
    }

    pub fn is_locked(&self) -> bool {
        self.locked
    }
}

impl std::ops::Deref for LockedKey {
    type Target = Key;
    fn deref(&self) -> &Key {
        &self.inner
    }
}

impl Drop for LockedKey {
    fn drop(&mut self) {
        // Xoá trước, mở khoá sau (Zeroizing cũng xoá khi Box bị drop — xoá 2 lần không hại).
        use zeroize::Zeroize;
        self.inner.as_mut().zeroize();
        if self.locked {
            unsafe { unlock(self.inner.as_ptr(), KEY_LEN) };
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

    #[test]
    fn locked_key_derefs_to_same_bytes() {
        let k = crate::crypto::random_key();
        let copy = *k;
        let l = LockedKey::new(k);
        assert_eq!(**l, copy);
        // Trong container/CI mlock có thể bị giới hạn; chỉ in ra, không bắt buộc.
        eprintln!("memory locked: {}", l.is_locked());
    }
}
