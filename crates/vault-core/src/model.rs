//! Mô hình dữ liệu bên trong kho (toàn bộ đều được mã hoá trên đĩa).

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Số bản mật khẩu cũ giữ lại cho mỗi mục.
pub const MAX_HISTORY: usize = 20;

/// Thời gian hiện tại, mili-giây kể từ 1970 (UTC).
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct HistoryItem {
    pub password: String,
    /// Thời điểm mật khẩu này bị thay thế.
    pub replaced_at: i64,
}

// Lưu ý: không dùng `#[serde(default)]` ở cấp struct vì `Entry` có `Drop` (zeroize);
// thay vào đó đặt default cho từng trường để file cũ thiếu trường vẫn đọc được.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Entry {
    pub id: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub urls: Vec<String>,
    #[serde(default)]
    pub notes: String,
    /// URI `otpauth://...` hoặc secret base32 cho mã 2FA.
    #[serde(default)]
    pub totp: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub password_history: Vec<HistoryItem>,
    #[serde(default)]
    pub created_at: i64,
    #[serde(default)]
    pub updated_at: i64,
}

impl Default for Entry {
    fn default() -> Self {
        let now = now_ms();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            title: String::new(),
            username: String::new(),
            password: String::new(),
            urls: Vec::new(),
            notes: String::new(),
            totp: None,
            tags: Vec::new(),
            favorite: false,
            password_history: Vec::new(),
            created_at: now,
            updated_at: now,
        }
    }
}

impl Entry {
    pub fn new(title: impl Into<String>) -> Self {
        let mut e = Self::default();
        e.title = title.into();
        e
    }

    /// Tìm kiếm không phân biệt hoa thường trong tiêu đề, username, URL, tag.
    /// Không tìm trong mật khẩu/ghi chú.
    pub fn matches(&self, query: &str) -> bool {
        let q = query.to_lowercase();
        if q.is_empty() {
            return true;
        }
        self.title.to_lowercase().contains(&q)
            || self.username.to_lowercase().contains(&q)
            || self.urls.iter().any(|u| u.to_lowercase().contains(&q))
            || self.tags.iter().any(|t| t.to_lowercase().contains(&q))
    }
}

/// Ghi nhận một mục đã bị xoá, để việc đồng bộ không làm nó "sống lại".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tombstone {
    pub id: String,
    pub deleted_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(default)]
pub struct VaultData {
    pub entries: Vec<Entry>,
    pub tombstones: Vec<Tombstone>,
    /// Lần sửa cuối cùng của nội dung kho.
    pub modified_at: i64,
}

/// Thống kê sau khi gộp hai phiên bản kho.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MergeStats {
    /// Mục chỉ có ở phía kia, được thêm vào.
    pub added: usize,
    /// Mục có ở cả hai, phía kia mới hơn nên được lấy.
    pub updated: usize,
    /// Mục bị xoá vì phía kia đã xoá.
    pub deleted: usize,
}

impl MergeStats {
    pub fn changed(&self) -> bool {
        self.added + self.updated + self.deleted > 0
    }
}

impl VaultData {
    /// Gộp `other` vào `self` theo từng mục: mục nào `updated_at` mới hơn thì thắng;
    /// mục bị xoá (tombstone) sau lần sửa cuối thì bị loại.
    /// Nếu cả hai phía đều đổi mật khẩu của cùng một mục, mật khẩu của phía thua
    /// được đưa vào lịch sử để không bao giờ bị mất.
    pub fn merge_from(&mut self, other: &VaultData) -> MergeStats {
        use std::collections::HashMap;
        let mut stats = MergeStats::default();

        // 1. Gộp tombstone (lấy thời điểm xoá muộn nhất).
        let mut tombs: HashMap<String, i64> = HashMap::new();
        for t in self.tombstones.iter().chain(other.tombstones.iter()) {
            let e = tombs.entry(t.id.clone()).or_insert(t.deleted_at);
            *e = (*e).max(t.deleted_at);
        }

        // 2. Gộp các mục.
        for theirs in &other.entries {
            match self.entries.iter_mut().find(|e| e.id == theirs.id) {
                None => {
                    self.entries.push(theirs.clone());
                    stats.added += 1;
                }
                Some(ours) if ours == theirs => {}
                Some(ours) => {
                    let (winner, loser) = if theirs.updated_at > ours.updated_at {
                        stats.updated += 1;
                        (theirs.clone(), ours.clone())
                    } else {
                        (ours.clone(), theirs.clone())
                    };
                    *ours = merge_histories(winner, &loser);
                }
            }
        }

        // 3. Loại các mục đã bị xoá sau lần sửa cuối cùng.
        let before = self.entries.len();
        self.entries.retain(|e| {
            tombs
                .get(&e.id)
                .is_none_or(|&deleted| deleted < e.updated_at)
        });
        stats.deleted = before - self.entries.len();

        self.tombstones = tombs
            .into_iter()
            .map(|(id, deleted_at)| Tombstone { id, deleted_at })
            .collect();
        self.tombstones.sort_by(|a, b| a.id.cmp(&b.id));
        self.entries.sort_by_key(|e| e.created_at);
        self.modified_at = self.modified_at.max(other.modified_at);
        stats
    }
}

fn merge_histories(mut winner: Entry, loser: &Entry) -> Entry {
    let mut hist: Vec<HistoryItem> = winner.password_history.clone();
    for h in &loser.password_history {
        if !hist.iter().any(|x| x.password == h.password) {
            hist.push(h.clone());
        }
    }
    if loser.password != winner.password
        && !loser.password.is_empty()
        && !hist.iter().any(|x| x.password == loser.password)
    {
        hist.push(HistoryItem {
            password: loser.password.clone(),
            replaced_at: loser.updated_at,
        });
    }
    hist.retain(|h| h.password != winner.password);
    hist.sort_by_key(|h| std::cmp::Reverse(h.replaced_at));
    hist.truncate(MAX_HISTORY);
    winner.password_history = hist;
    winner
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, pw: &str, updated: i64) -> Entry {
        let mut e = Entry::new(id);
        e.id = id.into();
        e.password = pw.into();
        e.created_at = 1;
        e.updated_at = updated;
        e
    }

    #[test]
    fn newer_wins_and_loser_password_kept_in_history() {
        let mut a = VaultData {
            entries: vec![entry("x", "A-pass", 10)],
            ..Default::default()
        };
        let b = VaultData {
            entries: vec![entry("x", "B-pass", 20), entry("y", "y", 5)],
            ..Default::default()
        };
        let s = a.merge_from(&b);
        assert_eq!(
            s,
            MergeStats {
                added: 1,
                updated: 1,
                deleted: 0
            }
        );
        let x = a.entries.iter().find(|e| e.id == "x").unwrap();
        assert_eq!(x.password, "B-pass");
        assert_eq!(x.password_history[0].password, "A-pass");
    }

    #[test]
    fn tombstone_removes_older_entry_but_not_newer_edit() {
        let mut a = VaultData {
            entries: vec![entry("x", "1", 10), entry("z", "1", 50)],
            ..Default::default()
        };
        let b = VaultData {
            tombstones: vec![
                Tombstone {
                    id: "x".into(),
                    deleted_at: 20,
                },
                Tombstone {
                    id: "z".into(),
                    deleted_at: 30,
                },
            ],
            ..Default::default()
        };
        let s = a.merge_from(&b);
        assert_eq!(s.deleted, 1);
        assert_eq!(a.entries.len(), 1);
        assert_eq!(a.entries[0].id, "z");
    }

    #[test]
    fn merge_is_idempotent_and_symmetric_in_content() {
        let a0 = VaultData {
            entries: vec![entry("x", "1", 10), entry("q", "q", 3)],
            tombstones: vec![Tombstone {
                id: "w".into(),
                deleted_at: 9,
            }],
            modified_at: 10,
        };
        let b0 = VaultData {
            entries: vec![entry("x", "2", 11), entry("w", "w", 2)],
            tombstones: vec![],
            modified_at: 11,
        };
        let mut ab = a0.clone();
        ab.merge_from(&b0);
        let mut ba = b0.clone();
        ba.merge_from(&a0);
        let ids = |v: &VaultData| {
            let mut i: Vec<_> = v
                .entries
                .iter()
                .map(|e| (e.id.clone(), e.password.clone()))
                .collect();
            i.sort();
            i
        };
        assert_eq!(ids(&ab), ids(&ba));
        let again = ab.clone();
        assert!(!ab.merge_from(&again).changed());
    }

    #[test]
    fn search() {
        let mut e = Entry::new("Vietcombank");
        e.urls.push("https://vcbdigibank.vietcombank.com.vn".into());
        e.tags.push("Ngân hàng".into());
        assert!(e.matches("vietcom"));
        assert!(e.matches("NGÂN"));
        assert!(!e.matches("gmail"));
    }
}
