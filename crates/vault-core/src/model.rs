//! Mô hình dữ liệu bên trong kho (toàn bộ đều được mã hoá trên đĩa) và thuật toán gộp hai
//! phiên bản của cùng một kho.
//!
//! # Gộp (merge)
//!
//! Mỗi trường của một mục là một "ô ghi-sau-thắng": cặp *(thời điểm sửa, giá trị)*. Gộp hai phiên
//! bản = với TỪNG TRƯỜNG lấy cặp lớn hơn (so thời điểm trước; nếu bằng nhau thì so giá trị theo thứ
//! tự từ điển — chỉ để hai máy luôn chọn giống nhau). Hệ quả:
//!
//! - Máy A đổi mật khẩu, máy B (chưa thấy thay đổi đó) sửa ghi chú ⇒ kết quả có cả hai thay đổi.
//! - Hai máy cùng đổi mật khẩu của một mục ⇒ bản sửa sau thắng, mật khẩu kia vào lịch sử.
//! - Xoá = chuyển vào thùng rác (cũng là một "trường" có thời điểm riêng), nên xoá ở máy này và sửa
//!   ở máy kia không làm mất gì: mục nằm trong thùng rác với nội dung mới nhất.
//! - Xoá vĩnh viễn để lại một *tombstone*: mục đó biến mất trên MỌI máy và không bao giờ quay lại
//!   qua đồng bộ (muốn lấy lại phải khôi phục từ bản sao lưu — khi đó nó là một mục mới).
//!
//! - Mục nhập từ CSV mang thời điểm [`IMPORTED_AT`] ở mọi trường: thua mọi lần sửa thật.
//!
//! Phép gộp có tính giao hoán, kết hợp và luỹ đẳng — kể cả khi lịch sử mật khẩu đã chạm trần
//! [`MAX_HISTORY`] (xem `Entry::canon_history`) — kiểm chứng bằng property test trong
//! `tests/merge_props.rs`. Nhờ vậy các máy gộp theo thứ tự nào cũng ra đúng một kết quả, và hai máy
//! không bao giờ "ghi đè qua lại" vô hạn. (Giả định: dữ liệu do app ghi ra; với thời điểm cực đoan
//! như `i64::MIN` — chỉ có ở dữ liệu méo — không bảo đảm.)

use std::collections::btree_map::Entry as MapEntry;
use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::KEY_LEN;
use crate::error::{Error, Result};

/// Số bản mật khẩu cũ giữ lại cho mỗi mục (thêm 1 nếu mật khẩu hiện tại rỗng — xem
/// `Entry::canon_history`).
pub const MAX_HISTORY: usize = 20;
/// Số khoá cũ (của các lần đổi master password trước) giữ lại để còn mở được bản sao lưu cũ.
pub const MAX_OLD_KEYS: usize = 16;

/// Thời điểm (ms) gán cho MỌI trường nội dung của một mục vừa nhập từ file CSV ("mục nguyên bản").
///
/// Nhập cùng một file CSV trên hai máy cho ra cùng một id (id suy ra từ nội dung). Nếu các trường
/// mang thời điểm nhập (`now`) thì lần nhập thứ hai trên một máy chưa đồng bộ sẽ "thắng" mọi lần sửa
/// thật đã làm trước đó ở máy kia — ghi chú và mã 2FA (không có lịch sử) mất luôn. Với thời điểm cố
/// định rất nhỏ này, hai lần nhập giống hệt nhau thì hoà (cùng giá trị), và BẤT KỲ lần sửa thật nào
/// cũng thắng. Mọi lần sửa thật đều được đóng dấu ≥ `IMPORTED_AT + 1`; 0 vẫn nghĩa là "chưa biết"
/// (file v1).
pub const IMPORTED_AT: i64 = 1;
/// Thời điểm nhỏ nhất của một lần sửa thật.
const MIN_REAL_STAMP: i64 = IMPORTED_AT + 1;

/// Thời gian hiện tại, mili-giây kể từ 1970 (UTC).
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct HistoryItem {
    pub password: String,
    /// Thời điểm (ms) gắn với mật khẩu cũ này, dùng để xếp thứ tự và để gộp. Có HAI nguồn:
    /// - sửa mật khẩu trên một máy: thời điểm nó bị thay = 1 ms trước thời điểm của mật khẩu mới;
    /// - thua khi gộp hai lần sửa đồng thời từ hai máy: thời điểm nó đã được ĐẶT (không thể dùng thời
    ///   điểm của bên thắng: kết quả sẽ phụ thuộc thứ tự gộp).
    ///
    /// Trong dạng chuẩn luôn nhỏ hơn (thời điểm, giá trị) của mật khẩu hiện tại.
    pub replaced_at: i64,
}

impl std::fmt::Debug for HistoryItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HistoryItem")
            .field("replaced_at", &self.replaced_at)
            .finish_non_exhaustive()
    }
}

/// Thời điểm sửa cuối (ms) của từng trường trong một mục. 0 = chưa biết (file định dạng v1):
/// khi nạp sẽ được thay bằng `updated_at` của mục. [`IMPORTED_AT`] = giá trị nhập từ CSV, chưa
/// từng được sửa.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FieldTimes {
    pub title: i64,
    pub username: i64,
    pub password: i64,
    pub urls: i64,
    pub notes: i64,
    pub totp: i64,
    pub tags: i64,
    pub favorite: i64,
    /// Lần cuối mục được chuyển vào / lấy ra khỏi thùng rác (0 = chưa bao giờ).
    pub deleted: i64,
}

impl FieldTimes {
    fn all_content(t: i64) -> Self {
        Self {
            title: t,
            username: t,
            password: t,
            urls: t,
            notes: t,
            totp: t,
            tags: t,
            favorite: t,
            deleted: 0,
        }
    }

    /// Thời điểm sửa nội dung gần nhất (không tính việc chuyển vào/ra thùng rác).
    fn content_max(&self) -> i64 {
        [
            self.title,
            self.username,
            self.password,
            self.urls,
            self.notes,
            self.totp,
            self.tags,
            self.favorite,
        ]
        .into_iter()
        .max()
        .unwrap_or(0)
    }
}

// Lưu ý: không dùng `#[serde(default)]` ở cấp struct vì `Entry` có `Drop` (zeroize);
// thay vào đó đặt default cho từng trường để file cũ thiếu trường vẫn đọc được.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
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
    /// Lúc tạo mục (ms). Khi gộp: giá trị nhỏ nhất của hai bên, bỏ qua 0 (= chưa biết).
    #[serde(default)]
    pub created_at: i64,
    /// Lần sửa nội dung gần nhất = max(`created_at`, giá trị lớn nhất trong `field_times` trừ
    /// `deleted`) — để mục vừa nhập (các trường mang [`IMPORTED_AT`]) không hiện "sửa năm 1970".
    /// (Nếu còn trường mang 0 = "chưa biết" thì chỉ tính `field_times`, như file v1.)
    #[serde(default)]
    pub updated_at: i64,
    #[serde(default)]
    #[zeroize(skip)]
    pub field_times: FieldTimes,
}

/// Không bao giờ in bí mật ra log / thông báo lỗi.
impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entry")
            .field("id", &self.id)
            .field("title", &self.title)
            .field("updated_at", &self.updated_at)
            .finish_non_exhaustive()
    }
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
            field_times: FieldTimes::all_content(now),
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

    /// Thời điểm mục được chuyển vào thùng rác (chỉ có nghĩa với mục đang nằm trong thùng rác).
    pub fn trashed_at(&self) -> i64 {
        self.field_times.deleted
    }

    /// Giá trị đúng của `updated_at` (xem tài liệu của trường đó).
    fn derived_updated_at(&self) -> i64 {
        let ft = &self.field_times;
        let unknown = [
            ft.title,
            ft.username,
            ft.password,
            ft.urls,
            ft.notes,
            ft.totp,
            ft.tags,
            ft.favorite,
        ]
        .contains(&0);
        // Còn trường "chưa biết" (chỉ xảy ra với dữ liệu có thời điểm ≤ 0): không lấy created_at,
        // nếu không lần chuẩn hoá sau sẽ lấy chính giá trị đó lấp vào ⇒ chuẩn hoá không luỹ đẳng.
        if unknown {
            ft.content_max()
        } else {
            ft.content_max().max(self.created_at)
        }
    }

    /// Điền thời điểm cho các trường chưa có (file v1) và tính lại `updated_at`.
    fn normalize_times(&mut self) {
        // max(...) để chuẩn hoá hai lần cũng cho cùng một kết quả.
        let base = self.updated_at.max(self.field_times.content_max());
        let ft = &mut self.field_times;
        for t in [
            &mut ft.title,
            &mut ft.username,
            &mut ft.password,
            &mut ft.urls,
            &mut ft.notes,
            &mut ft.totp,
            &mut ft.tags,
            &mut ft.favorite,
        ] {
            if *t == 0 {
                *t = base;
            }
        }
        self.updated_at = self.derived_updated_at();
    }

    /// Đưa lịch sử mật khẩu về dạng chuẩn.
    ///
    /// Hãy nghĩ về trạng thái mật khẩu của một mục như một TẬP các cặp *(mật khẩu, thời điểm)* gồm
    /// cả mật khẩu hiện tại (nếu khác rỗng) lẫn các dòng lịch sử, mỗi mật khẩu một cặp (giữ thời điểm
    /// muộn nhất), xếp theo MỘT thứ tự toàn phần: *(thời điểm, mật khẩu)* — đúng thứ tự mà phép gộp
    /// dùng để chọn mật khẩu hiện tại. Dạng chuẩn = [`MAX_HISTORY`] + 1 cặp lớn nhất của tập đó;
    /// lịch sử = các cặp ấy trừ mật khẩu hiện tại (nên tối đa [`MAX_HISTORY`] dòng, hoặc
    /// `MAX_HISTORY + 1` khi mật khẩu hiện tại rỗng — ô của nó không bị chiếm).
    ///
    /// Để mật khẩu hiện tại luôn là cặp LỚN NHẤT, dòng nào không đứng dưới nó bị hạ xuống ngay dưới
    /// nó (dữ liệu cũ: bản ≤ 0.2 ghi `replaced_at` = đúng thời điểm của mật khẩu mới). Nhờ vậy phép
    /// gộp = hợp hai tập rồi lấy phần đầu ⇒ giao hoán, kết hợp và luỹ đẳng kể cả khi lịch sử đã chạm
    /// trần. (Cách cũ cắt còn 20 dòng SAU khi bỏ mật khẩu hiện tại, nên một dòng về sau trở thành
    /// mật khẩu hiện tại đã "chiếm chỗ" ở một thứ tự gộp mà không chiếm ở thứ tự khác.)
    fn canon_history(&mut self) {
        let mut hist = std::mem::take(&mut self.password_history);
        let current_since = self.field_times.password;
        for h in &mut hist {
            // (thời điểm, mật khẩu) của mỗi dòng phải nhỏ hơn của mật khẩu hiện tại.
            let limit = if h.password < self.password {
                current_since
            } else {
                current_since.saturating_sub(1)
            };
            h.replaced_at = h.replaced_at.min(limit);
        }
        // Mới nhất trước; cùng thời điểm thì theo thứ tự ngược của mật khẩu — đúng thứ tự "lớn hơn
        // thắng" của phép gộp.
        hist.sort_by(|a, b| {
            b.replaced_at
                .cmp(&a.replaced_at)
                .then_with(|| b.password.cmp(&a.password))
        });
        let cap = if self.password.is_empty() {
            MAX_HISTORY + 1
        } else {
            MAX_HISTORY
        };
        let mut out: Vec<HistoryItem> = Vec::with_capacity(hist.len().min(cap));
        for h in hist {
            if h.password.is_empty()
                || h.password == self.password
                || out.iter().any(|x| x.password == h.password)
            {
                continue; // `h` bị drop ⇒ tự xoá khỏi RAM (ZeroizeOnDrop)
            }
            if out.len() < cap {
                out.push(h);
            }
        }
        self.password_history = out;
    }
}

/// Ghi nhận một mục đã bị xoá vĩnh viễn, để việc đồng bộ không làm nó "sống lại".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tombstone {
    pub id: String,
    pub deleted_at: i64,
}

/// Khoá kho của một lần đổi master password trước. Nằm TRONG phần đã mã hoá: ai mở được kho hiện
/// tại thì mở được các bản sao lưu / bản xung đột cũ; người chỉ biết mật khẩu cũ không mở được kho mới.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct OldKey {
    #[serde(with = "crate::format::b64_array")]
    pub key: [u8; KEY_LEN],
    /// Thời điểm khoá này ngừng được dùng (= lần đổi master password).
    pub retired_at: i64,
}

impl std::fmt::Debug for OldKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OldKey")
            .field("retired_at", &self.retired_at)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(default)]
pub struct VaultData {
    /// Các mục đang dùng.
    pub entries: Vec<Entry>,
    /// Thùng rác: các mục đã xoá nhưng còn khôi phục được.
    pub trash: Vec<Entry>,
    /// Các mục đã xoá vĩnh viễn.
    pub tombstones: Vec<Tombstone>,
    /// Lần sửa cuối cùng của nội dung kho.
    pub modified_at: i64,
    /// Khoá của các lần đổi master password trước (mới nhất trước).
    pub old_keys: Vec<OldKey>,
}

/// Thống kê sau khi gộp hai phiên bản kho (tính trên danh sách mục đang dùng).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MergeStats {
    /// Mục mới xuất hiện.
    pub added: usize,
    /// Mục có nội dung thay đổi.
    pub updated: usize,
    /// Mục biến mất (bị xoá ở phía kia).
    pub deleted: usize,
}

impl MergeStats {
    pub fn changed(&self) -> bool {
        self.added + self.updated + self.deleted > 0
    }
}

/// Một mục cùng trạng thái "đang trong thùng rác" trong lúc gộp.
struct State {
    e: Entry,
    deleted: bool,
}

/// `a.$f` ← giá trị thắng giữa `a.$f` và `b.$f`. Giá trị cũ được xoá khỏi RAM trước khi ghi đè.
macro_rules! lww {
    ($a:expr, $b:expr, $($f:ident),+) => {$(
        if ($b.field_times.$f, &$b.$f) > ($a.field_times.$f, &$a.$f) {
            $a.$f.zeroize();
            $a.$f = $b.$f.clone();
            $a.field_times.$f = $b.field_times.$f;
        }
    )+};
}

/// Gộp `b` vào `a` (cùng id).
fn merge_state(a: &mut State, b: &State) {
    lww!(a.e, b.e, title, username, urls, notes, totp, tags, favorite);

    // Mật khẩu: bản thua không bị mất mà vào lịch sử, kèm thời điểm nó được đặt.
    a.e.password_history
        .extend(b.e.password_history.iter().cloned());
    let b_wins =
        (b.e.field_times.password, &b.e.password) > (a.e.field_times.password, &a.e.password);
    if a.e.password != b.e.password {
        let (loser, loser_t) = if b_wins {
            (&a.e.password, a.e.field_times.password)
        } else {
            (&b.e.password, b.e.field_times.password)
        };
        if !loser.is_empty() {
            let item = HistoryItem {
                password: loser.clone(),
                replaced_at: loser_t,
            };
            a.e.password_history.push(item);
        }
    }
    if b_wins {
        a.e.password.zeroize();
        a.e.password = b.e.password.clone();
        a.e.field_times.password = b.e.field_times.password;
    }

    if (b.e.field_times.deleted, b.deleted) > (a.e.field_times.deleted, a.deleted) {
        a.deleted = b.deleted;
        a.e.field_times.deleted = b.e.field_times.deleted;
    }

    a.e.created_at = match (a.e.created_at, b.e.created_at) {
        (0, x) | (x, 0) => x,
        (x, y) => x.min(y),
    };
}

fn sort_entries(v: &mut [Entry]) {
    v.sort_by(|a, b| {
        a.created_at
            .cmp(&b.created_at)
            .then_with(|| a.id.cmp(&b.id))
    });
}

/// Hợp nhất nhiều phiên bản của cùng một kho thành một phiên bản ở DẠNG CHUẨN (thứ tự cố định,
/// thời điểm từng trường đầy đủ, lịch sử gọn) — hai kho giống nhau về nội dung thì bằng nhau từng byte.
fn join(parts: &[&VaultData]) -> VaultData {
    let mut tombs: BTreeMap<String, i64> = BTreeMap::new();
    let mut map: BTreeMap<String, State> = BTreeMap::new();
    let mut keys: Vec<OldKey> = Vec::new();
    let mut modified_at = 0;

    for part in parts {
        modified_at = modified_at.max(part.modified_at);
        for t in &part.tombstones {
            let x = tombs.entry(t.id.clone()).or_insert(t.deleted_at);
            *x = (*x).max(t.deleted_at);
        }
        for (list, deleted) in [(&part.entries, false), (&part.trash, true)] {
            for e in list {
                let mut st = State {
                    e: e.clone(),
                    deleted,
                };
                st.e.normalize_times();
                st.e.canon_history();
                match map.entry(e.id.clone()) {
                    MapEntry::Vacant(v) => {
                        v.insert(st);
                    }
                    MapEntry::Occupied(mut o) => merge_state(o.get_mut(), &st),
                }
            }
        }
        for k in &part.old_keys {
            match keys.iter_mut().find(|x| x.key == k.key) {
                Some(x) => x.retired_at = x.retired_at.max(k.retired_at),
                None => keys.push(k.clone()),
            }
        }
    }

    let mut out = VaultData {
        modified_at,
        ..Default::default()
    };
    for (id, mut st) in map {
        if tombs.contains_key(&id) {
            continue; // đã xoá vĩnh viễn ở đâu đó ⇒ xoá ở mọi nơi
        }
        st.e.canon_history();
        st.e.updated_at = st.e.derived_updated_at();
        let State { e, deleted } = st;
        if deleted {
            out.trash.push(e);
        } else {
            out.entries.push(e);
        }
    }
    sort_entries(&mut out.entries);
    sort_entries(&mut out.trash);
    out.tombstones = tombs
        .into_iter()
        .map(|(id, deleted_at)| Tombstone { id, deleted_at })
        .collect();
    keys.sort_by(|a, b| {
        b.retired_at
            .cmp(&a.retired_at)
            .then_with(|| a.key.cmp(&b.key))
    });
    keys.truncate(MAX_OLD_KEYS);
    out.old_keys = keys;
    out
}

impl VaultData {
    /// Đưa về dạng chuẩn (gọi sau khi đọc từ đĩa).
    pub fn normalize(&mut self) {
        *self = join(&[self]);
    }

    /// Gộp `other` vào `self` (xem mô tả ở đầu file). Kết quả luôn ở dạng chuẩn.
    pub fn merge_from(&mut self, other: &VaultData) -> MergeStats {
        let merged = join(&[self, other]);
        let before: HashMap<&str, &Entry> =
            self.entries.iter().map(|e| (e.id.as_str(), e)).collect();
        let mut stats = MergeStats::default();
        for e in &merged.entries {
            match before.get(e.id.as_str()) {
                None => stats.added += 1,
                Some(old) if *old != e => stats.updated += 1,
                Some(_) => {}
            }
        }
        stats.deleted = before
            .keys()
            .filter(|id| !merged.entries.iter().any(|e| e.id == **id))
            .count();
        *self = merged;
        stats
    }

    pub fn get(&self, id: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| e.id == id)
    }

    pub fn get_trashed(&self, id: &str) -> Option<&Entry> {
        self.trash.iter().find(|e| e.id == id)
    }

    fn tombstone_time(&self, id: &str) -> Option<i64> {
        self.tombstones
            .iter()
            .find(|t| t.id == id)
            .map(|t| t.deleted_at)
    }

    fn id_in_use(&self, id: &str) -> bool {
        self.get(id).is_some()
            || self.get_trashed(id).is_some()
            || self.tombstone_time(id).is_some()
    }

    fn touch(&mut self, t: i64) {
        self.modified_at = self.modified_at.max(t);
    }

    /// Thêm mục mới, trả về id. Id trùng (kể cả với mục trong thùng rác / đã xoá vĩnh viễn) hoặc
    /// rỗng thì được cấp id mới.
    pub fn add_at(&mut self, entry: Entry, now: i64) -> String {
        let now = now.max(MIN_REAL_STAMP);
        self.insert_new(entry, now, now)
    }

    /// Thêm một mục vừa nhập từ CSV ("nguyên bản"): như [`VaultData::add_at`] nhưng mọi trường nội
    /// dung mang thời điểm [`IMPORTED_AT`] (thua mọi lần sửa thật, xem tài liệu của hằng số đó);
    /// `created_at = now`.
    pub fn add_imported_at(&mut self, entry: Entry, now: i64) -> String {
        self.insert_new(entry, now.max(MIN_REAL_STAMP), IMPORTED_AT)
    }

    fn insert_new(&mut self, mut entry: Entry, now: i64, field_time: i64) -> String {
        if entry.id.is_empty() || self.id_in_use(&entry.id) {
            entry.id = uuid::Uuid::new_v4().to_string();
        }
        entry.created_at = now;
        entry.field_times = FieldTimes::all_content(field_time);
        entry.updated_at = entry.derived_updated_at();
        entry.canon_history();
        let id = entry.id.clone();
        self.entries.push(entry);
        sort_entries(&mut self.entries);
        self.touch(now);
        id
    }

    /// Sửa một mục đang dùng. Chỉ những trường THỰC SỰ thay đổi mới được ghi nhận thời điểm mới
    /// (nhờ vậy gộp với máy khác không đè lên trường mà lần sửa này không đụng tới).
    /// Nếu mật khẩu thay đổi, mật khẩu cũ được đưa vào lịch sử. Trả về true nếu có thay đổi.
    pub fn update_at(&mut self, id: &str, now: i64, edit: impl FnOnce(&mut Entry)) -> Result<bool> {
        let e = self
            .entries
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or_else(|| Error::EntryNotFound(id.to_string()))?;
        let before = e.clone();
        edit(e);
        // Các trường quản lý không cho sửa trực tiếp.
        e.id.clone_from(&before.id);
        e.created_at = before.created_at;
        e.field_times = before.field_times;
        e.password_history.clone_from(&before.password_history);

        let mut changed = false;
        macro_rules! stamp {
            ($($f:ident),+) => {$(
                if e.$f != before.$f {
                    e.field_times.$f = now
                        .max(before.field_times.$f.saturating_add(1))
                        .max(MIN_REAL_STAMP);
                    changed = true;
                }
            )+};
        }
        stamp!(title, username, password, urls, notes, totp, tags, favorite);
        if e.password != before.password {
            if !before.password.is_empty() {
                // "Bị thay lúc" = ngay trước thời điểm của mật khẩu mới (1 ms), để mật khẩu hiện tại
                // luôn đứng trên mọi dòng lịch sử (xem `canon_history`).
                e.password_history.push(HistoryItem {
                    password: before.password.clone(),
                    replaced_at: e.field_times.password.saturating_sub(1),
                });
            }
            e.canon_history();
        }
        e.updated_at = e.derived_updated_at();
        let t = e.updated_at;
        if changed {
            self.touch(t);
        }
        Ok(changed)
    }

    /// Chuyển một mục vào thùng rác.
    pub fn trash_at(&mut self, id: &str, now: i64) -> Result<()> {
        let idx = self
            .entries
            .iter()
            .position(|e| e.id == id)
            .ok_or_else(|| Error::EntryNotFound(id.to_string()))?;
        let mut e = self.entries.remove(idx);
        e.field_times.deleted = now
            .max(e.field_times.deleted.saturating_add(1))
            .max(MIN_REAL_STAMP);
        let t = e.field_times.deleted;
        self.trash.push(e);
        sort_entries(&mut self.trash);
        self.touch(t);
        Ok(())
    }

    /// Lấy một mục ra khỏi thùng rác.
    pub fn restore_at(&mut self, id: &str, now: i64) -> Result<()> {
        let idx = self
            .trash
            .iter()
            .position(|e| e.id == id)
            .ok_or_else(|| Error::EntryNotFound(id.to_string()))?;
        let mut e = self.trash.remove(idx);
        e.field_times.deleted = now
            .max(e.field_times.deleted.saturating_add(1))
            .max(MIN_REAL_STAMP);
        let t = e.field_times.deleted;
        self.entries.push(e);
        sort_entries(&mut self.entries);
        self.touch(t);
        Ok(())
    }

    /// Xoá vĩnh viễn một mục (đang dùng hoặc trong thùng rác) trên mọi thiết bị.
    /// Id của nó không bao giờ được dùng lại.
    pub fn purge_at(&mut self, id: &str, now: i64) -> Result<()> {
        if let Some(i) = self.trash.iter().position(|e| e.id == id) {
            self.trash.remove(i);
        } else if let Some(i) = self.entries.iter().position(|e| e.id == id) {
            self.entries.remove(i);
        } else {
            return Err(Error::EntryNotFound(id.to_string()));
        }
        match self.tombstones.iter_mut().find(|t| t.id == id) {
            Some(t) => t.deleted_at = t.deleted_at.max(now),
            None => self.tombstones.push(Tombstone {
                id: id.to_string(),
                deleted_at: now,
            }),
        }
        self.tombstones.sort_by(|a, b| a.id.cmp(&b.id));
        self.touch(now);
        Ok(())
    }

    /// Đưa phiên bản `old` của một mục (lấy từ bản sao lưu) trở lại làm phiên bản hiện hành, dưới
    /// dạng MỘT LẦN SỬA MỚI — nhờ vậy việc khôi phục lan sang mọi thiết bị thay vì bị gộp ngược lại.
    /// Mật khẩu đang dùng (nếu khác) được đưa vào lịch sử. Mục đã bị xoá vĩnh viễn được thêm lại
    /// như một mục mới (id mới). Trả về true nếu có thay đổi.
    pub fn reinstate_at(&mut self, old: &Entry, now: i64) -> bool {
        let id = old.id.as_str();
        let mut changed = false;
        if self.get_trashed(id).is_some() {
            let _ = self.restore_at(id, now);
            changed = true;
        }
        if self.get(id).is_some() {
            changed |= self
                .update_at(id, now, |e| {
                    macro_rules! copy {
                        ($($f:ident),+) => {$(
                            if e.$f != old.$f {
                                e.$f.zeroize();
                                e.$f = old.$f.clone();
                            }
                        )+};
                    }
                    copy!(title, username, password, urls, notes, totp, tags, favorite);
                })
                .unwrap_or(false);
            return changed;
        }
        // Không còn ở đâu: thêm lại (add_at cấp id mới nếu id cũ đã bị xoá vĩnh viễn).
        self.add_at(old.clone(), now);
        true
    }

    /// Quy tắc của định dạng v1 (bản 0.1.x): tombstone chỉ xoá mục có `updated_at` KHÔNG mới hơn lần
    /// xoá. Bỏ các tombstone mà mục cùng id còn sống và được sửa SAU lần xoá (đúng `deleted_at <
    /// updated_at`, như bản 0.1.2), để sau khi đọc như v2 (tombstone tuyệt đối) mục đó vẫn còn.
    pub(crate) fn drop_tombstones_superseded_in_v1(&mut self) {
        let entries = &self.entries;
        self.tombstones.retain(|t| {
            !entries
                .iter()
                .any(|e| e.id == t.id && t.deleted_at < e.updated_at)
        });
    }

    /// Ghi nhớ một khoá kho vừa ngừng dùng (khi đổi master password).
    pub(crate) fn push_old_key(&mut self, key: &[u8; KEY_LEN], retired_at: i64) {
        if !self.old_keys.iter().any(|k| &k.key == key) {
            self.old_keys.push(OldKey {
                key: *key,
                retired_at,
            });
        }
        self.old_keys.sort_by(|a, b| {
            b.retired_at
                .cmp(&a.retired_at)
                .then_with(|| a.key.cmp(&b.key))
        });
        self.old_keys.truncate(MAX_OLD_KEYS);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, pw: &str, t: i64) -> Entry {
        let mut e = Entry::new(id);
        e.id = id.into();
        e.password = pw.into();
        e.created_at = 1;
        e.updated_at = t;
        e.field_times = FieldTimes::all_content(t);
        e
    }

    fn data(entries: Vec<Entry>) -> VaultData {
        let mut d = VaultData {
            entries,
            ..Default::default()
        };
        d.normalize();
        d
    }

    #[test]
    fn newer_password_wins_and_loser_is_kept_in_history() {
        let mut a = data(vec![entry("x", "A-pass", 10)]);
        let b = data(vec![entry("x", "B-pass", 20), entry("y", "y", 5)]);
        let s = a.merge_from(&b);
        assert_eq!(
            s,
            MergeStats {
                added: 1,
                updated: 1,
                deleted: 0
            }
        );
        let x = a.get("x").unwrap();
        assert_eq!(x.password, "B-pass");
        assert_eq!(x.password_history.len(), 1);
        assert_eq!(x.password_history[0].password, "A-pass");
    }

    /// Lỗi của bản 0.1.2: máy B (chưa thấy mật khẩu mới của máy A) chỉ bấm ★ là đè mất mật khẩu mới.
    #[test]
    fn stale_device_editing_another_field_keeps_the_new_password() {
        let base = data(vec![entry("bank", "old", 10)]);
        let mut a = base.clone();
        let mut b = base.clone();
        a.update_at("bank", 100, |e| {
            e.password = "new-from-A".into();
            e.totp = Some("JBSWY3DPEHPK3PXP".into());
        })
        .unwrap();
        // B sửa SAU đó (theo đồng hồ) nhưng không biết thay đổi của A.
        b.update_at("bank", 200, |e| e.favorite = true).unwrap();
        b.update_at("bank", 201, |e| e.notes = "ghi chú từ B".into())
            .unwrap();

        let mut ab = a.clone();
        ab.merge_from(&b);
        let mut ba = b.clone();
        ba.merge_from(&a);
        assert_eq!(ab, ba);
        let e = ab.get("bank").unwrap();
        assert_eq!(e.password, "new-from-A");
        assert_eq!(e.totp.as_deref(), Some("JBSWY3DPEHPK3PXP"));
        assert!(e.favorite);
        assert_eq!(e.notes, "ghi chú từ B");
        assert_eq!(e.password_history[0].password, "old");
        assert_eq!(e.updated_at, 201);
    }

    #[test]
    fn equal_timestamps_converge_to_the_same_value_on_both_devices() {
        let a0 = data(vec![entry("x", "from-A", 50)]);
        let b0 = data(vec![entry("x", "from-B", 50)]);
        let mut ab = a0.clone();
        ab.merge_from(&b0);
        let mut ba = b0.clone();
        ba.merge_from(&a0);
        assert_eq!(ab, ba);
        let x = ab.get("x").unwrap();
        assert_eq!(x.password, "from-B", "thứ tự từ điển quyết định khi hoà");
        assert_eq!(x.password_history[0].password, "from-A");
    }

    #[test]
    fn delete_goes_to_trash_and_a_concurrent_edit_is_not_lost() {
        let base = data(vec![entry("x", "p1", 10)]);
        let mut a = base.clone();
        let mut b = base.clone();
        a.trash_at("x", 100).unwrap();
        assert!(a.get("x").is_none() && a.get_trashed("x").is_some());
        b.update_at("x", 150, |e| e.password = "p2".into()).unwrap();
        let mut m = a.clone();
        let s = m.merge_from(&b);
        assert_eq!(s.deleted, 0, "phía a đã không còn mục này trong danh sách");
        assert!(m.get("x").is_none(), "vẫn bị xoá…");
        let t = m.get_trashed("x").unwrap();
        assert_eq!(
            t.password, "p2",
            "…nhưng mật khẩu mới vẫn còn trong thùng rác"
        );
        assert_eq!(t.trashed_at(), 100);
        // Khôi phục ở đâu thì mọi máy cùng thấy lại.
        m.restore_at("x", 300).unwrap();
        let mut b2 = b.clone();
        b2.merge_from(&m);
        assert_eq!(b2.get("x").unwrap().password, "p2");
        let mut a2 = a.clone();
        a2.merge_from(&m);
        assert_eq!(a2, b2);
    }

    #[test]
    fn purge_is_permanent_on_every_device() {
        let base = data(vec![entry("x", "p1", 10), entry("z", "zz", 10)]);
        let mut a = base.clone();
        a.trash_at("x", 20).unwrap();
        a.purge_at("x", 100).unwrap();
        assert!(a.get_trashed("x").is_none());
        assert_eq!(a.tombstones.len(), 1);

        // Máy chưa biết gì: mục bị xoá hẳn, mục khác không ảnh hưởng.
        let mut stale = base.clone();
        let s = stale.merge_from(&a);
        assert_eq!(s.deleted, 1);
        assert!(stale.get("x").is_none() && stale.get_trashed("x").is_none());
        assert!(stale.get("z").is_some());

        // Máy đã sửa mục đó sau thời điểm xoá: vẫn bị xoá (xoá vĩnh viễn là dứt khoát), và hai
        // chiều gộp cho cùng một kết quả.
        let mut late = base.clone();
        late.update_at("x", 150, |e| e.notes = "sửa sau khi đã xoá".into())
            .unwrap();
        late.trash_at("x", 160).unwrap();
        late.restore_at("x", 170).unwrap();
        let mut m1 = late.clone();
        m1.merge_from(&a);
        let mut m2 = a.clone();
        m2.merge_from(&late);
        assert_eq!(m1, m2);
        assert!(m1.get("x").is_none() && m1.get_trashed("x").is_none());
        assert!(matches!(
            m1.purge_at("x", 200),
            Err(Error::EntryNotFound(_))
        ));
    }

    #[test]
    fn v1_data_without_field_times_behaves_like_whole_entry_timestamps() {
        // File định dạng v1: không có field_times, không có thùng rác.
        let v1 = r#"{"entries":[{"id":"x","title":"T","password":"p","created_at":1,"updated_at":10,
            "password_history":[{"password":"p","replaced_at":5},{"password":"o","replaced_at":4}]}],
            "tombstones":[{"id":"gone","deleted_at":7}],"modified_at":10}"#;
        let mut d: VaultData = serde_json::from_str(v1).unwrap();
        d.normalize();
        let x = d.get("x").unwrap();
        assert_eq!(x.field_times, FieldTimes::all_content(10));
        assert_eq!(
            x.password_history
                .iter()
                .map(|h| h.password.as_str())
                .collect::<Vec<_>>(),
            vec!["o"],
            "dòng lịch sử trùng mật khẩu hiện tại bị bỏ"
        );
        // Tombstone của file v1 vẫn có hiệu lực.
        let mut other = data(vec![entry("gone", "g", 6)]);
        other.merge_from(&d);
        assert!(other.get("gone").is_none() && other.get_trashed("gone").is_none());
    }

    #[test]
    fn update_only_stamps_fields_that_changed() {
        let mut d = data(vec![entry("x", "p", 10)]);
        assert!(!d.update_at("x", 50, |_| {}).unwrap());
        assert!(d
            .update_at("x", 50, |e| {
                e.title = "x".into(); // không đổi
                e.username = "u".into();
                e.id = "hack".into();
                e.created_at = 999;
                e.password_history.clear();
            })
            .unwrap());
        let e = d.get("x").unwrap();
        assert_eq!(e.created_at, 1);
        assert_eq!(e.field_times.username, 50);
        assert_eq!(e.field_times.title, 10);
        assert_eq!(e.field_times.password, 10);
        assert_eq!(e.updated_at, 50);
        // Đồng hồ lùi: thời điểm vẫn tăng.
        d.update_at("x", 3, |e| e.username = "u2".into()).unwrap();
        assert_eq!(d.get("x").unwrap().field_times.username, 51);
        assert!(matches!(
            d.update_at("nope", 1, |_| {}),
            Err(Error::EntryNotFound(_))
        ));
    }

    /// Thời điểm cực lớn (đồng hồ hỏng, dữ liệu méo) không được làm tràn số ⇒ không panic.
    #[test]
    fn extreme_timestamps_do_not_overflow() {
        let mut d = data(vec![entry("x", "p", i64::MAX)]);
        assert!(d.update_at("x", 5, |e| e.password = "q".into()).unwrap());
        assert_eq!(d.get("x").unwrap().field_times.password, i64::MAX);
        d.trash_at("x", 5).unwrap();
        d.restore_at("x", 5).unwrap();
        let mut e = entry("y", "p", 1);
        e.field_times.deleted = i64::MAX;
        let mut d2 = data(vec![e]);
        d2.trash_at("y", 5).unwrap();
        d2.restore_at("y", 5).unwrap();
        d2.merge_from(&d);
        let mut neg = data(vec![entry("z", "p", i64::MIN)]);
        neg.update_at("z", i64::MIN, |e| e.notes = "n".into())
            .unwrap();
        neg.merge_from(&d2);
        assert_eq!(neg.entries.len(), 3);
    }

    #[test]
    fn history_is_capped_and_unique() {
        let mut d = data(vec![entry("x", "p0", 10)]);
        for i in 1..=30 {
            d.update_at("x", 10 + i, |e| e.password = format!("p{i}"))
                .unwrap();
        }
        d.update_at("x", 100, |e| e.password = "p29".into())
            .unwrap();
        let e = d.get("x").unwrap();
        assert_eq!(e.password, "p29");
        assert_eq!(e.password_history.len(), MAX_HISTORY);
        assert_eq!(e.password_history[0].password, "p30");
        assert!(e.password_history.iter().all(|h| h.password != "p29"));
    }

    /// Rà soát "F-assoc": khi lịch sử chạm trần 20 dòng, (a∘b)∘c ≠ a∘(b∘c) — một dòng của b∘c trùng
    /// với mật khẩu hiện tại của a đã chiếm một chỗ rồi bị bỏ, nên một thứ tự gộp mất `p26`.
    /// (Phản ví dụ thu gọn do property test tìm ra.)
    #[test]
    fn merge_is_associative_when_history_is_at_the_cap() {
        let hist = |items: &[(&str, i64)]| -> Vec<HistoryItem> {
            items
                .iter()
                .map(|(p, t)| HistoryItem {
                    password: p.to_string(),
                    replaced_at: *t,
                })
                .collect()
        };
        let a = data(vec![entry("b", "p01", 6)]);
        let mut eb = entry("b", "", 1);
        eb.password_history = hist(&[
            ("p02", 0),
            ("p07", 0),
            ("p08", 0),
            ("p21", 0),
            ("p24", 0),
            ("p25", 0),
        ]);
        let b = data(vec![eb]);
        let mut ec = entry("b", "", 2);
        let mut items = vec![("p15", 1)];
        for p in [
            "p01", "p03", "p04", "p05", "p09", "p10", "p11", "p12", "p13", "p14", "p16", "p18",
            "p19", "p26",
        ] {
            items.push((p, 0));
        }
        ec.password_history = hist(&items);
        let c = data(vec![ec]);
        let m = |x: &VaultData, y: &VaultData| {
            let mut z = x.clone();
            z.merge_from(y);
            z
        };
        let left = m(&m(&a, &b), &c);
        let right = m(&a, &m(&b, &c));
        assert_eq!(left, right);
        let e = left.get("b").unwrap();
        assert_eq!(e.password, "p01");
        assert_eq!(e.password_history.len(), MAX_HISTORY);
        assert!(e.password_history.iter().any(|h| h.password == "p26"));
        assert!(e.password_history.iter().all(|h| h.password != "p01"));
        // Mật khẩu hiện tại rỗng: ô của nó không bị chiếm ⇒ giữ MAX_HISTORY + 1 dòng.
        let bc = m(&b, &c);
        assert_eq!(bc.get("b").unwrap().password_history.len(), MAX_HISTORY + 1);
    }

    #[test]
    fn reinstate_from_backup_is_a_new_edit_that_wins_everywhere() {
        let mut d = data(vec![entry("x", "good", 10)]);
        let backup = d.clone();
        d.update_at("x", 20, |e| {
            e.password = "mistake".into();
            e.notes = "oops".into();
        })
        .unwrap();
        let other_device = d.clone();
        // Khôi phục từ bản sao lưu.
        assert!(d.reinstate_at(backup.get("x").unwrap(), 30));
        assert!(
            !d.reinstate_at(backup.get("x").unwrap(), 31),
            "đã giống rồi"
        );
        let mut o = other_device.clone();
        o.merge_from(&d);
        assert_eq!(o.get("x").unwrap().password, "good");
        assert_eq!(o.get("x").unwrap().notes, "");
        assert_eq!(o.get("x").unwrap().password_history[0].password, "mistake");

        // Mục đang trong thùng rác / đã xoá vĩnh viễn cũng lấy lại được.
        d.trash_at("x", 40).unwrap();
        assert!(d.reinstate_at(backup.get("x").unwrap(), 50));
        assert!(d.get("x").is_some());
        d.purge_at("x", 60).unwrap();
        assert!(d.reinstate_at(backup.get("x").unwrap(), 55));
        let mut o2 = other_device.clone();
        o2.merge_from(&d);
        assert!(o2.get("x").is_none(), "id cũ đã bị xoá vĩnh viễn");
        assert_eq!(o2.entries.len(), 1);
        assert_eq!(o2.entries[0].password, "good");
        assert_ne!(o2.entries[0].id, "x");
        assert_eq!(o2, {
            let mut x = d.clone();
            x.merge_from(&other_device);
            x
        });
    }

    #[test]
    fn add_never_reuses_an_id_that_was_deleted() {
        let mut d = data(vec![entry("x", "p", 10)]);
        d.purge_at("x", 20).unwrap();
        let id = d.add_at(entry("x", "new", 0), 30);
        assert_ne!(id, "x");
        let id2 = d.add_at(entry("fresh", "new", 0), 31);
        assert_eq!(id2, "fresh");
        d.trash_at("fresh", 40).unwrap();
        assert_ne!(d.add_at(entry("fresh", "again", 0), 41), "fresh");
    }

    #[test]
    fn old_keys_are_merged_capped_and_never_printed() {
        let mut a = VaultData::default();
        for i in 0..20u8 {
            a.push_old_key(&[i; KEY_LEN], i64::from(i));
        }
        assert_eq!(a.old_keys.len(), MAX_OLD_KEYS);
        assert_eq!(a.old_keys[0].retired_at, 19);
        let mut b = VaultData::default();
        b.push_old_key(&[19; KEY_LEN], 25);
        b.push_old_key(&[99; KEY_LEN], 30);
        a.merge_from(&b);
        assert_eq!(a.old_keys[0].key, [99; KEY_LEN]);
        assert_eq!(a.old_keys[1].retired_at, 25);
        assert_eq!(a.old_keys.len(), MAX_OLD_KEYS);
        let dbg = format!("{a:?}");
        assert!(!dbg.contains("99, 99"), "khoá cũ không được lọt ra Debug");
    }

    #[test]
    fn debug_output_never_contains_secrets() {
        let mut e = entry("x", "S3CRET-PW", 10);
        e.notes = "S3CRET-NOTE".into();
        e.totp = Some("S3CRET-TOTP".into());
        e.password_history.push(HistoryItem {
            password: "S3CRET-OLD".into(),
            replaced_at: 5,
        });
        let d = data(vec![e]);
        let s = format!("{d:?} {:?}", d.entries[0].password_history);
        assert!(!s.contains("S3CRET"), "{s}");
    }

    /// Thêm/bớt/đổi tên trường trong dữ liệu lưu trên đĩa là thay đổi định dạng: bản app cũ sẽ làm
    /// mất trường mới khi ghi lại file. Nếu test này đỏ: tăng `format::VERSION` (để bản cũ từ chối
    /// mở thay vì âm thầm làm mất dữ liệu), cập nhật docs/FORMAT.md, tools/pwv_recover.py, rồi mới
    /// sửa danh sách dưới đây.
    #[test]
    fn schema_change_requires_format_version_bump() {
        fn keys(v: &serde_json::Value) -> Vec<String> {
            let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
            k.sort();
            k
        }
        assert_eq!(crate::format::VERSION, 2);
        let mut e = entry("x", "p", 10);
        e.password_history.push(HistoryItem {
            password: "o".into(),
            replaced_at: 1,
        });
        let mut d = VaultData {
            entries: vec![e],
            tombstones: vec![Tombstone {
                id: "t".into(),
                deleted_at: 1,
            }],
            ..Default::default()
        };
        d.push_old_key(&[1; KEY_LEN], 1);
        let v = serde_json::to_value(&d).unwrap();
        assert_eq!(
            keys(&v),
            ["entries", "modified_at", "old_keys", "tombstones", "trash"]
        );
        assert_eq!(
            keys(&v["entries"][0]),
            [
                "created_at",
                "favorite",
                "field_times",
                "id",
                "notes",
                "password",
                "password_history",
                "tags",
                "title",
                "totp",
                "updated_at",
                "urls",
                "username"
            ]
        );
        assert_eq!(
            keys(&v["entries"][0]["field_times"]),
            [
                "deleted", "favorite", "notes", "password", "tags", "title", "totp", "urls",
                "username"
            ]
        );
        assert_eq!(
            keys(&v["entries"][0]["password_history"][0]),
            ["password", "replaced_at"]
        );
        assert_eq!(keys(&v["tombstones"][0]), ["deleted_at", "id"]);
        assert_eq!(keys(&v["old_keys"][0]), ["key", "retired_at"]);
    }

    const CSV: &str = "name,url,username,password\nBank,https://bank.example,me,oldpw\n";

    fn imported() -> Entry {
        crate::import::import_csv(CSV.as_bytes(), &[])
            .unwrap()
            .entries[0]
            .clone()
    }

    /// Rà soát "import-race": máy A nhập CSV rồi sửa mật khẩu + ghi chú + mã 2FA; máy B (chưa đồng bộ)
    /// nhập lại CÙNG file CSV sau đó (theo đồng hồ). Trước đây bản nhập của B thắng mọi trường: ghi
    /// chú và mã 2FA mất hẳn (không có lịch sử), mật khẩu mới chỉ còn trong lịch sử.
    #[test]
    fn reimporting_the_same_csv_on_a_stale_device_never_reverts_real_edits() {
        let mut a = VaultData::default();
        let mut b = VaultData::default();
        let id = a.add_imported_at(imported(), 1000);
        a.update_at(&id, 2000, |e| {
            e.password = "NEW-from-A".into();
            e.notes = "recovery codes: 1111 2222".into();
            e.totp = Some("JBSWY3DPEHPK3PXP".into());
        })
        .unwrap();
        assert_eq!(
            b.add_imported_at(imported(), 3000),
            id,
            "id suy ra từ nội dung"
        );
        let mut ab = a.clone();
        ab.merge_from(&b);
        let mut ba = b.clone();
        ba.merge_from(&a);
        assert_eq!(ab, ba);
        let e = ab.get(&id).unwrap();
        assert_eq!(e.password, "NEW-from-A");
        assert_eq!(e.notes, "recovery codes: 1111 2222");
        assert_eq!(e.totp.as_deref(), Some("JBSWY3DPEHPK3PXP"));
        assert_eq!(
            e.password_history
                .iter()
                .map(|h| h.password.as_str())
                .collect::<Vec<_>>(),
            ["oldpw"]
        );
        assert_eq!(e.created_at, 1000);
        assert_eq!(e.updated_at, 2000);
    }

    #[test]
    fn the_same_csv_imported_on_two_devices_is_one_entry_without_history_noise() {
        let mut a = VaultData::default();
        let mut b = VaultData::default();
        let id = a.add_imported_at(imported(), 5000);
        b.add_imported_at(imported(), 3000);
        for x in [&a, &b] {
            let e = x.get(&id).unwrap();
            assert_eq!(e.field_times, FieldTimes::all_content(IMPORTED_AT));
            assert_eq!(e.updated_at, e.created_at, "không hiện 'sửa năm 1970'");
        }
        let mut ab = a.clone();
        ab.merge_from(&b);
        let mut ba = b.clone();
        ba.merge_from(&a);
        assert_eq!(ab, ba);
        assert_eq!(ab.entries.len(), 1);
        let e = ab.get(&id).unwrap();
        assert!(e.password_history.is_empty());
        // created_at nhỏ nhất của hai máy; updated_at = created_at.
        assert_eq!((e.created_at, e.updated_at), (3000, 3000));
        let mut again = ab.clone();
        again.normalize();
        assert_eq!(again, ab);
    }

    #[test]
    fn an_edit_after_import_wins_and_keeps_the_csv_password_in_history() {
        let mut a = VaultData::default();
        let id = a.add_imported_at(imported(), 1000);
        a.update_at(&id, 1500, |e| e.password = "doi-sau-khi-nhap".into())
            .unwrap();
        // Máy khác nhập cùng file CSV muộn hơn nhiều (theo đồng hồ của nó).
        let mut b = VaultData::default();
        b.add_imported_at(imported(), 9000);
        for (x, y) in [(&a, &b), (&b, &a)] {
            let mut m = x.clone();
            m.merge_from(y);
            let e = m.get(&id).unwrap();
            assert_eq!(e.password, "doi-sau-khi-nhap");
            assert_eq!(e.password_history.len(), 1);
            assert_eq!(e.password_history[0].password, "oldpw");
            assert_eq!((e.created_at, e.updated_at), (1000, 1500));
        }
    }

    /// Đồng hồ trước 1970 (hoặc dữ liệu méo) không được đóng dấu 0 ("chưa biết") hay IMPORTED_AT
    /// cho một lần sửa thật.
    #[test]
    fn real_edits_are_always_stamped_after_imported_at() {
        let mut d = VaultData::default();
        let id = d.add_at(entry("x", "p", 0), -5);
        assert_eq!(d.get(&id).unwrap().field_times.title, IMPORTED_AT + 1);
        let mut e = entry("y", "p", -1);
        e.id = "y".into();
        let mut d = data(vec![e]);
        d.update_at("y", -100, |e| e.notes = "n".into()).unwrap();
        assert_eq!(d.get("y").unwrap().field_times.notes, IMPORTED_AT + 1);
        d.trash_at("y", -100).unwrap();
        assert!(d.get_trashed("y").unwrap().field_times.deleted > IMPORTED_AT);
        let mut n = d.clone();
        n.normalize();
        assert_eq!(n, d);
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
