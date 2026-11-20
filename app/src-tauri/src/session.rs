//! Trạng thái phiên làm việc và toàn bộ logic của app, không phụ thuộc Tauri (test được).
//!
//! Nguyên tắc: mật khẩu và secret 2FA **không** được gửi sang giao diện (JavaScript) trừ khi
//! người dùng bấm "hiện". Sao chép được làm trực tiếp từ Rust vào clipboard.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use pwv_generator::{
    estimate_strength, generate_passphrase, generate_password, PassphraseOptions, PasswordOptions,
    Strength,
};
use pwv_vault_core::config::{is_uri, suggest_vault_location, Config};
use pwv_vault_core::{CreateOptions, Entry, KdfParams, MergeStats, SaveReport, Totp, Vault};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub type AppResult<T> = Result<T, String>;

fn err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

pub struct Session {
    pub vault: Option<Vault>,
    pub config: Config,
    pub last_activity: Instant,
    /// Tham số KDF khi tạo kho mới (test dùng tham số thấp).
    pub create_opts: CreateOptions,
}

impl Default for Session {
    fn default() -> Self {
        Self {
            vault: None,
            config: Config::load(),
            last_activity: Instant::now(),
            create_opts: CreateOptions::default(),
        }
    }
}

// ----------------------------------------------------------------------------- DTO

#[derive(Debug, Serialize)]
pub struct Status {
    pub unlocked: bool,
    pub vault_path: Option<String>,
    pub vault_exists: bool,
    pub suggested_path: String,
    pub conflict_copies: usize,
    pub memory_locked: bool,
    pub entry_count: usize,
}

#[derive(Debug, Serialize)]
pub struct EntrySummary {
    pub id: String,
    pub title: String,
    pub username: String,
    pub url: Option<String>,
    pub favorite: bool,
    pub tags: Vec<String>,
    pub has_totp: bool,
    pub updated_at: i64,
}

#[derive(Debug, Serialize)]
pub struct EntryDetail {
    pub id: String,
    pub title: String,
    pub username: String,
    pub urls: Vec<String>,
    pub notes: String,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub has_password: bool,
    pub has_totp: bool,
    pub totp_label: Option<String>,
    pub history_count: usize,
    pub strength: Strength,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct EntryInput {
    pub id: Option<String>,
    pub title: String,
    #[serde(default)]
    pub username: String,
    /// `None` = giữ nguyên mật khẩu cũ.
    pub password: Option<String>,
    #[serde(default)]
    pub urls: Vec<String>,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub favorite: bool,
    /// `None` = giữ nguyên; `Some("")` = xoá; còn lại = secret mới.
    pub totp: Option<String>,
}

impl Drop for EntryInput {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.password.zeroize();
        self.totp.zeroize();
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum GenRequest {
    Password(PasswordOptions),
    Passphrase(PassphraseOptions),
}

#[derive(Debug, Serialize)]
pub struct Generated {
    pub value: String,
    pub entropy_bits: f64,
    pub strength: Strength,
}

#[derive(Debug, Serialize)]
pub struct TotpCode {
    pub code: String,
    pub remaining: u64,
    pub period: u64,
}

#[derive(Debug, Serialize)]
pub struct HistoryView {
    pub password: String,
    pub replaced_at: i64,
}

#[derive(Debug, Serialize, Default)]
pub struct SyncResult {
    pub changed: bool,
    pub added: usize,
    pub updated: usize,
    pub deleted: usize,
    pub conflicts_merged: usize,
    pub errors: Vec<String>,
    pub password_changed_elsewhere: bool,
}

impl SyncResult {
    fn add(&mut self, s: MergeStats) {
        self.added += s.added;
        self.updated += s.updated;
        self.deleted += s.deleted;
        self.changed |= s.changed();
    }
    fn from_save(r: SaveReport) -> Self {
        let mut out = SyncResult {
            password_changed_elsewhere: r.adopted_remote_password,
            ..Default::default()
        };
        if let Some(s) = r.merged_remote {
            out.add(s);
        }
        out
    }
}

#[derive(Debug, Serialize)]
pub struct HealthItem {
    pub id: String,
    pub title: String,
    pub username: String,
    pub severity: u8,
    pub issues: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct HealthView {
    pub score: u8,
    pub checked: usize,
    pub breached: usize,
    pub reused: usize,
    pub weak: usize,
    pub old: usize,
    pub breach_check_done: bool,
    pub breach_error: Option<String>,
    pub items: Vec<HealthItem>,
}

#[derive(Debug, Serialize)]
pub struct ImportView {
    pub imported: usize,
    pub duplicates: usize,
    pub skipped: usize,
    pub detected: String,
    pub csv_deleted: bool,
}

#[derive(Debug, Serialize)]
pub struct MoveView {
    pub new_path: String,
    pub backups_moved: bool,
    pub old_removed: bool,
    pub conflicts_merged: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Settings {
    pub auto_lock_minutes: u32,
    pub clipboard_clear_secs: u32,
    #[serde(default = "yes")]
    pub check_updates: bool,
}

fn yes() -> bool {
    true
}

// ----------------------------------------------------------------------------- logic

pub fn check_master_strength(pw: &str) -> AppResult<()> {
    let s = estimate_strength(pw, &[]);
    if pw.chars().count() < 12 || s.score < 3 {
        return Err(format!(
            "Mật khẩu chính quá yếu ({}). Cần ít nhất 12 ký tự và độ mạnh ≥ 3/4 — hãy dùng một cụm 5–6 từ.",
            s.label
        ));
    }
    Ok(())
}

impl Session {
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Trả về true nếu vừa tự khoá.
    pub fn auto_lock_if_idle(&mut self) -> bool {
        let mins = self.config.auto_lock_minutes;
        if mins == 0 || self.vault.is_none() {
            return false;
        }
        if self.last_activity.elapsed() >= Duration::from_secs(u64::from(mins) * 60) {
            self.vault = None;
            return true;
        }
        false
    }

    fn vault(&self) -> AppResult<&Vault> {
        self.vault
            .as_ref()
            .ok_or_else(|| "Kho đang khoá".to_string())
    }

    fn vault_mut(&mut self) -> AppResult<&mut Vault> {
        self.vault
            .as_mut()
            .ok_or_else(|| "Kho đang khoá".to_string())
    }

    fn entry(&self, id: &str) -> AppResult<&Entry> {
        self.vault()?
            .get(id)
            .ok_or_else(|| format!("Không tìm thấy mục {id}"))
    }

    pub fn status(&self) -> Status {
        let path = self
            .vault
            .as_ref()
            .map(|v| v.path().to_path_buf())
            .or_else(|| self.config.vault.clone());
        Status {
            unlocked: self.vault.is_some(),
            // Đường dẫn dạng URI (Android) không kiểm tra được bằng is_file ⇒ coi như có.
            vault_exists: path.as_ref().is_some_and(|p| is_uri(p) || p.is_file()),
            vault_path: path.map(|p| p.display().to_string()),
            suggested_path: suggest_vault_location().display().to_string(),
            conflict_copies: self.vault.as_ref().map_or(0, |v| v.conflict_copies().len()),
            memory_locked: self.vault.as_ref().is_some_and(Vault::memory_locked),
            entry_count: self.vault.as_ref().map_or(0, |v| v.entries().len()),
        }
    }

    pub fn create_vault(&mut self, path: &Path, password: &str) -> AppResult<()> {
        check_master_strength(password)?;
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir).map_err(err)?;
        }
        let v = Vault::create(path, password.as_bytes(), self.create_opts).map_err(err)?;
        self.config.set_vault(v.path()).map_err(err)?;
        self.vault = Some(v);
        self.touch();
        Ok(())
    }

    pub fn unlock(&mut self, path: &Path, password: &str) -> AppResult<()> {
        let v = Vault::open(path, password.as_bytes()).map_err(err)?;
        if self.config.vault.as_deref() != Some(v.path()) {
            self.config.set_vault(v.path()).map_err(err)?;
        }
        self.vault = Some(v);
        self.touch();
        Ok(())
    }

    /// Mở kho chỉ đọc từ dữ liệu thô (điện thoại).
    pub fn unlock_bytes(&mut self, label: &str, bytes: &[u8], password: &str) -> AppResult<()> {
        let v = Vault::open_bytes(label, bytes, password.as_bytes()).map_err(err)?;
        self.vault = Some(v);
        self.touch();
        Ok(())
    }

    /// Thay nội dung kho chỉ đọc bằng bản mới vừa đọc được. Trả về true nếu có thay đổi.
    pub fn reload_bytes(&mut self, bytes: &[u8]) -> AppResult<bool> {
        self.touch();
        self.vault_mut()?.replace_from_bytes(bytes).map_err(err)
    }

    pub fn lock(&mut self) {
        self.vault = None;
    }

    /// Ghi nhớ vị trí kho mới mà không khoá kho đang mở (chọn lại file trên điện thoại).
    pub fn set_vault_location_keep_open(&mut self, location: &str) -> AppResult<()> {
        self.config.set_vault(Path::new(location)).map_err(err)
    }

    pub fn set_vault_path(&mut self, path: &Path) -> AppResult<()> {
        self.vault = None;
        self.config.set_vault(path).map_err(err)
    }

    pub fn list(&self, query: &str) -> AppResult<Vec<EntrySummary>> {
        Ok(self
            .vault()?
            .search(query)
            .into_iter()
            .map(|e| EntrySummary {
                id: e.id.clone(),
                title: e.title.clone(),
                username: e.username.clone(),
                url: e.urls.first().cloned(),
                favorite: e.favorite,
                tags: e.tags.clone(),
                has_totp: e.totp.is_some(),
                updated_at: e.updated_at,
            })
            .collect())
    }

    pub fn detail(&self, id: &str) -> AppResult<EntryDetail> {
        let e = self.entry(id)?;
        let totp_label = e
            .totp
            .as_deref()
            .and_then(|t| Totp::parse(t).ok())
            .map(|t| match (t.issuer, t.account) {
                (Some(i), Some(a)) => format!("{i} ({a})"),
                (Some(x), None) | (None, Some(x)) => x,
                (None, None) => "Mã 2FA".into(),
            });
        Ok(EntryDetail {
            id: e.id.clone(),
            title: e.title.clone(),
            username: e.username.clone(),
            urls: e.urls.clone(),
            notes: e.notes.clone(),
            tags: e.tags.clone(),
            favorite: e.favorite,
            has_password: !e.password.is_empty(),
            has_totp: e.totp.is_some(),
            totp_label,
            history_count: e.password_history.len(),
            strength: estimate_strength(&e.password, &[&e.username, &e.title]),
            created_at: e.created_at,
            updated_at: e.updated_at,
        })
    }

    pub fn reveal_password(&mut self, id: &str) -> AppResult<String> {
        self.touch();
        Ok(self.entry(id)?.password.clone())
    }

    pub fn history(&mut self, id: &str) -> AppResult<Vec<HistoryView>> {
        self.touch();
        Ok(self
            .entry(id)?
            .password_history
            .iter()
            .map(|h| HistoryView {
                password: h.password.clone(),
                replaced_at: h.replaced_at,
            })
            .collect())
    }

    /// Giá trị cần sao chép (field: "password" | "username" | "totp" | "url").
    pub fn field_value(&mut self, id: &str, field: &str) -> AppResult<Zeroizing<String>> {
        self.touch();
        let e = self.entry(id)?;
        let v = match field {
            "password" => e.password.clone(),
            "username" => e.username.clone(),
            "url" => e.urls.first().cloned().unwrap_or_default(),
            "totp" => {
                let t =
                    Totp::parse(e.totp.as_deref().ok_or("Mục này chưa có mã 2FA")?).map_err(err)?;
                t.now().0
            }
            _ => return Err(format!("Trường không hợp lệ: {field}")),
        };
        if v.is_empty() {
            return Err("Trường này đang trống".into());
        }
        Ok(Zeroizing::new(v))
    }

    pub fn totp(&self, id: &str) -> AppResult<TotpCode> {
        let e = self.entry(id)?;
        let t = Totp::parse(e.totp.as_deref().ok_or("Mục này chưa có mã 2FA")?).map_err(err)?;
        let (code, remaining) = t.now();
        Ok(TotpCode {
            code,
            remaining,
            period: t.period,
        })
    }

    pub fn save_entry(&mut self, input: EntryInput) -> AppResult<(String, SyncResult)> {
        self.touch();
        if input.title.trim().is_empty() {
            return Err("Tiêu đề không được để trống".into());
        }
        let totp = match input.totp.as_deref().map(str::trim) {
            None => None,
            Some("") => Some(None),
            Some(t) => {
                Totp::parse(t).map_err(err)?;
                Some(Some(t.to_string()))
            }
        };
        let urls: Vec<String> = input
            .urls
            .iter()
            .map(|u| u.trim().to_string())
            .filter(|u| !u.is_empty())
            .collect();
        let tags: Vec<String> = input
            .tags
            .iter()
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .collect();
        let v = self.vault_mut()?;
        let id = match input.id.as_deref() {
            Some(id) if !id.is_empty() => {
                v.update(id, |e| {
                    e.title = input.title.trim().to_string();
                    e.username = input.username.trim().to_string();
                    if let Some(p) = &input.password {
                        e.password = p.clone();
                    }
                    e.urls = urls;
                    e.notes = input.notes.clone();
                    e.tags = tags;
                    e.favorite = input.favorite;
                    if let Some(t) = totp {
                        e.totp = t;
                    }
                })
                .map_err(err)?;
                id.to_string()
            }
            _ => {
                let mut e = Entry::new(input.title.trim());
                e.username = input.username.trim().to_string();
                e.password = input.password.clone().unwrap_or_default();
                e.urls = urls;
                e.notes = input.notes.clone();
                e.tags = tags;
                e.favorite = input.favorite;
                e.totp = totp.flatten();
                v.add(e)
            }
        };
        let r = v.save().map_err(err)?;
        Ok((id, SyncResult::from_save(r)))
    }

    pub fn delete_entry(&mut self, id: &str) -> AppResult<SyncResult> {
        self.touch();
        let v = self.vault_mut()?;
        v.delete(id).map_err(err)?;
        Ok(SyncResult::from_save(v.save().map_err(err)?))
    }

    pub fn toggle_favorite(&mut self, id: &str) -> AppResult<()> {
        self.touch();
        let v = self.vault_mut()?;
        v.update(id, |e| e.favorite = !e.favorite).map_err(err)?;
        v.save().map_err(err)?;
        Ok(())
    }

    /// Nạp thay đổi từ máy khác (qua Google Drive) và gộp các bản xung đột.
    pub fn sync(&mut self) -> AppResult<SyncResult> {
        let v = self.vault_mut()?;
        let mut out = SyncResult::default();
        if let Some(s) = v.reload().map_err(err)? {
            out.add(s);
        }
        let mut merged_any = false;
        for (path, r) in v.merge_conflict_copies() {
            match r {
                Ok(s) => {
                    out.add(s);
                    out.conflicts_merged += 1;
                    merged_any = true;
                }
                Err(e) => out.errors.push(format!(
                    "{}: {e}",
                    path.file_name().unwrap_or_default().to_string_lossy()
                )),
            }
        }
        if merged_any {
            let r = v.save().map_err(err)?;
            let extra = SyncResult::from_save(r);
            out.password_changed_elsewhere |= extra.password_changed_elsewhere;
        }
        Ok(out)
    }

    pub fn change_master_password(&mut self, current: &str, new: &str) -> AppResult<()> {
        self.touch();
        check_master_strength(new)?;
        let kdf = self.create_opts.kdf;
        let allow_weak = self.create_opts.allow_weak_kdf;
        let v = self.vault_mut()?;
        if !v.verify_password(current.as_bytes()) {
            return Err("Mật khẩu chính hiện tại không đúng".into());
        }
        if allow_weak {
            v.change_password_insecure_for_tests(new.as_bytes(), kdf)
                .map_err(err)?;
        } else {
            v.change_password(new.as_bytes(), KdfParams::DEFAULT)
                .map_err(err)?;
        }
        v.save().map_err(err)?;
        Ok(())
    }

    pub fn health(&self, online: bool) -> AppResult<HealthView> {
        use pwv_health::{check_breaches, hibp_fetch, offline_report, Issue};
        let v = self.vault()?;
        let mut report = offline_report(v.entries());
        let mut breach_error = None;
        if online {
            if let Err(e) = check_breaches(v.entries(), &mut report, hibp_fetch) {
                breach_error = Some(e.to_string());
            }
        }
        let mut items: Vec<HealthItem> = report
            .issues
            .iter()
            .filter_map(|(id, issues)| {
                v.get(id).map(|e| HealthItem {
                    id: id.clone(),
                    title: e.title.clone(),
                    username: e.username.clone(),
                    severity: issues[0].severity(),
                    issues: issues.iter().map(Issue::describe).collect(),
                })
            })
            .collect();
        items.sort_by(|a, b| {
            a.severity
                .cmp(&b.severity)
                .then_with(|| a.title.to_lowercase().cmp(&b.title.to_lowercase()))
        });
        Ok(HealthView {
            score: report.score(),
            checked: report.checked,
            breached: report.count(|i| matches!(i, Issue::Breached { .. })),
            reused: report.count(|i| matches!(i, Issue::Reused { .. })),
            weak: report.count(|i| matches!(i, Issue::Weak { .. })),
            old: report.count(|i| matches!(i, Issue::Old { .. })),
            breach_check_done: report.breach_check_done,
            breach_error,
            items,
        })
    }

    pub fn import_csv(&mut self, path: &Path, delete_after: bool) -> AppResult<ImportView> {
        self.touch();
        let f = std::fs::File::open(path).map_err(err)?;
        let v = self.vault_mut()?;
        let res = pwv_vault_core::import::import_csv(f, v.entries()).map_err(err)?;
        let imported = res.entries.len();
        for e in res.entries {
            v.add(e);
        }
        v.save().map_err(err)?;
        let csv_deleted = delete_after && std::fs::remove_file(path).is_ok();
        Ok(ImportView {
            imported,
            duplicates: res.duplicates,
            skipped: res.skipped,
            detected: res.detected.to_string(),
            csv_deleted,
        })
    }

    /// Chuyển kho đang mở sang vị trí mới và ghi nhớ vị trí đó.
    pub fn move_vault(&mut self, new_path: &Path) -> AppResult<MoveView> {
        self.touch();
        let v = self.vault_mut()?;
        let r = v.move_to(new_path).map_err(err)?;
        let new_path = v.path().to_path_buf();
        self.config.set_vault(&new_path).map_err(err)?;
        Ok(MoveView {
            new_path: new_path.display().to_string(),
            backups_moved: r.backups_moved,
            old_removed: r.old_removed,
            conflicts_merged: r.conflicts_merged,
        })
    }

    pub fn settings(&self) -> Settings {
        Settings {
            auto_lock_minutes: self.config.auto_lock_minutes,
            clipboard_clear_secs: self.config.clipboard_clear_secs,
            check_updates: self.config.check_updates,
        }
    }

    pub fn set_settings(&mut self, s: Settings) -> AppResult<()> {
        self.config.auto_lock_minutes = s.auto_lock_minutes.min(240);
        self.config.clipboard_clear_secs = s.clipboard_clear_secs.clamp(5, 300);
        self.config.check_updates = s.check_updates;
        self.config.save().map_err(err)
    }

    pub fn backups_dir(&self) -> Option<PathBuf> {
        self.vault
            .as_ref()
            .map(|v| pwv_vault_core::fsutil::backup_dir(v.path()))
    }
}

pub fn generate(req: GenRequest) -> AppResult<Generated> {
    let (value, entropy_bits) = match req {
        GenRequest::Password(o) => (generate_password(&o).map_err(err)?, o.entropy_bits()),
        GenRequest::Passphrase(o) => (generate_passphrase(&o).map_err(err)?, o.entropy_bits()),
    };
    let strength = estimate_strength(&value, &[]);
    Ok(Generated {
        value: value.to_string(),
        entropy_bits,
        strength,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> (Session, tempfile::TempDir) {
        let d = tempfile::tempdir().unwrap();
        let s = Session {
            vault: None,
            config: Config::default(),
            last_activity: Instant::now(),
            create_opts: CreateOptions {
                kdf: KdfParams::INSECURE_TEST,
                allow_weak_kdf: true,
            },
        };
        (s, d)
    }

    const MP: &str = "ngua-pin-kep-dung-bien-xanh";

    fn input(title: &str, pw: Option<&str>) -> EntryInput {
        EntryInput {
            id: None,
            title: title.into(),
            username: "u".into(),
            password: pw.map(String::from),
            urls: vec![" https://a.vn ".into(), "".into()],
            notes: String::new(),
            tags: vec![],
            favorite: false,
            totp: None,
        }
    }

    // Lưu ý: create_vault/unlock ghi config thật của người chạy test, nên test dùng Vault trực tiếp.
    fn open(s: &mut Session, d: &tempfile::TempDir) {
        let p = d.path().join("v.pwv");
        s.vault = Some(Vault::create(&p, MP.as_bytes(), s.create_opts).unwrap());
    }

    #[test]
    fn rejects_weak_master_password() {
        assert!(check_master_strength("123456789012").is_err());
        assert!(check_master_strength("short").is_err());
        assert!(check_master_strength(MP).is_ok());
    }

    #[test]
    fn crud_and_secrets_stay_in_rust() {
        let (mut s, d) = session();
        open(&mut s, &d);
        let (id, _) = s.save_entry(input("Gmail", Some("S3cret-pass!"))).unwrap();
        let list = s.list("").unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].url.as_deref(), Some("https://a.vn"));
        // DTO gửi sang JS không chứa mật khẩu.
        let json = serde_json::to_string(&s.detail(&id).unwrap()).unwrap();
        assert!(!json.contains("S3cret-pass!"));
        assert!(!serde_json::to_string(&list)
            .unwrap()
            .contains("S3cret-pass!"));
        assert_eq!(s.reveal_password(&id).unwrap(), "S3cret-pass!");

        // Sửa nhưng không gửi password ⇒ giữ nguyên.
        let mut upd = input("Gmail 2", None);
        upd.id = Some(id.clone());
        s.save_entry(upd).unwrap();
        assert_eq!(s.reveal_password(&id).unwrap(), "S3cret-pass!");
        assert_eq!(s.detail(&id).unwrap().title, "Gmail 2");

        // Đổi password ⇒ vào lịch sử.
        let mut upd = input("Gmail 2", Some("new"));
        upd.id = Some(id.clone());
        s.save_entry(upd).unwrap();
        assert_eq!(s.history(&id).unwrap()[0].password, "S3cret-pass!");

        s.delete_entry(&id).unwrap();
        assert!(s.list("").unwrap().is_empty());
    }

    #[test]
    fn totp_set_keep_remove() {
        let (mut s, d) = session();
        open(&mut s, &d);
        let mut i = input("G", Some("x"));
        i.totp = Some("JBSWY3DPEHPK3PXP".into());
        let (id, _) = s.save_entry(i).unwrap();
        assert_eq!(s.totp(&id).unwrap().code.len(), 6);
        assert!(!serde_json::to_string(&s.detail(&id).unwrap())
            .unwrap()
            .contains("JBSWY3DPEHPK3PXP"));
        let mut i = input("G", None);
        i.id = Some(id.clone());
        s.save_entry(i).unwrap();
        assert!(s.detail(&id).unwrap().has_totp, "None = giữ nguyên");
        let mut i = input("G", None);
        i.id = Some(id.clone());
        i.totp = Some(String::new());
        s.save_entry(i).unwrap();
        assert!(!s.detail(&id).unwrap().has_totp, "chuỗi rỗng = xoá");
        let mut bad = input("B", None);
        bad.totp = Some("!!".into());
        assert!(s.save_entry(bad).is_err());
    }

    #[test]
    fn auto_lock() {
        let (mut s, d) = session();
        open(&mut s, &d);
        s.config.auto_lock_minutes = 1;
        assert!(!s.auto_lock_if_idle());
        s.last_activity = Instant::now() - Duration::from_secs(61);
        assert!(s.auto_lock_if_idle());
        assert!(s.vault.is_none());
        assert!(s.list("").is_err());
    }

    #[test]
    fn change_master_password_requires_current() {
        let (mut s, d) = session();
        open(&mut s, &d);
        assert!(s
            .change_master_password("sai", "mot-cum-tu-moi-rat-dai-42")
            .is_err());
        s.change_master_password(MP, "mot-cum-tu-moi-rat-dai-42")
            .unwrap();
        let p = s.vault.as_ref().unwrap().path().to_path_buf();
        assert!(Vault::open(&p, b"mot-cum-tu-moi-rat-dai-42").is_ok());
    }

    #[test]
    fn sync_picks_up_other_device_and_conflict_copy() {
        let (mut s, d) = session();
        open(&mut s, &d);
        s.save_entry(input("A", Some("a"))).unwrap();
        let p = s.vault.as_ref().unwrap().path().to_path_buf();
        // "Máy khác" thêm một mục.
        {
            let mut other = Vault::open(&p, MP.as_bytes()).unwrap();
            other.add(Entry::new("Từ laptop"));
            other.save().unwrap();
        }
        // Drive tạo bản xung đột có thêm mục.
        let conflict = d.path().join("v (1).pwv");
        std::fs::copy(&p, &conflict).unwrap();
        {
            let mut c = Vault::open(&conflict, MP.as_bytes()).unwrap();
            c.add(Entry::new("Từ bản xung đột"));
            c.save().unwrap();
        }
        let r = s.sync().unwrap();
        assert!(r.changed);
        assert_eq!(r.conflicts_merged, 1);
        let titles: Vec<String> = s.list("").unwrap().into_iter().map(|e| e.title).collect();
        assert!(titles.contains(&"Từ laptop".to_string()));
        assert!(titles.contains(&"Từ bản xung đột".to_string()));
        assert!(
            !conflict.exists(),
            "bản xung đột đã được chuyển vào thư mục sao lưu"
        );
        assert!(!s.sync().unwrap().changed);
    }

    #[test]
    fn move_vault_keeps_data() {
        let (mut s, d) = session();
        open(&mut s, &d);
        s.save_entry(input("A", Some("a"))).unwrap();
        let target = d.path().join("Dropbox").join("vault.pwv");
        // set_vault ghi config thật ⇒ chỉ kiểm tra phần Vault ở đây.
        let r = s.vault.as_mut().unwrap().move_to(&target).unwrap();
        assert!(r.old_removed);
        assert_eq!(s.list("").unwrap().len(), 1);
        assert!(Vault::open(&target, MP.as_bytes()).is_ok());
    }

    #[test]
    fn read_only_session_from_bytes() {
        let (mut s, d) = session();
        let p = d.path().join("v.pwv");
        let mut pc = Vault::create(&p, MP.as_bytes(), s.create_opts).unwrap();
        pc.add(Entry::new("A"));
        pc.save().unwrap();
        s.unlock_bytes("content://x/v.pwv", &std::fs::read(&p).unwrap(), MP)
            .unwrap();
        assert_eq!(s.list("").unwrap().len(), 1);
        // Ghi bị chặn ở chế độ chỉ đọc.
        assert!(s.save_entry(input("B", Some("b"))).is_err());
        pc.add(Entry::new("C"));
        pc.save().unwrap();
        assert!(s.reload_bytes(&std::fs::read(&p).unwrap()).unwrap());
        let titles: Vec<String> = s.list("").unwrap().into_iter().map(|e| e.title).collect();
        assert!(titles.contains(&"C".to_string()));
        assert!(!titles.contains(&"B".to_string()));
    }

    #[test]
    fn generator_requests() {
        let g: GenRequest =
            serde_json::from_str(r#"{"mode":"password","length":32,"symbols":false}"#).unwrap();
        let out = generate(g).unwrap();
        assert_eq!(out.value.len(), 32);
        let g: GenRequest =
            serde_json::from_str(r#"{"mode":"passphrase","words":5,"separator":" "}"#).unwrap();
        assert_eq!(generate(g).unwrap().value.split(' ').count(), 5);
    }

    #[test]
    fn import_and_health() {
        let (mut s, d) = session();
        open(&mut s, &d);
        let csv = d.path().join("c.csv");
        std::fs::write(
            &csv,
            "name,url,username,password\nA,https://a.vn,u,123456\nB,https://b.vn,u,123456\n",
        )
        .unwrap();
        let r = s.import_csv(&csv, true).unwrap();
        assert_eq!(r.imported, 2);
        assert!(r.csv_deleted && !csv.exists());
        let h = s.health(false).unwrap();
        assert_eq!(h.reused, 2);
        assert_eq!(h.weak, 2);
        assert_eq!(h.score, 0);
    }
}
