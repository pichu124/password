//! Nhập mật khẩu từ file CSV xuất ra bởi Chrome/Edge, Firefox, Bitwarden, KeePass/KeePassXC,
//! 1Password, Proton Pass... Cột được nhận dạng theo tên tiêu đề nên không cần chọn định dạng.

use std::io::Read;

use crate::model::{now_ms, Entry};

#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("không đọc được CSV: {0}")]
    Csv(#[from] csv::Error),
    #[error("không nhận ra cột mật khẩu trong file CSV (cần có cột 'password')")]
    NoPasswordColumn,
}

#[derive(Debug, Default)]
pub struct ImportResult {
    pub entries: Vec<Entry>,
    /// Dòng bị bỏ qua vì trùng với mục đã có (cùng URL/username/mật khẩu).
    pub duplicates: usize,
    /// Dòng trống / không có dữ liệu.
    pub skipped: usize,
    /// Tên định dạng đoán được (chỉ để hiển thị).
    pub detected: &'static str,
}

#[derive(Default)]
struct Columns {
    title: Option<usize>,
    url: Option<usize>,
    username: Option<usize>,
    password: Option<usize>,
    notes: Option<usize>,
    totp: Option<usize>,
    group: Option<usize>,
    favorite: Option<usize>,
    kind: Option<usize>,
}

fn normalize(h: &str) -> String {
    h.trim_start_matches('\u{feff}')
        .trim()
        .to_lowercase()
        .replace([' ', '-'], "_")
}

impl Columns {
    fn detect(headers: &csv::StringRecord) -> Columns {
        let mut c = Columns::default();
        for (i, h) in headers.iter().enumerate() {
            let slot = match normalize(h).as_str() {
                "name" | "title" | "account" => &mut c.title,
                "url" | "login_uri" | "website" | "web_site" | "uri" | "urls" => &mut c.url,
                "username" | "login_username" | "user_name" | "login" | "email" => &mut c.username,
                "password" | "login_password" | "pass" => &mut c.password,
                "note" | "notes" | "extra" | "comments" => &mut c.notes,
                "totp" | "login_totp" | "otpauth" | "otp" | "one_time_password" => &mut c.totp,
                "folder" | "group" | "grouping" | "vault" | "category" => &mut c.group,
                "favorite" | "fav" | "favourite" => &mut c.favorite,
                "type" => &mut c.kind,
                _ => continue,
            };
            // Giữ cột xuất hiện đầu tiên (ví dụ "email" là phương án dự phòng cho username).
            slot.get_or_insert(i);
        }
        c
    }

    fn guess_format(headers: &csv::StringRecord) -> &'static str {
        let hs: Vec<String> = headers.iter().map(normalize).collect();
        let has = |n: &str| hs.iter().any(|h| h == n);
        if has("login_uri") && has("login_password") {
            "Bitwarden"
        } else if has("httprealm") || has("formactionorigin") {
            "Firefox"
        } else if has("group") && has("title") {
            "KeePass / KeePassXC"
        } else if has("name") && has("url") && has("note") {
            "Chrome / Edge"
        } else if has("otpauth") {
            "1Password"
        } else {
            "CSV"
        }
    }
}

/// Đọc CSV và chuyển thành các mục mới. `existing` dùng để bỏ trùng.
pub fn import_csv<R: Read>(reader: R, existing: &[Entry]) -> Result<ImportResult, ImportError> {
    let mut rdr = csv::ReaderBuilder::new()
        .flexible(true)
        .trim(csv::Trim::Fields)
        .from_reader(reader);
    let headers = rdr.headers()?.clone();
    let cols = Columns::detect(&headers);
    let pw_col = cols.password.ok_or(ImportError::NoPasswordColumn)?;
    let mut res = ImportResult {
        detected: Columns::guess_format(&headers),
        ..Default::default()
    };

    let mut seen: Vec<(String, String, String)> = existing.iter().map(fingerprint).collect();

    for rec in rdr.records() {
        let rec = rec?;
        let get = |c: Option<usize>| c.and_then(|i| rec.get(i)).unwrap_or("").to_string();

        let kind = get(cols.kind).to_lowercase();
        let password = rec.get(pw_col).unwrap_or("").to_string();
        let username = get(cols.username);
        let urls: Vec<String> = get(cols.url)
            .split(['\n', ','])
            .map(str::trim)
            .filter(|u| !u.is_empty())
            .map(String::from)
            .collect();
        let notes = get(cols.notes);
        let mut title = get(cols.title);

        if password.is_empty() && username.is_empty() && notes.is_empty() && kind != "note" {
            res.skipped += 1;
            continue;
        }
        if title.is_empty() {
            title = urls
                .first()
                .map(|u| host_of(u))
                .unwrap_or_else(|| "(không tên)".into());
        }

        let mut e = Entry::new(title);
        e.username = username;
        e.password = password;
        e.urls = urls;
        e.notes = notes;
        let totp = get(cols.totp);
        if !totp.is_empty() {
            e.totp = Some(totp);
        }
        let group = get(cols.group);
        // KeePass xuất nhóm dạng "Root/Ngân hàng"; bỏ nhóm gốc mặc định.
        let group = group.rsplit('/').next().unwrap_or("").trim().to_string();
        if !group.is_empty()
            && !matches!(
                group.to_lowercase().as_str(),
                "root" | "database" | "passwords"
            )
        {
            e.tags.push(group);
        }
        e.favorite = matches!(
            get(cols.favorite).to_lowercase().as_str(),
            "1" | "true" | "yes" | "x"
        );
        e.updated_at = now_ms();

        let fp = fingerprint(&e);
        if seen.contains(&fp) {
            res.duplicates += 1;
            continue;
        }
        seen.push(fp);
        res.entries.push(e);
    }
    Ok(res)
}

fn fingerprint(e: &Entry) -> (String, String, String) {
    (
        e.urls.first().map(|u| host_of(u)).unwrap_or_default(),
        e.username.to_lowercase(),
        e.password.clone(),
    )
}

/// `https://www.example.com/login?x` → `example.com`.
pub fn host_of(url: &str) -> String {
    let s = url.trim();
    let s = s.split_once("://").map(|(_, r)| r).unwrap_or(s);
    let s = s.split(['/', '?', '#']).next().unwrap_or("");
    let s = s.rsplit('@').next().unwrap_or("");
    let s = s.split(':').next().unwrap_or("");
    s.trim_start_matches("www.").to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chrome_csv() {
        let csv = "name,url,username,password,note\n\
            vietcombank.com.vn,https://vcbdigibank.vietcombank.com.vn/,nguyenvana,Abc123!,\n\
            ,https://www.facebook.com/login,toi@gmail.com,fbpass,ghi chú\n\
            ,,,,\n";
        let r = import_csv(csv.as_bytes(), &[]).unwrap();
        assert_eq!(r.detected, "Chrome / Edge");
        assert_eq!(r.entries.len(), 2);
        assert_eq!(r.skipped, 1);
        assert_eq!(r.entries[1].title, "facebook.com");
        assert_eq!(r.entries[1].notes, "ghi chú");
    }

    #[test]
    fn bitwarden_csv_with_bom_and_totp() {
        let csv = "\u{feff}folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
            Ngân hàng,1,login,VCB,,,0,https://vcb.com.vn,a,p1,otpauth://totp/VCB?secret=JBSWY3DPEHPK3PXP\n\
            ,,note,Ghi chú bí mật,số tài khoản 123,,0,,,,\n";
        let r = import_csv(csv.as_bytes(), &[]).unwrap();
        assert_eq!(r.detected, "Bitwarden");
        assert_eq!(r.entries.len(), 2);
        let e = &r.entries[0];
        assert!(e.favorite);
        assert_eq!(e.tags, vec!["Ngân hàng"]);
        assert!(e.totp.as_deref().unwrap().starts_with("otpauth://"));
        assert_eq!(r.entries[1].notes, "số tài khoản 123");
    }

    #[test]
    fn keepassxc_csv_and_dedupe() {
        let csv = "\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\",\"TOTP\",\"Icon\",\"Last Modified\",\"Created\"\n\
            \"Root/Email\",\"Gmail\",\"toi@gmail.com\",\"g-pass\",\"https://mail.google.com\",\"\",\"\",\"0\",\"\",\"\"\n\
            \"Root\",\"Gmail copy\",\"TOI@gmail.com\",\"g-pass\",\"https://mail.google.com/x\",\"\",\"\",\"0\",\"\",\"\"\n";
        let r = import_csv(csv.as_bytes(), &[]).unwrap();
        assert_eq!(r.detected, "KeePass / KeePassXC");
        assert_eq!(r.entries.len(), 1);
        assert_eq!(r.duplicates, 1);
        assert_eq!(r.entries[0].tags, vec!["Email"]);

        // Nhập lại lần nữa vào kho đã có ⇒ tất cả là trùng.
        let again = import_csv(csv.as_bytes(), &r.entries).unwrap();
        assert_eq!(again.entries.len(), 0);
        assert_eq!(again.duplicates, 2);
    }

    #[test]
    fn firefox_csv() {
        let csv = "\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\",\"timeCreated\",\"timeLastUsed\",\"timePasswordChanged\"\n\
            \"https://shopee.vn\",\"u\",\"p\",,\"https://shopee.vn\",\"{x}\",\"1\",\"1\",\"1\"\n";
        let r = import_csv(csv.as_bytes(), &[]).unwrap();
        assert_eq!(r.detected, "Firefox");
        assert_eq!(r.entries[0].title, "shopee.vn");
    }

    #[test]
    fn missing_password_column() {
        assert!(matches!(
            import_csv("a,b\n1,2\n".as_bytes(), &[]),
            Err(ImportError::NoPasswordColumn)
        ));
    }

    #[test]
    fn host_extraction() {
        assert_eq!(
            host_of("https://user@www.Example.com:8443/a?b#c"),
            "example.com"
        );
        assert_eq!(host_of("example.com/login"), "example.com");
        assert_eq!(host_of(""), "");
    }
}
