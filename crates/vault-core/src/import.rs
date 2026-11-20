//! Nhập mật khẩu từ file CSV xuất ra bởi Chrome/Edge, Firefox, Bitwarden, KeePass 2/KeePassXC,
//! 1Password, Proton Pass, LastPass, Dashlane, Safari... Cột được nhận dạng theo tên tiêu đề nên
//! không cần chọn định dạng.
//!
//! Nguyên tắc: **không bao giờ âm thầm bỏ dữ liệu**. Một dòng chỉ bị bỏ khi nó hoàn toàn trống
//! hoặc giống hệt (mọi trường) một mục đã có. Thứ gì không hiểu được (mã 2FA sai định dạng, cột
//! phụ) được giữ lại trong ghi chú và báo cho người dùng.

use std::collections::HashSet;
use std::io::Read;

use sha2::{Digest, Sha256};

use crate::model::Entry;
use crate::totp::Totp;

/// Giới hạn số dòng của một file CSV (chống file rác làm treo app).
pub const MAX_IMPORT_ROWS: usize = 50_000;

#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("không đọc được CSV: {0}")]
    Csv(#[from] csv::Error),
    #[error("không nhận ra cột mật khẩu trong file CSV (cần có cột 'password')")]
    NoPasswordColumn,
    #[error("file CSV có quá nhiều dòng (tối đa {MAX_IMPORT_ROWS})")]
    TooManyRows,
}

#[derive(Default)]
pub struct ImportResult {
    pub entries: Vec<Entry>,
    /// Dòng bị bỏ qua vì giống hệt MỌI trường (tên, địa chỉ, username, mật khẩu, ghi chú, mã 2FA)
    /// với một mục đã có hoặc một dòng trước đó.
    pub duplicates: usize,
    /// Dòng hoàn toàn không có dữ liệu.
    pub skipped: usize,
    /// Tiêu đề các mục ĐÃ ĐƯỢC NHẬP nhưng có cùng trang web + username + mật khẩu với một mục
    /// khác (có thể là trùng, có thể không — người dùng tự rà lại).
    pub similar: Vec<String>,
    /// Tiêu đề các mục có mã 2FA không đọc được: giá trị gốc được chép vào ghi chú.
    pub bad_totp: Vec<String>,
    /// Tên định dạng đoán được (chỉ để hiển thị).
    pub detected: &'static str,
}

// Không derive Debug: `entries` chứa mật khẩu.
impl std::fmt::Debug for ImportResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportResult")
            .field("entries", &self.entries.len())
            .field("duplicates", &self.duplicates)
            .field("skipped", &self.skipped)
            .field("detected", &self.detected)
            .finish_non_exhaustive()
    }
}

#[derive(Default)]
struct Columns {
    title: Option<usize>,
    url: Option<usize>,
    username: Option<usize>,
    email: Option<usize>,
    password: Option<usize>,
    notes: Option<usize>,
    totp: Option<usize>,
    group: Option<usize>,
    favorite: Option<usize>,
    kind: Option<usize>,
    /// Các cột phụ có giá trị (trường tuỳ biến của Bitwarden, username phụ của Dashlane...):
    /// không có chỗ riêng nên được chép vào ghi chú kèm tên cột.
    extras: Vec<(usize, String)>,
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
                "username" | "login_username" | "user_name" | "login_name" | "login" | "user" => {
                    &mut c.username
                }
                "email" | "e_mail" => &mut c.email,
                "password" | "login_password" | "pass" => &mut c.password,
                "note" | "notes" | "extra" | "comments" => &mut c.notes,
                "totp" | "login_totp" | "otpauth" | "otp" | "one_time_password" | "otpsecret"
                | "otp_secret" | "otpurl" | "otp_url" | "totp_secret" => &mut c.totp,
                "folder" | "group" | "grouping" | "vault" | "category" => &mut c.group,
                "favorite" | "fav" | "favourite" => &mut c.favorite,
                "type" => &mut c.kind,
                "fields" | "custom_fields" | "username2" | "username3" => {
                    c.extras.push((i, h.trim().to_string()));
                    continue;
                }
                _ => continue,
            };
            // Giữ cột xuất hiện đầu tiên.
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
        } else if has("createtime") && has("vault") {
            "Proton Pass"
        } else if has("login_name") && has("web_site") {
            "KeePass 2"
        } else if has("group") && has("title") {
            "KeePass / KeePassXC"
        } else if has("grouping") && has("extra") {
            "LastPass"
        } else if has("otpsecret") || has("otpurl") || has("username2") {
            "Dashlane"
        } else if has("otpauth") {
            "1Password / Safari"
        } else if has("name") && has("url") && has("note") {
            "Chrome / Edge"
        } else {
            "CSV"
        }
    }
}

/// Tách cột địa chỉ thành danh sách URL. Luôn tách theo dòng; chỉ tách theo dấu phẩy khi MỌI phần
/// đều là URL đầy đủ (có `://`) — để không cắt đôi một địa chỉ có dấu phẩy trong tham số.
fn split_urls(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in raw.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let parts: Vec<&str> = line.split(',').map(str::trim).collect();
        if parts.len() > 1 && parts.iter().all(|p| p.contains("://")) {
            out.extend(parts.into_iter().map(String::from));
        } else {
            out.push(line.to_string());
        }
    }
    out
}

/// Dấu vân tay của TOÀN BỘ nội dung một mục: hai mục chỉ là "trùng" khi mọi trường giống hệt nhau.
fn exact_fingerprint(e: &Entry) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"pwv/import/v1");
    let mut field = |s: &str| {
        h.update((s.len() as u64).to_le_bytes());
        h.update(s.as_bytes());
    };
    field(&e.title);
    field(&e.username);
    field(&e.password);
    field(&e.notes);
    field(e.totp.as_deref().unwrap_or(""));
    field(&e.urls.len().to_string());
    for u in &e.urls {
        field(u);
    }
    h.finalize().into()
}

/// (trang web, username, mật khẩu) — chỉ dùng để GỢI Ý "có vẻ trùng", không bao giờ để bỏ dữ liệu.
fn similar_key(e: &Entry) -> Option<(String, String, String)> {
    if e.password.is_empty() && e.username.is_empty() {
        return None; // ghi chú bảo mật, mục chỉ có mã 2FA...: không so kiểu này
    }
    Some((
        e.urls.first().map(|u| host_of(u)).unwrap_or_default(),
        e.username.to_lowercase(),
        e.password.clone(),
    ))
}

/// Đọc CSV và chuyển thành các mục mới. `existing` dùng để bỏ các dòng giống hệt mục đã có.
///
/// Mỗi mục được cấp một id suy ra từ nội dung của nó, nên nếu cùng một file được nhập trên hai
/// máy trước khi chúng kịp đồng bộ thì khi gộp lại không sinh ra mục trùng.
pub fn import_csv<R: Read>(reader: R, existing: &[Entry]) -> Result<ImportResult, ImportError> {
    // Chỉ cắt khoảng trắng ở tên cột. KHÔNG cắt nội dung: mật khẩu có thể bắt đầu/kết thúc bằng
    // dấu cách (các trường không bí mật được cắt riêng ở dưới).
    let mut rdr = csv::ReaderBuilder::new()
        .flexible(true)
        .trim(csv::Trim::Headers)
        .from_reader(reader);
    let headers = rdr.headers()?.clone();
    let cols = Columns::detect(&headers);
    let pw_col = cols.password.ok_or(ImportError::NoPasswordColumn)?;
    let mut res = ImportResult {
        detected: Columns::guess_format(&headers),
        ..Default::default()
    };

    let mut seen: HashSet<[u8; 32]> = existing.iter().map(exact_fingerprint).collect();
    let mut seen_similar: HashSet<(String, String, String)> =
        existing.iter().filter_map(similar_key).collect();

    for (n, rec) in rdr.records().enumerate() {
        if n >= MAX_IMPORT_ROWS {
            return Err(ImportError::TooManyRows);
        }
        let rec = rec?;
        let raw = |c: Option<usize>| c.and_then(|i| rec.get(i)).unwrap_or("");
        let get = |c: Option<usize>| raw(c).trim().to_string();

        let kind = get(cols.kind).to_lowercase();
        let password = rec.get(pw_col).unwrap_or("").to_string();
        let email = get(cols.email);
        let mut username = get(cols.username);
        let mut notes = raw(cols.notes).to_string();
        let mut extra_lines: Vec<String> = Vec::new();
        if username.is_empty() {
            username.clone_from(&email);
        } else if !email.is_empty() && email != username {
            extra_lines.push(format!("Email: {email}"));
        }
        for (i, name) in &cols.extras {
            let v = rec.get(*i).unwrap_or("").trim();
            if !v.is_empty() {
                extra_lines.push(format!("{name}: {v}"));
            }
        }
        let urls = split_urls(raw(cols.url));
        let totp_raw = get(cols.totp);
        let mut title = get(cols.title);

        if password.is_empty()
            && username.is_empty()
            && notes.trim().is_empty()
            && totp_raw.is_empty()
            && extra_lines.is_empty()
            && kind != "note"
        {
            res.skipped += 1;
            continue;
        }
        if title.is_empty() {
            title = urls
                .first()
                .map(|u| host_of(u))
                .filter(|h| !h.is_empty())
                .unwrap_or_else(|| "(không tên)".into());
        }

        // Mã 2FA: chỉ nhận khi đọc được; nếu không thì giữ nguyên văn trong ghi chú để không mất.
        let mut totp = None;
        if !totp_raw.is_empty() {
            if Totp::parse(&totp_raw).is_ok() {
                totp = Some(totp_raw);
            } else {
                extra_lines.push(format!("Mã 2FA (không đọc được, hãy nhập lại): {totp_raw}"));
                res.bad_totp.push(title.clone());
            }
        }
        if !extra_lines.is_empty() {
            if !notes.trim().is_empty() {
                notes.push('\n');
            }
            notes.push_str(&extra_lines.join("\n"));
        }

        let mut e = Entry::new(title);
        e.username = username;
        e.password = password;
        e.urls = urls;
        e.notes = notes;
        e.totp = totp;
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

        let fp = exact_fingerprint(&e);
        if !seen.insert(fp) {
            res.duplicates += 1;
            continue;
        }
        if let Some(k) = similar_key(&e) {
            if !seen_similar.insert(k) {
                res.similar.push(e.title.clone());
            }
        }
        let mut id = [0u8; 16];
        id.copy_from_slice(&fp[..16]);
        e.id = uuid::Uuid::from_bytes(id).to_string();
        res.entries.push(e);
    }
    Ok(res)
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
    fn keepassxc_csv_and_exact_dedupe() {
        let csv = "\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\",\"TOTP\",\"Icon\",\"Last Modified\",\"Created\"\n\
            \"Root/Email\",\"Gmail\",\"toi@gmail.com\",\"g-pass\",\"https://mail.google.com\",\"\",\"\",\"0\",\"\",\"\"\n\
            \"Root\",\"Gmail copy\",\"TOI@gmail.com\",\"g-pass\",\"https://mail.google.com/x\",\"\",\"\",\"0\",\"\",\"\"\n\
            \"Root/Email\",\"Gmail\",\"toi@gmail.com\",\"g-pass\",\"https://mail.google.com\",\"\",\"\",\"0\",\"\",\"\"\n";
        let r = import_csv(csv.as_bytes(), &[]).unwrap();
        assert_eq!(r.detected, "KeePass / KeePassXC");
        // Dòng 2 khác tiêu đề/URL ⇒ vẫn được nhập, chỉ được đánh dấu "có vẻ trùng".
        assert_eq!(r.entries.len(), 2);
        assert_eq!(r.similar, vec!["Gmail copy"]);
        // Dòng 3 giống hệt dòng 1 ⇒ bỏ.
        assert_eq!(r.duplicates, 1);
        assert_eq!(r.entries[0].tags, vec!["Email"]);

        // Nhập lại lần nữa vào kho đã có ⇒ tất cả là trùng, không sinh thêm gì.
        let again = import_csv(csv.as_bytes(), &r.entries).unwrap();
        assert_eq!(again.entries.len(), 0);
        assert_eq!(again.duplicates, 3);
        assert!(again.similar.is_empty());
    }

    /// Lỗi của bản 0.1.2: mọi ghi chú bảo mật bị coi là "trùng" nhau (chỉ giữ cái đầu tiên), và
    /// hai tài khoản dùng chung username + mật khẩu bị gộp làm một, mất ghi chú và mã 2FA.
    #[test]
    fn distinct_notes_and_reused_credentials_are_all_imported() {
        let csv = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
            ,,note,Số tài khoản,STK 0123,,0,,,,\n\
            ,,note,Mã khôi phục Google,1111 2222,,0,,,,\n\
            ,,note,PIN thẻ,9999,,0,,,,\n\
            ,,login,VCB,ghi chú VCB,,0,,nguyenvana,Chung-1-mat-khau,JBSWY3DPEHPK3PXP\n\
            ,,login,BIDV,ghi chú BIDV,PIN: 1234,0,,nguyenvana,Chung-1-mat-khau,GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n";
        let existing_note = {
            let mut e = Entry::new("Ghi chú có sẵn");
            e.notes = "abc".into();
            e
        };
        let r = import_csv(csv.as_bytes(), &[existing_note]).unwrap();
        assert_eq!(r.entries.len(), 5);
        assert_eq!((r.duplicates, r.skipped), (0, 0));
        assert_eq!(
            r.similar,
            vec!["BIDV"],
            "được nhập, chỉ nhắc người dùng rà lại"
        );
        let bidv = &r.entries[4];
        assert_eq!(
            bidv.totp.as_deref(),
            Some("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        );
        assert_eq!(bidv.notes, "ghi chú BIDV\nfields: PIN: 1234");
        // Id suy ra từ nội dung: nhập cùng file trên máy khác cho đúng các id này.
        let again = import_csv(csv.as_bytes(), &[]).unwrap();
        let ids = |r: &ImportResult| r.entries.iter().map(|e| e.id.clone()).collect::<Vec<_>>();
        assert_eq!(ids(&r), ids(&again));
        assert_eq!(ids(&r).iter().collect::<HashSet<_>>().len(), 5);
    }

    #[test]
    fn keepass2_proton_and_dashlane_headers() {
        // KeePass 2: cột username tên là "Login Name".
        let kp = "Account,Login Name,Password,Web Site,Comments\nVCB,nguyenvana,pw1,https://vcb.com.vn,ghi chú\n";
        let r = import_csv(kp.as_bytes(), &[]).unwrap();
        assert_eq!(r.detected, "KeePass 2");
        assert_eq!(r.entries[0].username, "nguyenvana");
        assert_eq!(r.entries[0].urls, vec!["https://vcb.com.vn"]);

        // Proton Pass: có cả email lẫn username; ưu tiên username, email khác thì giữ trong ghi chú.
        let proton =
            "type,name,url,email,username,password,note,totp,createTime,modifyTime,vault\n\
            login,A,https://a.vn,,nguyenvana,pw,,,1,1,Personal\n\
            login,B,https://b.vn,toi@gmail.com,nguyenvanb,pw2,n,,1,1,Personal\n\
            login,C,https://c.vn,toi@gmail.com,,pw3,,,1,1,Personal\n";
        let r = import_csv(proton.as_bytes(), &[]).unwrap();
        assert_eq!(r.detected, "Proton Pass");
        assert_eq!(r.entries[0].username, "nguyenvana");
        assert_eq!(r.entries[1].username, "nguyenvanb");
        assert_eq!(r.entries[1].notes, "n\nEmail: toi@gmail.com");
        assert_eq!(r.entries[2].username, "toi@gmail.com");
        assert_eq!(r.entries[2].tags, vec!["Personal"]);

        // Dashlane: mã 2FA nằm ở cột otpSecret / otpUrl.
        let dl = "username,username2,username3,title,password,note,url,category,otpSecret\n\
            u,u-phu,,Bank,pw,,https://bank.vn,Tài chính,JBSWY3DPEHPK3PXP\n";
        let r = import_csv(dl.as_bytes(), &[]).unwrap();
        assert_eq!(r.detected, "Dashlane");
        assert_eq!(r.entries[0].totp.as_deref(), Some("JBSWY3DPEHPK3PXP"));
        assert_eq!(r.entries[0].notes, "username2: u-phu");
    }

    #[test]
    fn passwords_are_never_trimmed_and_totp_only_rows_are_kept() {
        let csv = "Title,URL,Username,Password,Notes,OTPAuth\n\
            Có dấu cách,https://a.vn, user ,\" mật khẩu có dấu cách \",,\n\
            Chỉ có 2FA,,,,,otpauth://totp/X?secret=JBSWY3DPEHPK3PXP\n\
            2FA hỏng,https://b.vn,u,p,ghi chú,steam://ABC\n\
            ,,,,,\n";
        let r = import_csv(csv.as_bytes(), &[]).unwrap();
        assert_eq!(r.detected, "1Password / Safari");
        assert_eq!(r.entries.len(), 3);
        assert_eq!(r.skipped, 1);
        assert_eq!(r.entries[0].password, " mật khẩu có dấu cách ");
        assert_eq!(
            r.entries[0].username, "user",
            "trường không bí mật thì được cắt"
        );
        assert!(r.entries[1].totp.is_some());
        assert_eq!(r.bad_totp, vec!["2FA hỏng"]);
        assert!(r.entries[2].totp.is_none());
        assert!(
            r.entries[2].notes.contains("steam://ABC"),
            "không được làm mất secret"
        );
    }

    #[test]
    fn urls_with_commas_are_not_split() {
        assert_eq!(
            split_urls("https://a.com/login?x=1,2"),
            vec!["https://a.com/login?x=1,2"]
        );
        assert_eq!(
            split_urls("https://a.com, https://b.com\nhttps://c.com"),
            vec!["https://a.com", "https://b.com", "https://c.com"]
        );
        assert!(split_urls("  \n ").is_empty());
    }

    #[test]
    fn huge_files_are_rejected_quickly() {
        let mut csv = String::from("name,url,username,password\n");
        for i in 0..=MAX_IMPORT_ROWS {
            csv.push_str(&format!("s{i},https://x{i}.vn,u,p{i}\n"));
        }
        let t = std::time::Instant::now();
        assert!(matches!(
            import_csv(csv.as_bytes(), &[]),
            Err(ImportError::TooManyRows)
        ));
        assert!(t.elapsed().as_secs() < 20, "bỏ trùng không còn là O(n²)");
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
