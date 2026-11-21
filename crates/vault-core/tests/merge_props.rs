//! Property test cho thuật toán gộp (đồng bộ nhiều máy).
//!
//! Phần 1 — trạng thái BẤT KỲ (kể cả dữ liệu méo mó): phép gộp phải giao hoán, kết hợp, luỹ đẳng
//! và "hấp thụ" (gộp lại thứ đã gộp không đổi gì). Đây là điều bảo đảm hai máy không bao giờ ghi đè
//! qua lại vô hạn và mọi máy đều đi tới cùng một kết quả, bất kể thứ tự đồng bộ.
//!
//! Phần 2 — mô phỏng 3 máy thao tác ngẫu nhiên (thêm, sửa từng trường, xoá, khôi phục, xoá vĩnh
//! viễn, đồng bộ lẫn nhau, đồng hồ lệch) và so với một "bộ chấm điểm" độc lập: không lần sửa nào
//! được phép biến mất trừ khi có lần sửa muộn hơn của chính trường đó, hoặc mục bị xoá vĩnh viễn.

use std::collections::{BTreeMap, BTreeSet};

use proptest::prelude::*;
use pwv_vault_core::model::{IMPORTED_AT, MAX_HISTORY};
use pwv_vault_core::{Entry, FieldTimes, HistoryItem, OldKey, Tombstone, VaultData};

fn pick(choices: &'static [&'static str]) -> impl Strategy<Value = String> {
    proptest::sample::select(choices).prop_map(String::from)
}

/// Mật khẩu từ một "kho" nhỏ ~30 giá trị (kể cả rỗng), để lịch sử chạm trần [`MAX_HISTORY`] và
/// trùng nhau giữa các máy / với mật khẩu hiện hành.
fn pool_pw() -> impl Strategy<Value = String> {
    (0u8..30).prop_map(|i| {
        if i == 0 {
            String::new()
        } else {
            format!("p{i:02}")
        }
    })
}

fn arb_entry() -> impl Strategy<Value = Entry> {
    (
        pick(&["a", "b", "c"]),
        (
            pick(&["", "t1", "t2"]),
            pick(&["", "u1"]),
            pool_pw(),
            proptest::collection::vec(pick(&["x", "y"]), 0..2),
            pick(&["", "n1"]),
        ),
        (
            proptest::option::of(pick(&["o1", "o2"])),
            proptest::collection::vec(pick(&["g1", "g2"]), 0..2),
            any::<bool>(),
        ),
        // 0..26 dòng: vượt trần 20 dòng (trước đây 0..3 nên không bao giờ chạm trần).
        proptest::collection::vec((pool_pw(), 0i64..7), 0..26),
        (0i64..5, 0i64..7),
        proptest::array::uniform9(0i64..7),
        // Mục "nguyên bản" vừa nhập từ CSV: mọi trường nội dung mang IMPORTED_AT.
        proptest::bool::weighted(0.2),
    )
        .prop_map(
            |(
                id,
                (title, username, password, urls, notes),
                (totp, tags, favorite),
                hist,
                times,
                ft,
                pristine,
            )| {
                let mut e = Entry::new(title);
                e.id = id;
                e.username = username;
                e.password = password;
                e.urls = urls;
                e.notes = notes;
                e.totp = totp;
                e.tags = tags;
                e.favorite = favorite;
                e.password_history = hist
                    .into_iter()
                    .map(|(password, replaced_at)| HistoryItem {
                        password,
                        replaced_at,
                    })
                    .collect();
                e.created_at = times.0;
                e.updated_at = times.1;
                e.field_times = FieldTimes {
                    title: ft[0],
                    username: ft[1],
                    password: ft[2],
                    urls: ft[3],
                    notes: ft[4],
                    totp: ft[5],
                    tags: ft[6],
                    favorite: ft[7],
                    deleted: ft[8],
                };
                if pristine {
                    let t = IMPORTED_AT;
                    e.field_times = FieldTimes {
                        title: t,
                        username: t,
                        password: t,
                        urls: t,
                        notes: t,
                        totp: t,
                        tags: t,
                        favorite: t,
                        deleted: ft[8],
                    };
                }
                e
            },
        )
}

/// Một kho bất kỳ (đã đưa về dạng chuẩn như khi đọc từ đĩa).
fn arb_data() -> impl Strategy<Value = VaultData> {
    (
        proptest::collection::vec(arb_entry(), 0..3),
        proptest::collection::vec(arb_entry(), 0..3),
        proptest::collection::vec((pick(&["a", "b", "c"]), 0i64..7), 0..2),
        proptest::collection::vec((1u8..4, 0i64..7), 0..2),
        0i64..7,
    )
        .prop_map(|(entries, trash, tombs, keys, modified_at)| {
            let mut d = VaultData {
                entries,
                trash,
                tombstones: tombs
                    .into_iter()
                    .map(|(id, deleted_at)| Tombstone { id, deleted_at })
                    .collect(),
                modified_at,
                old_keys: keys
                    .into_iter()
                    .map(|(k, retired_at)| OldKey {
                        key: [k; 32],
                        retired_at,
                    })
                    .collect(),
            };
            d.normalize();
            d
        })
}

/// Số ca thử: mặc định `n`, hoặc `PROPTEST_CASES` nếu được đặt (ví dụ 20000 cho lần chạy dài).
fn cases(n: u32) -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(n)
}

/// `Debug` của dữ liệu kho cố ý che bí mật; khi so sánh trong test thì in JSON đầy đủ.
fn js(d: &VaultData) -> String {
    serde_json::to_string(d).unwrap()
}

fn merged(a: &VaultData, b: &VaultData) -> VaultData {
    let mut m = a.clone();
    m.merge_from(b);
    m
}

proptest! {
    #![proptest_config(ProptestConfig { cases: cases(3000), ..ProptestConfig::default() })]

    #[test]
    fn normalize_is_idempotent(a in arb_data()) {
        let mut again = a.clone();
        again.normalize();
        prop_assert_eq!(js(&again), js(&a));
    }

    #[test]
    fn merge_is_commutative(a in arb_data(), b in arb_data()) {
        prop_assert_eq!(js(&merged(&a, &b)), js(&merged(&b, &a)));
    }

    #[test]
    fn merge_is_idempotent_and_absorbing(a in arb_data(), b in arb_data()) {
        prop_assert_eq!(js(&merged(&a, &a)), js(&a));
        let ab = merged(&a, &b);
        // Máy A đọc lại file mà chính nó (hoặc máy B) vừa ghi sau khi gộp: không còn gì để ghi nữa.
        prop_assert_eq!(js(&merged(&a, &ab)), js(&ab));
        prop_assert_eq!(js(&merged(&ab, &b)), js(&ab));
        prop_assert_eq!(js(&merged(&ab, &ab)), js(&ab));
    }

    #[test]
    fn merge_is_associative(a in arb_data(), b in arb_data(), c in arb_data()) {
        prop_assert_eq!(js(&merged(&merged(&a, &b), &c)), js(&merged(&a, &merged(&b, &c))));
    }

    #[test]
    fn merged_data_survives_a_json_round_trip(a in arb_data(), b in arb_data()) {
        let ab = merged(&a, &b);
        let json = serde_json::to_string(&ab).unwrap();
        let mut back: VaultData = serde_json::from_str(&json).unwrap();
        back.normalize();
        prop_assert_eq!(js(&back), js(&ab));
    }
}

// ----------------------------------------------------------------------------- mô phỏng 3 máy

#[derive(Debug, Clone)]
enum Op {
    Add {
        r: usize,
        id: usize,
        now: i64,
    },
    Set {
        r: usize,
        id: usize,
        field: usize,
        val: usize,
        now: i64,
    },
    Trash {
        r: usize,
        id: usize,
        now: i64,
    },
    Restore {
        r: usize,
        id: usize,
        now: i64,
    },
    Purge {
        r: usize,
        id: usize,
        now: i64,
    },
    /// Máy `r` nhập cùng một dòng CSV (nội dung cố định, giống nhau trên mọi máy).
    Import {
        r: usize,
        id: usize,
        now: i64,
    },
    /// Máy `r` đọc file do máy `from` ghi.
    Sync {
        r: usize,
        from: usize,
    },
}

fn arb_op() -> impl Strategy<Value = Op> {
    let (r, id, now) = (0usize..3, 0usize..3, 1i64..9);
    prop_oneof![
        2 => (r.clone(), id.clone(), now.clone()).prop_map(|(r, id, now)| Op::Add { r, id, now }),
        6 => (r.clone(), id.clone(), 0usize..8, 0usize..3, now.clone())
            .prop_map(|(r, id, field, val, now)| Op::Set { r, id, field, val, now }),
        2 => (r.clone(), id.clone(), now.clone()).prop_map(|(r, id, now)| Op::Trash { r, id, now }),
        1 => (r.clone(), id.clone(), now.clone()).prop_map(|(r, id, now)| Op::Restore { r, id, now }),
        1 => (r.clone(), id.clone(), now.clone()).prop_map(|(r, id, now)| Op::Purge { r, id, now }),
        2 => (r.clone(), id.clone(), now.clone()).prop_map(|(r, id, now)| Op::Import { r, id, now }),
        3 => (r, 0usize..3).prop_map(|(r, from)| Op::Sync { r, from }),
    ]
}

const IDS: [&str; 3] = ["a", "b", "c"];

/// Giá trị của một trường, so sánh theo đúng thứ tự mà phép gộp dùng.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Val {
    S(String),
    V(Vec<String>),
    O(Option<String>),
    B(bool),
}

fn registers(e: &Entry) -> [(i64, Val); 8] {
    let t = &e.field_times;
    [
        (t.title, Val::S(e.title.clone())),
        (t.username, Val::S(e.username.clone())),
        (t.password, Val::S(e.password.clone())),
        (t.urls, Val::V(e.urls.clone())),
        (t.notes, Val::S(e.notes.clone())),
        (t.totp, Val::O(e.totp.clone())),
        (t.tags, Val::V(e.tags.clone())),
        (t.favorite, Val::B(e.favorite)),
    ]
}

fn set_field(e: &mut Entry, field: usize, val: usize) {
    let s = |opts: [&str; 3]| opts[val].to_string();
    match field {
        0 => e.title = s(["T0", "T1", ""]),
        1 => e.username = s(["U0", "U1", ""]),
        2 => e.password = s(["P0", "P1", "P2"]),
        3 => {
            e.urls = [
                vec![],
                vec!["x".to_string()],
                vec!["x".to_string(), "y".to_string()],
            ][val]
                .clone()
        }
        4 => e.notes = s(["N0", "N1", ""]),
        5 => e.totp = [None, Some("o1".to_string()), Some("o2".to_string())][val].clone(),
        6 => e.tags = [vec![], vec!["g".to_string()], vec!["h".to_string()]][val].clone(),
        _ => e.favorite = val % 2 == 1,
    }
}

/// Mọi thứ từng quan sát được trên bất kỳ máy nào, ở bất kỳ bước nào.
#[derive(Default)]
struct Observed {
    /// (id, trường) → các cặp (thời điểm, giá trị) đã thấy.
    fields: BTreeMap<(String, usize), BTreeSet<(i64, Val)>>,
    /// id → các cặp (thời điểm, đang trong thùng rác).
    deleted: BTreeMap<String, BTreeSet<(i64, bool)>>,
    /// Các id đã bị xoá vĩnh viễn ở đâu đó.
    purged: BTreeMap<String, i64>,
    /// id → mọi mật khẩu từng xuất hiện (hiện hành hoặc trong lịch sử).
    passwords: BTreeMap<String, BTreeSet<String>>,
}

impl Observed {
    fn record(&mut self, d: &VaultData) {
        for (list, in_trash) in [(&d.entries, false), (&d.trash, true)] {
            for e in list {
                for (i, reg) in registers(e).into_iter().enumerate() {
                    self.fields
                        .entry((e.id.clone(), i))
                        .or_default()
                        .insert(reg);
                }
                self.deleted
                    .entry(e.id.clone())
                    .or_default()
                    .insert((e.field_times.deleted, in_trash));
                let pws = self.passwords.entry(e.id.clone()).or_default();
                pws.insert(e.password.clone());
                pws.extend(e.password_history.iter().map(|h| h.password.clone()));
            }
        }
        for t in &d.tombstones {
            let p = self.purged.entry(t.id.clone()).or_insert(t.deleted_at);
            *p = (*p).max(t.deleted_at);
        }
    }
}

fn run(ops: &[Op]) -> (Vec<VaultData>, Observed) {
    let mut reps = vec![VaultData::default(); 3];
    let mut seen = Observed::default();
    for op in ops {
        match *op {
            Op::Add { r, id, now } => {
                let mut e = Entry::new("new");
                e.id = IDS[id].to_string();
                e.password = "P-init".into();
                reps[r].add_at(e, now);
            }
            Op::Set {
                r,
                id,
                field,
                val,
                now,
            } => {
                let _ = reps[r].update_at(IDS[id], now, |e| set_field(e, field, val));
            }
            Op::Trash { r, id, now } => {
                let _ = reps[r].trash_at(IDS[id], now);
            }
            Op::Restore { r, id, now } => {
                let _ = reps[r].restore_at(IDS[id], now);
            }
            Op::Purge { r, id, now } => {
                let _ = reps[r].purge_at(IDS[id], now);
            }
            Op::Import { r, id, now } => {
                // Ứng dụng chỉ nhập khi máy này chưa có mục trùng (bỏ trùng theo nội dung).
                if reps[r].get(IDS[id]).is_none() && reps[r].get_trashed(IDS[id]).is_none() {
                    let mut e = Entry::new("csv");
                    e.id = IDS[id].to_string();
                    e.username = "csv-user".into();
                    e.password = "P-csv".into();
                    e.notes = "csv-note".into();
                    reps[r].add_imported_at(e, now);
                }
            }
            Op::Sync { r, from } => {
                if r != from {
                    let other = reps[from].clone();
                    reps[r].merge_from(&other);
                }
            }
        }
        for d in &reps {
            // Mọi thao tác đều giữ dữ liệu ở dạng chuẩn (không cần chuẩn hoá lại trước khi so sánh).
            let mut n = d.clone();
            n.normalize();
            assert_eq!(
                js(&n),
                js(d),
                "thao tác {op:?} làm dữ liệu rời khỏi dạng chuẩn"
            );
            seen.record(d);
        }
    }
    (reps, seen)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: cases(1500), ..ProptestConfig::default() })]

    #[test]
    fn three_devices_converge_and_never_lose_an_edit(ops in proptest::collection::vec(arb_op(), 1..40)) {
        let (reps, seen) = run(&ops);

        // 1. Hội tụ: gộp theo thứ tự nào cũng ra một kết quả.
        let f1 = merged(&merged(&reps[0], &reps[1]), &reps[2]);
        let f2 = merged(&reps[2], &merged(&reps[1], &reps[0]));
        let f3 = merged(&merged(&reps[1], &reps[2]), &reps[0]);
        prop_assert_eq!(js(&f1), js(&f2));
        prop_assert_eq!(js(&f1), js(&f3));
        // Sau khi mọi máy đã nhận kết quả chung thì không máy nào còn gì để ghi.
        for r in &reps {
            prop_assert_eq!(js(&merged(r, &f1)), js(&f1));
        }

        // 2. So với bộ chấm điểm: mỗi trường mang giá trị "muộn nhất từng được ghi ở bất kỳ đâu";
        //    mục đã xoá vĩnh viễn ở bất kỳ đâu thì biến mất ở mọi nơi.
        let ids: BTreeSet<&String> = seen.deleted.keys().collect();
        for id in ids {
            let live = f1.get(id);
            let trashed = f1.get_trashed(id);
            if seen.purged.contains_key(id) {
                prop_assert!(live.is_none() && trashed.is_none(), "{} phải bị xoá hẳn", id);
                continue;
            }
            let expected: Vec<(i64, Val)> = (0..8)
                .map(|field| seen.fields[&(id.clone(), field)].iter().next_back().unwrap().clone())
                .collect();
            let (_, in_trash) = *seen.deleted[id].iter().next_back().unwrap();
            let e = if in_trash {
                prop_assert!(live.is_none(), "{} phải nằm trong thùng rác", id);
                trashed
            } else {
                prop_assert!(trashed.is_none(), "{} phải nằm trong danh sách đang dùng", id);
                live
            };
            let e = e.unwrap_or_else(|| panic!("{id} biến mất"));
            prop_assert_eq!(registers(e).to_vec(), expected, "mục {}", id);
            // updated_at = max(created_at, thời điểm lớn nhất của các trường) — mục nhập từ CSV không
            // hiện "sửa năm 1970".
            let content_max = registers(e).iter().map(|(t, _)| *t).max().unwrap();
            prop_assert_eq!(e.updated_at, content_max.max(e.created_at));

            // 3. Lịch sử mật khẩu: không bịa ra mật khẩu, không chứa mật khẩu hiện hành, không quá
            //    dài, và mật khẩu nào từng được dùng rồi bị thay thì phải còn trong đó.
            let hist: BTreeSet<&str> = e.password_history.iter().map(|h| h.password.as_str()).collect();
            prop_assert!(hist.len() == e.password_history.len() && hist.len() <= MAX_HISTORY);
            prop_assert!(!hist.contains(e.password.as_str()) && !hist.contains(""));
            for h in &hist {
                prop_assert!(seen.passwords[id].contains(*h));
            }
            for (t, v) in &seen.fields[&(id.clone(), 2)] {
                let Val::S(pw) = v else { unreachable!() };
                let _ = t;
                if !pw.is_empty() && *pw != e.password {
                    prop_assert!(hist.contains(pw.as_str()), "mật khẩu {} của {} bị mất", pw, id);
                }
            }
        }
    }
}
