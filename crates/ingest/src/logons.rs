//! Session evidence from logon data, for environments where SharpHound's
//! session collection (NetSessionEnum / NetWkstaUserEnum) is blocked:
//!
//! * **CopperHound logon export** (`scripts/Export-CopperHoundLogons.ps1`):
//!   `{"meta": {"type": "copperhound-logons", "version": 1}, "data": [
//!   {"computer": "WS01.CORP.LOCAL", "computersid"?: "S-1-5-21-…-1104",
//!   "user": "S-1-5-21-…-1105", "logontype": 10, "first": "<RFC 3339>",
//!   "last": "<RFC 3339>"}, …]}` — one record per computer, user and logon
//!   type, aggregated from Security event 4624.
//! * **Microsoft Defender XDR `DeviceLogonEvents`** (advanced hunting export,
//!   JSON array or CSV): `Timestamp`, `DeviceName`, `ActionType`,
//!   `LogonType`, `AccountSid`. Only `LogonSuccess` rows count.
//!
//! Only logon types that leave reusable credentials on the computer count
//! ([`CREDENTIAL_LOGON_TYPES`]); network logons (type 3) do not. The user must
//! be a domain account (`S-1-5-21-…`) that the collected data knows as a user;
//! the computer is matched by SID or by its DNS name. Observations whose
//! endpoints are not in the graph are dropped, never invented.

use crate::emit::{upper, Emitted, Emitter, ObsRef, SessionObs, Shared};
use crate::merge::parse_rfc3339;
use ch_store::session_source as ss;
use serde::Deserialize;
use serde_json::Value;

/// Interactive (2), batch (4), service (5), unlock (7), network cleartext
/// (8), new credentials (9), remote interactive (10), cached interactive
/// (11), cached remote interactive (12), cached unlock (13).
pub const CREDENTIAL_LOGON_TYPES: u16 =
    1 << 2 | 1 << 4 | 1 << 5 | 1 << 7 | 1 << 8 | 1 << 9 | 1 << 10 | 1 << 11 | 1 << 12 | 1 << 13;

/// Windows logon type from its number or its name (Defender spells them out).
pub fn logon_type(v: &str) -> Option<u16> {
    let v = v.trim();
    if let Ok(n) = v.parse::<u16>() {
        return (n < 16).then_some(n);
    }
    let key: String = v.chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>().to_ascii_lowercase();
    Some(match key.as_str() {
        "interactive" => 2,
        "network" => 3,
        "batch" => 4,
        "service" => 5,
        "unlock" => 7,
        "networkcleartext" => 8,
        "newcredentials" => 9,
        "remoteinteractive" => 10,
        "cachedinteractive" => 11,
        "cachedremoteinteractive" => 12,
        "cachedunlock" => 13,
        _ => return None,
    })
}

/// Unix seconds from RFC 3339 text or a number (seconds, or milliseconds when
/// larger than 10^11).
fn time_of(v: &Value) -> Option<i64> {
    match v {
        Value::String(s) => parse_rfc3339(s).or_else(|| s.trim().parse::<f64>().ok().map(num_time)),
        Value::Number(n) => n.as_f64().map(num_time),
        _ => None,
    }
    .filter(|&t| t > 0)
}

fn num_time(x: f64) -> i64 {
    if x > 1e11 {
        (x / 1000.0) as i64
    } else {
        x as i64
    }
}

fn text(v: Option<&Value>) -> Option<String> {
    match v? {
        Value::String(s) if !s.trim().is_empty() => Some(s.trim().to_string()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn domain_sid(s: &str) -> bool {
    s.len() > 9 && s[..9].eq_ignore_ascii_case("S-1-5-21-")
}

/// One logon observation, before it is recorded.
struct Obs<'a> {
    computer: Option<String>,
    computer_sid: Option<String>,
    user: Option<String>,
    logon: Option<&'a Value>,
    first: Option<i64>,
    last: Option<i64>,
    source: u16,
}

fn record(o: Obs, em: &mut Emitter) {
    let Some(user) = o.user.filter(|u| domain_sid(u)) else { return };
    let Some(lt) = o.logon.and_then(|v| text(Some(v))).and_then(|t| logon_type(&t)) else { return };
    if CREDENTIAL_LOGON_TYPES & (1 << lt) == 0 {
        return;
    }
    let computer = match (o.computer_sid.filter(|s| domain_sid(s)), o.computer) {
        (Some(sid), _) => ObsRef::Oid(upper(&sid).into()),
        (None, Some(name)) => ObsRef::Name(upper(name.trim_end_matches('.')).into()),
        (None, None) => return,
    };
    let (first, last) = match (o.first, o.last) {
        (Some(f), Some(l)) => (f.min(l), f.max(l)),
        (Some(t), None) | (None, Some(t)) => (t, t),
        (None, None) => (0, 0),
    };
    if last > 0 {
        em.note_changed(last);
    }
    em.session(SessionObs {
        computer,
        user: ObsRef::Oid(upper(&user).into()),
        first,
        last,
        sources: o.source,
        logon_types: 1 << lt,
        add_edge: true,
    });
}

/// A record of the CopperHound logon export.
pub fn extract(raw: &[u8], em: &mut Emitter) -> serde_json::Result<()> {
    let v: serde_json::Map<String, Value> = serde_json::from_slice(raw)?;
    let get = |k: &str| v.iter().find(|(kk, _)| kk.eq_ignore_ascii_case(k)).map(|(_, x)| x);
    let t = |k: &str| get(k).and_then(time_of);
    record(
        Obs {
            computer: text(get("computer")),
            computer_sid: text(get("computersid")),
            user: text(get("user")),
            logon: get("logontype"),
            first: t("first").or_else(|| t("time")),
            last: t("last").or_else(|| t("time")),
            source: ss::LOGON_EVENTS,
        },
        em,
    );
    Ok(())
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct DefenderRecord {
    #[serde(rename = "Timestamp", alias = "timestamp", alias = "TimeGenerated")]
    pub timestamp: Option<Value>,
    #[serde(rename = "DeviceName", alias = "deviceName")]
    pub device: Option<Value>,
    #[serde(rename = "ActionType", alias = "actionType")]
    pub action: Option<Value>,
    #[serde(rename = "LogonType", alias = "logonType")]
    pub logon_type: Option<Value>,
    #[serde(rename = "AccountSid", alias = "accountSid")]
    pub account_sid: Option<Value>,
}

/// A `DeviceLogonEvents` row.
pub fn extract_defender(r: DefenderRecord, em: &mut Emitter) {
    if !text(r.action.as_ref()).is_some_and(|a| a.eq_ignore_ascii_case("LogonSuccess")) {
        return;
    }
    let t = r.timestamp.as_ref().and_then(time_of);
    record(
        Obs {
            computer: text(r.device.as_ref()),
            computer_sid: None,
            user: text(r.account_sid.as_ref()),
            logon: r.logon_type.as_ref(),
            first: t,
            last: t,
            source: ss::DEFENDER,
        },
        em,
    );
}

/// A JSON array record that is a Defender `DeviceLogonEvents` row.
pub fn looks_like_defender(record: &[u8]) -> bool {
    let head = &record[..record.len().min(4096)];
    let has = |k: &[u8]| head.windows(k.len()).any(|w| w.eq_ignore_ascii_case(k));
    has(b"\"DeviceName\"") && has(b"\"AccountSid\"") && has(b"\"LogonType\"")
}

/// A CSV header (first line) of a Defender `DeviceLogonEvents` export.
pub fn looks_like_defender_csv(head: &[u8]) -> bool {
    let line = head.split(|&b| b == b'\n').next().unwrap_or(&[]);
    let cols: Vec<String> = split_csv_line(&String::from_utf8_lossy(line)).into_iter().map(|c| c.to_ascii_lowercase()).collect();
    ["devicename", "accountsid", "logontype"].iter().all(|k| cols.iter().any(|c| c == k))
}

/// Split one CSV line without embedded newlines (header detection only).
fn split_csv_line(line: &str) -> Vec<String> {
    let mut r = CsvReader::new(line.trim_start_matches('\u{feff}').trim_end_matches(['\r', '\n']).as_bytes());
    r.next_row().unwrap_or_default()
}

/// Minimal RFC 4180 reader: quoted fields may hold commas, doubled quotes and
/// newlines (Defender's `AdditionalFields` column does).
pub struct CsvReader<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> CsvReader<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        let b = b.strip_prefix(b"\xef\xbb\xbf").unwrap_or(b);
        CsvReader { b, i: 0 }
    }

    /// The next row, or `None` at the end of input.
    pub fn next_row(&mut self) -> Option<Vec<String>> {
        if self.i >= self.b.len() {
            return None;
        }
        let mut row = Vec::new();
        let mut field = Vec::new();
        let mut quoted = false;
        while self.i < self.b.len() {
            let c = self.b[self.i];
            self.i += 1;
            if quoted {
                if c == b'"' {
                    if self.b.get(self.i) == Some(&b'"') {
                        field.push(b'"');
                        self.i += 1;
                    } else {
                        quoted = false;
                    }
                } else {
                    field.push(c);
                }
                continue;
            }
            match c {
                b'"' if field.is_empty() => quoted = true,
                b',' => row.push(String::from_utf8_lossy(&std::mem::take(&mut field)).into_owned()),
                b'\n' => break,
                b'\r' => {}
                _ => field.push(c),
            }
        }
        row.push(String::from_utf8_lossy(&field).into_owned());
        Some(row)
    }
}

/// Parse a Defender `DeviceLogonEvents` CSV export into one emitter output.
pub fn ingest_csv(bytes: &[u8], shared: &Shared, source: u32, display: &str) -> Emitted {
    let mut em = Emitter::new(shared, None);
    em.out.source = source;
    let mut r = CsvReader::new(bytes);
    let Some(header) = r.next_row() else { return em.finish() };
    let col = |name: &str| header.iter().position(|h| h.trim().eq_ignore_ascii_case(name));
    let (ts, dev, act, lt, sid) = (col("Timestamp").or_else(|| col("TimeGenerated")), col("DeviceName"), col("ActionType"), col("LogonType"), col("AccountSid"));
    if dev.is_none() || sid.is_none() || lt.is_none() {
        em.error(|| format!("{display}: not a DeviceLogonEvents export (DeviceName, AccountSid and LogonType columns needed)"));
        return em.finish();
    }
    let mut rows = 0u64;
    while let Some(row) = r.next_row() {
        if row.len() == 1 && row[0].trim().is_empty() {
            continue;
        }
        rows += 1;
        let cell = |i: Option<usize>| i.and_then(|i| row.get(i)).map(|s| Value::String(s.clone()));
        em.begin();
        extract_defender(
            DefenderRecord { timestamp: cell(ts), device: cell(dev), action: cell(act), logon_type: cell(lt), account_sid: cell(sid) },
            &mut em,
        );
    }
    em.out.records = rows;
    em.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logon_types() {
        assert_eq!(logon_type("10"), Some(10));
        assert_eq!(logon_type("RemoteInteractive"), Some(10));
        assert_eq!(logon_type("Network cleartext"), Some(8));
        assert_eq!(logon_type("CachedInteractive"), Some(11));
        assert_eq!(logon_type("Bogus"), None);
        assert_eq!(logon_type("99"), None);
        assert_eq!(CREDENTIAL_LOGON_TYPES & (1 << 3), 0, "network logons leave no credentials");
        assert_ne!(CREDENTIAL_LOGON_TYPES & (1 << 10), 0);
    }

    #[test]
    fn csv_reader_handles_quotes_and_newlines() {
        let data = "a,b,c\r\n1,\"x, \"\"y\"\"\",\"line1\nline2\"\n\n2,,3";
        let mut r = CsvReader::new(data.as_bytes());
        assert_eq!(r.next_row().unwrap(), ["a", "b", "c"]);
        assert_eq!(r.next_row().unwrap(), ["1", "x, \"y\"", "line1\nline2"]);
        assert_eq!(r.next_row().unwrap(), [""]);
        assert_eq!(r.next_row().unwrap(), ["2", "", "3"]);
        assert!(r.next_row().is_none());
        assert!(looks_like_defender_csv(b"\xef\xbb\xbfTimestamp,DeviceName,ActionType,LogonType,AccountSid\n"));
        assert!(!looks_like_defender_csv(b"Timestamp,DeviceName\n"));
    }

    #[test]
    fn times() {
        assert_eq!(time_of(&Value::String("2026-11-10T08:15:30.1234567Z".into())), Some(1_794_298_530));
        assert_eq!(time_of(&serde_json::json!(1_794_298_530_000u64)), Some(1_794_298_530));
        assert_eq!(time_of(&serde_json::json!(1_794_298_530)), Some(1_794_298_530));
        assert_eq!(time_of(&Value::Null), None);
    }
}
