//! Sysinternals AD Explorer snapshot (`.dat`) reader.
//!
//! The format is undocumented by Microsoft. This implementation follows the
//! community description of the layout in ADExplorerSnapshot.py
//! (<https://github.com/c3c/ADExplorerSnapshot.py>, `adexpsnapshot/parser/
//! structure.py` and `classes.py`, Cedric Van Bockhaven / NVISO) and was
//! written independently from that description. All integers are
//! little-endian:
//!
//! ```text
//! 0x000  char   signature[10]
//! 0x00a  i32    marker
//! 0x00e  u64    filetime of the snapshot
//! 0x016  WCHAR  description[260]
//! 0x21e  WCHAR  server[260]
//! 0x426  u32    numObjects
//! 0x42a  u32    numAttributes
//! 0x42e  u32    propertiesOffset (low)    ┐ offset of the property table
//! 0x432  u32    propertiesOffset (high)   ┘
//! 0x436  u32    classesOffset
//! 0x43a  i32    unknown
//! 0x43e  objects[numObjects], back to back:
//!          u32 objSize            (whole object, including this header)
//!          u32 tableSize
//!          { u32 attrIndex; i32 attrOffset }[tableSize]
//!                                 (attrOffset is relative to the object start)
//!          attribute values …
//! props  u32 numProperties, then per property:
//!          u32 nameLen (bytes) ; WCHAR name[nameLen/2] ; i32 unknown
//!          u32 adsType ; u32 dnLen (bytes) ; WCHAR dn[dnLen/2]
//!          GUID schemaIDGUID ; GUID attributeSecurityGUID ; u8 blob[4]
//! classes (not needed: objectClass values are stored on every object)
//! ```
//!
//! An attribute value block starts with `u32 numValues`, then by ADSTYPE:
//! strings (DN, case exact/ignore, printable, numeric, object class) — `u32`
//! offsets (relative to the block) of NUL-terminated UTF-16 strings; octet
//! strings — `u32` lengths followed by the bytes; boolean / integer — `u32`
//! each; large integer — `i64` each; UTC time — 16-byte `SYSTEMTIME` each;
//! security descriptor — `u32` length + bytes, per value.
//!
//! Values are converted to their LDAP text form (integers as decimal, times
//! as GeneralizedTime, booleans as `TRUE`/`FALSE`) so the LDIF and snapshot
//! paths share one extractor. The file is memory-mapped; objects are visited
//! in place, chunked by offset for parallel reads.

use super::{Entry, Need, Sink, A};
use anyhow::{bail, Context, Result};
use memmap2::Mmap;
use std::borrow::Cow;
use std::fs::File;
use std::path::Path;

pub const HEADER_LEN: usize = 0x43e;
const CHUNK_BYTES: usize = 4 << 20;

pub const ADS_DN_STRING: u32 = 1;
pub const ADS_CASE_EXACT_STRING: u32 = 2;
pub const ADS_CASE_IGNORE_STRING: u32 = 3;
pub const ADS_PRINTABLE_STRING: u32 = 4;
pub const ADS_NUMERIC_STRING: u32 = 5;
pub const ADS_BOOLEAN: u32 = 6;
pub const ADS_INTEGER: u32 = 7;
pub const ADS_OCTET_STRING: u32 = 8;
pub const ADS_UTC_TIME: u32 = 9;
pub const ADS_LARGE_INTEGER: u32 = 10;
pub const ADS_OBJECT_CLASS: u32 = 12;
pub const ADS_NT_SECURITY_DESCRIPTOR: u32 = 25;

fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(o..o.checked_add(4)?)?.try_into().ok()?))
}

struct Prop {
    attr: Option<A>,
    is_dn: bool,
    ads: u32,
}

pub struct Snapshot {
    map: Mmap,
    props: Vec<Prop>,
    /// `(offset of first object, object count)` per chunk.
    chunks: Vec<(usize, u32)>,
    pub server: String,
    pub objects: u32,
}

/// Plausibility check on the first bytes of a file (`head`) of `len` bytes.
pub fn looks_like(head: &[u8], len: u64) -> bool {
    let (Some(n), Some(lo), Some(hi)) = (u32_at(head, 0x426), u32_at(head, 0x42e), u32_at(head, 0x432)) else {
        return false;
    };
    let props = (hi as u64) << 32 | lo as u64;
    if props < HEADER_LEN as u64 || props + 4 > len || n as u64 * 8 > props {
        return false;
    }
    if !matches!(u32_at(head, 0x42a), Some(a) if a <= 1 << 20) {
        return false;
    }
    // Server name: UTF-16 text.
    let server_ok = head[0x21e] != 0 && head[0x21f] == 0;
    let first_ok = n == 0
        || u32_at(head, HEADER_LEN).is_some_and(|s| s >= 8 && HEADER_LEN as u64 + s as u64 <= props);
    server_ok && first_ok
}

/// NUL-terminated UTF-16 at `o`, at most `max_bytes` long.
fn utf16z(b: &[u8], o: usize, max_bytes: usize) -> Option<String> {
    let mut units = Vec::new();
    let mut p = o;
    loop {
        if p - o >= max_bytes {
            return None;
        }
        let u = u16::from_le_bytes(b.get(p..p + 2)?.try_into().ok()?);
        if u == 0 {
            break;
        }
        units.push(u);
        p += 2;
    }
    Some(String::from_utf16_lossy(&units))
}

fn utf16_len(b: &[u8], o: usize, len: usize) -> Option<String> {
    let s = b.get(o..o + len)?;
    let units: Vec<u16> =
        (0..s.len() / 2).map(|i| u16::from_le_bytes([s[2 * i], s[2 * i + 1]])).take_while(|&u| u != 0).collect();
    Some(String::from_utf16_lossy(&units))
}

impl Snapshot {
    pub fn open(path: &Path) -> Result<Self> {
        let f = File::open(path)?;
        // SAFETY: inputs are only read; modifying them during ingest is unsupported.
        let map = unsafe { Mmap::map(&f)? };
        let b = &map[..];
        if !looks_like(b, b.len() as u64) {
            bail!("not an AD Explorer snapshot");
        }
        let n = u32_at(b, 0x426).unwrap_or(0);
        let props_off = (u32_at(b, 0x432).unwrap_or(0) as usize) << 32 | u32_at(b, 0x42e).unwrap_or(0) as usize;
        let server = utf16_len(b, 0x21e, 520).unwrap_or_default();

        // Property table.
        let corrupt = || format!("corrupt property table in {}", path.display());
        let np = u32_at(b, props_off).with_context(corrupt)? as usize;
        let mut props = Vec::with_capacity(np.min(1 << 20));
        let mut p = props_off + 4;
        for _ in 0..np {
            let nl = u32_at(b, p).with_context(corrupt)? as usize;
            let name = utf16_len(b, p + 4, nl).with_context(corrupt)?;
            p += 4 + nl + 4;
            let ads = u32_at(b, p).with_context(corrupt)?;
            let dl = u32_at(b, p + 4).with_context(corrupt)? as usize;
            p += 8 + dl + 16 + 16 + 4;
            if p > b.len() {
                bail!(corrupt());
            }
            props.push(Prop {
                attr: A::lookup(name.as_bytes()),
                is_dn: name.eq_ignore_ascii_case("distinguishedName"),
                ads,
            });
        }

        // Object walk: chunk boundaries only (no per-object index).
        let mut chunks = Vec::new();
        let mut off = HEADER_LEN;
        let (mut start, mut count) = (off, 0u32);
        for i in 0..n {
            let size = u32_at(b, off).with_context(|| format!("truncated object {i} in {}", path.display()))? as usize;
            if size < 8 || off + size > props_off {
                bail!("corrupt object {i} at offset {off} in {}", path.display());
            }
            off += size;
            count += 1;
            if off - start >= CHUNK_BYTES {
                chunks.push((start, count));
                start = off;
                count = 0;
            }
        }
        if count > 0 {
            chunks.push((start, count));
        }
        Ok(Self { map, props, chunks, server, objects: n })
    }

    /// Snapshot time from the header (FILETIME at 0x0e), unix seconds.
    pub fn time(&self) -> Option<i64> {
        let ft = i64::from_le_bytes(self.map.get(0x0e..0x16)?.try_into().ok()?);
        let t = ft.checked_div(10_000_000)? - 11_644_473_600;
        (631_152_000..7_258_118_400).contains(&t).then_some(t)
    }

    pub fn chunks(&self) -> usize {
        self.chunks.len()
    }
    pub fn len(&self) -> u64 {
        self.map.len() as u64
    }
    pub fn is_empty(&self) -> bool {
        self.objects == 0
    }

    pub fn read(&self, chunk: usize, need: Need, f: &mut Sink) {
        let b = &self.map[..];
        let (mut off, count) = self.chunks[chunk];
        for _ in 0..count {
            let size = u32_at(b, off).unwrap_or(0) as usize;
            match self.object(b, off, need) {
                Some(e) => {
                    if !e.dn.is_empty() {
                        f(Ok(e))
                    }
                }
                None => f(Err(format!("malformed object at offset {off}"))),
            }
            off += size;
        }
    }

    fn object<'a>(&self, b: &'a [u8], off: usize, need: Need) -> Option<Entry<'a>> {
        let size = u32_at(b, off)? as usize;
        let obj = b.get(off..off + size)?;
        let table = u32_at(obj, 4)? as usize;
        if 8 + table * 8 > size {
            return None;
        }
        let mut e = Entry::default();
        // Values lie inside their object and each is stored once, so the
        // text decoded from one object never exceeds its size; offsets that
        // point many values at the same long string are malformed.
        let ob = b.get(..off + size)?;
        let mut budget = size;
        for t in 0..table {
            let idx = u32_at(obj, 8 + t * 8)? as usize;
            let rel = u32_at(obj, 12 + t * 8)? as i32 as i64;
            let Some(p) = self.props.get(idx) else { continue };
            let wanted = p.attr.filter(|a| need & a.bit() != 0);
            if wanted.is_none() && !p.is_dn {
                continue;
            }
            let at = off as i64 + rel;
            if at < 0 || at as usize >= ob.len() {
                return None;
            }
            // Only the first DN value is used unless the attribute is wanted.
            let max = if wanted.is_some() { usize::MAX } else { 1 };
            let vals = values(ob, at as usize, p.ads, max, &mut budget)?;
            if p.is_dn {
                if let Some(Cow::Owned(v)) = vals.first() {
                    e.dn = Cow::Owned(String::from_utf8_lossy(v).into_owned());
                }
            }
            if let Some(a) = wanted {
                e.vals.extend(vals.into_iter().map(|v| (a, v)));
            }
        }
        Some(e)
    }
}

/// Decode the value block at `at` into LDAP-text / raw-binary values: at
/// most `max` of them, and strings only while `budget` (bytes of UTF-16
/// decoded from this object) lasts.
fn values<'a>(b: &'a [u8], at: usize, ads: u32, max: usize, budget: &mut usize) -> Option<Vec<Cow<'a, [u8]>>> {
    let n = u32_at(b, at)? as usize;
    if n > (b.len() - at) / 2 {
        return None;
    }
    let n_read = n.min(max);
    let mut out = Vec::with_capacity(n_read.min(1024));
    let base = at + 4;
    match ads {
        ADS_DN_STRING | ADS_CASE_EXACT_STRING | ADS_CASE_IGNORE_STRING | ADS_PRINTABLE_STRING | ADS_NUMERIC_STRING
        | ADS_OBJECT_CLASS => {
            for i in 0..n_read {
                let rel = u32_at(b, base + 4 * i)? as usize;
                let s = utf16z(b, at.checked_add(rel)?, *budget)?;
                *budget = budget.checked_sub(2 * s.encode_utf16().count() + 2)?;
                out.push(Cow::Owned(s.into_bytes()));
            }
        }
        ADS_OCTET_STRING => {
            let mut p = base + 4 * n;
            for i in 0..n {
                let len = u32_at(b, base + 4 * i)? as usize;
                out.push(Cow::Borrowed(b.get(p..p + len)?));
                p += len;
            }
        }
        ADS_BOOLEAN => {
            for i in 0..n {
                let v = u32_at(b, base + 4 * i)?;
                out.push(Cow::Borrowed(if v != 0 { &b"TRUE"[..] } else { &b"FALSE"[..] }));
            }
        }
        ADS_INTEGER => {
            for i in 0..n {
                out.push(Cow::Owned((u32_at(b, base + 4 * i)? as i32).to_string().into_bytes()));
            }
        }
        ADS_LARGE_INTEGER => {
            for i in 0..n {
                let v = i64::from_le_bytes(b.get(base + 8 * i..base + 8 * i + 8)?.try_into().ok()?);
                out.push(Cow::Owned(v.to_string().into_bytes()));
            }
        }
        ADS_UTC_TIME => {
            for i in 0..n {
                let s = b.get(base + 16 * i..base + 16 * i + 16)?;
                let w = |k: usize| u16::from_le_bytes([s[2 * k], s[2 * k + 1]]);
                // SYSTEMTIME: year, month, dayOfWeek, day, hour, minute, second, ms
                let t = format!("{:04}{:02}{:02}{:02}{:02}{:02}.0Z", w(0), w(1), w(3), w(4), w(5), w(6));
                out.push(Cow::Owned(t.into_bytes()));
            }
        }
        ADS_NT_SECURITY_DESCRIPTOR => {
            let mut p = base;
            for _ in 0..n {
                let len = u32_at(b, p)? as usize;
                out.push(Cow::Borrowed(b.get(p + 4..p + 4 + len)?));
                p += 4 + len;
            }
        }
        _ => {}
    }
    Some(out)
}

/// Snapshot writer for tests: lays out objects exactly as [`Snapshot`] reads
/// them. Not a full AD Explorer implementation (no class table).
#[doc(hidden)]
pub mod testing {
    use super::*;

    /// ADSTYPE used for an attribute when writing a test snapshot.
    pub fn ads_type(name: &str) -> u32 {
        let Some(a) = A::lookup(name.as_bytes()) else { return ADS_CASE_IGNORE_STRING };
        match a {
            A::Sd | A::AllowedToAct | A::GmsaMembership => ADS_NT_SECURITY_DESCRIPTOR,
            a if a.binary() => ADS_OCTET_STRING,
            A::Uac
            | A::AdminCount
            | A::PrimaryGroupId
            | A::Flags
            | A::SchemaVersion
            | A::EnrollmentFlag
            | A::NameFlag
            | A::RaSignature
            | A::TrustDirection
            | A::TrustType
            | A::TrustAttributes
            | A::GpOptions
            | A::BehaviorVersion
            | A::MachineAccountQuota => ADS_INTEGER,
            A::LastLogon | A::LastLogonTimestamp | A::PwdLastSet | A::LapsLegacyExpiry | A::LapsExpiry => {
                ADS_LARGE_INTEGER
            }
            A::WhenCreated => ADS_UTC_TIME,
            A::IsDeleted => ADS_BOOLEAN,
            A::ObjectClass => ADS_OBJECT_CLASS,
            A::DistinguishedName | A::Member | A::OidToGroupLink | A::NcName => ADS_DN_STRING,
            _ => ADS_CASE_IGNORE_STRING,
        }
    }

    fn wstr(s: &str) -> Vec<u8> {
        s.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect()
    }

    fn block(ads: u32, vals: &[Vec<u8>]) -> Vec<u8> {
        let mut out = (vals.len() as u32).to_le_bytes().to_vec();
        let text = |v: &Vec<u8>| String::from_utf8_lossy(v).into_owned();
        match ads {
            ADS_OCTET_STRING => {
                for v in vals {
                    out.extend_from_slice(&(v.len() as u32).to_le_bytes());
                }
                for v in vals {
                    out.extend_from_slice(v);
                }
            }
            ADS_NT_SECURITY_DESCRIPTOR => {
                for v in vals {
                    out.extend_from_slice(&(v.len() as u32).to_le_bytes());
                    out.extend_from_slice(v);
                }
            }
            ADS_BOOLEAN => {
                for v in vals {
                    out.extend_from_slice(&u32::from(text(v).eq_ignore_ascii_case("TRUE")).to_le_bytes());
                }
            }
            ADS_INTEGER => {
                for v in vals {
                    let x: i64 = text(v).trim().parse().unwrap_or(0);
                    out.extend_from_slice(&(x as i32).to_le_bytes());
                }
            }
            ADS_LARGE_INTEGER => {
                for v in vals {
                    let x: i64 = text(v).trim().parse().unwrap_or(0);
                    out.extend_from_slice(&x.to_le_bytes());
                }
            }
            ADS_UTC_TIME => {
                for v in vals {
                    let t = text(v);
                    let num = |r: std::ops::Range<usize>| t.get(r).and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
                    for w in [num(0..4), num(4..6), 0, num(6..8), num(8..10), num(10..12), num(12..14), 0] {
                        out.extend_from_slice(&w.to_le_bytes());
                    }
                }
            }
            _ => {
                let mut offs = Vec::new();
                let mut data = Vec::new();
                let head = 4 + 4 * vals.len();
                for v in vals {
                    offs.push((head + data.len()) as u32);
                    data.extend(wstr(&text(v)));
                }
                for o in offs {
                    out.extend_from_slice(&o.to_le_bytes());
                }
                out.extend(data);
            }
        }
        out
    }

    /// One object: DN and `(attribute name, values)`; the DN is also written
    /// as `distinguishedName`.
    pub type Object = (String, Vec<(String, Vec<Vec<u8>>)>);

    pub fn write(path: &Path, server: &str, objects: &[Object]) -> std::io::Result<()> {
        let mut names: Vec<String> = vec!["distinguishedName".into()];
        let index = |n: &str, names: &mut Vec<String>| -> u32 {
            match names.iter().position(|x| x.eq_ignore_ascii_case(n)) {
                Some(i) => i as u32,
                None => {
                    names.push(n.to_string());
                    (names.len() - 1) as u32
                }
            }
        };
        let mut body = Vec::new();
        for (dn, attrs) in objects {
            let mut list: Vec<(u32, Vec<u8>)> = vec![(0, block(ADS_DN_STRING, &[dn.as_bytes().to_vec()]))];
            for (n, vals) in attrs {
                if n.eq_ignore_ascii_case("distinguishedName") {
                    continue;
                }
                let i = index(n, &mut names);
                list.push((i, block(ads_type(n), vals)));
            }
            let head = 8 + 8 * list.len();
            let mut table = Vec::new();
            let mut data = Vec::new();
            for (i, blk) in &list {
                table.extend_from_slice(&i.to_le_bytes());
                table.extend_from_slice(&((head + data.len()) as i32).to_le_bytes());
                data.extend_from_slice(blk);
            }
            body.extend_from_slice(&((head + data.len()) as u32).to_le_bytes());
            body.extend_from_slice(&(list.len() as u32).to_le_bytes());
            body.extend(table);
            body.extend(data);
        }
        let props_off = (HEADER_LEN + body.len()) as u64;
        let mut props = (names.len() as u32).to_le_bytes().to_vec();
        for n in &names {
            let w = wstr(n);
            props.extend_from_slice(&(w.len() as u32).to_le_bytes());
            props.extend(w);
            props.extend_from_slice(&0i32.to_le_bytes());
            props.extend_from_slice(&ads_type(n).to_le_bytes());
            let dn = wstr(&format!("CN={n},CN=Schema,CN=Configuration,DC=example"));
            props.extend_from_slice(&(dn.len() as u32).to_le_bytes());
            props.extend(dn);
            props.extend_from_slice(&[0u8; 36]);
        }
        let classes_off = props_off + props.len() as u64;
        props.extend_from_slice(&0u32.to_le_bytes()); // numClasses

        let mut header = vec![0u8; HEADER_LEN];
        header[..10].copy_from_slice(b"win-ad-ob\0");
        let sw = wstr(server);
        header[0x21e..0x21e + sw.len().min(520)].copy_from_slice(&sw[..sw.len().min(520)]);
        header[0x426..0x42a].copy_from_slice(&(objects.len() as u32).to_le_bytes());
        header[0x42a..0x42e].copy_from_slice(&(names.len() as u32).to_le_bytes());
        header[0x42e..0x432].copy_from_slice(&(props_off as u32).to_le_bytes());
        header[0x432..0x436].copy_from_slice(&((props_off >> 32) as u32).to_le_bytes());
        header[0x436..0x43a].copy_from_slice(&(classes_off as u32).to_le_bytes());
        let mut out = header;
        out.extend(body);
        out.extend(props);
        std::fs::write(path, out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ldap::NEED_ALL;

    #[test]
    fn roundtrip_values() {
        let dir = std::env::temp_dir().join(format!("ch-adx-unit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("snap.dat");
        let sid = crate::ldap::sd::sid_bytes("S-1-5-21-1-2-3-1104").unwrap();
        let objs: Vec<testing::Object> = vec![(
            "CN=Alice,DC=corp,DC=local".into(),
            vec![
                ("objectClass".into(), vec![b"top".to_vec(), b"user".to_vec()]),
                ("objectSid".into(), vec![sid.clone()]),
                ("userAccountControl".into(), vec![b"66048".to_vec()]),
                ("pwdLastSet".into(), vec![b"133500000000000000".to_vec()]),
                ("whenCreated".into(), vec![b"20240102030405.0Z".to_vec()]),
                ("isDeleted".into(), vec![b"FALSE".to_vec()]),
                ("someUnknownAttr".into(), vec![b"x".to_vec()]),
            ],
        )];
        testing::write(&p, "dc01.corp.local", &objs).unwrap();
        let head = std::fs::read(&p).unwrap();
        assert!(looks_like(&head, head.len() as u64));
        let s = Snapshot::open(&p).unwrap();
        assert_eq!(s.server, "dc01.corp.local");
        assert_eq!(s.chunks(), 1);
        let mut seen = 0;
        s.read(0, NEED_ALL, &mut |r| {
            let e = r.unwrap();
            seen += 1;
            assert_eq!(e.dn, "CN=Alice,DC=corp,DC=local");
            assert!(e.has_class("user"));
            assert_eq!(e.first(A::ObjectSid).unwrap(), &sid[..]);
            assert_eq!(e.int(A::Uac), Some(66048));
            assert_eq!(e.int(A::PwdLastSet), Some(133500000000000000));
            assert_eq!(e.text(A::WhenCreated), Some("20240102030405.0Z"));
            assert_eq!(e.text(A::IsDeleted), Some("FALSE"));
        });
        assert_eq!(seen, 1);
        drop(s);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
