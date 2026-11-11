//! Streaming LDIF reader (RFC 2849), as written by OpenLDAP `ldapsearch`
//! (`-LLL` or not) and Windows `ldifde`.
//!
//! Handles `version:` lines, `#` comments (including folded comments and
//! `# refldap` / search-result trailers), records without a `dn` (`search:`,
//! `result:`, `ref:`), line folding (a leading space continues the previous
//! line), base64 values (`attr:: …`), attribute options (`member;range=…`),
//! LF and CRLF line ends. `attr:< URL` values are skipped.
//!
//! A blank line always ends a record (folded values cannot contain one), so
//! the memory-mapped file is cut at blank lines into ~4 MB chunks that are
//! parsed independently.

use super::{Entry, Need, Sink, A};
use anyhow::Result;
use memmap2::Mmap;
use std::borrow::Cow;
use std::fs::File;
use std::path::Path;

const CHUNK: usize = 4 << 20;

pub struct LdifFile {
    map: Option<Mmap>,
    /// Chunk `i` is `bounds[i]..bounds[i + 1]`.
    bounds: Vec<usize>,
}

impl LdifFile {
    pub fn open(path: &Path) -> Result<Self> {
        let f = File::open(path)?;
        if f.metadata()?.len() == 0 {
            return Ok(Self { map: None, bounds: vec![0] });
        }
        // SAFETY: inputs are only read; modifying them during ingest is unsupported.
        let map = unsafe { Mmap::map(&f)? };
        let bounds = split(&map, CHUNK);
        Ok(Self { map: Some(map), bounds })
    }
    pub fn chunks(&self) -> usize {
        self.bounds.len() - 1
    }
    pub fn len(&self) -> u64 {
        self.map.as_ref().map_or(0, |m| m.len() as u64)
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn read(&self, chunk: usize, need: Need, f: &mut Sink) {
        if let Some(m) = &self.map {
            parse(&m[self.bounds[chunk]..self.bounds[chunk + 1]], need, f);
        }
    }
}

/// Byte offsets cutting `b` at record boundaries into pieces of ≈ `target`.
pub fn split(b: &[u8], target: usize) -> Vec<usize> {
    let mut bounds = vec![0];
    let mut pos = 0;
    while pos < b.len() {
        let next = match pos.checked_add(target).filter(|&t| t < b.len()) {
            Some(t) => record_start_after(b, t),
            None => b.len(),
        };
        bounds.push(next);
        pos = next;
    }
    bounds
}

/// Index just past the first blank line at or after `from`.
fn record_start_after(b: &[u8], from: usize) -> usize {
    let mut i = from;
    while let Some(k) = memchr::memchr(b'\n', &b[i..]) {
        let p = i + k + 1;
        match b.get(p) {
            Some(b'\n') => return p + 1,
            Some(b'\r') if b.get(p + 1) == Some(&b'\n') => return p + 2,
            None => return b.len(),
            _ => i = p,
        }
    }
    b.len()
}

/// Heuristic: the first meaningful line (after BOM, comments, blank lines
/// and `version:`) is a `dn:` line.
pub fn looks_like(head: &[u8]) -> bool {
    let head = head.strip_prefix(&[0xEF, 0xBB, 0xBF][..]).unwrap_or(head);
    for line in head.split(|&c| c == b'\n') {
        let l = line.strip_suffix(b"\r").unwrap_or(line);
        if l.is_empty() || l[0] == b'#' || l[0] == b' ' {
            continue;
        }
        let lower = l.to_ascii_lowercase();
        if lower.starts_with(b"version:") {
            continue;
        }
        return lower.starts_with(b"dn:");
    }
    false
}

/// Decode standard base64, ignoring whitespace. `None` on invalid input.
pub fn base64(s: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0;
    for &c in s {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            b' ' | b'\t' | b'\r' | b'\n' => continue,
            _ => return None,
        };
        acc = acc << 6 | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// Parse every record in `b` (which starts at a record boundary).
pub fn parse(b: &[u8], need: Need, f: &mut Sink) {
    let mut lines: Vec<Cow<[u8]>> = Vec::with_capacity(64);
    let mut in_comment = false;
    let mut pos = 0;
    while pos <= b.len() {
        let end = memchr::memchr(b'\n', &b[pos..]).map_or(b.len(), |k| pos + k);
        let raw = &b[pos..end];
        let line = raw.strip_suffix(b"\r").unwrap_or(raw);
        pos = end + 1;
        if line.is_empty() {
            in_comment = false;
            if !lines.is_empty() {
                record(std::mem::take(&mut lines), need, f);
            }
            continue;
        }
        match line[0] {
            b' ' => {
                if !in_comment {
                    if let Some(last) = lines.last_mut() {
                        last.to_mut().extend_from_slice(&line[1..]);
                    }
                }
            }
            b'#' => in_comment = true,
            _ => {
                in_comment = false;
                lines.push(Cow::Borrowed(line));
            }
        }
    }
    if !lines.is_empty() {
        record(lines, need, f);
    }
}

fn sub<'a>(c: &Cow<'a, [u8]>, start: usize) -> Cow<'a, [u8]> {
    match c {
        Cow::Borrowed(b) => {
            let b: &'a [u8] = b;
            Cow::Borrowed(&b[start..])
        }
        Cow::Owned(v) => Cow::Owned(v[start..].to_vec()),
    }
}

/// Value of a `name[;options]: value` line with base64 decoded. `Ok(None)`
/// for URL values (`name:< url`) and lines without a colon.
fn line_value<'a>(l: &Cow<'a, [u8]>) -> std::result::Result<Option<Cow<'a, [u8]>>, String> {
    let bytes: &[u8] = l.as_ref();
    let Some(colon) = memchr::memchr(b':', bytes) else { return Ok(None) };
    let mut v = colon + 1;
    Ok(Some(match bytes.get(v) {
        Some(b':') => {
            v += 1;
            let decoded = base64(&bytes[v..])
                .ok_or_else(|| format!("invalid base64 in attribute {}", String::from_utf8_lossy(&bytes[..colon])))?;
            Cow::Owned(decoded)
        }
        Some(b'<') => return Ok(None),
        _ => {
            while bytes.get(v) == Some(&b' ') {
                v += 1;
            }
            sub(l, v)
        }
    }))
}

/// First value index of a `;range=X-Y` attribute option (`;range=1500-*`
/// → 1500). `None` without a range option.
fn range_start(options: &[u8]) -> Option<u64> {
    for opt in options.split(|&c| c == b';') {
        if opt.len() > 6 && opt[..6].eq_ignore_ascii_case(b"range=") {
            let r = &opt[6..];
            let end = r.iter().position(|&c| c == b'-').unwrap_or(r.len());
            return std::str::from_utf8(&r[..end]).ok()?.trim().parse().ok();
        }
    }
    None
}

fn record(lines: Vec<Cow<[u8]>>, need: Need, f: &mut Sink) {
    let mut e = Entry::default();
    let mut have_dn = false;
    for l in &lines {
        let bytes: &[u8] = l.as_ref();
        let Some(colon) = memchr::memchr(b':', bytes) else { continue };
        let name_full = &bytes[..colon];
        let name = &name_full[..memchr::memchr(b';', name_full).unwrap_or(name_full.len())];
        if !have_dn {
            if name.eq_ignore_ascii_case(b"dn") {
                match line_value(l) {
                    Ok(Some(v)) => {
                        e.dn = match v {
                            Cow::Borrowed(b) => String::from_utf8_lossy(b),
                            Cow::Owned(b) => Cow::Owned(String::from_utf8_lossy(&b).into_owned()),
                        };
                        have_dn = true;
                    }
                    Ok(None) => return,
                    Err(err) => return f(Err(err)),
                }
                continue;
            }
            if name.eq_ignore_ascii_case(b"version") {
                continue;
            }
            return; // search:/result:/ref: trailers, anything without a dn
        }
        if name.eq_ignore_ascii_case(b"changetype") {
            let v = &bytes[colon + 1..];
            if !v.trim_ascii().eq_ignore_ascii_case(b"add") {
                return; // modify / delete records describe changes, not objects
            }
            continue;
        }
        let Some(a) = A::lookup(name) else { continue };
        if need & a.bit() == 0 {
            continue;
        }
        if a == A::Member {
            if range_start(&name_full[name.len()..]).is_some_and(|s| s > 0) {
                e.member_tail = true;
            } else {
                e.member_head = true;
            }
        }
        match line_value(l) {
            Ok(Some(v)) => e.vals.push((a, v)),
            Ok(None) => {}
            Err(err) => return f(Err(format!("{}: {err}", e.dn))),
        }
    }
    if have_dn && !e.dn.trim().is_empty() {
        f(Ok(e));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ldap::NEED_ALL;

    type Owned = (String, Vec<(A, Vec<u8>)>);

    fn entries(src: &str) -> Vec<Owned> {
        let mut out = Vec::new();
        parse(src.as_bytes(), NEED_ALL, &mut |r| {
            let e = r.unwrap();
            out.push((e.dn.into_owned(), e.vals.into_iter().map(|(a, v)| (a, v.into_owned())).collect()));
        });
        out
    }

    #[test]
    fn folding_base64_comments() {
        let src = "version: 1\n\n# extended LDIF\n# continued\n  comment\ndn: CN=Alice Smith,OU=St\n aff,DC=corp,DC=local\nobjectClass: top\nobjectClass: user\ndescription: line one \n continued\nobjectSid:: AQUAAAAAAAUVAAAA\n AQAAAAIAAAADAAAAUAQAAA==\nmember;range=0-1: CN=X,DC=corp,DC=local\ncn:< file:///tmp/x\n\n# search result\nsearch: 2\nresult: 0 Success\n\n# refldap://corp.local/CN=Configuration,DC=corp,DC=local\n";
        let e = entries(src);
        assert_eq!(e.len(), 1);
        let (dn, vals) = &e[0];
        assert_eq!(dn, "CN=Alice Smith,OU=Staff,DC=corp,DC=local");
        let get = |a: A| vals.iter().filter(|(x, _)| *x == a).map(|(_, v)| v.clone()).collect::<Vec<_>>();
        assert_eq!(get(A::ObjectClass), vec![b"top".to_vec(), b"user".to_vec()]);
        assert_eq!(get(A::Description), vec![b"line one continued".to_vec()]);
        assert_eq!(
            crate::ldap::sd::sid_string(&get(A::ObjectSid)[0]).unwrap(),
            "S-1-5-21-1-2-3-1104"
        );
        assert_eq!(get(A::Member), vec![b"CN=X,DC=corp,DC=local".to_vec()]);
        assert!(get(A::Cn).is_empty());
    }

    #[test]
    fn crlf_base64_dn_and_split() {
        let mut s = String::new();
        for i in 0..1000 {
            s.push_str(&format!("dn:: {}\r\ncn: u{i}\r\n\r\n", b64(&format!("CN=u{i},DC=x"))));
        }
        let b = s.as_bytes();
        let bounds = split(b, 1000);
        assert!(bounds.len() > 10);
        let mut n = 0;
        for w in bounds.windows(2) {
            parse(&b[w[0]..w[1]], NEED_ALL, &mut |r| {
                let e = r.unwrap();
                assert_eq!(e.dn, format!("CN=u{n},DC=x"));
                n += 1;
            });
        }
        assert_eq!(n, 1000);
        assert!(looks_like(b"\xEF\xBB\xBF# x\nversion: 1\n\ndn: DC=x\n"));
        assert!(!looks_like(b"{\"data\":[]}"));
    }

    fn b64(s: &str) -> String {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for c in s.as_bytes().chunks(3) {
            let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
            for i in 0..4 {
                if i <= c.len() {
                    out.push(T[(n >> (18 - 6 * i)) as usize & 63] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    #[test]
    fn base64_decode() {
        assert_eq!(base64(b"aGVsbG8=").unwrap(), b"hello");
        assert_eq!(base64(b"aGVs bG8").unwrap(), b"hello");
        assert!(base64(b"a*b").is_none());
        assert_eq!(base64(b64("CN=u1,DC=x").as_bytes()).unwrap(), b"CN=u1,DC=x");
    }
}
