//! Structural JSON scanner.
//!
//! Splits a collector file into the byte ranges of its records without
//! parsing them, so records can be deserialised in parallel. Handles:
//!
//! * SharpHound / bloodhound-python: `{"data":[ {...}, ... ], "meta":{...}}`
//!   (`meta` may come before or after `data`).
//! * ldapdomaindump and other array dumps: `[ {...}, ... ]`.
//!
//! The scanner tracks only string boundaries and brace depth, jumping with
//! SIMD `memchr`. Large record arrays are scanned in parallel speculatively:
//! each chunk guesses its first record boundary (`}` `,` `{`), scans from it,
//! and chunks are stitched in order. A chunk is accepted only if its guessed
//! start equals the exact position where the previous chunk stopped;
//! otherwise it is rescanned from that position. The result is therefore
//! identical to a sequential scan, whatever the file contains.

use anyhow::{bail, Result};
use rayon::prelude::*;

/// Input file type, from the extension and the first bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputKind {
    /// SharpHound / bloodhound-python / ldapdomaindump / AzureHound JSON.
    Json,
    Zip,
    /// RFC 2849 LDIF (`ldapsearch`, `ldifde`).
    Ldif,
    /// gzip; LDIF inside is checked after decompressing the head.
    Gzip,
    /// Sysinternals AD Explorer snapshot.
    AdExplorer,
}

/// Detect the input kind of `path` (reads at most 4 KB). `None` for files
/// that are not collector output.
pub fn detect(path: &std::path::Path) -> Option<InputKind> {
    use std::io::Read;
    let lower = path.file_name()?.to_string_lossy().to_ascii_lowercase();
    if lower.ends_with(".json") {
        return Some(InputKind::Json);
    }
    let mut f = std::fs::File::open(path).ok()?;
    let len = f.metadata().ok()?.len();
    let mut head = Vec::with_capacity(4096);
    (&mut f).take(4096).read_to_end(&mut head).ok()?;
    if head.starts_with(b"PK\x03\x04") || (lower.ends_with(".zip") && head.is_empty()) {
        return Some(InputKind::Zip);
    }
    if head.starts_with(&[0x1f, 0x8b]) {
        return Some(InputKind::Gzip);
    }
    if crate::ldap::adexplorer::looks_like(&head, len) {
        return Some(InputKind::AdExplorer);
    }
    if crate::ldap::ldif::looks_like(&head) {
        return Some(InputKind::Ldif);
    }
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// `{"data":[...], "meta":{...}}`
    Wrapped,
    /// Top-level array of records.
    Array,
}

#[derive(Debug)]
pub struct Scanned<'a> {
    pub layout: Layout,
    pub meta: Option<&'a [u8]>,
    /// `(start, end)` byte range of every record, in file order.
    pub ranges: Vec<(usize, usize)>,
}

/// Arrays smaller than this are scanned sequentially.
const PARALLEL_MIN: usize = 32 << 20;
const CHUNK_MIN: usize = 8 << 20;

#[inline]
fn is_ws(c: u8) -> bool {
    matches!(c, b' ' | b'\n' | b'\r' | b'\t')
}

#[inline]
fn skip_ws(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && is_ws(b[i]) {
        i += 1;
    }
    i
}

/// `b[i]` must be `"`. Returns the index just past the closing quote.
#[inline]
fn skip_string(b: &[u8], i: usize) -> Result<usize> {
    let mut j = i + 1;
    loop {
        if j >= b.len() {
            bail!("unterminated string starting at byte {i}");
        }
        match memchr::memchr2(b'"', b'\\', &b[j..]) {
            None => bail!("unterminated string starting at byte {i}"),
            Some(k) => {
                let p = j + k;
                if b[p] == b'\\' {
                    j = p + 2;
                } else {
                    return Ok(p + 1);
                }
            }
        }
    }
}

/// Skip one JSON value starting at `b[i]` (non-whitespace). Returns the end index.
fn skip_value(b: &[u8], i: usize) -> Result<usize> {
    match b[i] {
        b'"' => skip_string(b, i),
        b'{' => {
            // Only braces affect object depth (arrays nest inside but cannot
            // close an object), so jump between `"`, `{`, `}` with SIMD memchr.
            let mut depth = 0usize;
            let mut j = i;
            while let Some(k) = memchr::memchr3(b'"', b'{', b'}', &b[j..]) {
                let p = j + k;
                match b[p] {
                    b'"' => {
                        j = skip_string(b, p)?;
                        continue;
                    }
                    b'{' => depth += 1,
                    _ => {
                        depth -= 1;
                        if depth == 0 {
                            return Ok(p + 1);
                        }
                    }
                }
                j = p + 1;
            }
            bail!("unterminated object starting at byte {i}")
        }
        b'[' => {
            let mut depth = 0usize;
            let mut j = i;
            while j < b.len() {
                match b[j] {
                    b'"' => {
                        j = skip_string(b, j)?;
                        continue;
                    }
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' => {
                        depth -= 1;
                        if depth == 0 {
                            return Ok(j + 1);
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
            bail!("unterminated array starting at byte {i}")
        }
        _ => {
            let mut j = i;
            while j < b.len() && !matches!(b[j], b',' | b'}' | b']') && !is_ws(b[j]) {
                j += 1;
            }
            // A value is never empty: a stray `}` / `]` / `,` here would make
            // the record scanner loop without advancing.
            if j == i {
                bail!("unexpected '{}' at byte {i}", b.get(i).map_or('?', |&c| c as char));
            }
            Ok(j)
        }
    }
}

struct Chunk {
    ranges: Vec<(usize, usize)>,
    /// Array closed: index just past `]`.
    end: Option<usize>,
    /// Otherwise: first record start at or beyond the chunk limit.
    next: usize,
}

/// Scan records starting at `start` (a record start, a `,`, `]` or whitespace)
/// until the array closes or a record would start at/after `limit`.
fn scan_chunk(b: &[u8], start: usize, limit: usize) -> Result<Chunk> {
    let mut ranges = Vec::new();
    let mut i = start;
    loop {
        i = skip_ws(b, i);
        match b.get(i) {
            None => bail!("unterminated record array"),
            Some(b']') => {
                return Ok(Chunk {
                    ranges,
                    end: Some(i + 1),
                    next: i,
                })
            }
            Some(b',') => i += 1,
            Some(_) => {
                if i >= limit {
                    return Ok(Chunk {
                        ranges,
                        end: None,
                        next: i,
                    });
                }
                let e = skip_value(b, i)?;
                ranges.push((i, e));
                i = e;
            }
        }
    }
}

/// First `{` at or after `from` that is preceded by `}` `,` (ignoring
/// whitespace) — a likely record boundary. Searches up to `limit`.
fn boundary_candidate(b: &[u8], from: usize, limit: usize) -> Option<usize> {
    let limit = limit.min(b.len());
    let mut j = from;
    while j < limit {
        let p = j + memchr::memchr(b'{', &b[j..limit])?;
        let mut q = p;
        while q > 0 && is_ws(b[q - 1]) {
            q -= 1;
        }
        if q > 0 && b[q - 1] == b',' {
            let mut r = q - 1;
            while r > 0 && is_ws(b[r - 1]) {
                r -= 1;
            }
            if r > 0 && b[r - 1] == b'}' {
                return Some(p);
            }
        }
        j = p + 1;
    }
    None
}

/// Scan the array whose `[` is at `b[open]`. Returns record ranges and the
/// index just past `]`.
fn scan_array(b: &[u8], open: usize) -> Result<(Vec<(usize, usize)>, usize)> {
    debug_assert_eq!(b[open], b'[');
    let first = open + 1;
    let len = b.len() - first;
    let threads = rayon::current_num_threads();
    if len < PARALLEL_MIN || threads < 2 {
        let c = scan_chunk(b, first, usize::MAX)?;
        return Ok((c.ranges, c.end.expect("unbounded scan ends at ']'")));
    }

    let n = (len / CHUNK_MIN).clamp(2, threads * 4);
    let step = len / n;
    let bounds: Vec<usize> = (0..=n)
        .map(|k| if k == n { b.len() } else { first + k * step })
        .collect();

    // Speculative pass: (guessed start, result) per chunk.
    let spec: Vec<Option<(usize, Chunk)>> = (0..n)
        .into_par_iter()
        .map(|k| {
            let start = if k == 0 {
                first
            } else {
                boundary_candidate(b, bounds[k], bounds[k + 1] + (64 << 20))?
            };
            scan_chunk(b, start, bounds[k + 1]).ok().map(|c| (start, c))
        })
        .collect();

    // Stitch, verifying each chunk starts exactly where the previous stopped.
    let mut ranges = Vec::new();
    let mut pos = first;
    for (k, s) in spec.into_iter().enumerate() {
        let chunk = match s {
            Some((start, c)) if start == pos => c,
            _ => scan_chunk(b, pos, bounds[k + 1])?,
        };
        ranges.extend_from_slice(&chunk.ranges);
        if let Some(end) = chunk.end {
            return Ok((ranges, end));
        }
        pos = chunk.next;
    }
    bail!("record array not terminated")
}

/// Scan a collector file into record ranges.
pub fn scan_records(buf: &[u8]) -> Result<Scanned<'_>> {
    let b = buf;
    let mut i = if b.starts_with(&[0xEF, 0xBB, 0xBF]) {
        3
    } else {
        0
    };
    i = skip_ws(b, i);
    match b.get(i) {
        Some(b'[') => {
            let (ranges, _) = scan_array(b, i)?;
            Ok(Scanned {
                layout: Layout::Array,
                meta: None,
                ranges,
            })
        }
        Some(b'{') => {
            i += 1;
            let mut meta = None;
            let mut ranges = Vec::new();
            loop {
                i = skip_ws(b, i);
                match b.get(i) {
                    None => bail!("unterminated top-level object"),
                    Some(b'}') => break,
                    Some(b',') => {
                        i += 1;
                        continue;
                    }
                    Some(b'"') => {}
                    Some(c) => bail!("unexpected byte {:?} at offset {i}", *c as char),
                }
                let ke = skip_string(b, i)?;
                let key = &b[i + 1..ke - 1];
                i = skip_ws(b, ke);
                if b.get(i) != Some(&b':') {
                    bail!("expected ':' at offset {i}");
                }
                i = skip_ws(b, i + 1);
                if i >= b.len() {
                    bail!("truncated file");
                }
                if key == b"data" && b[i] == b'[' {
                    let (r, end) = scan_array(b, i)?;
                    ranges = r;
                    i = end;
                } else {
                    let e = skip_value(b, i)?;
                    if key == b"meta" {
                        meta = Some(&b[i..e]);
                    }
                    i = e;
                }
            }
            Ok(Scanned {
                layout: Layout::Wrapped,
                meta,
                ranges,
            })
        }
        _ => bail!("not a JSON object or array"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recs(src: &str) -> (Vec<String>, Scanned<'_>) {
        let s = scan_records(src.as_bytes()).unwrap();
        (
            s.ranges
                .iter()
                .map(|(a, b)| src[*a..*b].to_string())
                .collect(),
            s,
        )
    }

    /// Stray closing brackets are errors, not an endless loop.
    #[test]
    fn stray_closers_fail() {
        for src in ["[}]", "[ } ]", "[1,}]", r#"{"data":[{"a":1},}]}"#, "[1 }]"] {
            let t = std::time::Instant::now();
            assert!(scan_records(src.as_bytes()).is_err(), "{src}");
            assert!(t.elapsed().as_secs() < 1, "{src}");
        }
    }

    #[test]
    fn wrapped_meta_after_data() {
        let src =
            r#"{"data":[{"a":"x}\"]{"},{"b":[1,{"c":2}]}],"meta":{"type":"users","count":2}}"#;
        let (r, s) = recs(src);
        assert_eq!(r, vec![r#"{"a":"x}\"]{"}"#, r#"{"b":[1,{"c":2}]}"#]);
        assert_eq!(s.layout, Layout::Wrapped);
        assert_eq!(s.meta.unwrap(), br#"{"type":"users","count":2}"#);
    }

    #[test]
    fn wrapped_meta_first_with_bom_and_ws() {
        let src = "\u{feff} { \"meta\" : {\"type\":\"groups\"} ,\n \"data\" : [ {\"x\":1} , {\"y\":null} ] }";
        let (r, s) = recs(src);
        assert_eq!(r.len(), 2);
        assert!(s.meta.is_some());
    }

    #[test]
    fn top_level_array() {
        let (r, s) = recs(r#"[ {"attributes":{"cn":["a"]}}, {"attributes":{}} ]"#);
        assert_eq!(r.len(), 2);
        assert_eq!(s.layout, Layout::Array);
    }

    #[test]
    fn truncated_is_error() {
        assert!(scan_records(br#"{"data":[{"a":1}"#).is_err());
        assert!(scan_records(br#"{"data":[{"a":"unterminated}]}"#).is_err());
    }

    /// Parallel scan must equal sequential scan, including when string values
    /// contain fake record boundaries designed to fool the speculation.
    #[test]
    fn parallel_matches_sequential_adversarial() {
        let mut s = String::from("{\"data\":[");
        for i in 0..1_000_000 {
            if i > 0 {
                s.push(',');
            }
            if i % 7 == 0 {
                // A string containing `},{` — a false boundary candidate.
                s.push_str(&format!(
                    r#"{{"id":{i},"trap":"x}},{{\"y\":\"}},{{","n":[{{"z":1}}]}}"#
                ));
            } else {
                s.push_str(&format!(r#"{{"id":{i},"name":"OBJECT{i}@CORP.LOCAL"}}"#));
            }
        }
        s.push_str("],\"meta\":{\"type\":\"users\"}}");
        assert!(s.len() > PARALLEL_MIN);
        let b = s.as_bytes();
        let par = scan_records(b).unwrap();
        let open = s.find('[').unwrap();
        let seq = scan_chunk(b, open + 1, usize::MAX).unwrap();
        assert_eq!(par.ranges.len(), 1_000_000);
        assert_eq!(par.ranges, seq.ranges);
        assert!(par.meta.is_some());
    }
}
