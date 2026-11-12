//! OpenGraph: generic nodes and edges in BloodHound CE's OpenGraph JSON
//! format, for data from any system (GitHub, Okta, databases, custom tools).
//!
//! ```json
//! {"metadata": {"source_kind": "GitHub"},
//!  "graph": {
//!    "nodes": [{"id": "u1", "kinds": ["GHUser"], "properties": {"name": "alice"}}],
//!    "edges": [{"kind": "GHAdminOf",
//!               "start": {"value": "u1"},
//!               "end": {"value": "acme", "match_by": "name", "kind": "GHOrg"}}]}}
//! ```
//!
//! * **Nodes.** `id` is the object id. The first kind that is not a tag
//!   (`Tag_*`) is the node's kind: a built-in kind when the name is one
//!   (`User`, `Computer`, `AZUser`, …, case-insensitive) — then AD/Entra
//!   analysis applies to it — else a custom kind, kept by name in the graph.
//!   All kinds, plus `metadata.source_kind`, are stored in the `kinds`
//!   property. `properties.name` (else `displayname`, else the id) is the
//!   display name.
//! * **Flags.** `enabled: true` sets Enabled. The `Tag_Tier_Zero` kind,
//!   `system_tags` containing `admin_tier_0`, or a true `isTierZero` /
//!   `highvalue` property mark Tier Zero; `Tag_Owned` (or `system_tags`
//!   `owned`) marks owned.
//! * **Edges.** `kind` is the edge kind (built-in if the name is one, else a
//!   custom traversable kind). `start` / `end` match by `id` (default) or by
//!   `name`; an optional `kind` restricts a name match (and is a kind hint for
//!   id matches). Name matches are resolved after all inputs are read, against
//!   every node's display name; an end matching no node or several nodes drops
//!   the edge (counted in the ingest report). Edge properties are not stored.
//!
//! A file is OpenGraph when its first top-level key is `graph` or `metadata`.
//! The file is parsed whole (not streamed).

use crate::emit::{upper, Emitter, EndRef};
use ch_model::flags;
use serde::Deserialize;
use serde_json::{Map, Value};

#[derive(Deserialize)]
pub struct File {
    #[serde(default)]
    pub metadata: Option<Metadata>,
    pub graph: Graph,
}

#[derive(Deserialize, Default)]
pub struct Metadata {
    #[serde(default)]
    pub source_kind: Option<String>,
}

#[derive(Deserialize)]
pub struct Graph {
    #[serde(default)]
    pub nodes: Vec<Node>,
    #[serde(default)]
    pub edges: Vec<Edge>,
}

#[derive(Deserialize)]
pub struct Node {
    #[serde(default, deserialize_with = "crate::de::lenient_string")]
    pub id: Option<String>,
    #[serde(default)]
    pub kinds: Vec<String>,
    #[serde(default)]
    pub properties: Map<String, Value>,
}

#[derive(Deserialize)]
pub struct Edge {
    pub kind: String,
    pub start: End,
    pub end: End,
}

#[derive(Deserialize)]
pub struct End {
    #[serde(default, deserialize_with = "crate::de::lenient_string")]
    pub value: Option<String>,
    #[serde(default)]
    pub match_by: Option<String>,
    #[serde(default)]
    pub kind: Option<String>,
}

/// First top-level key of a JSON object (`None` if not an object or the key
/// is not a plain string).
pub fn first_key(buf: &[u8]) -> Option<&str> {
    let b = buf.strip_prefix(&[0xEF, 0xBB, 0xBF][..]).unwrap_or(buf);
    let mut i = b.iter().position(|c| !c.is_ascii_whitespace())?;
    if b[i] != b'{' {
        return None;
    }
    i += 1;
    i += b[i..].iter().position(|c| !c.is_ascii_whitespace())?;
    if b[i] != b'"' {
        return None;
    }
    let start = i + 1;
    let len = b[start..].iter().take(64).position(|&c| c == b'"' || c == b'\\')?;
    if b[start + len] != b'"' {
        return None;
    }
    std::str::from_utf8(&b[start..start + len]).ok()
}

pub fn is_opengraph(buf: &[u8]) -> bool {
    matches!(first_key(buf), Some("graph" | "metadata"))
}

fn is_tag(k: &str) -> bool {
    k.len() > 4 && k[..4].eq_ignore_ascii_case("tag_")
}

fn truthy(p: &Map<String, Value>, key: &str) -> bool {
    p.iter().any(|(k, v)| k.eq_ignore_ascii_case(key) && v.as_bool() == Some(true))
}

fn system_tags(p: &Map<String, Value>) -> String {
    match p.iter().find(|(k, _)| k.eq_ignore_ascii_case("system_tags")).map(|(_, v)| v) {
        Some(Value::String(s)) => s.to_ascii_lowercase(),
        Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(" ").to_ascii_lowercase(),
        _ => String::new(),
    }
}

fn end_ref(em: &mut Emitter, e: &End) -> Option<EndRef> {
    let v = e.value.as_deref().map(str::trim).filter(|v| !v.is_empty())?;
    let by_name = e.match_by.as_deref().is_some_and(|m| m.eq_ignore_ascii_case("name"));
    if by_name {
        let kind = e.kind.as_deref().map(str::trim).filter(|k| !k.is_empty()).map(Box::from);
        return Some(EndRef::Name(upper(v).into_owned().into_boxed_str(), kind));
    }
    let hint = e.kind.as_deref().map(|k| em.node_kind_raw(k)).unwrap_or(0);
    em.hint_raw(v, hint).map(EndRef::Id)
}

/// Emit one OpenGraph file.
pub fn extract(f: File, em: &mut Emitter) {
    let source_kind = f.metadata.and_then(|m| m.source_kind).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    em.unscoped();
    for (i, n) in f.graph.nodes.into_iter().enumerate() {
        let Some(id) = n.id.as_deref().map(str::trim).filter(|s| !s.is_empty()) else {
            em.error(|| format!("OpenGraph node #{i}: missing id"));
            continue;
        };
        let primary = n.kinds.iter().map(|k| k.trim()).find(|k| !k.is_empty() && !is_tag(k));
        let kind = primary.map(|k| em.node_kind_raw(k)).unwrap_or(0);
        let p = &n.properties;
        let mut fl = 0;
        if truthy(p, "enabled") {
            fl |= flags::ENABLED;
        }
        let tags = system_tags(p);
        let has_kind = |name: &str| n.kinds.iter().any(|k| k.trim().eq_ignore_ascii_case(name));
        if has_kind("Tag_Tier_Zero") || tags.contains("admin_tier_0") || truthy(p, "isTierZero") || truthy(p, "highvalue") {
            fl |= flags::TIER0;
        }
        if has_kind("Tag_Owned") || tags.split_whitespace().any(|t| t == "owned") {
            fl |= flags::OWNED;
        }
        let str_prop = |key: &str| {
            p.iter().find(|(k, _)| k.eq_ignore_ascii_case(key)).and_then(|(_, v)| v.as_str()).map(str::trim).filter(|s| !s.is_empty())
        };
        // Without a name the id is only a fallback: an enrichment record
        // (built-in kind, same id as a collected object) must not replace
        // the collected name.
        let name = str_prop("name").or_else(|| str_prop("displayname")).map(str::to_string);
        let props = em.keep_props().then(|| {
            let mut m = n.properties.clone();
            let mut kinds: Vec<Value> = n.kinds.iter().map(|k| Value::String(k.trim().to_string())).collect();
            if let Some(sk) = &source_kind {
                if !n.kinds.iter().any(|k| k.trim().eq_ignore_ascii_case(sk)) {
                    kinds.push(Value::String(sk.clone()));
                }
            }
            m.insert("kinds".into(), Value::Array(kinds));
            Value::Object(m).to_string().into_boxed_str()
        });
        em.own_raw(id, kind, name.as_deref(), fl, props);
        if name.is_none() {
            em.hint_named(id, ch_model::NodeKind::Unknown, Some(id));
        }
    }
    for (i, e) in f.graph.edges.into_iter().enumerate() {
        let kind = e.kind.trim();
        if kind.is_empty() {
            em.error(|| format!("OpenGraph edge #{i}: missing kind"));
            continue;
        }
        let k = em.kind_id(kind);
        let (Some(s), Some(d)) = (end_ref(em, &e.start), end_ref(em, &e.end)) else {
            em.error(|| format!("OpenGraph edge #{i} ({kind}): missing start or end value"));
            continue;
        };
        match (s, d) {
            (EndRef::Id(s), EndRef::Id(d)) => em.edge(s, d, k),
            (s, d) => em.name_edge(s, d, k),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_by_first_key() {
        assert!(is_opengraph(br#"  {"graph": {"nodes": []}}"#));
        assert!(is_opengraph(b"\xEF\xBB\xBF{\n \"metadata\": {}, \"graph\": {}}"));
        assert!(!is_opengraph(br#"{"data": [], "meta": {}}"#));
        assert!(!is_opengraph(br#"[{"graph": 1}]"#));
    }
}
