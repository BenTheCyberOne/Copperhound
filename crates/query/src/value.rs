//! Runtime values, comparison semantics and node property access.

use crate::ast::{CmpOp, Lit};
use ch_model::flags;
use ch_store::Graph;
use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, Visitor};
use serde_json::Value;
use std::borrow::Cow;
use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

/// `(src, dst, kind)` in graph orientation.
pub type E = (u32, u32, u16);

#[derive(Clone, Debug, Default)]
pub enum Val {
    #[default]
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    List(Vec<Val>),
    Node(u32),
    /// One relationship.
    Edge(E),
    /// A variable-length relationship: the edges in pattern order.
    Edges(Arc<[E]>),
    Path(Arc<PathVal>),
    /// `allShortestPaths` result: union of every shortest path (not a
    /// sequence).
    Subgraph(Arc<PathVal>),
    /// Small map (e.g. `datetime()`); keys lower-case.
    Map(Arc<Vec<(String, Val)>>),
}

#[derive(Debug, Default)]
pub struct PathVal {
    pub nodes: Vec<u32>,
    pub edges: Vec<E>,
}

impl Val {
    pub fn from_json(v: Value) -> Val {
        match v {
            Value::Null => Val::Null,
            Value::Bool(b) => Val::Bool(b),
            Value::Number(n) => Val::Num(n.as_f64().unwrap_or(f64::NAN)),
            Value::String(s) => Val::Str(s),
            Value::Array(a) => Val::List(a.into_iter().map(Val::from_json).collect()),
            Value::Object(_) => Val::Str(v.to_string()),
        }
    }
    pub fn from_lit(l: &Lit) -> Val {
        match l {
            Lit::Str(s) => Val::Str(s.clone()),
            Lit::Int(i) => Val::Num(*i as f64),
            Lit::Float(f) => Val::Num(*f),
            Lit::Bool(b) => Val::Bool(*b),
            Lit::Null => Val::Null,
        }
    }
    pub fn is_null(&self) -> bool {
        matches!(self, Val::Null)
    }
    /// Truthiness used by WHERE (CHQL keeps two-valued logic: null is false).
    pub fn truthy(&self) -> bool {
        match self {
            Val::Null => false,
            Val::Bool(b) => *b,
            Val::Num(n) => *n != 0.0,
            Val::Str(s) => !s.is_empty(),
            Val::List(v) => !v.is_empty(),
            _ => true,
        }
    }
    pub fn as_num(&self) -> Option<f64> {
        match self {
            Val::Num(n) => Some(*n),
            Val::Str(s) => s.trim().parse().ok(),
            Val::Bool(b) => Some(*b as u8 as f64),
            _ => None,
        }
    }
    /// True for values that render on the graph canvas.
    pub fn is_graph(&self) -> bool {
        match self {
            Val::Node(_) | Val::Edge(_) | Val::Edges(_) | Val::Path(_) | Val::Subgraph(_) | Val::Null => true,
            Val::List(v) => !v.is_empty() && v.iter().all(Val::is_graph),
            _ => false,
        }
    }
    /// Table cell: nodes render as names, relationships as kind names.
    pub fn to_json(&self, g: &Graph) -> Value {
        match self {
            Val::Null => Value::Null,
            Val::Bool(b) => Value::Bool(*b),
            Val::Num(n) => num_json(*n),
            Val::Str(s) => Value::String(s.clone()),
            Val::List(v) => Value::Array(v.iter().map(|x| x.to_json(g)).collect()),
            Val::Node(id) => Value::String(g.name(*id).to_string()),
            Val::Edge(e) => Value::String(g.edge_kind_name(e.2).to_string()),
            Val::Edges(es) => Value::Array(es.iter().map(|e| Value::String(g.edge_kind_name(e.2).into())).collect()),
            Val::Path(p) | Val::Subgraph(p) => Value::Array(p.nodes.iter().map(|&n| Value::String(g.name(n).into())).collect()),
            Val::Map(m) => Value::Object(m.iter().map(|(k, v)| (k.clone(), v.to_json(g))).collect()),
        }
    }
    fn rank(&self) -> u8 {
        // Cypher ascending order: map, node, relationship, list, path, string, boolean, number, null.
        match self {
            Val::Map(_) => 0,
            Val::Node(_) => 1,
            Val::Edge(_) | Val::Edges(_) => 2,
            Val::List(_) => 3,
            Val::Path(_) | Val::Subgraph(_) => 4,
            Val::Str(_) => 5,
            Val::Bool(_) => 6,
            Val::Num(_) => 7,
            Val::Null => 8,
        }
    }
}

pub fn num_json(n: f64) -> Value {
    if n.fract() == 0.0 && n.abs() < 9e15 {
        Value::from(n as i64)
    } else {
        serde_json::Number::from_f64(n).map(Value::Number).unwrap_or(Value::Null)
    }
}

/// CHQL equality: strings compare case-insensitively; `list = scalar` is
/// membership (collector properties are often lists).
pub fn val_eq(a: &Val, b: &Val) -> bool {
    match (a, b) {
        (Val::List(xs), Val::List(ys)) => xs.len() == ys.len() && xs.iter().zip(ys).all(|(x, y)| val_eq(x, y)),
        (Val::List(xs), y) => xs.iter().any(|x| val_eq(x, y)),
        (Val::Null, Val::Null) => true,
        (Val::Null, _) | (_, Val::Null) => false,
        (Val::Str(x), Val::Str(y)) => x.eq_ignore_ascii_case(y),
        (Val::Bool(x), Val::Bool(y)) => x == y,
        (Val::Node(x), Val::Node(y)) => x == y,
        (Val::Edge(x), Val::Edge(y)) => x == y,
        (Val::Edges(x), Val::Edges(y)) => x == y,
        (Val::Path(x), Val::Path(y)) | (Val::Subgraph(x), Val::Subgraph(y)) => x.nodes == y.nodes && x.edges == y.edges,
        (Val::Node(_) | Val::Edge(_) | Val::Edges(_) | Val::Path(_) | Val::Subgraph(_) | Val::Map(_), _)
        | (_, Val::Node(_) | Val::Edge(_) | Val::Edges(_) | Val::Path(_) | Val::Subgraph(_) | Val::Map(_)) => false,
        (x, y) => match (x.as_num(), y.as_num()) {
            (Some(p), Some(q)) => p == q,
            _ => false,
        },
    }
}

/// Ordering for `<`/`>` comparisons: `None` when incomparable.
pub fn val_ord(a: &Val, b: &Val) -> Option<Ordering> {
    match (a, b) {
        (Val::Null, _) | (_, Val::Null) => None,
        (Val::Str(x), Val::Str(y)) if x.parse::<f64>().is_err() || y.parse::<f64>().is_err() => Some(cmp_ci(x, y)),
        (Val::Node(x), Val::Node(y)) => Some(x.cmp(y)),
        (x, y) => x.as_num()?.partial_cmp(&y.as_num()?),
    }
}

fn cmp_ci(x: &str, y: &str) -> Ordering {
    let a = x.bytes().map(|c| c.to_ascii_uppercase());
    let b = y.bytes().map(|c| c.to_ascii_uppercase());
    a.cmp(b).then_with(|| x.cmp(y))
}

/// Total order for ORDER BY / min / max (nulls last ascending).
pub fn sort_cmp(a: &Val, b: &Val) -> Ordering {
    let (ra, rb) = (a.rank(), b.rank());
    if ra != rb {
        return ra.cmp(&rb);
    }
    match (a, b) {
        (Val::Num(x), Val::Num(y)) => x.total_cmp(y),
        (Val::Str(x), Val::Str(y)) => cmp_ci(x, y),
        (Val::Bool(x), Val::Bool(y)) => x.cmp(y),
        (Val::Node(x), Val::Node(y)) => x.cmp(y),
        (Val::Edge(x), Val::Edge(y)) => x.cmp(y),
        (Val::List(x), Val::List(y)) => {
            for (p, q) in x.iter().zip(y) {
                let o = sort_cmp(p, q);
                if o != Ordering::Equal {
                    return o;
                }
            }
            x.len().cmp(&y.len())
        }
        (Val::Path(x), Val::Path(y)) => x.nodes.len().cmp(&y.nodes.len()).then_with(|| x.nodes.cmp(&y.nodes)),
        _ => Ordering::Equal,
    }
}

fn str_op(a: &Val, needle: &Val, f: fn(&str, &str) -> bool) -> bool {
    let Val::Str(n) = needle else { return false };
    let n = n.to_ascii_uppercase();
    match a {
        Val::Str(s) => f(&s.to_ascii_uppercase(), &n),
        Val::List(v) => v.iter().any(|x| matches!(x, Val::Str(s) if f(&s.to_ascii_uppercase(), &n))),
        _ => false,
    }
}

/// Every comparison except `=~` (compiled separately).
pub fn compare(a: &Val, op: CmpOp, b: &Val) -> bool {
    use Ordering::*;
    match op {
        // `x = null` is never true (Cypher: null); `IS NULL` tests for null.
        CmpOp::Eq => !a.is_null() && !b.is_null() && val_eq(a, b),
        CmpOp::Ne => !a.is_null() && !b.is_null() && !val_eq(a, b),
        CmpOp::Lt => val_ord(a, b) == Some(Less),
        CmpOp::Le => matches!(val_ord(a, b), Some(Less | Equal)),
        CmpOp::Gt => val_ord(a, b) == Some(Greater),
        CmpOp::Ge => matches!(val_ord(a, b), Some(Greater | Equal)),
        CmpOp::StartsWith => str_op(a, b, |s, n| s.starts_with(n)),
        CmpOp::EndsWith => str_op(a, b, |s, n| s.ends_with(n)),
        CmpOp::Contains => str_op(a, b, |s, n| s.contains(n)),
        CmpOp::In => match b {
            Val::List(items) => !a.is_null() && items.iter().any(|x| val_eq(a, x)),
            other => val_eq(a, other),
        },
        CmpOp::Regex => false,
    }
}

// ----------------------------------------------------------- hashing (DISTINCT / grouping)

/// Exact (case-sensitive) structural identity for grouping and DISTINCT.
#[derive(Clone, Debug)]
pub struct Key(pub Vec<Val>);

fn hash_val<H: Hasher>(v: &Val, h: &mut H) {
    std::mem::discriminant(v).hash(h);
    match v {
        Val::Null => {}
        Val::Bool(b) => b.hash(h),
        Val::Num(n) => (if *n == 0.0 { 0.0f64 } else { *n }).to_bits().hash(h),
        Val::Str(s) => s.hash(h),
        Val::List(xs) => {
            xs.len().hash(h);
            xs.iter().for_each(|x| hash_val(x, h));
        }
        Val::Node(id) => id.hash(h),
        Val::Edge(e) => e.hash(h),
        Val::Edges(es) => es.hash(h),
        Val::Path(p) | Val::Subgraph(p) => {
            p.nodes.hash(h);
            p.edges.hash(h);
        }
        Val::Map(m) => {
            for (k, v) in m.iter() {
                k.hash(h);
                hash_val(v, h);
            }
        }
    }
}

fn same(a: &Val, b: &Val) -> bool {
    match (a, b) {
        (Val::Null, Val::Null) => true,
        (Val::Bool(x), Val::Bool(y)) => x == y,
        (Val::Num(x), Val::Num(y)) => x == y || (x.is_nan() && y.is_nan()),
        (Val::Str(x), Val::Str(y)) => x == y,
        (Val::List(x), Val::List(y)) => x.len() == y.len() && x.iter().zip(y).all(|(p, q)| same(p, q)),
        (Val::Node(x), Val::Node(y)) => x == y,
        (Val::Edge(x), Val::Edge(y)) => x == y,
        (Val::Edges(x), Val::Edges(y)) => x == y,
        (Val::Path(x), Val::Path(y)) | (Val::Subgraph(x), Val::Subgraph(y)) => x.nodes == y.nodes && x.edges == y.edges,
        (Val::Map(x), Val::Map(y)) => x.len() == y.len() && x.iter().zip(y.iter()).all(|(p, q)| p.0 == q.0 && same(&p.1, &q.1)),
        _ => false,
    }
}

impl Hash for Key {
    fn hash<H: Hasher>(&self, h: &mut H) {
        self.0.len().hash(h);
        self.0.iter().for_each(|v| hash_val(v, h));
    }
}
impl PartialEq for Key {
    fn eq(&self, o: &Self) -> bool {
        self.0.len() == o.0.len() && self.0.iter().zip(&o.0).all(|(a, b)| same(a, b))
    }
}
impl Eq for Key {}

/// Single-value hash key.
#[derive(Clone, Debug)]
pub struct VKey(pub Val);
impl Hash for VKey {
    fn hash<H: Hasher>(&self, h: &mut H) {
        hash_val(&self.0, h)
    }
}
impl PartialEq for VKey {
    fn eq(&self, o: &Self) -> bool {
        same(&self.0, &o.0)
    }
}
impl Eq for VKey {}

// ---------------------------------------------------------- properties

struct KeyStr<'de>(Cow<'de, str>);
impl<'de> serde::Deserialize<'de> for KeyStr<'de> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = KeyStr<'de>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a key")
            }
            fn visit_borrowed_str<Er>(self, v: &'de str) -> Result<KeyStr<'de>, Er> {
                Ok(KeyStr(Cow::Borrowed(v)))
            }
            fn visit_str<Er>(self, v: &str) -> Result<KeyStr<'de>, Er> {
                Ok(KeyStr(Cow::Owned(v.to_owned())))
            }
        }
        d.deserialize_str(V)
    }
}

/// Find one key (case-insensitive) in a JSON object without building the rest.
struct FindKey<'k>(&'k str);
impl<'de> DeserializeSeed<'de> for FindKey<'_> {
    type Value = Option<Value>;
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_map(self)
    }
}
impl<'de> Visitor<'de> for FindKey<'_> {
    type Value = Option<Value>;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("an object")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Self::Value, A::Error> {
        let mut found = None;
        while let Some(KeyStr(k)) = m.next_key()? {
            if found.is_none() && k.eq_ignore_ascii_case(self.0) {
                found = Some(m.next_value::<Value>()?);
            } else {
                m.next_value::<IgnoredAny>()?;
            }
        }
        Ok(found)
    }
}

pub fn raw_prop(json: &str, key: &str) -> Option<Value> {
    if json.is_empty() {
        return None;
    }
    let mut de = serde_json::Deserializer::from_str(json);
    FindKey(key).deserialize(&mut de).ok().flatten()
}

/// All raw property keys of a node (for `keys(n)` / `properties(n)`).
pub fn raw_props(json: &str) -> Vec<(String, Value)> {
    match serde_json::from_str::<serde_json::Map<String, Value>>(json) {
        Ok(m) => m.into_iter().collect(),
        Err(_) => Vec::new(),
    }
}

pub fn flag_prop(key: &str) -> Option<u32> {
    Some(match key {
        "tier0" | "highvalue_tier0" | "istierzero" => flags::TIER0,
        "owned" => flags::OWNED,
        "enabled" => flags::ENABLED,
        "admincount" => flags::ADMINCOUNT,
        "highvalue" => flags::HIGHVALUE,
        "unconstraineddelegation" => flags::UNCONSTRAINED_DELEGATION,
        "dontreqpreauth" => flags::DONT_REQ_PREAUTH,
        "hasspn" => flags::HAS_SPN,
        _ => return None,
    })
}

/// Property lookup; `key` must be lower-case.
pub fn node_prop(g: &Graph, id: u32, key: &str) -> Val {
    match key {
        "name" => Val::Str(g.name(id).to_string()),
        "objectid" => Val::Str(g.oid(id).to_string()),
        "kind" | "label" => Val::Str(g.kind_name(id).to_string()),
        "id" => Val::Num(id as f64),
        // BloodHound CE tags.
        "system_tags" => {
            let mut tags = Vec::new();
            if g.has_flag(id, flags::TIER0) {
                tags.push("admin_tier_0");
            }
            if g.has_flag(id, flags::OWNED) {
                tags.push("owned");
            }
            let s = tags.join(" ");
            match raw_prop(g.props(id), key) {
                Some(Value::String(r)) if !r.is_empty() => Val::Str(if s.is_empty() { r } else { format!("{r} {s}") }),
                _ if s.is_empty() => Val::Null,
                _ => Val::Str(s),
            }
        }
        k => match flag_prop(k) {
            // `enabled` exists only when the collector reported it.
            Some(flags::ENABLED) if g.flags(id) & flags::ENABLED == 0 => {
                raw_prop(g.props(id), k).map(Val::from_json).unwrap_or(Val::Bool(false))
            }
            Some(f) => Val::Bool(g.has_flag(id, f)),
            None => raw_prop(g.props(id), k).map(Val::from_json).unwrap_or(Val::Null),
        },
    }
}

/// Property of any value; `key` lower-case.
pub fn val_prop(g: &Graph, v: &Val, key: &str) -> Val {
    match v {
        Val::Node(id) => node_prop(g, *id, key),
        Val::Edge(e) => match key {
            "kind" | "type" | "label" => Val::Str(g.edge_kind_name(e.2).to_string()),
            "traversable" => Val::Bool(g.is_traversable(e.2)),
            _ => Val::Null,
        },
        Val::Edges(es) => match key {
            "kind" | "type" => Val::List(es.iter().map(|e| Val::Str(g.edge_kind_name(e.2).to_string())).collect()),
            "length" => Val::Num(es.len() as f64),
            _ => Val::Null,
        },
        Val::Path(p) | Val::Subgraph(p) if key == "length" => Val::Num(p.edges.len() as f64),
        Val::Map(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone()).unwrap_or(Val::Null),
        _ => Val::Null,
    }
}
