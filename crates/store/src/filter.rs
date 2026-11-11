//! Node filters over property columns.
//!
//! A [`Filter`] is a boolean tree of per-node predicates (`kind`, comparisons,
//! `IS NULL`, truthiness) evaluated to a [`RoaringBitmap`] of node ids by
//! [`Graph::filter`]. Leaves are answered from indexes where possible (kind
//! and flag bitmaps, string equality bitmaps, sorted dictionaries, the folded
//! name order) and otherwise by a parallel scan of a typed column; only keys
//! without a usable column (mixed types, lists, objects) parse JSON. Inside an
//! `And`, cheap leaves run first and later leaves only look at the surviving
//! candidates.
//!
//! **Semantics** follow CHQL's `WHERE` (`crates/query/src/exec.rs`), so CHQL
//! can push node predicates down here unchanged:
//!
//! - Property keys are case-insensitive. `name`, `objectid`, `kind`/`label`
//!   and `id` are node attributes; `tier0`, `owned`, `enabled`, `admincount`,
//!   `highvalue`, `unconstraineddelegation`, `dontreqpreauth`, `hasspn`
//!   (and `highvalue_tier0`, `istierzero`) read node flags and are never null
//!   (`enabled` is also true when the collector property is `true`).
//!   Anything else is the collector property; absent and JSON `null` are null.
//! - String equality and `STARTS WITH`/`ENDS WITH`/`CONTAINS` ignore ASCII case.
//! - Numbers compare as `f64`; strings that parse as numbers and booleans
//!   (0/1) coerce when compared with numbers. `<`, `>`… on two strings compare
//!   case-folded text (ties broken by the exact bytes, so `'a' > 'A'`) unless
//!   both parse as numbers.
//! - A list value equals a scalar if any element does; string operators match
//!   if any string element does.
//! - `<>` never matches null and `x <> null` matches nothing; `= null`
//!   matches null; a null value is in no list (`null IN [null]` is false).
//!   `NOT` is plain set complement (no three-valued logic): `NOT (x = 1)`
//!   includes nodes where `x` is null.
//! - One deliberate difference from CHQL: with the flag unset, a JSON `null`
//!   `enabled` reads `false` here (null in CHQL). CHQL only pushes `enabled`
//!   tests that treat null and `false` alike.
//!
//! [`Filter::matches`] evaluates one node directly from the JSON properties
//! and is the reference the indexed evaluation is tested against.

use crate::columns::{bitmap_from_sorted, cmp_fold, partition, Codes, ColView, Columns, Dict, NumVals};
use crate::Graph;
use ch_model::{flags, NodeKind};
use rayon::prelude::*;
use roaring::RoaringBitmap;
use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::borrow::Cow;
use std::cmp::Ordering;
use std::fmt;

/// Comparison operator of a [`Filter::Cmp`] leaf.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    #[serde(alias = "=", alias = "==")]
    Eq,
    #[serde(alias = "<>", alias = "!=")]
    Ne,
    #[serde(alias = "<")]
    Lt,
    #[serde(alias = "<=")]
    Le,
    #[serde(alias = ">")]
    Gt,
    #[serde(alias = ">=")]
    Ge,
    #[serde(alias = "prefix")]
    StartsWith,
    #[serde(alias = "suffix")]
    EndsWith,
    Contains,
    In,
}

/// A node predicate tree. JSON form (externally tagged, snake case):
///
/// ```json
/// {"and": [
///   {"kind": ["User"]},
///   {"truthy": "enabled"},
///   {"cmp": {"key": "domain", "op": "eq", "value": "CORP.LOCAL"}},
///   {"not": {"is_null": {"key": "lastlogon"}}}
/// ]}
/// ```
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Filter {
    Const(bool),
    /// Node kind is one of these.
    Kind(#[serde(with = "kind_names")] Vec<NodeKind>),
    Cmp {
        key: String,
        op: Op,
        value: Value,
    },
    IsNull {
        key: String,
        #[serde(default = "yes")]
        null: bool,
    },
    Truthy(String),
    And(Vec<Filter>),
    Or(Vec<Filter>),
    Not(Box<Filter>),
}

fn yes() -> bool {
    true
}

mod kind_names {
    use ch_model::NodeKind;
    use serde::{de::Error, Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(ks: &[NodeKind], s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(ks.iter().map(|k| k.as_str()))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<NodeKind>, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum OneOrMany {
            One(String),
            Many(Vec<String>),
        }
        let names = match OneOrMany::deserialize(d)? {
            OneOrMany::One(s) => vec![s],
            OneOrMany::Many(v) => v,
        };
        names
            .iter()
            .map(|s| match NodeKind::parse(s) {
                NodeKind::Unknown if !s.eq_ignore_ascii_case("unknown") => Err(D::Error::custom(format!("unknown node kind '{s}'"))),
                k => Ok(k),
            })
            .collect()
    }
}

impl Filter {
    pub fn kind(k: NodeKind) -> Filter {
        Filter::Kind(vec![k])
    }
    pub fn cmp(key: impl Into<String>, op: Op, value: impl Into<Value>) -> Filter {
        Filter::Cmp { key: key.into(), op, value: value.into() }
    }
    pub fn eq(key: impl Into<String>, value: impl Into<Value>) -> Filter {
        Filter::cmp(key, Op::Eq, value)
    }
    pub fn is_null(key: impl Into<String>) -> Filter {
        Filter::IsNull { key: key.into(), null: true }
    }
    pub fn truthy(key: impl Into<String>) -> Filter {
        Filter::Truthy(key.into())
    }
    #[allow(clippy::should_implement_trait)]
    pub fn not(f: Filter) -> Filter {
        Filter::Not(Box::new(f))
    }

    /// Evaluate for one node from the stored JSON properties — no columns.
    /// The reference semantics; [`Graph::filter`] must agree with it.
    pub fn matches(&self, g: &Graph, id: u32) -> bool {
        match self {
            Filter::Const(b) => *b,
            Filter::Kind(ks) => ks.contains(&g.kind(id)),
            Filter::And(fs) => fs.iter().all(|f| f.matches(g, id)),
            Filter::Or(fs) => fs.iter().any(|f| f.matches(g, id)),
            Filter::Not(f) => !f.matches(g, id),
            Filter::Cmp { key, op, value } => Test::Cmp(*op, Lit::new(value)).on_val(&g.node_value(id, key)),
            Filter::IsNull { key, null } => Test::IsNull(*null).on_val(&g.node_value(id, key)),
            Filter::Truthy(key) => Test::Truthy.on_val(&g.node_value(id, key)),
        }
    }
}

// ------------------------------------------------------------------ values

/// A node property value as filters see it.
#[derive(Clone, Debug, PartialEq)]
pub enum Val {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    List(Vec<Val>),
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
}

/// Borrowed view of a value, so column scans do not allocate.
#[derive(Clone, Copy, Debug)]
pub(crate) enum V<'a> {
    Null,
    Bool(bool),
    Num(f64),
    Str(&'a str),
    List(&'a [Val]),
}

impl<'a> From<&'a Val> for V<'a> {
    fn from(v: &'a Val) -> V<'a> {
        match v {
            Val::Null => V::Null,
            Val::Bool(b) => V::Bool(*b),
            Val::Num(n) => V::Num(*n),
            Val::Str(s) => V::Str(s),
            Val::List(l) => V::List(l),
        }
    }
}

fn as_num(v: V) -> Option<f64> {
    match v {
        V::Num(n) => Some(n),
        V::Str(s) => s.trim().parse().ok(),
        V::Bool(b) => Some(b as u8 as f64),
        _ => None,
    }
}

/// A comparison literal with its derived forms precomputed.
#[derive(Clone, Debug)]
pub(crate) struct Lit {
    v: Val,
    num: Option<f64>,
    /// String literal that parses as a number (untrimmed, as CHQL checks).
    str_numeric: bool,
    upper: Option<Vec<u8>>,
    items: Vec<Lit>,
}

impl Lit {
    pub(crate) fn new(v: &Value) -> Lit {
        Lit::from_val(Val::from_json(v.clone()))
    }
    fn from_val(v: Val) -> Lit {
        let num = as_num(V::from(&v));
        let (str_numeric, upper) = match &v {
            Val::Str(s) => (s.parse::<f64>().is_ok(), Some(s.to_ascii_uppercase().into_bytes())),
            _ => (false, None),
        };
        let items = match &v {
            Val::List(l) => l.iter().cloned().map(Lit::from_val).collect(),
            _ => Vec::new(),
        };
        Lit { v, num, str_numeric, upper, items }
    }
    fn as_str(&self) -> Option<&str> {
        match &self.v {
            Val::Str(s) => Some(s),
            _ => None,
        }
    }
}

fn val_eq_vv(a: V, b: V) -> bool {
    match (a, b) {
        (V::List(xs), V::List(ys)) => xs.len() == ys.len() && xs.iter().zip(ys).all(|(x, y)| val_eq_vv(x.into(), y.into())),
        (V::List(xs), y) => xs.iter().any(|x| val_eq_vv(x.into(), y)),
        (V::Null, V::Null) => true,
        (V::Null, _) | (_, V::Null) => false,
        (V::Str(x), V::Str(y)) => x.eq_ignore_ascii_case(y),
        (V::Bool(x), V::Bool(y)) => x == y,
        (x, y) => match (as_num(x), as_num(y)) {
            (Some(p), Some(q)) => p == q,
            _ => false,
        },
    }
}

fn val_eq(a: V, b: &Lit) -> bool {
    match (a, &b.v) {
        (V::List(xs), Val::List(ys)) => xs.len() == ys.len() && xs.iter().zip(ys).all(|(x, y)| val_eq_vv(x.into(), y.into())),
        (V::List(xs), _) => xs.iter().any(|x| val_eq(x.into(), b)),
        (V::Null, Val::Null) => true,
        (V::Null, _) | (_, Val::Null) => false,
        (V::Str(x), Val::Str(y)) => x.eq_ignore_ascii_case(y),
        (V::Bool(x), Val::Bool(y)) => x == *y,
        (x, _) => match (as_num(x), b.num) {
            (Some(p), Some(q)) => p == q,
            _ => false,
        },
    }
}

fn val_ord(a: V, b: &Lit) -> Option<Ordering> {
    match (a, &b.v) {
        // Case-folded order, ties broken by the exact bytes (CHQL's `cmp_ci`).
        (V::Str(x), Val::Str(y)) if x.parse::<f64>().is_err() || !b.str_numeric => Some(cmp_fold(x.as_bytes(), y.as_bytes()).then_with(|| x.cmp(y))),
        (x, _) => as_num(x)?.partial_cmp(&b.num?),
    }
}

#[inline]
fn starts_with_fold(s: &[u8], nu: &[u8]) -> bool {
    s.len() >= nu.len() && s[..nu.len()].eq_ignore_ascii_case(nu)
}
#[inline]
fn ends_with_fold(s: &[u8], nu: &[u8]) -> bool {
    s.len() >= nu.len() && s[s.len() - nu.len()..].eq_ignore_ascii_case(nu)
}
/// `nu` (already upper case) occurs in `s` ignoring ASCII case.
pub(crate) fn contains_fold(s: &[u8], nu: &[u8]) -> bool {
    let Some(&first) = nu.first() else { return true };
    if s.len() < nu.len() {
        return false;
    }
    let last_start = s.len() - nu.len();
    let hay = &s[..last_start + 1];
    let check = |p: usize| s[p..p + nu.len()].eq_ignore_ascii_case(nu);
    let lo = first.to_ascii_lowercase();
    if lo != first {
        memchr::memchr2_iter(first, lo, hay).any(check)
    } else {
        memchr::memchr_iter(first, hay).any(check)
    }
}

fn str_op(a: V, b: &Lit, f: fn(&[u8], &[u8]) -> bool) -> bool {
    let Some(nu) = &b.upper else { return false };
    match a {
        V::Str(s) => f(s.as_bytes(), nu),
        V::List(v) => v.iter().any(|x| matches!(x, Val::Str(s) if f(s.as_bytes(), nu))),
        _ => false,
    }
}

/// A prepared leaf predicate on one value.
#[derive(Clone, Debug)]
pub(crate) enum Test {
    Cmp(Op, Lit),
    IsNull(bool),
    Truthy,
}

impl Test {
    pub(crate) fn on(&self, a: V) -> bool {
        match self {
            Test::IsNull(n) => matches!(a, V::Null) == *n,
            Test::Truthy => match a {
                V::Null => false,
                V::Bool(b) => b,
                V::Num(n) => n != 0.0,
                V::Str(s) => !s.is_empty(),
                V::List(l) => !l.is_empty(),
            },
            Test::Cmp(op, lit) => match op {
                Op::Eq => val_eq(a, lit),
                // `x <> null` never matches (CHQL), whatever `x` is.
                Op::Ne => !matches!(a, V::Null) && !matches!(lit.v, Val::Null) && !val_eq(a, lit),
                Op::Lt => val_ord(a, lit) == Some(Ordering::Less),
                Op::Le => matches!(val_ord(a, lit), Some(Ordering::Less | Ordering::Equal)),
                Op::Gt => val_ord(a, lit) == Some(Ordering::Greater),
                Op::Ge => matches!(val_ord(a, lit), Some(Ordering::Greater | Ordering::Equal)),
                Op::StartsWith => str_op(a, lit, starts_with_fold),
                Op::EndsWith => str_op(a, lit, ends_with_fold),
                Op::Contains => str_op(a, lit, contains_fold),
                Op::In => match &lit.v {
                    // Like CHQL, a null value is in no list (not even `[null]`).
                    Val::List(_) => !matches!(a, V::Null) && lit.items.iter().any(|x| val_eq(a, x)),
                    _ => val_eq(a, lit),
                },
            },
        }
    }
    pub(crate) fn on_val(&self, v: &Val) -> bool {
        self.on(V::from(v))
    }
    /// String literals of an `=` / `IN` test, if it is purely that.
    fn eq_strings(&self) -> Option<Vec<&str>> {
        match self {
            Test::Cmp(Op::Eq, l) => l.as_str().map(|s| vec![s]),
            Test::Cmp(Op::In, l) if matches!(l.v, Val::List(_)) => l.items.iter().map(|x| x.as_str()).collect(),
            _ => None,
        }
    }
}

// --------------------------------------------------------- node properties

/// Flag bit behind a flag-backed property key (lower case).
pub fn flag_key(key_lower: &str) -> Option<u32> {
    Some(match key_lower {
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

struct FindKey<'k>(&'k str);
impl<'de> DeserializeSeed<'de> for FindKey<'_> {
    type Value = Option<Value>;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
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
        while let Some(k) = m.next_key::<Cow<'de, str>>()? {
            if found.is_none() && k.eq_ignore_ascii_case(self.0) {
                found = Some(m.next_value::<Value>()?);
            } else {
                m.next_value::<IgnoredAny>()?;
            }
        }
        Ok(found)
    }
}

/// Value of `key` (matched ignoring ASCII case; first occurrence) in a JSON
/// object, or `None` if absent or the object does not parse.
pub fn raw_prop(json: &str, key: &str) -> Option<Value> {
    if json.is_empty() {
        return None;
    }
    let mut de = serde_json::Deserializer::from_str(json);
    FindKey(key).deserialize(&mut de).ok().flatten()
}

impl Graph {
    /// A node's property as filters see it (see the module docs).
    pub fn node_value(&self, id: u32, key: &str) -> Val {
        let lower = key.to_ascii_lowercase();
        match lower.as_str() {
            "name" => Val::Str(self.name(id).to_string()),
            "objectid" => Val::Str(self.oid(id).to_string()),
            "kind" | "label" => Val::Str(self.kind_name(id).to_string()),
            "id" => Val::Num(id as f64),
            k => match flag_key(k) {
                Some(flags::ENABLED) if !self.has_flag(id, flags::ENABLED) => match raw_prop(self.props(id), k).map(Val::from_json) {
                    None | Some(Val::Null) => Val::Bool(false),
                    Some(v) => v,
                },
                Some(f) => Val::Bool(self.has_flag(id, f)),
                None => raw_prop(self.props(id), k).map(Val::from_json).unwrap_or(Val::Null),
            },
        }
    }

    /// Ids of all nodes matching `f`, using columns and indexes. Builds (and
    /// persists) the property columns on first use; see [`Graph::columns`].
    pub fn filter(&self, f: &Filter) -> RoaringBitmap {
        Eval::new(self).eval(f, None)
    }

    /// [`Graph::filter`] restricted to `candidates` (e.g. nodes already
    /// bound by a traversal). Expensive leaves only examine candidates.
    pub fn filter_within(&self, f: &Filter, candidates: &RoaringBitmap) -> RoaringBitmap {
        Eval::new(self).eval(f, Some(candidates))
    }

    /// Reference evaluation: [`Filter::matches`] on every node, in parallel.
    /// What a filter costs without columns.
    pub fn filter_scan(&self, f: &Filter) -> RoaringBitmap {
        par_range(self.node_count() as u32, |id| f.matches(self, id))
    }

    /// Bitmap of all nodes of kind `k`.
    pub fn kind_bitmap(&self, k: NodeKind) -> &RoaringBitmap {
        &self.kind_bitmaps()[k as u8 as usize]
    }

    /// Nodes whose kind satisfies `pred` (stored kind bytes that are not a
    /// known kind read as `Unknown`, as [`Graph::kind`] does).
    fn kinds_where(&self, pred: impl Fn(NodeKind) -> bool) -> RoaringBitmap {
        let mut r = RoaringBitmap::new();
        for (raw, bm) in self.kind_bitmaps().iter().enumerate() {
            if !bm.is_empty() && pred(NodeKind::from_u8(raw as u8)) {
                r |= bm;
            }
        }
        r
    }

    fn kind_bitmaps(&self) -> &[RoaringBitmap] {
        self.kind_bms.get_or_init(|| {
            let n = self.node_count();
            let kinds: &[u8] = &self.kinds;
            let parts: Vec<Vec<(u8, RoaringBitmap)>> = (0..n.div_ceil(BLOCK))
                .into_par_iter()
                .map(|b| {
                    let mut lists: Vec<Vec<u32>> = vec![Vec::new(); 256];
                    for i in b * BLOCK..((b + 1) * BLOCK).min(n) {
                        lists[kinds[i] as usize].push(i as u32);
                    }
                    lists
                        .into_iter()
                        .enumerate()
                        .filter(|(_, l)| !l.is_empty())
                        .map(|(k, l)| (k as u8, RoaringBitmap::from_sorted_iter(l).expect("ascending")))
                        .collect()
                })
                .collect();
            let mut out = vec![RoaringBitmap::new(); 256];
            for p in parts {
                for (k, bm) in p {
                    out[k as usize] |= bm;
                }
            }
            out
        })
    }

    /// Bitmap of nodes with flag bit `f` set (single bit), cached until the
    /// flag column changes.
    pub fn flag_bitmap(&self, f: u32) -> &RoaringBitmap {
        let bit = f.trailing_zeros() as usize & 31;
        self.flag_bms[bit].get_or_init(|| {
            let fl: &[u32] = &self.flags;
            par_range(self.node_count() as u32, |id| fl[id as usize] & (1 << bit) != 0)
        })
    }

    /// Ranked name search for autocomplete: exact name/objectid matches, then
    /// names starting with `text` (shortest first), then names containing it
    /// (shortest first); all ASCII-case-insensitive. Uses the folded name
    /// order and a SIMD substring scan when columns are ready, else falls
    /// back to [`Graph::search_prefix`] alone.
    pub fn search(&self, text: &str, kind: Option<NodeKind>, limit: usize) -> Vec<u32> {
        self.search_raw(text, kind.map(|k| k as u8), limit)
    }

    /// [`Graph::search`] with a raw kind filter (custom kinds included).
    pub fn search_raw(&self, text: &str, kind: Option<u8>, limit: usize) -> Vec<u32> {
        let text = text.trim();
        if text.is_empty() || limit == 0 {
            return Vec::new();
        }
        let ok_kind = |id: u32| kind.is_none_or(|k| self.kind_raw(id) == k);
        let by_len = |a: &u32, b: &u32| {
            let (x, y) = (self.name(*a), self.name(*b));
            x.len().cmp(&y.len()).then_with(|| x.cmp(y)).then(a.cmp(b))
        };
        let mut out: Vec<u32> = Vec::new();
        let push = |out: &mut Vec<u32>, id: u32| {
            if !out.contains(&id) && ok_kind(id) {
                out.push(id);
            }
        };
        if let Some(id) = self.lookup(text) {
            push(&mut out, id);
        }
        // Prefix matches are a contiguous range in name order, but name order is
        // not length order ("USER1@…" sorts after "USER10000@…"), so the
        // shortest ones must be selected from the whole range, not from its
        // first few hundred entries.
        let Some(cols) = self.columns_ready() else {
            let prefix: Vec<u32> =
                self.search_prefix_raw(text, kind, usize::MAX).into_iter().filter(|id| !out.contains(id)).collect();
            let want = limit.saturating_sub(out.len());
            out.extend(top_k(&prefix, want, by_len));
            out.truncate(limit);
            return out;
        };
        let ev = Eval { g: self, c: cols, n: self.node_count() as u32 };
        let order = ev.name_order();
        let r = ev.name_range(text.as_bytes(), false);
        for &id in &order[r.clone()] {
            push(&mut out, id);
        }
        let r = ev.name_range(text.as_bytes(), true);
        if out.len() < limit {
            let prefix: Vec<u32> =
                order[r].par_iter().copied().filter(|&id| ok_kind(id) && !out.contains(&id)).collect();
            let want = limit - out.len();
            out.extend(top_k(&prefix, want, by_len));
        }
        if out.len() < limit {
            let mut hits = ev.name_contains(text.as_bytes());
            if let Some(k) = kind {
                hits &= &self.kind_bitmaps()[k as usize];
            }
            for &id in &out {
                hits.remove(id);
            }
            let ids: Vec<u32> = hits.iter().collect();
            let want = limit - out.len();
            out.extend(top_k(&ids, want, by_len));
        }
        out.truncate(limit);
        out
    }
}

/// The `k` smallest of `ids` under `cmp`, sorted, computed in parallel.
fn top_k(ids: &[u32], k: usize, cmp: impl Fn(&u32, &u32) -> Ordering + Sync) -> Vec<u32> {
    let pick = |v: &mut Vec<u32>| {
        if v.len() > k {
            v.select_nth_unstable_by(k, &cmp);
            v.truncate(k);
        }
    };
    let mut best: Vec<u32> = ids
        .par_chunks(1 << 16)
        .map(|c| {
            let mut v = c.to_vec();
            pick(&mut v);
            v
        })
        .reduce(Vec::new, |mut a, b| {
            a.extend(b);
            pick(&mut a);
            a
        });
    best.sort_by(&cmp);
    best
}

const BLOCK: usize = 1 << 16;

/// Ids in `0..n` satisfying `pred`, scanned in parallel per 2^16-id block.
fn par_range(n: u32, pred: impl Fn(u32) -> bool + Sync) -> RoaringBitmap {
    let n = n as usize;
    (0..n.div_ceil(BLOCK))
        .into_par_iter()
        .map(|b| {
            let ids = (b * BLOCK..((b + 1) * BLOCK).min(n)).map(|i| i as u32).filter(|&i| pred(i));
            RoaringBitmap::from_sorted_iter(ids).expect("ascending")
        })
        .reduce(RoaringBitmap::new, |a, b| a | b)
}

/// Ids in `set` satisfying `pred`, scanned in parallel.
fn par_set(set: &RoaringBitmap, pred: impl Fn(u32) -> bool + Sync) -> RoaringBitmap {
    let ids: Vec<u32> = set.iter().collect();
    let hits: Vec<u32> = ids.par_chunks(4096).flat_map_iter(|c| c.iter().copied().filter(|&i| pred(i)).collect::<Vec<_>>()).collect();
    bitmap_from_sorted(&hits)
}

/// Positions `0..len` of a column satisfying `pred`, mapped to node ids.
fn par_positions(ids: Option<&[u32]>, len: usize, pred: impl Fn(usize) -> bool + Sync) -> RoaringBitmap {
    (0..len.div_ceil(BLOCK))
        .into_par_iter()
        .map(|b| {
            let r = b * BLOCK..((b + 1) * BLOCK).min(len);
            match ids {
                Some(ids) => RoaringBitmap::from_sorted_iter(r.filter(|&j| pred(j)).map(|j| ids[j])).unwrap_or_default(),
                None => RoaringBitmap::from_sorted_iter(r.filter(|&j| pred(j)).map(|j| j as u32)).unwrap_or_default(),
            }
        })
        .reduce(RoaringBitmap::new, |a, b| a | b)
}

// ------------------------------------------------------------ evaluation

struct Eval<'g> {
    g: &'g Graph,
    c: &'g Columns,
    n: u32,
}

/// Rough cost class of a leaf/tree; `And` evaluates cheap children first.
const COST_INDEX: u8 = 0;
const COST_COLUMN: u8 = 1;
const COST_ROW: u8 = 2;
const COST_JSON: u8 = 3;

impl<'g> Eval<'g> {
    fn new(g: &'g Graph) -> Eval<'g> {
        Eval { g, c: g.columns(), n: g.node_count() as u32 }
    }

    fn all(&self) -> RoaringBitmap {
        let mut b = RoaringBitmap::new();
        b.insert_range(0..self.n);
        b
    }
    fn base(&self, within: Option<&RoaringBitmap>) -> RoaringBitmap {
        within.cloned().unwrap_or_else(|| self.all())
    }
    fn restrict(r: RoaringBitmap, within: Option<&RoaringBitmap>) -> RoaringBitmap {
        match within {
            Some(w) => r & w,
            None => r,
        }
    }
    /// Cheap per-node predicate: full parallel range scan unless the
    /// candidate set is small.
    fn scan(&self, within: Option<&RoaringBitmap>, pred: impl Fn(u32) -> bool + Sync) -> RoaringBitmap {
        match within {
            Some(w) if w.len() < self.n as u64 / 4 => par_set(w, pred),
            _ => Self::restrict(par_range(self.n, pred), within),
        }
    }

    fn cost(&self, f: &Filter) -> u8 {
        match f {
            Filter::Const(_) | Filter::Kind(_) => COST_INDEX,
            Filter::And(fs) | Filter::Or(fs) => fs.iter().map(|f| self.cost(f)).max().unwrap_or(COST_INDEX),
            Filter::Not(f) => self.cost(f),
            Filter::Cmp { key, op, value } => self.leaf_cost(key, &Test::Cmp(*op, Lit::new(value))),
            Filter::IsNull { key, null } => self.leaf_cost(key, &Test::IsNull(*null)),
            Filter::Truthy(key) => self.leaf_cost(key, &Test::Truthy),
        }
    }

    fn leaf_cost(&self, key: &str, t: &Test) -> u8 {
        let k = key.to_ascii_lowercase();
        let str_cmp = |op: Op| matches!(t, Test::Cmp(o, l) if *o == op && l.as_str().is_some());
        match k.as_str() {
            "name" if t.eq_strings().is_some() || str_cmp(Op::StartsWith) || matches!(t, Test::IsNull(_)) => COST_INDEX,
            "name" if str_cmp(Op::Contains) => COST_COLUMN,
            "name" => COST_ROW,
            "objectid" if self.c.oids_upper() && t.eq_strings().is_some() => COST_INDEX,
            "objectid" => COST_ROW,
            "kind" | "label" => COST_INDEX,
            "id" => COST_COLUMN,
            "enabled" => match self.c.col("enabled").map(|c| self.c.view(c)) {
                None | Some(ColView::Bool) | Some(ColView::Null) => COST_INDEX,
                _ => COST_JSON,
            },
            k if flag_key(k).is_some() => COST_INDEX,
            k => match self.c.col(k) {
                None if self.c.complete() => COST_INDEX,
                None => COST_JSON,
                Some(_) if matches!(t, Test::IsNull(_)) => COST_INDEX,
                Some(c) => match self.c.view(c) {
                    ColView::Bool | ColView::Null => COST_INDEX,
                    ColView::Str { has_eq: true, .. } => COST_INDEX,
                    ColView::Str { .. } | ColView::Num { .. } => COST_COLUMN,
                    ColView::Raw => COST_JSON,
                },
            },
        }
    }

    /// Evaluate `f`; the result is always a subset of `within`.
    fn eval(&self, f: &Filter, within: Option<&RoaringBitmap>) -> RoaringBitmap {
        match f {
            Filter::Const(true) => self.base(within),
            Filter::Const(false) => RoaringBitmap::new(),
            Filter::Kind(ks) => Self::restrict(self.g.kinds_where(|k| ks.contains(&k)), within),
            Filter::And(fs) => {
                let mut order: Vec<&Filter> = fs.iter().collect();
                order.sort_by_key(|f| self.cost(f));
                let mut acc: Option<RoaringBitmap> = None;
                for f in order {
                    let r = self.eval(f, acc.as_ref().or(within));
                    let empty = r.is_empty();
                    acc = Some(r);
                    if empty {
                        break;
                    }
                }
                acc.unwrap_or_else(|| self.base(within))
            }
            Filter::Or(fs) => {
                let mut r = RoaringBitmap::new();
                for f in fs {
                    r |= self.eval(f, within);
                }
                r
            }
            Filter::Not(f) => self.base(within) - self.eval(f, within),
            Filter::Cmp { key, op, value } => self.leaf(key, &Test::Cmp(*op, Lit::new(value)), within),
            Filter::IsNull { key, null } => self.leaf(key, &Test::IsNull(*null), within),
            Filter::Truthy(key) => self.leaf(key, &Test::Truthy, within),
        }
    }

    fn leaf(&self, key: &str, t: &Test, within: Option<&RoaringBitmap>) -> RoaringBitmap {
        let k = key.to_ascii_lowercase();
        let g = self.g;
        match k.as_str() {
            "name" => self.name_leaf(t, within),
            "objectid" => match t.eq_strings() {
                // The hash index skips empty object ids; every node sharing an
                // object id matches (`find_all`), as a scan would.
                Some(keys) if self.c.oids_upper() && keys.iter().all(|s| !s.is_empty()) => {
                    let mut r = RoaringBitmap::new();
                    for s in keys {
                        let up = s.to_ascii_uppercase();
                        crate::find_all(&g.oid_idx, &up, |id| g.oid(id), |id| {
                            r.insert(id);
                        });
                    }
                    Self::restrict(r, within)
                }
                _ => self.scan(within, |id| t.on(V::Str(g.oid(id)))),
            },
            "kind" | "label" => Self::restrict(g.kinds_where(|k| t.on(V::Str(k.as_str()))), within),
            "id" => self.scan(within, |id| t.on(V::Num(id as f64))),
            _ => match flag_key(&k) {
                Some(f) => self.flag_leaf(&k, f, t, within),
                None => self.col_leaf(&k, t, within),
            },
        }
    }

    /// Combine a boolean-valued property: `trues` hold `true`, the rest of
    /// `present` (all nodes if `None`) hold `false`, others are null.
    fn bool_leaf(&self, trues: &RoaringBitmap, present: Option<&RoaringBitmap>, t: &Test, within: Option<&RoaringBitmap>) -> RoaringBitmap {
        let (tt, tf, tn) = (t.on(V::Bool(true)), t.on(V::Bool(false)), t.on(V::Null));
        let base = self.base(within);
        let present = match present {
            Some(p) => Cow::Owned(p & &base),
            None => Cow::Borrowed(&base),
        };
        let mut r = RoaringBitmap::new();
        if tt {
            r |= trues & present.as_ref();
        }
        if tf {
            r |= present.as_ref() - trues;
        }
        if tn {
            r |= &base - present.as_ref();
        }
        r
    }

    fn flag_leaf(&self, k: &str, f: u32, t: &Test, within: Option<&RoaringBitmap>) -> RoaringBitmap {
        let flag = self.g.flag_bitmap(f);
        if f == flags::ENABLED {
            match self.c.col("enabled").map(|c| (c, self.c.view(c))) {
                Some((c, ColView::Bool)) => return self.bool_leaf(&(flag | self.c.trues(c)), None, t, within),
                None | Some((_, ColView::Null)) => {}
                Some(_) => {
                    let g = self.g;
                    return self.scan(within, |id| t.on_val(&g.node_value(id, k)));
                }
            }
        }
        self.bool_leaf(flag, None, t, within)
    }

    fn col_leaf(&self, k: &str, t: &Test, within: Option<&RoaringBitmap>) -> RoaringBitmap {
        let g = self.g;
        let null_match = t.on(V::Null);
        let Some(c) = self.c.col(k) else {
            if self.c.complete() {
                return if null_match { self.base(within) } else { RoaringBitmap::new() };
            }
            return self.scan_json(k, t, &self.base(within));
        };
        let present = self.c.present(c);
        if let Test::IsNull(is_null) = t {
            return if *is_null { self.base(within) - present } else { Self::restrict(present.clone(), within) };
        }
        let hits = match self.c.view(c) {
            ColView::Null => RoaringBitmap::new(),
            ColView::Bool => return self.bool_leaf(self.c.trues(c), Some(present), t, within),
            ColView::Num { ids, vals } => match vals {
                NumVals::I(v) => par_positions(ids, v.len(), |j| t.on(V::Num(v[j] as f64))),
                NumVals::F(v) => par_positions(ids, v.len(), |j| t.on(V::Num(v[j]))),
            },
            ColView::Str { ids, codes, dict, has_eq } => {
                let m = dict_matches(dict, t);
                if m.is_empty() {
                    RoaringBitmap::new()
                } else if has_eq {
                    let eq = self.c.eq_index(c).unwrap_or(&[]);
                    let mut r = RoaringBitmap::new();
                    for (i, bm) in eq.iter().enumerate() {
                        if m.contains(i) {
                            r |= bm;
                        }
                    }
                    r
                } else {
                    code_scan(ids, codes, &m)
                }
            }
            ColView::Raw => {
                let cand = match within {
                    Some(w) => present & w,
                    None => present.clone(),
                };
                par_set(&cand, |id| t.on_val(&g.node_value(id, k)))
            }
        };
        let mut r = Self::restrict(hits, within);
        if null_match {
            r |= self.base(within) - present;
        }
        r
    }

    /// Evaluate on stored JSON for nodes in `set` (key without a column).
    fn scan_json(&self, k: &str, t: &Test, set: &RoaringBitmap) -> RoaringBitmap {
        let g = self.g;
        par_set(set, |id| t.on_val(&g.node_value(id, k)))
    }

    // ---- names

    fn name_order(&self) -> &'g [u32] {
        self.c.name_fold_sorted().unwrap_or(&self.g.name_sorted[..])
    }

    /// Range of [`Self::name_order`] whose display name equals (or, with
    /// `prefix`, starts with) `s`, ignoring ASCII case.
    fn name_range(&self, s: &[u8], prefix: bool) -> std::ops::Range<usize> {
        let order = self.name_order();
        let key = |i: usize| {
            let b = self.g.name(order[i]).as_bytes();
            if prefix {
                cmp_fold(&b[..b.len().min(s.len())], s)
            } else {
                cmp_fold(b, s)
            }
        };
        let lo = partition(order.len(), |i| key(i).is_lt());
        let hi = lo + partition(order.len() - lo, |i| key(lo + i).is_eq());
        lo..hi
    }

    fn range_bitmap(&self, r: std::ops::Range<usize>) -> RoaringBitmap {
        let mut ids = self.name_order()[r].to_vec();
        ids.par_sort_unstable();
        bitmap_from_sorted(&ids)
    }

    /// Nodes whose display name contains `needle`, ignoring ASCII case: a
    /// SIMD substring scan over the (folded) name blob in parallel id ranges.
    fn name_contains(&self, needle: &[u8]) -> RoaringBitmap {
        let nu = needle.to_ascii_uppercase();
        if nu.is_empty() {
            return self.all();
        }
        let g = self.g;
        let off: &[u64] = &g.name_off;
        let blob: &[u8] = self.c.name_fold_blob().unwrap_or(&g.name_blob);
        let finder = memchr::memmem::Finder::new(&nu);
        let n = self.n as usize;
        let mut r = (0..n.div_ceil(BLOCK))
            .into_par_iter()
            .map(|b| {
                let (a, e) = (b * BLOCK, ((b + 1) * BLOCK).min(n));
                let (start, end) = (off[a] as usize, off[e] as usize);
                let hay = &blob[start..end];
                let mut ids = Vec::new();
                let mut pos = 0;
                while let Some(p) = finder.find(&hay[pos..]) {
                    let abs = (start + pos + p) as u64;
                    let id = a + off[a..=e].partition_point(|&o| o <= abs) - 1;
                    let id_end = off[id + 1];
                    if abs + nu.len() as u64 <= id_end {
                        ids.push(id as u32);
                        pos = (id_end as usize) - start;
                    } else {
                        pos += p + 1;
                    }
                    if pos >= hay.len() {
                        break;
                    }
                }
                RoaringBitmap::from_sorted_iter(ids).expect("ascending")
            })
            .reduce(RoaringBitmap::new, |a, b| a | b);
        for &id in self.c.nameless() {
            if contains_fold(g.oid(id).as_bytes(), &nu) {
                r.insert(id);
            }
        }
        r
    }

    fn name_leaf(&self, t: &Test, within: Option<&RoaringBitmap>) -> RoaringBitmap {
        let g = self.g;
        if let Some(keys) = t.eq_strings() {
            let mut r = RoaringBitmap::new();
            for s in keys {
                r |= self.range_bitmap(self.name_range(s.as_bytes(), false));
            }
            return Self::restrict(r, within);
        }
        match t {
            Test::IsNull(true) => RoaringBitmap::new(),
            Test::IsNull(false) => self.base(within),
            Test::Cmp(Op::StartsWith, l) if l.as_str().is_some() => {
                let s = l.as_str().unwrap_or_default();
                Self::restrict(self.range_bitmap(self.name_range(s.as_bytes(), true)), within)
            }
            Test::Cmp(Op::Contains, l) if l.as_str().is_some() && within.is_none_or(|w| w.len() >= self.n as u64 / 64) => {
                Self::restrict(self.name_contains(l.as_str().unwrap_or_default().as_bytes()), within)
            }
            _ => self.scan(within, |id| t.on(V::Str(g.name(id)))),
        }
    }
}

/// Dictionary codes satisfying a test: a contiguous range (equality with one
/// string, prefix — the dictionary is in folded order) or a mask.
enum CodeSet {
    Range(std::ops::Range<usize>),
    Mask(Vec<bool>),
}

impl CodeSet {
    fn is_empty(&self) -> bool {
        match self {
            CodeSet::Range(r) => r.is_empty(),
            CodeSet::Mask(m) => !m.contains(&true),
        }
    }
    fn contains(&self, c: usize) -> bool {
        match self {
            CodeSet::Range(r) => r.contains(&c),
            CodeSet::Mask(m) => m[c],
        }
    }
}

/// Which dictionary codes satisfy `t`.
fn dict_matches(dict: Dict, t: &Test) -> CodeSet {
    let d = dict.len();
    if let Some(keys) = t.eq_strings() {
        if let [s] = keys.as_slice() {
            return CodeSet::Range(dict.eq_range(s));
        }
        let mut m = vec![false; d];
        for s in keys {
            m[dict.eq_range(s)].fill(true);
        }
        return CodeSet::Mask(m);
    }
    if let Test::Cmp(Op::StartsWith, l) = t {
        if let Some(s) = l.as_str() {
            return CodeSet::Range(dict.prefix_range(s));
        }
    }
    let mut m = vec![false; d];
    m.par_iter_mut().enumerate().with_min_len(1024).for_each(|(i, x)| *x = t.on(V::Str(dict.get(i))));
    CodeSet::Mask(m)
}

fn code_scan(ids: Option<&[u32]>, codes: Codes, m: &CodeSet) -> RoaringBitmap {
    match (codes, m) {
        (Codes::U8(c), CodeSet::Range(r)) => par_positions(ids, c.len(), |j| r.contains(&(c[j] as usize))),
        (Codes::U16(c), CodeSet::Range(r)) => par_positions(ids, c.len(), |j| r.contains(&(c[j] as usize))),
        (Codes::U32(c), CodeSet::Range(r)) => par_positions(ids, c.len(), |j| r.contains(&(c[j] as usize))),
        (Codes::U8(c), CodeSet::Mask(m)) => par_positions(ids, c.len(), |j| m[c[j] as usize]),
        (Codes::U16(c), CodeSet::Mask(m)) => par_positions(ids, c.len(), |j| m[c[j] as usize]),
        (Codes::U32(c), CodeSet::Mask(m)) => par_positions(ids, c.len(), |j| m[c[j] as usize]),
    }
}
