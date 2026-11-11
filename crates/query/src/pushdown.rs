//! Translation of single-variable node predicates into [`ch_store::Filter`]
//! trees, answered from property columns and bitmap indexes.
//!
//! Pushdown is an optimisation only: a predicate is translated **only** when
//! the store evaluates it exactly as CHQL's evaluator (`value.rs`) does, for
//! every node — including nulls, mixed types, list-valued properties, numeric
//! strings and case variants. Anything else returns `None` and stays in the
//! CHQL evaluator. Known differences and how they are handled:
//!
//! * `enabled`: when the flag is unset, CHQL reads the collector property
//!   (`null` stays null), the store reads JSON `null` as `false`. A leaf on
//!   `enabled` is pushed only if its outcome is the same for null and `false`
//!   (`= true`, `<> false`, truthiness, …); `IS NULL` and the rest stay.
//! * `system_tags`: synthesised by CHQL from flags; never pushed.
//! * Literal on the left: `=`/`<>`/`IN`/string operators are asymmetric with
//!   list-valued properties (`'x' = n.list` is false, `n.list = 'x'` is
//!   membership), so only `<`, `<=`, `>`, `>=` are flipped (CHQL's ordering
//!   is antisymmetric).
//! * Literals that have no JSON form (NaN, ±inf, maps, nodes) are not pushed.
//!
//! Store-side fixes made so the remaining operators agree exactly are listed
//! in `docs/CHQL.md` ("Performance notes").

use crate::ast::{CmpOp, Expr, LabelPred, Labels};
use crate::value::{compare, Val};
use ch_model::{flags, NodeKind};
use ch_store::{Filter, Op};
use serde_json::Value;

/// JSON form of a constant, if it has one that round-trips exactly through
/// the store's `Val::from_json`.
pub(crate) fn json_of(v: &Val) -> Option<Value> {
    Some(match v {
        Val::Null => Value::Null,
        Val::Bool(b) => Value::Bool(*b),
        Val::Num(n) => Value::Number(serde_json::Number::from_f64(*n)?),
        Val::Str(s) => Value::String(s.clone()),
        Val::List(xs) => Value::Array(xs.iter().map(json_of).collect::<Option<_>>()?),
        _ => return None,
    })
}

fn op_of(op: CmpOp) -> Option<Op> {
    Some(match op {
        CmpOp::Eq => Op::Eq,
        CmpOp::Ne => Op::Ne,
        CmpOp::Lt => Op::Lt,
        CmpOp::Le => Op::Le,
        CmpOp::Gt => Op::Gt,
        CmpOp::Ge => Op::Ge,
        CmpOp::StartsWith => Op::StartsWith,
        CmpOp::EndsWith => Op::EndsWith,
        CmpOp::Contains => Op::Contains,
        CmpOp::In => Op::In,
        CmpOp::Regex => return None,
    })
}

fn flip(op: CmpOp) -> Option<CmpOp> {
    Some(match op {
        CmpOp::Lt => CmpOp::Gt,
        CmpOp::Le => CmpOp::Ge,
        CmpOp::Gt => CmpOp::Lt,
        CmpOp::Ge => CmpOp::Le,
        _ => return None,
    })
}

/// Keys CHQL synthesises itself.
fn never(key: &str) -> bool {
    key == "system_tags"
}

/// `n.<key> <op> v` (key lower-case), if the store agrees with CHQL on it.
pub(crate) fn leaf_cmp(key: &str, op: CmpOp, v: &Val) -> Option<Filter> {
    if never(key) {
        return None;
    }
    let sop = op_of(op)?;
    if key == "enabled" && compare(&Val::Null, op, v) != compare(&Val::Bool(false), op, v) {
        return None;
    }
    Some(Filter::Cmp { key: key.to_string(), op: sop, value: json_of(v)? })
}

fn leaf_is_null(key: &str, null: bool) -> Option<Filter> {
    if never(key) || key == "enabled" {
        return None;
    }
    Some(Filter::IsNull { key: key.to_string(), null })
}

fn leaf_truthy(key: &str) -> Option<Filter> {
    // `enabled`: null and false are both falsy, so the difference is moot.
    if never(key) {
        return None;
    }
    Some(Filter::Truthy(key.to_string()))
}

/// Property key that reads flag `f` (labels like `Tag_Tier_Zero`).
fn flag_key(f: u32) -> Option<&'static str> {
    Some(match f {
        flags::TIER0 => "tier0",
        flags::OWNED => "owned",
        flags::ADMINCOUNT => "admincount",
        flags::HIGHVALUE => "highvalue",
        flags::UNCONSTRAINED_DELEGATION => "unconstraineddelegation",
        flags::DONT_REQ_PREAUTH => "dontreqpreauth",
        flags::HAS_SPN => "hasspn",
        _ => return None,
    })
}

/// Label groups (conjunction of disjunctions), as `label_ok` evaluates them.
pub(crate) fn labels(ls: &Labels) -> Option<Filter> {
    let mut all = Vec::new();
    for any in ls {
        let mut alts = Vec::new();
        for l in any {
            alts.push(match *l {
                LabelPred::Kind(k) => Filter::Kind(vec![k]),
                LabelPred::Any(None) => Filter::Const(true),
                LabelPred::Any(Some(az)) => Filter::Kind(NodeKind::ALL.iter().copied().filter(|k| k.is_azure() == az).collect()),
                LabelPred::Flag(f) => Filter::Truthy(flag_key(f)?.to_string()),
                LabelPred::Raw(_) => return None,
            });
        }
        all.push(if alts.len() == 1 { alts.pop().expect("one") } else { Filter::Or(alts) });
    }
    match all.len() {
        0 => None,
        1 => all.pop(),
        _ => Some(Filter::And(all)),
    }
}

/// `n.key` where `n` is `var`; the key lower-cased.
fn prop_of(e: &Expr, var: &str) -> Option<String> {
    match e {
        Expr::Prop(base, key) if matches!(&**base, Expr::Var(v, _) if v == var) => Some(key.to_ascii_lowercase()),
        _ => None,
    }
}

/// Children of a flattened `And` (`and`) / `Or` (`!and`).
fn flat(a: Filter, b: Filter, and: bool) -> Vec<Filter> {
    let mut out = Vec::new();
    for f in [a, b] {
        match f {
            Filter::And(v) if and => out.extend(v),
            Filter::Or(v) if !and => out.extend(v),
            f => out.push(f),
        }
    }
    out
}

/// Translate a WHERE expression over the single node variable `var`.
/// `konst` folds variable-free sub-expressions to constants.
pub(crate) fn expr(e: &Expr, var: &str, konst: &dyn Fn(&Expr) -> Option<Val>) -> Option<Filter> {
    Some(match e {
        Expr::And(a, b) => Filter::And(flat(expr(a, var, konst)?, expr(b, var, konst)?, true)),
        Expr::Or(a, b) => Filter::Or(flat(expr(a, var, konst)?, expr(b, var, konst)?, false)),
        Expr::Not(a) => Filter::Not(Box::new(expr(a, var, konst)?)),
        Expr::Lit(l) => Filter::Const(Val::from_lit(l).truthy()),
        Expr::Cmp(a, op, b) => {
            if let Some(key) = prop_of(a, var) {
                return leaf_cmp(&key, *op, &konst(b)?);
            }
            if let Some(key) = prop_of(b, var) {
                return leaf_cmp(&key, flip(*op)?, &konst(a)?);
            }
            return None;
        }
        Expr::IsNull(a, null) => leaf_is_null(&prop_of(a, var)?, *null)?,
        Expr::HasLabel(a, ls) if matches!(&**a, Expr::Var(v, _) if v == var) => labels(ls)?,
        Expr::Prop(..) => leaf_truthy(&prop_of(e, var)?)?,
        _ => return None,
    })
}
