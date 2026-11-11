//! Compiled expressions: variables resolved to row slots, functions to
//! enums, regexes compiled once, pattern predicates planned.

use crate::ast::*;
use crate::exec::{plan_pattern_pred, Ctx, PatPred};
use crate::value::*;
use crate::QueryError;
use ahash::AHashSet;
use ch_model::flags;
use ch_store::Graph;
use regex_automata::meta::Regex;
use std::sync::Arc;

/// Longest accepted `=~` pattern.
const MAX_REGEX_LEN: usize = 1024;
/// Longest list built by `range()` / `split()` / list comprehensions.
const MAX_LIST: usize = 1_000_000;
/// Elements kept by one `collect()`.
pub(crate) const MAX_COLLECT: usize = 100_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Func {
    ToLower,
    ToUpper,
    Coalesce,
    Size,
    Length,
    Type,
    Labels,
    Id,
    ElementId,
    Nodes,
    Rels,
    StartNode,
    EndNode,
    ToString,
    ToInteger,
    ToFloat,
    ToBoolean,
    Trim,
    LTrim,
    RTrim,
    Split,
    Substring,
    Replace,
    Left,
    Right,
    Head,
    Last,
    Tail,
    Reverse,
    Keys,
    Properties,
    Exists,
    Abs,
    Round,
    Floor,
    Ceil,
    Sqrt,
    Sign,
    Range,
    IsEmpty,
    Datetime,
    Timestamp,
}

fn func_of(name: &str) -> Option<(Func, usize, usize)> {
    use Func::*;
    Some(match name {
        "tolower" | "lower" => (ToLower, 1, 1),
        "toupper" | "upper" => (ToUpper, 1, 1),
        "coalesce" => (Coalesce, 1, 64),
        "size" => (Size, 1, 1),
        "length" => (Length, 1, 1),
        "type" => (Type, 1, 1),
        "labels" => (Labels, 1, 1),
        "id" => (Id, 1, 1),
        "elementid" => (ElementId, 1, 1),
        "nodes" => (Nodes, 1, 1),
        "relationships" | "rels" => (Rels, 1, 1),
        "startnode" => (StartNode, 1, 1),
        "endnode" => (EndNode, 1, 1),
        "tostring" | "tostringornull" => (ToString, 1, 1),
        "tointeger" | "toint" | "tointegerornull" => (ToInteger, 1, 1),
        "tofloat" | "tofloatornull" => (ToFloat, 1, 1),
        "toboolean" | "tobooleanornull" => (ToBoolean, 1, 1),
        "trim" => (Trim, 1, 1),
        "ltrim" => (LTrim, 1, 1),
        "rtrim" => (RTrim, 1, 1),
        "split" => (Split, 2, 2),
        "substring" => (Substring, 2, 3),
        "replace" => (Replace, 3, 3),
        "left" => (Left, 2, 2),
        "right" => (Right, 2, 2),
        "head" => (Head, 1, 1),
        "last" => (Last, 1, 1),
        "tail" => (Tail, 1, 1),
        "reverse" => (Reverse, 1, 1),
        "keys" => (Keys, 1, 1),
        "properties" => (Properties, 1, 1),
        "exists" => (Exists, 1, 1),
        "abs" => (Abs, 1, 1),
        "round" => (Round, 1, 2),
        "floor" => (Floor, 1, 1),
        "ceil" => (Ceil, 1, 1),
        "sqrt" => (Sqrt, 1, 1),
        "sign" => (Sign, 1, 1),
        "range" => (Range, 2, 3),
        "isempty" => (IsEmpty, 1, 1),
        "datetime" | "localdatetime" => (Datetime, 0, 0),
        "timestamp" => (Timestamp, 0, 0),
        _ => return None,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AggFn {
    Count,
    CountStar,
    Collect,
    Min,
    Max,
    Sum,
    Avg,
    StDev,
    StDevP,
}

#[derive(Debug)]
pub(crate) struct AggSpec {
    pub f: AggFn,
    pub distinct: bool,
    pub arg: Option<CExpr>,
}

#[derive(Debug)]
pub(crate) enum CExpr {
    Const(Val),
    Slot(usize),
    Prop(Box<CExpr>, Box<str>),
    /// Fast path: flag property of a node slot.
    Flag(usize, u32),
    Index(Box<CExpr>, Box<CExpr>),
    Slice(Box<CExpr>, Option<Box<CExpr>>, Option<Box<CExpr>>),
    List(Vec<CExpr>),
    Or(Box<CExpr>, Box<CExpr>),
    Xor(Box<CExpr>, Box<CExpr>),
    And(Box<CExpr>, Box<CExpr>),
    Not(Box<CExpr>),
    Cmp(Box<CExpr>, CmpOp, Box<CExpr>),
    Regex(Box<CExpr>, Arc<Regex>),
    DynRegex(Box<CExpr>, Box<CExpr>),
    IsNull(Box<CExpr>, bool),
    HasLabel(Box<CExpr>, Labels),
    Arith(Box<CExpr>, ArOp, Box<CExpr>),
    Neg(Box<CExpr>),
    Func(Func, Vec<CExpr>),
    Agg(usize),
    Pattern(Box<PatPred>),
    PatternCount(Box<PatPred>),
    Quant(Quant, usize, Box<CExpr>, Box<CExpr>),
    ListComp(usize, Box<CExpr>, Option<Box<CExpr>>, Option<Box<CExpr>>),
    Case(Option<Box<CExpr>>, Vec<(CExpr, CExpr)>, Option<Box<CExpr>>),
}

/// Evaluation environment: the current row (slots), aggregate results
/// (post-aggregation expressions) and local variables (comprehensions).
pub(crate) struct Env<'a, 'g> {
    pub cx: &'a Ctx<'g>,
    pub row: &'a [Val],
    pub aggs: &'a [Val],
    pub locals: Vec<Val>,
}

impl<'a, 'g> Env<'a, 'g> {
    pub fn new(cx: &'a Ctx<'g>, row: &'a [Val]) -> Self {
        Env { cx, row, aggs: &[], locals: Vec::new() }
    }
    #[inline]
    fn slot(&self, s: usize) -> &Val {
        if s < self.row.len() {
            &self.row[s]
        } else {
            self.locals.get(s - self.row.len()).unwrap_or(&Val::Null)
        }
    }
    fn set_local(&mut self, s: usize, v: Val) {
        let i = s - self.row.len();
        if self.locals.len() <= i {
            self.locals.resize(i + 1, Val::Null);
        }
        self.locals[i] = v;
    }
}

pub(crate) fn label_ok(g: &Graph, id: u32, labels: &Labels) -> bool {
    labels.iter().all(|any| {
        any.iter().any(|l| match *l {
            LabelPred::Kind(k) => g.kind(id) == k,
            LabelPred::Any(None) => true,
            LabelPred::Any(Some(az)) => g.kind(id).is_azure() == az,
            LabelPred::Flag(f) => g.has_flag(id, f),
            LabelPred::Raw(r) => g.kind_raw(id) == r,
        })
    })
}

pub(crate) fn compile_regex(pat: &str) -> Result<Regex, String> {
    if pat.len() > MAX_REGEX_LEN {
        return Err(format!("regular expression longer than {MAX_REGEX_LEN} characters"));
    }
    Regex::builder()
        .syntax(regex_automata::util::syntax::Config::new().case_insensitive(true).nest_limit(64))
        .configure(Regex::config().nfa_size_limit(Some(4 << 20)).hybrid_cache_capacity(2 << 20).dfa_size_limit(Some(4 << 20)))
        .build(&format!("^(?:{pat})$"))
        .map_err(|e| format!("invalid regular expression: {e}"))
}

fn now_secs() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

/// Compiles AST expressions against a scope (slot `i` = `scope[i]`).
pub(crate) struct Compiler<'c, 'g> {
    pub g: &'g Graph,
    /// `Some` while compiling WITH/RETURN items: aggregates register here.
    pub aggs: Option<&'c mut Vec<AggSpec>>,
}

impl<'c, 'g> Compiler<'c, 'g> {
    pub fn new(g: &'g Graph) -> Self {
        Compiler { g, aggs: None }
    }

    pub fn compile(&mut self, e: &Expr, scope: &mut Vec<String>) -> Result<CExpr, QueryError> {
        Ok(match e {
            Expr::Lit(l) => CExpr::Const(Val::from_lit(l)),
            Expr::Var(v, pos) => match scope.iter().rposition(|s| s == v) {
                Some(i) => CExpr::Slot(i),
                None => return Err(QueryError::sem_at(format!("unknown variable '{v}'"), *pos)),
            },
            Expr::Prop(a, key) => {
                let key = key.to_ascii_lowercase();
                let a = self.compile(a, scope)?;
                match (&a, flag_prop(&key)) {
                    (CExpr::Slot(s), Some(f)) if f != flags::ENABLED => CExpr::Flag(*s, f),
                    _ => CExpr::Prop(Box::new(a), key.into()),
                }
            }
            Expr::Index(a, b) => CExpr::Index(Box::new(self.compile(a, scope)?), Box::new(self.compile(b, scope)?)),
            Expr::Slice(a, b, c) => CExpr::Slice(
                Box::new(self.compile(a, scope)?),
                b.as_ref().map(|x| self.compile(x, scope).map(Box::new)).transpose()?,
                c.as_ref().map(|x| self.compile(x, scope).map(Box::new)).transpose()?,
            ),
            Expr::List(xs) => {
                let v = xs.iter().map(|x| self.compile(x, scope)).collect::<Result<Vec<_>, _>>()?;
                if v.iter().all(|x| matches!(x, CExpr::Const(_))) {
                    CExpr::Const(Val::List(v.into_iter().map(|x| if let CExpr::Const(c) = x { c } else { Val::Null }).collect()))
                } else {
                    CExpr::List(v)
                }
            }
            Expr::Or(a, b) => CExpr::Or(Box::new(self.compile(a, scope)?), Box::new(self.compile(b, scope)?)),
            Expr::Xor(a, b) => CExpr::Xor(Box::new(self.compile(a, scope)?), Box::new(self.compile(b, scope)?)),
            Expr::And(a, b) => CExpr::And(Box::new(self.compile(a, scope)?), Box::new(self.compile(b, scope)?)),
            Expr::Not(a) => CExpr::Not(Box::new(self.compile(a, scope)?)),
            Expr::Cmp(a, CmpOp::Regex, b) => {
                let a = Box::new(self.compile(a, scope)?);
                match self.compile(b, scope)? {
                    CExpr::Const(Val::Str(p)) => CExpr::Regex(a, Arc::new(compile_regex(&p).map_err(QueryError::new)?)),
                    CExpr::Const(_) => CExpr::Const(Val::Bool(false)),
                    b => CExpr::DynRegex(a, Box::new(b)),
                }
            }
            Expr::Cmp(a, op, b) => CExpr::Cmp(Box::new(self.compile(a, scope)?), *op, Box::new(self.compile(b, scope)?)),
            Expr::IsNull(a, n) => CExpr::IsNull(Box::new(self.compile(a, scope)?), *n),
            Expr::HasLabel(a, l) => CExpr::HasLabel(Box::new(self.compile(a, scope)?), l.clone()),
            Expr::Arith(a, op, b) => CExpr::Arith(Box::new(self.compile(a, scope)?), *op, Box::new(self.compile(b, scope)?)),
            Expr::Neg(a) => CExpr::Neg(Box::new(self.compile(a, scope)?)),
            Expr::Pattern(p) => CExpr::Pattern(Box::new(plan_pattern_pred(self.g, p, scope)?)),
            Expr::Quant { q, var, list, pred } => {
                let list = self.compile(list, scope)?;
                scope.push(var.clone());
                let slot = scope.len() - 1;
                let pred = self.compile(pred, scope);
                scope.pop();
                CExpr::Quant(*q, slot, Box::new(list), Box::new(pred?))
            }
            Expr::ListComp { var, list, pred, map } => {
                let list = self.compile(list, scope)?;
                scope.push(var.clone());
                let slot = scope.len() - 1;
                let r = (|| {
                    Ok::<_, QueryError>((
                        pred.as_ref().map(|x| self.compile(x, scope).map(Box::new)).transpose()?,
                        map.as_ref().map(|x| self.compile(x, scope).map(Box::new)).transpose()?,
                    ))
                })();
                scope.pop();
                let (pred, map) = r?;
                CExpr::ListComp(slot, Box::new(list), pred, map)
            }
            Expr::Case { subject, whens, default } => CExpr::Case(
                subject.as_ref().map(|x| self.compile(x, scope).map(Box::new)).transpose()?,
                whens.iter().map(|(a, b)| Ok((self.compile(a, scope)?, self.compile(b, scope)?))).collect::<Result<Vec<_>, QueryError>>()?,
                default.as_ref().map(|x| self.compile(x, scope).map(Box::new)).transpose()?,
            ),
            Expr::Call { name, distinct, star, args, pos } => return self.call(name, *distinct, *star, args, *pos, scope),
        })
    }

    fn call(&mut self, name: &str, distinct: bool, star: bool, args: &[Expr], pos: usize, scope: &mut Vec<String>) -> Result<CExpr, QueryError> {
        if is_aggregate(name) {
            let f = match name {
                "count" if star => AggFn::CountStar,
                "count" => AggFn::Count,
                "collect" => AggFn::Collect,
                "min" => AggFn::Min,
                "max" => AggFn::Max,
                "sum" => AggFn::Sum,
                "avg" => AggFn::Avg,
                "stdev" => AggFn::StDev,
                _ => AggFn::StDevP,
            };
            if f != AggFn::CountStar && args.len() != 1 {
                return Err(QueryError::sem_at(format!("{name}() takes exactly one argument"), pos));
            }
            let Some(aggs) = self.aggs.take() else {
                return Err(QueryError::sem_at(format!("aggregate function {name}() is only allowed in WITH / RETURN"), pos));
            };
            let arg = match args.first() {
                Some(a) => {
                    // Nested aggregates are invalid: compile the argument without the registry.
                    match self.compile(a, scope) {
                        Ok(c) => Some(c),
                        Err(e) => {
                            self.aggs = Some(aggs);
                            return Err(if e.message.contains("only allowed in WITH") {
                                QueryError::sem_at("aggregate functions cannot be nested", pos)
                            } else {
                                e
                            });
                        }
                    }
                }
                None => None,
            };
            aggs.push(AggSpec { f, distinct, arg });
            let i = aggs.len() - 1;
            self.aggs = Some(aggs);
            return Ok(CExpr::Agg(i));
        }
        if distinct {
            return Err(QueryError::sem_at(format!("DISTINCT is only allowed in aggregate functions, not {name}()"), pos));
        }
        // Relative-time helpers fold to constants.
        if name == "days_ago" || name == "now" {
            let days = if name == "days_ago" {
                match args {
                    [Expr::Lit(Lit::Int(n))] => *n as f64,
                    [Expr::Lit(Lit::Float(f))] => *f,
                    _ => return Err(QueryError::sem_at("days_ago() takes a number of days", pos)),
                }
            } else {
                0.0
            };
            return Ok(CExpr::Const(Val::Num((now_secs() - days * 86400.0).floor())));
        }
        if name == "exists" {
            if let [Expr::Pattern(p)] = args {
                return Ok(CExpr::Pattern(Box::new(plan_pattern_pred(self.g, p, scope)?)));
            }
        }
        if name == "size" || name == "length" {
            if let [Expr::Pattern(p)] = args {
                return Ok(CExpr::PatternCount(Box::new(plan_pattern_pred(self.g, p, scope)?)));
            }
        }
        let Some((f, lo, hi)) = func_of(name) else {
            return Err(QueryError::sem_at(format!("unknown function '{name}'"), pos));
        };
        if args.len() < lo || args.len() > hi {
            return Err(QueryError::sem_at(format!("wrong number of arguments to {name}()"), pos));
        }
        let args = args.iter().map(|a| self.compile(a, scope)).collect::<Result<Vec<_>, _>>()?;
        Ok(CExpr::Func(f, args))
    }
}

fn as_str(v: &Val) -> Option<&str> {
    match v {
        Val::Str(s) => Some(s),
        _ => None,
    }
}

fn to_string(g: &Graph, v: &Val) -> Val {
    match v {
        Val::Null => Val::Null,
        Val::Str(s) => Val::Str(s.clone()),
        Val::Num(n) => Val::Str(if n.fract() == 0.0 && n.abs() < 9e15 { format!("{}", *n as i64) } else { format!("{n}") }),
        Val::Bool(b) => Val::Str(b.to_string()),
        Val::Node(id) => Val::Str(g.name(*id).to_string()),
        Val::Edge(e) => Val::Str(g.edge_kind_name(e.2).to_string()),
        other => Val::Str(other.to_json(g).to_string()),
    }
}

fn list_of(v: Val) -> Option<Vec<Val>> {
    match v {
        Val::List(xs) => Some(xs),
        Val::Edges(es) => Some(es.iter().map(|e| Val::Edge(*e)).collect()),
        Val::Path(p) | Val::Subgraph(p) => Some(p.nodes.iter().map(|&n| Val::Node(n)).collect()),
        _ => None,
    }
}

fn index_of(i: f64, len: usize) -> Option<usize> {
    let i = i as i64;
    let j = if i < 0 { len as i64 + i } else { i };
    (j >= 0 && (j as usize) < len).then_some(j as usize)
}

impl CExpr {
    /// Visit every pattern predicate inside this expression.
    pub fn visit_pats(&self, f: &mut dyn FnMut(&PatPred)) {
        match self {
            CExpr::Pattern(p) | CExpr::PatternCount(p) => f(p),
            CExpr::Const(_) | CExpr::Slot(_) | CExpr::Flag(..) | CExpr::Agg(_) => {}
            CExpr::Prop(a, _) | CExpr::Not(a) | CExpr::Neg(a) | CExpr::IsNull(a, _) | CExpr::HasLabel(a, _) | CExpr::Regex(a, _) => a.visit_pats(f),
            CExpr::Index(a, b) | CExpr::Or(a, b) | CExpr::Xor(a, b) | CExpr::And(a, b) | CExpr::Cmp(a, _, b) | CExpr::Arith(a, _, b) | CExpr::DynRegex(a, b) | CExpr::Quant(_, _, a, b) => {
                a.visit_pats(f);
                b.visit_pats(f);
            }
            CExpr::Slice(a, b, c) => {
                a.visit_pats(f);
                for x in [b, c].into_iter().flatten() {
                    x.visit_pats(f);
                }
            }
            CExpr::List(xs) | CExpr::Func(_, xs) => xs.iter().for_each(|x| x.visit_pats(f)),
            CExpr::ListComp(_, a, b, c) => {
                a.visit_pats(f);
                for x in [b, c].into_iter().flatten() {
                    x.visit_pats(f);
                }
            }
            CExpr::Case(a, ws, d) => {
                for x in [a, d].into_iter().flatten() {
                    x.visit_pats(f);
                }
                for (w, t) in ws {
                    w.visit_pats(f);
                    t.visit_pats(f);
                }
            }
        }
    }

    /// WHERE semantics: two-valued, null → false.
    pub fn test(&self, env: &mut Env) -> bool {
        match self {
            CExpr::And(a, b) => a.test(env) && b.test(env),
            CExpr::Or(a, b) => a.test(env) || b.test(env),
            CExpr::Not(a) => !a.test(env),
            CExpr::Xor(a, b) => a.test(env) != b.test(env),
            CExpr::Flag(s, f) => match env.slot(*s) {
                Val::Node(id) => env.cx.g.has_flag(*id, *f),
                _ => false,
            },
            CExpr::Cmp(a, op, b) => {
                let row = env.row;
                let x = a.eval_cow(row, env);
                let y = b.eval_cow(row, env);
                compare(&x, *op, &y)
            }
            CExpr::Regex(a, re) => match a.eval(env) {
                Val::Str(s) => re.is_match(s.as_str()),
                Val::List(v) => v.iter().any(|x| matches!(x, Val::Str(s) if re.is_match(s.as_str()))),
                _ => false,
            },
            CExpr::IsNull(a, n) => a.eval(env).is_null() == *n,
            CExpr::HasLabel(a, l) => match a.eval(env) {
                Val::Node(id) => label_ok(env.cx.g, id, l),
                _ => false,
            },
            CExpr::Pattern(p) => p.exists(env),
            CExpr::Quant(..) => self.eval(env).truthy(),
            e => e.eval(env).truthy(),
        }
    }

    /// Borrow constants and slots instead of cloning them.
    fn eval_cow<'r>(&'r self, row: &'r [Val], env: &mut Env) -> std::borrow::Cow<'r, Val> {
        use std::borrow::Cow;
        match self {
            CExpr::Const(v) => Cow::Borrowed(v),
            CExpr::Slot(s) if *s < row.len() => Cow::Borrowed(&row[*s]),
            e => Cow::Owned(e.eval(env)),
        }
    }

    pub fn eval(&self, env: &mut Env) -> Val {
        let g = env.cx.g;
        match self {
            CExpr::Const(v) => v.clone(),
            CExpr::Slot(s) => env.slot(*s).clone(),
            CExpr::Flag(s, f) => match env.slot(*s) {
                Val::Node(id) => Val::Bool(g.has_flag(*id, *f)),
                _ => Val::Null,
            },
            CExpr::Prop(a, key) => {
                if let CExpr::Slot(s) = **a {
                    return val_prop(g, env.slot(s), key);
                }
                let v = a.eval(env);
                val_prop(g, &v, key)
            }
            CExpr::Index(a, i) => {
                let v = a.eval(env);
                let i = i.eval(env);
                match (v, i) {
                    (Val::Map(m), Val::Str(k)) => m.iter().find(|(x, _)| x.eq_ignore_ascii_case(&k)).map(|(_, v)| v.clone()).unwrap_or_default(),
                    (Val::Node(id), Val::Str(k)) => node_prop(g, id, &k.to_ascii_lowercase()),
                    (v, Val::Num(i)) => match list_of(v) {
                        Some(xs) => index_of(i, xs.len()).map(|j| xs[j].clone()).unwrap_or_default(),
                        None => Val::Null,
                    },
                    _ => Val::Null,
                }
            }
            CExpr::Slice(a, lo, hi) => {
                let Some(xs) = list_of(a.eval(env)) else { return Val::Null };
                let n = xs.len() as i64;
                let norm = |v: Option<f64>, d: i64| -> i64 {
                    match v {
                        None => d,
                        Some(i) => {
                            let i = i as i64;
                            (if i < 0 { n + i } else { i }).clamp(0, n)
                        }
                    }
                };
                let l = norm(lo.as_ref().and_then(|x| x.eval(env).as_num()), 0);
                let h = norm(hi.as_ref().and_then(|x| x.eval(env).as_num()), n);
                if l >= h {
                    Val::List(Vec::new())
                } else {
                    Val::List(xs[l as usize..h as usize].to_vec())
                }
            }
            CExpr::List(xs) => Val::List(xs.iter().map(|x| x.eval(env)).collect()),
            CExpr::Or(..) | CExpr::And(..) | CExpr::Not(_) | CExpr::Xor(..) | CExpr::Cmp(..) | CExpr::Regex(..) | CExpr::IsNull(..) | CExpr::HasLabel(..) | CExpr::Pattern(_) => {
                Val::Bool(self.test(env))
            }
            CExpr::DynRegex(a, p) => {
                let Val::Str(pat) = p.eval(env) else { return Val::Bool(false) };
                let Ok(re) = compile_regex(&pat) else { return Val::Bool(false) };
                Val::Bool(match a.eval(env) {
                    Val::Str(s) => re.is_match(s.as_str()),
                    _ => false,
                })
            }
            CExpr::Arith(a, op, b) => arith(g, a.eval(env), *op, b.eval(env)),
            CExpr::Neg(a) => match a.eval(env).as_num() {
                Some(n) => Val::Num(-n),
                None => Val::Null,
            },
            CExpr::Agg(i) => env.aggs.get(*i).cloned().unwrap_or_default(),
            CExpr::PatternCount(p) => Val::Num(p.count(env) as f64),
            CExpr::Quant(q, slot, list, pred) => {
                let Some(xs) = list_of(list.eval(env)) else { return Val::Null };
                let mut n = 0usize;
                for x in xs {
                    env.set_local(*slot, x);
                    if pred.test(env) {
                        n += 1;
                        match q {
                            Quant::Any => return Val::Bool(true),
                            Quant::None => return Val::Bool(false),
                            Quant::Single if n > 1 => return Val::Bool(false),
                            _ => {}
                        }
                    } else if *q == Quant::All {
                        return Val::Bool(false);
                    }
                }
                Val::Bool(match q {
                    Quant::Any => false,
                    Quant::All | Quant::None => true,
                    Quant::Single => n == 1,
                })
            }
            CExpr::ListComp(slot, list, pred, map) => {
                let Some(xs) = list_of(list.eval(env)) else { return Val::Null };
                let mut out = Vec::new();
                for x in xs {
                    env.set_local(*slot, x.clone());
                    if pred.as_ref().is_none_or(|p| p.test(env)) {
                        out.push(match map {
                            Some(m) => m.eval(env),
                            None => x,
                        });
                    }
                }
                Val::List(out)
            }
            CExpr::Case(subject, whens, default) => {
                let s = subject.as_ref().map(|x| x.eval(env));
                for (w, t) in whens {
                    let hit = match &s {
                        Some(s) => val_eq(s, &w.eval(env)),
                        None => w.test(env),
                    };
                    if hit {
                        return t.eval(env);
                    }
                }
                default.as_ref().map(|d| d.eval(env)).unwrap_or_default()
            }
            CExpr::Func(f, args) => self.func(*f, args, env),
        }
    }

    fn func(&self, f: Func, args: &[CExpr], env: &mut Env) -> Val {
        let g = env.cx.g;
        if f == Func::Coalesce {
            for a in args {
                let v = a.eval(env);
                if !v.is_null() {
                    return v;
                }
            }
            return Val::Null;
        }
        let mut av: Vec<Val> = args.iter().map(|a| a.eval(env)).collect();
        let a0 = if av.is_empty() { Val::Null } else { std::mem::take(&mut av[0]) };
        let num = |v: &Val| v.as_num();
        match f {
            Func::ToLower => as_str(&a0).map(|s| Val::Str(s.to_lowercase())).unwrap_or_default(),
            Func::ToUpper => as_str(&a0).map(|s| Val::Str(s.to_uppercase())).unwrap_or_default(),
            Func::Trim => as_str(&a0).map(|s| Val::Str(s.trim().into())).unwrap_or_default(),
            Func::LTrim => as_str(&a0).map(|s| Val::Str(s.trim_start().into())).unwrap_or_default(),
            Func::RTrim => as_str(&a0).map(|s| Val::Str(s.trim_end().into())).unwrap_or_default(),
            Func::Size | Func::Length => match &a0 {
                Val::Str(s) => Val::Num(s.chars().count() as f64),
                Val::List(v) => Val::Num(v.len() as f64),
                Val::Edges(es) => Val::Num(es.len() as f64),
                Val::Edge(_) => Val::Num(1.0),
                Val::Path(p) | Val::Subgraph(p) => Val::Num(p.edges.len() as f64),
                Val::Map(m) => Val::Num(m.len() as f64),
                _ => Val::Null,
            },
            Func::IsEmpty => match &a0 {
                Val::Str(s) => Val::Bool(s.is_empty()),
                Val::List(v) => Val::Bool(v.is_empty()),
                Val::Map(m) => Val::Bool(m.is_empty()),
                _ => Val::Null,
            },
            Func::Type => match &a0 {
                Val::Edge(e) => Val::Str(g.edge_kind_name(e.2).to_string()),
                Val::Edges(es) if es.len() == 1 => Val::Str(g.edge_kind_name(es[0].2).to_string()),
                _ => Val::Null,
            },
            Func::Labels => match &a0 {
                Val::Node(id) => {
                    let k = g.kind(*id);
                    let mut v = vec![Val::Str(g.kind_name(*id).to_string()), Val::Str(if k.is_azure() { "AZBase" } else { "Base" }.into())];
                    if g.has_flag(*id, flags::TIER0) {
                        v.push(Val::Str("Tag_Tier_Zero".into()));
                    }
                    if g.has_flag(*id, flags::OWNED) {
                        v.push(Val::Str("Tag_Owned".into()));
                    }
                    Val::List(v)
                }
                _ => Val::Null,
            },
            Func::Id => match &a0 {
                Val::Node(id) => Val::Num(*id as f64),
                _ => Val::Null,
            },
            Func::ElementId => match &a0 {
                Val::Node(id) => Val::Str(id.to_string()),
                Val::Edge(e) => Val::Str(format!("{}:{}:{}", e.0, e.1, e.2)),
                _ => Val::Null,
            },
            Func::Nodes => match &a0 {
                Val::Path(p) | Val::Subgraph(p) => Val::List(p.nodes.iter().map(|&n| Val::Node(n)).collect()),
                Val::Edge(e) => Val::List(vec![Val::Node(e.0), Val::Node(e.1)]),
                _ => Val::Null,
            },
            Func::Rels => match &a0 {
                Val::Path(p) | Val::Subgraph(p) => Val::List(p.edges.iter().map(|&e| Val::Edge(e)).collect()),
                Val::Edges(es) => Val::List(es.iter().map(|&e| Val::Edge(e)).collect()),
                Val::Edge(e) => Val::List(vec![Val::Edge(*e)]),
                _ => Val::Null,
            },
            Func::StartNode => match &a0 {
                Val::Edge(e) => Val::Node(e.0),
                _ => Val::Null,
            },
            Func::EndNode => match &a0 {
                Val::Edge(e) => Val::Node(e.1),
                _ => Val::Null,
            },
            Func::ToString => to_string(g, &a0),
            Func::ToInteger => match &a0 {
                Val::Num(n) => Val::Num(n.trunc()),
                Val::Bool(b) => Val::Num(*b as u8 as f64),
                Val::Str(s) => s.trim().parse::<f64>().map(|n| Val::Num(n.trunc())).unwrap_or_default(),
                _ => Val::Null,
            },
            Func::ToFloat => num(&a0).map(Val::Num).unwrap_or_default(),
            Func::ToBoolean => match &a0 {
                Val::Bool(b) => Val::Bool(*b),
                Val::Str(s) if s.eq_ignore_ascii_case("true") => Val::Bool(true),
                Val::Str(s) if s.eq_ignore_ascii_case("false") => Val::Bool(false),
                Val::Num(n) => Val::Bool(*n != 0.0),
                _ => Val::Null,
            },
            Func::Split => match (&a0, &av[1]) {
                (Val::Str(s), Val::Str(d)) => {
                    let parts: Vec<Val> = if d.is_empty() {
                        s.chars().map(|c| Val::Str(c.to_string())).take(MAX_LIST).collect()
                    } else {
                        s.split(d.as_str()).map(|p| Val::Str(p.to_string())).take(MAX_LIST).collect()
                    };
                    Val::List(parts)
                }
                _ => Val::Null,
            },
            Func::Substring => {
                let Val::Str(s) = &a0 else { return Val::Null };
                let start = num(&av[1]).unwrap_or(0.0).max(0.0) as usize;
                let it = s.chars().skip(start);
                Val::Str(match av.get(2).and_then(num) {
                    Some(l) => it.take(l.max(0.0) as usize).collect(),
                    None => it.collect(),
                })
            }
            Func::Left | Func::Right => {
                let (Val::Str(s), Some(n)) = (&a0, num(&av[1])) else { return Val::Null };
                let n = n.max(0.0) as usize;
                let cs: Vec<char> = s.chars().collect();
                let n = n.min(cs.len());
                Val::Str(if f == Func::Left { cs[..n].iter().collect() } else { cs[cs.len() - n..].iter().collect() })
            }
            Func::Replace => match (&a0, &av[1], &av[2]) {
                (Val::Str(s), Val::Str(a), Val::Str(b)) if !a.is_empty() => Val::Str(s.replace(a.as_str(), b)),
                (Val::Str(s), _, _) => Val::Str(s.clone()),
                _ => Val::Null,
            },
            Func::Head => list_of(a0).and_then(|v| v.into_iter().next()).unwrap_or_default(),
            Func::Last => list_of(a0).and_then(|v| v.into_iter().last()).unwrap_or_default(),
            Func::Tail => list_of(a0).map(|v| Val::List(v.into_iter().skip(1).collect())).unwrap_or_default(),
            Func::Reverse => match a0 {
                Val::Str(s) => Val::Str(s.chars().rev().collect()),
                v => list_of(v).map(|mut v| {
                    v.reverse();
                    Val::List(v)
                })
                .unwrap_or_default(),
            },
            Func::Keys => match &a0 {
                Val::Node(id) => {
                    let mut ks: Vec<Val> = vec![Val::Str("name".into()), Val::Str("objectid".into())];
                    for (k, _) in raw_props(g.props(*id)) {
                        if !k.eq_ignore_ascii_case("name") && !k.eq_ignore_ascii_case("objectid") {
                            ks.push(Val::Str(k));
                        }
                    }
                    Val::List(ks)
                }
                Val::Map(m) => Val::List(m.iter().map(|(k, _)| Val::Str(k.clone())).collect()),
                _ => Val::Null,
            },
            Func::Properties => match &a0 {
                Val::Node(id) => {
                    let mut m: Vec<(String, Val)> = vec![
                        ("name".into(), Val::Str(g.name(*id).to_string())),
                        ("objectid".into(), Val::Str(g.oid(*id).to_string())),
                    ];
                    for (k, v) in raw_props(g.props(*id)) {
                        let lk = k.to_ascii_lowercase();
                        if lk != "name" && lk != "objectid" {
                            m.push((lk, Val::from_json(v)));
                        }
                    }
                    Val::Map(Arc::new(m))
                }
                Val::Map(m) => Val::Map(m.clone()),
                _ => Val::Null,
            },
            Func::Exists => Val::Bool(!a0.is_null()),
            Func::Abs => num(&a0).map(|n| Val::Num(n.abs())).unwrap_or_default(),
            Func::Round => match (num(&a0), av.get(1).and_then(num)) {
                (Some(n), Some(p)) => {
                    let m = 10f64.powi(p as i32);
                    Val::Num((n * m).round() / m)
                }
                (Some(n), None) => Val::Num(n.round()),
                _ => Val::Null,
            },
            Func::Floor => num(&a0).map(|n| Val::Num(n.floor())).unwrap_or_default(),
            Func::Ceil => num(&a0).map(|n| Val::Num(n.ceil())).unwrap_or_default(),
            Func::Sqrt => num(&a0).map(|n| Val::Num(n.sqrt())).unwrap_or_default(),
            Func::Sign => num(&a0).map(|n| Val::Num(if n > 0.0 { 1.0 } else if n < 0.0 { -1.0 } else { 0.0 })).unwrap_or_default(),
            Func::Range => {
                let (Some(a), Some(b)) = (num(&a0), num(&av[1])) else { return Val::Null };
                let step = av.get(2).and_then(num).unwrap_or(1.0);
                if step == 0.0 {
                    return Val::Null;
                }
                let mut out = Vec::new();
                let mut x = a;
                while (step > 0.0 && x <= b) || (step < 0.0 && x >= b) {
                    if out.len() >= MAX_LIST {
                        break;
                    }
                    out.push(Val::Num(x));
                    x += step;
                }
                Val::List(out)
            }
            Func::Datetime => {
                let s = now_secs();
                Val::Map(Arc::new(vec![("epochseconds".into(), Val::Num(s.floor())), ("epochmillis".into(), Val::Num((s * 1000.0).floor()))]))
            }
            Func::Timestamp => Val::Num((now_secs() * 1000.0).floor()),
            Func::Coalesce => unreachable!(),
        }
    }
}

fn arith(g: &Graph, a: Val, op: ArOp, b: Val) -> Val {
    if a.is_null() || b.is_null() {
        return Val::Null;
    }
    if op == ArOp::Add {
        match (a, b) {
            (Val::List(mut x), Val::List(y)) => {
                x.extend(y);
                return Val::List(x);
            }
            (Val::List(mut x), y) => {
                x.push(y);
                return Val::List(x);
            }
            (x, Val::List(mut y)) => {
                y.insert(0, x);
                return Val::List(y);
            }
            (x @ Val::Str(_), y) | (x, y @ Val::Str(_)) => {
                let (Val::Str(p), Val::Str(q)) = (to_string(g, &x), to_string(g, &y)) else { return Val::Null };
                return Val::Str(p + &q);
            }
            (x, y) => return arith_num(x.as_num(), op, y.as_num()),
        }
    }
    arith_num(a.as_num(), op, b.as_num())
}

fn arith_num(a: Option<f64>, op: ArOp, b: Option<f64>) -> Val {
    let (Some(x), Some(y)) = (a, b) else { return Val::Null };
    let r = match op {
        ArOp::Add => x + y,
        ArOp::Sub => x - y,
        ArOp::Mul => x * y,
        ArOp::Div if y == 0.0 => return Val::Null,
        ArOp::Div => x / y,
        ArOp::Mod if y == 0.0 => return Val::Null,
        ArOp::Mod => x % y,
        ArOp::Pow => x.powf(y),
    };
    Val::Num(r)
}

// ------------------------------------------------------------ aggregation state

#[derive(Debug)]
pub(crate) enum AggState {
    Count(u64),
    Collect(Vec<Val>),
    Min(Option<Val>),
    Max(Option<Val>),
    Sum(f64),
    Avg(f64, u64),
    /// Welford: n, mean, m2.
    Dev(u64, f64, f64),
}

#[derive(Debug)]
pub(crate) struct Acc {
    pub state: AggState,
    pub seen: Option<AHashSet<VKey>>,
}

impl AggSpec {
    pub fn init(&self) -> Acc {
        let state = match self.f {
            AggFn::Count | AggFn::CountStar => AggState::Count(0),
            AggFn::Collect => AggState::Collect(Vec::new()),
            AggFn::Min => AggState::Min(None),
            AggFn::Max => AggState::Max(None),
            AggFn::Sum => AggState::Sum(0.0),
            AggFn::Avg => AggState::Avg(0.0, 0),
            AggFn::StDev | AggFn::StDevP => AggState::Dev(0, 0.0, 0.0),
        };
        Acc { state, seen: self.distinct.then(AHashSet::new) }
    }

    /// Returns false when a `collect()` hit its cap.
    pub fn update(&self, acc: &mut Acc, env: &mut Env) -> bool {
        let v = match &self.arg {
            None => {
                if let AggState::Count(n) = &mut acc.state {
                    *n += 1;
                }
                return true;
            }
            Some(a) => a.eval(env),
        };
        if v.is_null() {
            return true;
        }
        if let Some(seen) = &mut acc.seen {
            if !seen.insert(VKey(v.clone())) {
                return true;
            }
        }
        Self::apply(&mut acc.state, v)
    }

    /// Combine a partial accumulator (from another thread) into `acc`.
    pub fn merge(&self, acc: &mut Acc, other: Acc) -> bool {
        let mut ok = true;
        if let (Some(mine), Some(theirs)) = (&mut acc.seen, other.seen) {
            for v in theirs {
                if mine.insert(v.clone()) {
                    ok &= Self::apply(&mut acc.state, v.0);
                }
            }
            return ok;
        }
        match (&mut acc.state, other.state) {
            (AggState::Count(a), AggState::Count(b)) => *a += b,
            (AggState::Collect(a), AggState::Collect(b)) => {
                let room = MAX_COLLECT.saturating_sub(a.len());
                ok = b.len() <= room;
                a.extend(b.into_iter().take(room));
            }
            (AggState::Min(a), AggState::Min(Some(b))) => {
                if a.as_ref().is_none_or(|x| sort_cmp(&b, x).is_lt()) {
                    *a = Some(b);
                }
            }
            (AggState::Max(a), AggState::Max(Some(b))) => {
                if a.as_ref().is_none_or(|x| sort_cmp(&b, x).is_gt()) {
                    *a = Some(b);
                }
            }
            (AggState::Sum(a), AggState::Sum(b)) => *a += b,
            (AggState::Avg(s, n), AggState::Avg(s2, n2)) => {
                *s += s2;
                *n += n2;
            }
            (AggState::Dev(n, mean, m2), AggState::Dev(nb, mb, m2b)) if nb > 0 => {
                let na = *n as f64;
                let tot = na + nb as f64;
                let delta = mb - *mean;
                *mean += delta * nb as f64 / tot;
                *m2 += m2b + delta * delta * na * nb as f64 / tot;
                *n += nb;
            }
            _ => {}
        }
        ok
    }

    fn apply(state: &mut AggState, v: Val) -> bool {
        match state {
            AggState::Count(n) => *n += 1,
            AggState::Collect(xs) => {
                if xs.len() >= MAX_COLLECT {
                    return false;
                }
                xs.push(v);
            }
            AggState::Min(m) => {
                if m.as_ref().is_none_or(|x| sort_cmp(&v, x).is_lt()) {
                    *m = Some(v);
                }
            }
            AggState::Max(m) => {
                if m.as_ref().is_none_or(|x| sort_cmp(&v, x).is_gt()) {
                    *m = Some(v);
                }
            }
            AggState::Sum(s) => *s += v.as_num().unwrap_or(0.0),
            AggState::Avg(s, n) => {
                if let Some(x) = v.as_num() {
                    *s += x;
                    *n += 1;
                }
            }
            AggState::Dev(n, mean, m2) => {
                if let Some(x) = v.as_num() {
                    *n += 1;
                    let d = x - *mean;
                    *mean += d / *n as f64;
                    *m2 += d * (x - *mean);
                }
            }
        }
        true
    }

    pub fn finish(&self, acc: Acc) -> Val {
        match acc.state {
            AggState::Count(n) => Val::Num(n as f64),
            AggState::Collect(xs) => Val::List(xs),
            AggState::Min(m) | AggState::Max(m) => m.unwrap_or_default(),
            AggState::Sum(s) => Val::Num(s),
            AggState::Avg(_, 0) => Val::Null,
            AggState::Avg(s, n) => Val::Num(s / n as f64),
            AggState::Dev(n, _, m2) => {
                let d = if self.f == AggFn::StDev { n.saturating_sub(1) } else { n };
                if d == 0 {
                    Val::Num(0.0)
                } else {
                    Val::Num((m2 / d as f64).sqrt())
                }
            }
        }
    }
}
