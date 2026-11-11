//! CHQL abstract syntax tree.

use ch_model::NodeKind;

#[derive(Debug, Clone, PartialEq)]
pub enum Lit {
    Str(String),
    Int(i64),
    Float(f64),
    Bool(bool),
    Null,
}

/// One label in a node pattern or label predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelPred {
    Kind(NodeKind),
    /// `Base` / `AZBase`-style catch-alls: `None` = any node, `Some(true)` =
    /// Azure kinds, `Some(false)` = Active Directory kinds.
    Any(Option<bool>),
    /// BloodHound CE tag labels mapped onto node flags (`Tag_Tier_Zero`,
    /// `Tag_Owned`).
    Flag(u32),
    /// A custom (OpenGraph) node kind, by raw stored kind.
    Raw(u8),
}

/// Conjunction of disjunctions: `(n:User:Base)` = `[[User],[Base]]`,
/// `(n:User|Computer)` = `[[User, Computer]]`.
pub type Labels = Vec<Vec<LabelPred>>;

#[derive(Debug, Clone, Default)]
pub struct NodePat {
    pub var: Option<String>,
    pub labels: Labels,
    pub props: Vec<(String, Expr)>,
    pub pos: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    Out,
    In,
    /// Undirected `-[]-`: either direction.
    Both,
}

impl Dir {
    pub fn flip(self) -> Dir {
        match self {
            Dir::Out => Dir::In,
            Dir::In => Dir::Out,
            Dir::Both => Dir::Both,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RelPat {
    pub var: Option<String>,
    /// Edge kind names; empty = default set (see executor).
    pub kinds: Vec<String>,
    pub dir: Dir,
    /// `Some((min, max))` for variable length (`*`, `*2..`, `*..5`, `*1..3`).
    pub var_len: Option<(u32, Option<u32>)>,
    pub pos: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathFn {
    None,
    Shortest,
    AllShortest,
}

#[derive(Debug, Clone)]
pub struct Pattern {
    pub path_var: Option<String>,
    pub func: PathFn,
    pub nodes: Vec<NodePat>,
    /// `rels[i]` connects `nodes[i]` and `nodes[i + 1]`.
    pub rels: Vec<RelPat>,
    pub pos: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    StartsWith,
    EndsWith,
    Contains,
    In,
    Regex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Pow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quant {
    Any,
    All,
    None,
    Single,
}

#[derive(Debug, Clone)]
pub enum Expr {
    Lit(Lit),
    Var(String, usize),
    Prop(Box<Expr>, String),
    Index(Box<Expr>, Box<Expr>),
    Slice(Box<Expr>, Option<Box<Expr>>, Option<Box<Expr>>),
    List(Vec<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Xor(Box<Expr>, Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Cmp(Box<Expr>, CmpOp, Box<Expr>),
    IsNull(Box<Expr>, bool),
    HasLabel(Box<Expr>, Labels),
    Arith(Box<Expr>, ArOp, Box<Expr>),
    Neg(Box<Expr>),
    /// Function call; `name` is lower-cased. `count(*)` has `star`.
    Call { name: String, distinct: bool, star: bool, args: Vec<Expr>, pos: usize },
    /// Pattern predicate: `(a)-[:MemberOf]->(b)` / `exists((a)-->())`.
    Pattern(Box<Pattern>),
    Quant { q: Quant, var: String, list: Box<Expr>, pred: Box<Expr> },
    ListComp { var: String, list: Box<Expr>, pred: Option<Box<Expr>>, map: Option<Box<Expr>> },
    Case { subject: Option<Box<Expr>>, whens: Vec<(Expr, Expr)>, default: Option<Box<Expr>> },
}

impl Expr {
    /// Free variables referenced by this expression (not bound inside it).
    pub fn vars(&self, out: &mut Vec<String>) {
        let mut bound = Vec::new();
        self.vars_in(&mut bound, out);
    }

    fn vars_in(&self, bound: &mut Vec<String>, out: &mut Vec<String>) {
        match self {
            Expr::Lit(_) => {}
            Expr::Var(v, _) => {
                if !bound.contains(v) {
                    out.push(v.clone())
                }
            }
            Expr::Prop(a, _) | Expr::Not(a) | Expr::Neg(a) | Expr::IsNull(a, _) | Expr::HasLabel(a, _) => a.vars_in(bound, out),
            Expr::Index(a, b) | Expr::Or(a, b) | Expr::Xor(a, b) | Expr::And(a, b) | Expr::Cmp(a, _, b) | Expr::Arith(a, _, b) => {
                a.vars_in(bound, out);
                b.vars_in(bound, out);
            }
            Expr::Slice(a, b, c) => {
                a.vars_in(bound, out);
                for x in [b, c].into_iter().flatten() {
                    x.vars_in(bound, out);
                }
            }
            Expr::List(xs) | Expr::Call { args: xs, .. } => xs.iter().for_each(|x| x.vars_in(bound, out)),
            Expr::Pattern(p) => {
                for n in &p.nodes {
                    if let Some(v) = &n.var {
                        if !bound.contains(v) {
                            out.push(v.clone());
                        }
                    }
                    for (_, e) in &n.props {
                        e.vars_in(bound, out);
                    }
                }
                for r in &p.rels {
                    if let Some(v) = &r.var {
                        if !bound.contains(v) {
                            out.push(v.clone());
                        }
                    }
                }
            }
            Expr::Quant { var, list, pred, .. } => {
                list.vars_in(bound, out);
                bound.push(var.clone());
                pred.vars_in(bound, out);
                bound.pop();
            }
            Expr::ListComp { var, list, pred, map } => {
                list.vars_in(bound, out);
                bound.push(var.clone());
                for x in [pred, map].into_iter().flatten() {
                    x.vars_in(bound, out);
                }
                bound.pop();
            }
            Expr::Case { subject, whens, default } => {
                for x in [subject, default].into_iter().flatten() {
                    x.vars_in(bound, out);
                }
                for (a, b) in whens {
                    a.vars_in(bound, out);
                    b.vars_in(bound, out);
                }
            }
        }
    }

    /// Split top-level ANDs into conjuncts.
    pub fn conjuncts(self, out: &mut Vec<Expr>) {
        match self {
            Expr::And(a, b) => {
                a.conjuncts(out);
                b.conjuncts(out);
            }
            e => out.push(e),
        }
    }

    /// True when the expression contains an aggregate function call.
    pub fn has_aggregate(&self) -> bool {
        match self {
            Expr::Call { name, args, .. } => is_aggregate(name) || args.iter().any(Expr::has_aggregate),
            Expr::Lit(_) | Expr::Var(..) | Expr::Pattern(_) => false,
            Expr::Prop(a, _) | Expr::Not(a) | Expr::Neg(a) | Expr::IsNull(a, _) | Expr::HasLabel(a, _) => a.has_aggregate(),
            Expr::Index(a, b) | Expr::Or(a, b) | Expr::Xor(a, b) | Expr::And(a, b) | Expr::Cmp(a, _, b) | Expr::Arith(a, _, b) => {
                a.has_aggregate() || b.has_aggregate()
            }
            Expr::Slice(a, b, c) => a.has_aggregate() || [b, c].into_iter().flatten().any(|x| x.has_aggregate()),
            Expr::List(xs) => xs.iter().any(Expr::has_aggregate),
            Expr::Quant { list, pred, .. } => list.has_aggregate() || pred.has_aggregate(),
            Expr::ListComp { list, pred, map, .. } => list.has_aggregate() || [pred, map].into_iter().flatten().any(|x| x.has_aggregate()),
            Expr::Case { subject, whens, default } => {
                [subject, default].into_iter().flatten().any(|x| x.has_aggregate())
                    || whens.iter().any(|(a, b)| a.has_aggregate() || b.has_aggregate())
            }
        }
    }
}

pub fn is_aggregate(name: &str) -> bool {
    matches!(name, "count" | "collect" | "min" | "max" | "sum" | "avg" | "stdev" | "stdevp")
}

#[derive(Debug, Clone)]
pub struct ProjItem {
    pub expr: Expr,
    pub alias: Option<String>,
    /// Source text of the expression (default column name).
    pub text: String,
}

#[derive(Debug, Clone)]
pub struct SortItem {
    pub expr: Expr,
    pub desc: bool,
    pub text: String,
}

#[derive(Debug, Clone, Default)]
pub struct Projection {
    pub distinct: bool,
    /// `*`: every named variable in scope (before `items`).
    pub star: bool,
    pub items: Vec<ProjItem>,
    pub order: Vec<SortItem>,
    pub skip: Option<usize>,
    pub limit: Option<usize>,
    /// `WITH … WHERE`.
    pub filter: Option<Expr>,
}

#[derive(Debug, Clone)]
pub enum Clause {
    Match { optional: bool, patterns: Vec<Pattern>, filter: Option<Expr> },
    Unwind { expr: Expr, var: String },
    With(Projection),
    Return(Projection),
}

/// One `… RETURN …` query; several are joined with `UNION`.
#[derive(Debug, Clone)]
pub struct SingleQuery {
    pub clauses: Vec<Clause>,
}

impl SingleQuery {
    pub fn ret(&self) -> &Projection {
        match self.clauses.last() {
            Some(Clause::Return(p)) => p,
            _ => unreachable!("parser guarantees a final RETURN"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Query {
    pub parts: Vec<SingleQuery>,
    /// `UNION ALL` (keep duplicates) vs `UNION`.
    pub union_all: bool,
}

impl Query {
    /// LIMIT of the final RETURN (first part for UNIONs).
    pub fn limit(&self) -> Option<usize> {
        self.parts[0].ret().limit
    }
}
