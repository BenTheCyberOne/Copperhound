//! CHQL lexer and recursive-descent parser.

use crate::ast::*;
use crate::QueryError;
use ch_model::{flags, NodeKind};

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    /// A keyword-looking identifier written with backticks: never a keyword.
    Quoted(String),
    Str(String),
    Int(i64),
    Float(f64),
    LParen,
    RParen,
    LBracket,
    RBracket,
    LBrace,
    RBrace,
    Colon,
    Comma,
    Dot,
    DotDot,
    Pipe,
    Star,
    Minus,
    Plus,
    Slash,
    Percent,
    Caret,
    Dollar,
    Semicolon,
    Arrow,     // ->
    BackArrow, // <-
    Eq,
    RegexEq, // =~
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Eof,
}

/// Maximum nesting depth of expressions / patterns (stack safety).
const MAX_DEPTH: usize = 200;
/// Maximum query text length.
pub const MAX_QUERY_LEN: usize = 256 * 1024;

struct Lexer<'a> {
    src: &'a str,
    b: &'a [u8],
    i: usize,
}

type Spanned = (Tok, usize, usize);

impl<'a> Lexer<'a> {
    fn tokens(src: &'a str) -> Result<Vec<Spanned>, QueryError> {
        let mut lx = Lexer { src, b: src.as_bytes(), i: 0 };
        let mut out = Vec::new();
        loop {
            lx.skip_ws()?;
            let start = lx.i;
            let t = lx.next()?;
            let eof = t == Tok::Eof;
            out.push((t, start, lx.i));
            if eof {
                return Ok(out);
            }
        }
    }

    fn skip_ws(&mut self) -> Result<(), QueryError> {
        loop {
            while self.i < self.b.len() && self.b[self.i].is_ascii_whitespace() {
                self.i += 1;
            }
            if self.b[self.i..].starts_with(b"//") {
                while self.i < self.b.len() && self.b[self.i] != b'\n' {
                    self.i += 1;
                }
            } else if self.b[self.i..].starts_with(b"/*") {
                let start = self.i;
                match self.src[self.i + 2..].find("*/") {
                    Some(e) => self.i += 2 + e + 2,
                    None => return Err(QueryError::at("unterminated /* comment", start)),
                }
            } else {
                return Ok(());
            }
        }
    }

    fn peek(&self, k: usize) -> u8 {
        self.b.get(self.i + k).copied().unwrap_or(0)
    }

    fn next(&mut self) -> Result<Tok, QueryError> {
        let c = self.peek(0);
        let start = self.i;
        let two = |s: &mut Self, t: Tok| {
            s.i += 2;
            Ok(t)
        };
        let one = |s: &mut Self, t: Tok| {
            s.i += 1;
            Ok(t)
        };
        match c {
            0 if self.i >= self.b.len() => Ok(Tok::Eof),
            b'(' => one(self, Tok::LParen),
            b')' => one(self, Tok::RParen),
            b'[' => one(self, Tok::LBracket),
            b']' => one(self, Tok::RBracket),
            b'{' => one(self, Tok::LBrace),
            b'}' => one(self, Tok::RBrace),
            b':' => one(self, Tok::Colon),
            b',' => one(self, Tok::Comma),
            b'|' => one(self, Tok::Pipe),
            b'*' => one(self, Tok::Star),
            b'+' => one(self, Tok::Plus),
            b'/' => one(self, Tok::Slash),
            b'%' => one(self, Tok::Percent),
            b'^' => one(self, Tok::Caret),
            b'$' => one(self, Tok::Dollar),
            b';' => one(self, Tok::Semicolon),
            b'=' if self.peek(1) == b'~' => two(self, Tok::RegexEq),
            b'=' => one(self, Tok::Eq),
            b'.' if self.peek(1) == b'.' => two(self, Tok::DotDot),
            b'.' if self.peek(1).is_ascii_digit() => self.number(),
            b'.' => one(self, Tok::Dot),
            b'-' if self.peek(1) == b'>' => two(self, Tok::Arrow),
            b'-' => one(self, Tok::Minus),
            b'<' if self.peek(1) == b'-' => two(self, Tok::BackArrow),
            b'<' if self.peek(1) == b'>' => two(self, Tok::Ne),
            b'<' if self.peek(1) == b'=' => two(self, Tok::Le),
            b'<' => one(self, Tok::Lt),
            b'>' if self.peek(1) == b'=' => two(self, Tok::Ge),
            b'>' => one(self, Tok::Gt),
            b'!' if self.peek(1) == b'=' => two(self, Tok::Ne),
            b'\'' | b'"' => self.string(c),
            b'`' => {
                // `quoted identifier`
                let end = self.src[start + 1..]
                    .find('`')
                    .ok_or_else(|| QueryError::at("unterminated `identifier`", start))?;
                self.i = start + 1 + end + 1;
                Ok(Tok::Quoted(self.src[start + 1..start + 1 + end].to_string()))
            }
            c if c.is_ascii_digit() => self.number(),
            c if c.is_ascii_alphabetic() || c == b'_' => {
                while self.peek(0).is_ascii_alphanumeric() || self.peek(0) == b'_' {
                    self.i += 1;
                }
                Ok(Tok::Ident(self.src[start..self.i].to_string()))
            }
            _ => Err(QueryError::at(
                format!("unexpected character '{}'", self.src[start..].chars().next().unwrap_or('?')),
                start,
            )),
        }
    }

    fn string(&mut self, quote: u8) -> Result<Tok, QueryError> {
        let start = self.i;
        self.i += 1;
        let mut s = String::new();
        loop {
            if self.i >= self.b.len() {
                return Err(QueryError::at("unterminated string", start));
            }
            let c = self.peek(0);
            match c {
                b'\\' => {
                    let e = self.peek(1);
                    let regexy = matches!(
                        e,
                        b'.' | b'd' | b'w' | b's' | b'b' | b'(' | b')' | b'[' | b']' | b'{' | b'}' | b'*' | b'+' | b'?' | b'|' | b'^' | b'$' | b'-' | b'D' | b'W' | b'S' | b'B'
                    );
                    if regexy {
                        // Regex escapes such as `\.` or `\d` pass through.
                        s.push('\\');
                        s.push(e as char);
                        self.i += 2;
                        continue;
                    }
                    s.push(match e {
                        b'n' => '\n',
                        b't' => '\t',
                        b'r' => '\r',
                        b'\\' => '\\',
                        b'\'' => '\'',
                        b'"' => '"',
                        b'`' => '`',
                        _ => return Err(QueryError::at("invalid escape", self.i)),
                    });
                    self.i += 2;
                }
                c if c == quote => {
                    self.i += 1;
                    return Ok(Tok::Str(s));
                }
                _ => {
                    let ch = self.src[self.i..].chars().next().unwrap_or('?');
                    s.push(ch);
                    self.i += ch.len_utf8();
                }
            }
        }
    }

    fn number(&mut self) -> Result<Tok, QueryError> {
        let start = self.i;
        while self.peek(0).is_ascii_digit() {
            self.i += 1;
        }
        let mut float = false;
        // `1..3` is a range, not a float.
        if self.peek(0) == b'.' && self.peek(1).is_ascii_digit() {
            float = true;
            self.i += 1;
            while self.peek(0).is_ascii_digit() {
                self.i += 1;
            }
        }
        if matches!(self.peek(0), b'e' | b'E')
            && (self.peek(1).is_ascii_digit() || (matches!(self.peek(1), b'-' | b'+') && self.peek(2).is_ascii_digit()))
        {
            float = true;
            self.i += 2;
            while self.peek(0).is_ascii_digit() {
                self.i += 1;
            }
        }
        let text = &self.src[start..self.i];
        if float {
            text.parse().map(Tok::Float).map_err(|_| QueryError::at("invalid number", start))
        } else {
            text.parse().map(Tok::Int).map_err(|_| QueryError::at("invalid number (integer overflow?)", start))
        }
    }
}

pub struct Parser<'s> {
    src: &'s str,
    toks: Vec<Spanned>,
    p: usize,
    depth: usize,
    /// Custom node kinds of the target graph (labels resolve to `Raw`).
    custom: &'s [String],
    /// Accept unknown labels (syntax check without a graph).
    lenient: bool,
}

pub fn parse(src: &str) -> Result<Query, QueryError> {
    parse_opts(src, &[], false)
}

/// Parse against a graph's custom node kinds (`MATCH (n:GHUser)`).
pub fn parse_with_kinds(src: &str, custom: &[String]) -> Result<Query, QueryError> {
    parse_opts(src, custom, false)
}

/// Syntax check that accepts labels not known yet (custom kinds of graphs
/// loaded later); the result must not be executed.
pub fn parse_syntax(src: &str) -> Result<Query, QueryError> {
    parse_opts(src, &[], true)
}

fn parse_opts(src: &str, custom: &[String], lenient: bool) -> Result<Query, QueryError> {
    if src.len() > MAX_QUERY_LEN {
        return Err(QueryError::at(format!("query text exceeds {MAX_QUERY_LEN} bytes"), 0));
    }
    let mut p = Parser { src, toks: Lexer::tokens(src)?, p: 0, depth: 0, custom, lenient };
    let q = p.query()?;
    while p.peek() == &Tok::Semicolon {
        p.bump();
    }
    if p.peek() != &Tok::Eof {
        return Err(p.err("unexpected input after query (expected end of query or UNION)"));
    }
    Ok(q)
}

const WRITE_CLAUSES: &[&str] = &["CREATE", "MERGE", "SET", "DELETE", "DETACH", "REMOVE", "FOREACH", "LOAD"];

fn label_pred(l: &str, custom: &[String]) -> Option<LabelPred> {
    if let Some(i) = custom.iter().position(|c| c.eq_ignore_ascii_case(l)) {
        return Some(LabelPred::Raw(ch_model::CUSTOM_KIND_BASE + i as u8));
    }
    let lower = l.to_ascii_lowercase();
    Some(match lower.as_str() {
        "base" => LabelPred::Any(Some(false)),
        "azbase" => LabelPred::Any(Some(true)),
        "unknown" => LabelPred::Kind(NodeKind::Unknown),
        "tag_tier_zero" | "tag_tierzero" | "tierzero" => LabelPred::Flag(flags::TIER0),
        "tag_owned" | "owned" => LabelPred::Flag(flags::OWNED),
        _ => match NodeKind::parse(l) {
            NodeKind::Unknown => return None,
            k => LabelPred::Kind(k),
        },
    })
}

impl<'s> Parser<'s> {
    fn peek(&self) -> &Tok {
        &self.toks[self.p].0
    }
    fn peek_at(&self, k: usize) -> &Tok {
        &self.toks[(self.p + k).min(self.toks.len() - 1)].0
    }
    fn pos(&self) -> usize {
        self.toks[self.p].1
    }
    /// End offset of the previously consumed token.
    fn prev_end(&self) -> usize {
        if self.p == 0 {
            0
        } else {
            self.toks[self.p - 1].2
        }
    }
    fn bump(&mut self) -> Tok {
        let t = self.toks[self.p].0.clone();
        if self.p < self.toks.len() - 1 {
            self.p += 1;
        }
        t
    }
    fn err(&self, msg: impl Into<String>) -> QueryError {
        let found = match self.peek() {
            Tok::Eof => "end of query".to_string(),
            _ => {
                let (_, s, e) = &self.toks[self.p];
                format!("'{}'", &self.src[*s..*e])
            }
        };
        QueryError::at(format!("{}, found {found}", msg.into()), self.pos())
    }
    fn expect(&mut self, t: Tok, what: &str) -> Result<(), QueryError> {
        if self.peek() == &t {
            self.bump();
            Ok(())
        } else {
            Err(self.err(format!("expected {what}")))
        }
    }
    fn is_kw(&self, kw: &str) -> bool {
        matches!(self.peek(), Tok::Ident(s) if s.eq_ignore_ascii_case(kw))
    }
    fn is_kw_at(&self, k: usize, kw: &str) -> bool {
        matches!(self.peek_at(k), Tok::Ident(s) if s.eq_ignore_ascii_case(kw))
    }
    fn eat_kw(&mut self, kw: &str) -> bool {
        if self.is_kw(kw) {
            self.bump();
            true
        } else {
            false
        }
    }
    fn expect_kw(&mut self, kw: &str) -> Result<(), QueryError> {
        if self.eat_kw(kw) {
            Ok(())
        } else {
            Err(self.err(format!("expected {kw}")))
        }
    }
    fn is_ident(&self) -> bool {
        matches!(self.peek(), Tok::Ident(_) | Tok::Quoted(_))
    }
    fn ident(&mut self, what: &str) -> Result<String, QueryError> {
        match self.peek().clone() {
            Tok::Ident(s) | Tok::Quoted(s) => {
                self.bump();
                Ok(s)
            }
            _ => Err(self.err(format!("expected {what}"))),
        }
    }
    fn enter(&mut self) -> Result<(), QueryError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(self.err("query is nested too deeply"));
        }
        Ok(())
    }
    fn leave(&mut self) {
        self.depth -= 1;
    }

    // ------------------------------------------------------------ clauses

    fn query(&mut self) -> Result<Query, QueryError> {
        let mut parts = vec![self.single_query()?];
        let mut union_all = None;
        while self.is_kw("UNION") {
            let pos = self.pos();
            self.bump();
            let all = self.eat_kw("ALL");
            if union_all.is_some_and(|a| a != all) {
                return Err(QueryError::at("cannot mix UNION and UNION ALL", pos));
            }
            union_all = Some(all);
            parts.push(self.single_query()?);
        }
        let cols = |q: &SingleQuery| -> Option<Vec<String>> {
            let r = q.ret();
            if r.star {
                return None;
            }
            Some(r.items.iter().map(|i| i.alias.clone().unwrap_or_else(|| i.text.clone())).collect())
        };
        let first = cols(&parts[0]);
        for q in &parts[1..] {
            if cols(q) != first {
                return Err(QueryError::at("all UNION parts must return the same column names (use AS aliases)", 0));
            }
        }
        Ok(Query { parts, union_all: union_all.unwrap_or(false) })
    }

    fn single_query(&mut self) -> Result<SingleQuery, QueryError> {
        let mut clauses = Vec::new();
        loop {
            let pos = self.pos();
            if self.is_kw("MATCH") || (self.is_kw("OPTIONAL") && self.is_kw_at(1, "MATCH")) {
                let optional = self.eat_kw("OPTIONAL");
                self.bump();
                let mut patterns = vec![self.pattern()?];
                while self.peek() == &Tok::Comma {
                    self.bump();
                    patterns.push(self.pattern()?);
                }
                let filter = if self.eat_kw("WHERE") { Some(self.expr()?) } else { None };
                clauses.push(Clause::Match { optional, patterns, filter });
            } else if self.eat_kw("UNWIND") {
                let expr = self.expr()?;
                self.expect_kw("AS")?;
                let var = self.ident("variable after AS")?;
                clauses.push(Clause::Unwind { expr, var });
            } else if self.eat_kw("WITH") {
                let mut p = self.projection()?;
                if self.eat_kw("WHERE") {
                    p.filter = Some(self.expr()?);
                    // Cypher puts WHERE before ORDER BY/SKIP/LIMIT is not valid,
                    // but accept a trailing ORDER BY/SKIP/LIMIT after WHERE too.
                    if p.order.is_empty() && p.skip.is_none() && p.limit.is_none() {
                        self.order_skip_limit(&mut p)?;
                    }
                }
                clauses.push(Clause::With(p));
            } else if self.eat_kw("RETURN") {
                let p = self.projection()?;
                clauses.push(Clause::Return(p));
                return Ok(SingleQuery { clauses });
            } else if self.is_kw("CALL") {
                return Err(QueryError::at("CALL procedures are not supported", pos));
            } else if WRITE_CLAUSES.iter().any(|w| self.is_kw(w)) {
                return Err(QueryError::at("CHQL is read-only: write clauses (CREATE, MERGE, SET, DELETE, REMOVE) are not supported", pos));
            } else if self.is_kw("START") {
                return Err(QueryError::at("legacy START clauses are not supported; use MATCH", pos));
            } else if clauses.is_empty() {
                return Err(self.err("expected MATCH, OPTIONAL MATCH, UNWIND, WITH or RETURN"));
            } else {
                return Err(self.err("expected MATCH, OPTIONAL MATCH, WITH, UNWIND or RETURN"));
            }
        }
    }

    fn projection(&mut self) -> Result<Projection, QueryError> {
        let mut p = Projection { distinct: self.eat_kw("DISTINCT"), ..Default::default() };
        if self.peek() == &Tok::Star {
            self.bump();
            p.star = true;
            if self.peek() == &Tok::Comma {
                self.bump();
            } else {
                self.order_skip_limit(&mut p)?;
                return Ok(p);
            }
        }
        loop {
            let start = self.pos();
            let expr = self.expr()?;
            let text = self.src[start..self.prev_end()].trim().to_string();
            let alias = if self.eat_kw("AS") { Some(self.ident("alias")?) } else { None };
            p.items.push(ProjItem { expr, alias, text });
            if self.peek() == &Tok::Comma {
                self.bump();
            } else {
                break;
            }
        }
        self.order_skip_limit(&mut p)?;
        Ok(p)
    }

    fn order_skip_limit(&mut self, p: &mut Projection) -> Result<(), QueryError> {
        if self.is_kw("ORDER") {
            self.bump();
            self.expect_kw("BY")?;
            loop {
                let start = self.pos();
                let expr = self.expr()?;
                let text = self.src[start..self.prev_end()].trim().to_string();
                let desc = if self.eat_kw("DESC") || self.eat_kw("DESCENDING") {
                    true
                } else {
                    let _ = self.eat_kw("ASC") || self.eat_kw("ASCENDING");
                    false
                };
                p.order.push(SortItem { expr, desc, text });
                if self.peek() == &Tok::Comma {
                    self.bump();
                } else {
                    break;
                }
            }
        }
        if self.eat_kw("SKIP") {
            p.skip = Some(self.count_arg("SKIP")?);
        }
        if self.eat_kw("LIMIT") {
            p.limit = Some(self.count_arg("LIMIT")?);
        }
        Ok(())
    }

    fn count_arg(&mut self, what: &str) -> Result<usize, QueryError> {
        match self.peek() {
            Tok::Int(n) if *n >= 0 => {
                let n = *n as usize;
                self.bump();
                Ok(n)
            }
            _ => Err(self.err(format!("expected a non-negative integer after {what}"))),
        }
    }

    // ------------------------------------------------------------ patterns

    fn pattern(&mut self) -> Result<Pattern, QueryError> {
        let pos = self.pos();
        let path_var = if self.is_ident() && self.peek_at(1) == &Tok::Eq {
            let v = self.ident("path variable")?;
            self.bump(); // =
            Some(v)
        } else {
            None
        };
        let func = if self.is_kw("shortestPath") {
            PathFn::Shortest
        } else if self.is_kw("allShortestPaths") {
            PathFn::AllShortest
        } else {
            PathFn::None
        };
        let (nodes, rels) = if func != PathFn::None {
            self.bump();
            self.expect(Tok::LParen, "'(' after path function")?;
            let c = self.chain()?;
            self.expect(Tok::RParen, "')' closing path function")?;
            if c.1.len() != 1 {
                return Err(QueryError::at("shortestPath/allShortestPaths need exactly one relationship: (a)-[*]->(b)", pos));
            }
            c
        } else {
            self.chain()?
        };
        Ok(Pattern { path_var, func, nodes, rels, pos })
    }

    fn chain(&mut self) -> Result<(Vec<NodePat>, Vec<RelPat>), QueryError> {
        let mut nodes = vec![self.node()?];
        let mut rels = Vec::new();
        while matches!(self.peek(), Tok::Minus | Tok::BackArrow) {
            rels.push(self.rel()?);
            nodes.push(self.node()?);
        }
        Ok((nodes, rels))
    }

    fn node(&mut self) -> Result<NodePat, QueryError> {
        let pos = self.pos();
        self.expect(Tok::LParen, "'(' starting a node pattern")?;
        let mut n = NodePat { pos, ..Default::default() };
        if self.is_ident() {
            n.var = Some(self.ident("variable")?);
        }
        if self.peek() == &Tok::Colon {
            n.labels = self.labels()?;
        }
        if self.peek() == &Tok::LBrace {
            n.props = self.prop_map()?;
        }
        self.expect(Tok::RParen, "')' closing a node pattern")?;
        Ok(n)
    }

    /// `:A|B:C` (leading colon included).
    fn labels(&mut self) -> Result<Labels, QueryError> {
        let mut all = Vec::new();
        while self.peek() == &Tok::Colon {
            self.bump();
            let mut any = Vec::new();
            loop {
                let pos = self.pos();
                let l = self.ident("label")?;
                let pred = match label_pred(&l, self.custom) {
                    Some(p) => p,
                    // Matches nothing; only used for syntax checks.
                    None if self.lenient => LabelPred::Raw(u8::MAX),
                    None => return Err(QueryError::at(format!("unknown label '{l}'"), pos)),
                };
                any.push(pred);
                if self.peek() == &Tok::Pipe {
                    self.bump();
                    if self.peek() == &Tok::Colon {
                        self.bump();
                    }
                } else {
                    break;
                }
            }
            all.push(any);
        }
        Ok(all)
    }

    fn prop_map(&mut self) -> Result<Vec<(String, Expr)>, QueryError> {
        self.expect(Tok::LBrace, "'{'")?;
        let mut out = Vec::new();
        if self.peek() != &Tok::RBrace {
            loop {
                let k = self.ident("property name")?;
                self.expect(Tok::Colon, "':' after property name")?;
                out.push((k, self.expr()?));
                if self.peek() == &Tok::Comma {
                    self.bump();
                } else {
                    break;
                }
            }
        }
        self.expect(Tok::RBrace, "'}'")?;
        Ok(out)
    }

    fn rel(&mut self) -> Result<RelPat, QueryError> {
        let pos = self.pos();
        let incoming = match self.bump() {
            Tok::BackArrow => true,
            Tok::Minus => false,
            _ => unreachable!("caller checked"),
        };
        let mut r = RelPat { var: None, kinds: Vec::new(), dir: Dir::Out, var_len: None, pos };
        if self.peek() == &Tok::LBracket {
            self.bump();
            if self.is_ident() {
                r.var = Some(self.ident("variable")?);
            }
            if self.peek() == &Tok::Colon {
                self.bump();
                loop {
                    r.kinds.push(self.ident("relationship type")?);
                    if self.peek() == &Tok::Pipe {
                        self.bump();
                        if self.peek() == &Tok::Colon {
                            self.bump();
                        }
                    } else {
                        break;
                    }
                }
            }
            if self.peek() == &Tok::Star {
                self.bump();
                let mut min = 1u32;
                let mut max = None;
                let num = |t: &Tok| match t {
                    Tok::Int(n) if *n >= 0 && *n <= u32::MAX as i64 => Some(*n as u32),
                    _ => None,
                };
                if let Some(n) = num(self.peek()) {
                    self.bump();
                    min = n;
                    max = Some(n);
                }
                if self.peek() == &Tok::DotDot {
                    self.bump();
                    max = None;
                    if let Some(n) = num(self.peek()) {
                        self.bump();
                        max = Some(n);
                    }
                }
                if max.is_some_and(|m| m < min) {
                    return Err(self.err("variable-length upper bound is below the lower bound"));
                }
                r.var_len = Some((min, max));
            }
            if self.peek() == &Tok::LBrace {
                return Err(self.err("relationship property maps are not supported (relationships carry no properties)"));
            }
            self.expect(Tok::RBracket, "']'")?;
        }
        match (incoming, self.peek()) {
            (false, Tok::Arrow) => r.dir = Dir::Out,
            (true, Tok::Minus) => r.dir = Dir::In,
            (false, Tok::Minus) => r.dir = Dir::Both,
            (true, Tok::Arrow) => return Err(self.err("bidirectional '<-[]->' relationships are not supported; use '-[]-' for either direction")),
            _ => return Err(self.err("expected '->' or '-' to close the relationship")),
        }
        self.bump();
        Ok(r)
    }

    // ------------------------------------------------------------ expressions

    pub(crate) fn expr(&mut self) -> Result<Expr, QueryError> {
        self.enter()?;
        let r = self.or_expr();
        self.leave();
        r
    }

    /// Every node the loop below adds nests the tree one level deeper:
    /// counted against MAX_DEPTH, restored when the chain ends.
    fn or_expr(&mut self) -> Result<Expr, QueryError> {
        let d = self.depth;
        let r = self.or_expr_chain();
        self.depth = d;
        r
    }

    fn or_expr_chain(&mut self) -> Result<Expr, QueryError> {
        let mut e = self.xor_expr()?;
        while self.eat_kw("OR") {
            self.enter()?;
            e = Expr::Or(Box::new(e), Box::new(self.xor_expr()?));
        }
        Ok(e)
    }

    fn xor_expr(&mut self) -> Result<Expr, QueryError> {
        let d = self.depth;
        let r = self.xor_expr_chain();
        self.depth = d;
        r
    }

    fn xor_expr_chain(&mut self) -> Result<Expr, QueryError> {
        let mut e = self.and_expr()?;
        while self.eat_kw("XOR") {
            self.enter()?;
            e = Expr::Xor(Box::new(e), Box::new(self.and_expr()?));
        }
        Ok(e)
    }

    fn and_expr(&mut self) -> Result<Expr, QueryError> {
        let d = self.depth;
        let r = self.and_expr_chain();
        self.depth = d;
        r
    }

    fn and_expr_chain(&mut self) -> Result<Expr, QueryError> {
        let mut e = self.not_expr()?;
        while self.eat_kw("AND") {
            self.enter()?;
            e = Expr::And(Box::new(e), Box::new(self.not_expr()?));
        }
        Ok(e)
    }

    fn not_expr(&mut self) -> Result<Expr, QueryError> {
        if self.eat_kw("NOT") {
            self.enter()?;
            let e = self.not_expr();
            self.leave();
            return Ok(Expr::Not(Box::new(e?)));
        }
        self.cmp_expr()
    }

    fn cmp_expr(&mut self) -> Result<Expr, QueryError> {
        let d = self.depth;
        let r = self.cmp_expr_chain();
        self.depth = d;
        r
    }

    fn cmp_expr_chain(&mut self) -> Result<Expr, QueryError> {
        let mut e = self.add_expr()?;
        loop {
            let op = match self.peek() {
                Tok::Eq => Some(CmpOp::Eq),
                Tok::Ne => Some(CmpOp::Ne),
                Tok::Lt => Some(CmpOp::Lt),
                Tok::Le => Some(CmpOp::Le),
                Tok::Gt => Some(CmpOp::Gt),
                Tok::Ge => Some(CmpOp::Ge),
                Tok::RegexEq => Some(CmpOp::Regex),
                _ => None,
            };
            if let Some(op) = op {
                self.bump();
                self.enter()?;
                e = Expr::Cmp(Box::new(e), op, Box::new(self.add_expr()?));
                continue;
            }
            if self.is_kw("STARTS") && self.is_kw_at(1, "WITH") {
                self.bump();
                self.bump();
                self.enter()?;
                e = Expr::Cmp(Box::new(e), CmpOp::StartsWith, Box::new(self.add_expr()?));
            } else if self.is_kw("ENDS") && self.is_kw_at(1, "WITH") {
                self.bump();
                self.bump();
                self.enter()?;
                e = Expr::Cmp(Box::new(e), CmpOp::EndsWith, Box::new(self.add_expr()?));
            } else if self.eat_kw("CONTAINS") {
                self.enter()?;
                e = Expr::Cmp(Box::new(e), CmpOp::Contains, Box::new(self.add_expr()?));
            } else if self.eat_kw("IN") {
                self.enter()?;
                e = Expr::Cmp(Box::new(e), CmpOp::In, Box::new(self.add_expr()?));
            } else if self.is_kw("IS") {
                self.bump();
                let not = self.eat_kw("NOT");
                self.expect_kw("NULL")?;
                self.enter()?;
                e = Expr::IsNull(Box::new(e), !not);
            } else {
                return Ok(e);
            }
        }
    }

    fn add_expr(&mut self) -> Result<Expr, QueryError> {
        let d = self.depth;
        let r = self.add_expr_chain();
        self.depth = d;
        r
    }

    fn add_expr_chain(&mut self) -> Result<Expr, QueryError> {
        let mut e = self.mul_expr()?;
        loop {
            let op = match self.peek() {
                Tok::Plus => ArOp::Add,
                Tok::Minus => ArOp::Sub,
                _ => return Ok(e),
            };
            self.bump();
            self.enter()?;
            e = Expr::Arith(Box::new(e), op, Box::new(self.mul_expr()?));
        }
    }

    fn mul_expr(&mut self) -> Result<Expr, QueryError> {
        let d = self.depth;
        let r = self.mul_expr_chain();
        self.depth = d;
        r
    }

    fn mul_expr_chain(&mut self) -> Result<Expr, QueryError> {
        let mut e = self.pow_expr()?;
        loop {
            let op = match self.peek() {
                Tok::Star => ArOp::Mul,
                Tok::Slash => ArOp::Div,
                Tok::Percent => ArOp::Mod,
                _ => return Ok(e),
            };
            self.bump();
            self.enter()?;
            e = Expr::Arith(Box::new(e), op, Box::new(self.pow_expr()?));
        }
    }

    fn pow_expr(&mut self) -> Result<Expr, QueryError> {
        let d = self.depth;
        let r = self.pow_expr_chain();
        self.depth = d;
        r
    }

    fn pow_expr_chain(&mut self) -> Result<Expr, QueryError> {
        let mut e = self.unary_expr()?;
        while self.peek() == &Tok::Caret {
            self.bump();
            self.enter()?;
            e = Expr::Arith(Box::new(e), ArOp::Pow, Box::new(self.unary_expr()?));
        }
        Ok(e)
    }

    fn unary_expr(&mut self) -> Result<Expr, QueryError> {
        match self.peek() {
            Tok::Minus => {
                self.bump();
                self.enter()?;
                let e = self.unary_expr();
                self.leave();
                Ok(match e? {
                    Expr::Lit(Lit::Int(i)) => Expr::Lit(Lit::Int(-i)),
                    Expr::Lit(Lit::Float(f)) => Expr::Lit(Lit::Float(-f)),
                    e => Expr::Neg(Box::new(e)),
                })
            }
            Tok::Plus => {
                self.bump();
                self.enter()?;
                let e = self.unary_expr();
                self.leave();
                e
            }
            _ => self.postfix_expr(),
        }
    }

    fn postfix_expr(&mut self) -> Result<Expr, QueryError> {
        let d = self.depth;
        let r = self.postfix_expr_chain();
        self.depth = d;
        r
    }

    fn postfix_expr_chain(&mut self) -> Result<Expr, QueryError> {
        let mut e = self.atom()?;
        loop {
            match self.peek() {
                Tok::Dot => {
                    self.bump();
                    let key = self.ident("property name")?;
                    self.enter()?;
                    e = Expr::Prop(Box::new(e), key);
                }
                Tok::LBracket => {
                    self.bump();
                    if self.peek() == &Tok::DotDot {
                        self.bump();
                        let hi = if self.peek() == &Tok::RBracket { None } else { Some(Box::new(self.expr()?)) };
                        self.expect(Tok::RBracket, "']'")?;
                        self.enter()?;
                        e = Expr::Slice(Box::new(e), None, hi);
                        continue;
                    }
                    let i = self.expr()?;
                    if self.peek() == &Tok::DotDot {
                        self.bump();
                        let hi = if self.peek() == &Tok::RBracket { None } else { Some(Box::new(self.expr()?)) };
                        self.expect(Tok::RBracket, "']'")?;
                        self.enter()?;
                        e = Expr::Slice(Box::new(e), Some(Box::new(i)), hi);
                    } else {
                        self.expect(Tok::RBracket, "']'")?;
                        self.enter()?;
                        e = Expr::Index(Box::new(e), Box::new(i));
                    }
                }
                Tok::Colon if matches!(e, Expr::Var(..)) => {
                    let labels = self.labels()?;
                    self.enter()?;
                    e = Expr::HasLabel(Box::new(e), labels);
                }
                _ => return Ok(e),
            }
        }
    }

    fn atom(&mut self) -> Result<Expr, QueryError> {
        let pos = self.pos();
        match self.peek().clone() {
            Tok::Str(s) => {
                self.bump();
                Ok(Expr::Lit(Lit::Str(s)))
            }
            Tok::Int(i) => {
                self.bump();
                Ok(Expr::Lit(Lit::Int(i)))
            }
            Tok::Float(f) => {
                self.bump();
                Ok(Expr::Lit(Lit::Float(f)))
            }
            Tok::Dollar => Err(QueryError::at("query parameters ($name) are not supported; inline the value", pos)),
            Tok::LBrace => Err(QueryError::at("map literals are not supported", pos)),
            Tok::LBracket => {
                self.bump();
                // List comprehension: [x IN list WHERE pred | expr]
                if self.is_ident() && self.is_kw_at(1, "IN") {
                    let var = self.ident("variable")?;
                    self.bump(); // IN
                    let list = self.expr()?;
                    let pred = if self.eat_kw("WHERE") { Some(Box::new(self.expr()?)) } else { None };
                    let map = if self.peek() == &Tok::Pipe {
                        self.bump();
                        Some(Box::new(self.expr()?))
                    } else {
                        None
                    };
                    self.expect(Tok::RBracket, "']' closing the list comprehension")?;
                    return Ok(Expr::ListComp { var, list: Box::new(list), pred, map });
                }
                let mut v = Vec::new();
                if self.peek() != &Tok::RBracket {
                    loop {
                        v.push(self.expr()?);
                        if self.peek() == &Tok::Comma {
                            self.bump();
                        } else {
                            break;
                        }
                    }
                }
                self.expect(Tok::RBracket, "']' closing the list")?;
                Ok(Expr::List(v))
            }
            Tok::LParen => {
                // Pattern predicate `(a)-[..]->(b)` or a parenthesised expression.
                let save = self.p;
                let depth = self.depth;
                if let Ok((nodes, rels)) = self.chain() {
                    if !rels.is_empty() {
                        return Ok(Expr::Pattern(Box::new(Pattern { path_var: None, func: PathFn::None, nodes, rels, pos })));
                    }
                }
                self.p = save;
                self.depth = depth;
                self.bump();
                let e = self.expr()?;
                self.expect(Tok::RParen, "')'")?;
                Ok(e)
            }
            Tok::Quoted(s) => {
                self.bump();
                Ok(Expr::Var(s, pos))
            }
            Tok::Ident(s) => {
                let lower = s.to_ascii_lowercase();
                match lower.as_str() {
                    "true" => {
                        self.bump();
                        return Ok(Expr::Lit(Lit::Bool(true)));
                    }
                    "false" => {
                        self.bump();
                        return Ok(Expr::Lit(Lit::Bool(false)));
                    }
                    "null" => {
                        self.bump();
                        return Ok(Expr::Lit(Lit::Null));
                    }
                    "case" => return self.case_expr(),
                    _ => {}
                }
                if self.peek_at(1) != &Tok::LParen {
                    self.bump();
                    return Ok(Expr::Var(s, pos));
                }
                // Function call.
                self.bump();
                self.bump(); // (
                if matches!(lower.as_str(), "any" | "all" | "none" | "single") && self.is_ident() && self.is_kw_at(1, "IN") {
                    let q = match lower.as_str() {
                        "any" => Quant::Any,
                        "all" => Quant::All,
                        "none" => Quant::None,
                        _ => Quant::Single,
                    };
                    let var = self.ident("variable")?;
                    self.bump(); // IN
                    let list = self.expr()?;
                    self.expect_kw("WHERE")?;
                    let pred = self.expr()?;
                    self.expect(Tok::RParen, "')'")?;
                    return Ok(Expr::Quant { q, var, list: Box::new(list), pred: Box::new(pred) });
                }
                if lower == "shortestpath" || lower == "allshortestpaths" {
                    return Err(QueryError::at("shortestPath/allShortestPaths are only supported in MATCH patterns", pos));
                }
                let distinct = self.eat_kw("DISTINCT");
                let mut star = false;
                let mut args = Vec::new();
                if self.peek() == &Tok::Star {
                    self.bump();
                    star = true;
                } else if self.peek() != &Tok::RParen {
                    loop {
                        args.push(self.expr()?);
                        if self.peek() == &Tok::Comma {
                            self.bump();
                        } else {
                            break;
                        }
                    }
                }
                self.expect(Tok::RParen, "')' closing the function call")?;
                if star && lower != "count" {
                    return Err(QueryError::at(format!("'*' is only allowed in count(*), not {s}()"), pos));
                }
                Ok(Expr::Call { name: lower, distinct, star, args, pos })
            }
            _ => Err(self.err("expected an expression")),
        }
    }

    fn case_expr(&mut self) -> Result<Expr, QueryError> {
        self.bump(); // CASE
        let subject = if self.is_kw("WHEN") { None } else { Some(Box::new(self.expr()?)) };
        let mut whens = Vec::new();
        while self.eat_kw("WHEN") {
            let w = self.expr()?;
            self.expect_kw("THEN")?;
            whens.push((w, self.expr()?));
        }
        if whens.is_empty() {
            return Err(self.err("expected WHEN"));
        }
        let default = if self.eat_kw("ELSE") { Some(Box::new(self.expr()?)) } else { None };
        self.expect_kw("END")?;
        Ok(Expr::Case { subject, whens, default })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn first_match(q: &Query) -> (&Vec<Pattern>, &Option<Expr>) {
        match &q.parts[0].clauses[0] {
            Clause::Match { patterns, filter, .. } => (patterns, filter),
            _ => panic!("not a match"),
        }
    }

    #[test]
    fn parses_shortest_path() {
        let q = parse(
            "MATCH p = shortestPath((u:User {name:'ALICE@CORP.LOCAL'})-[:MemberOf|AdminTo*1..]->(t {tier0:true})) RETURN p LIMIT 5",
        )
        .unwrap();
        let (pats, _) = first_match(&q);
        assert_eq!(pats[0].func, PathFn::Shortest);
        assert_eq!(pats[0].path_var.as_deref(), Some("p"));
        assert_eq!(pats[0].nodes.len(), 2);
        assert_eq!(pats[0].rels[0].kinds, vec!["MemberOf", "AdminTo"]);
        assert_eq!(pats[0].rels[0].var_len, Some((1, None)));
        assert_eq!(q.limit(), Some(5));
    }

    #[test]
    fn parses_where_and_count() {
        let q = parse(
            "match (c:Computer)<-[r:AdminTo]-(g:Group) where c.name starts with 'WS' and not c.tier0 or g:User return g.name as n, count(c)",
        )
        .unwrap();
        let (pats, filter) = first_match(&q);
        assert_eq!(pats[0].rels[0].dir, Dir::In);
        assert!(matches!(filter, Some(Expr::Or(..))));
        let r = q.parts[0].ret();
        assert_eq!(r.items.len(), 2);
        assert_eq!(r.items[1].text, "count(c)");
        assert!(r.items[1].expr.has_aggregate());
    }

    #[test]
    fn parses_clauses() {
        let q = parse(
            "MATCH (u:User), (c:Computer) OPTIONAL MATCH (u)-[:AdminTo]-(c) WITH u, count(c) AS n WHERE n > 1 \
             RETURN u.name AS name, n ORDER BY n DESC, name SKIP 1 LIMIT 3 UNION ALL MATCH (x) RETURN x.name AS name, 0 AS n",
        )
        .unwrap();
        assert_eq!(q.parts.len(), 2);
        assert!(q.union_all);
        assert_eq!(q.parts[0].clauses.len(), 4);
        let r = q.parts[0].ret();
        assert_eq!(r.order.len(), 2);
        assert!(r.order[0].desc);
        assert_eq!((r.skip, r.limit), (Some(1), Some(3)));
        let q = parse("MATCH (a) WHERE NOT (a)-[:MemberOf*1..]->(:Group {name:'X'}) AND a.name =~ '(?i)adm.*' RETURN a").unwrap();
        let (_, f) = first_match(&q);
        assert!(matches!(f, Some(Expr::And(..))));
        parse("MATCH (n) WHERE any(x IN n.spns WHERE x CONTAINS 'MSSQL') RETURN [y IN n.spns | toLower(y)][0..2], CASE WHEN n.enabled THEN 1 ELSE 0 END").unwrap();
        parse("MATCH (n:User:Base) WHERE n:Tag_Tier_Zero RETURN n").unwrap();
    }

    #[test]
    fn errors_have_positions() {
        let e = parse("MATCH (n:Bogus) RETURN n").unwrap_err();
        assert_eq!(e.position, Some(9));
        let e = parse("MATCH (a)<-[]->(b) RETURN a").unwrap_err();
        assert!(e.message.contains("bidirectional"));
        assert!(parse("MATCH (a)-[]-(b) RETURN a").is_ok());
        assert!(parse("MATCH (n) RETURN n LIMIT -1").is_err());
        assert!(parse("MATCH (n {x: [1, 'a', -2.5, null]}) RETURN n").is_ok());
        let e = parse("MATCH (n) SET n.x = 1 RETURN n").unwrap_err();
        assert!(e.message.contains("read-only"), "{e}");
        assert_eq!(e.position, Some(10));
        let e = parse("MATCH (n) RETURN n.name AS a UNION MATCH (m) RETURN m.name AS b").unwrap_err();
        assert!(e.message.contains("same column"));
        let e = parse("MATCH (n) WHERE n.x = $p RETURN n").unwrap_err();
        assert_eq!(e.position, Some(22));
        let e = parse("MATCH (n) RETURN n,").unwrap_err();
        assert!(e.message.contains("found end of query"), "{e}");
    }
}
