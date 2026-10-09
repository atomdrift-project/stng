//! Bounded syntax-only Lua constants. Only data operations are modelled.
//! Unknown calls, mutable captures and unknown branch outcomes are not executed.
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::rc::Rc;
use tree_sitter::Node;

use super::prometheus::{Cipher, Discovery};
use super::whole;
const MAX_STEPS: usize = 8_000_000;
const MAX_DEPTH: usize = 96;
const MAX_BYTES: usize = 1024 * 1024;
const MAX_LOOP: usize = 100_000;
const MAX_TABLE: usize = 10_000;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    Number(i64),
    Bytes(Vec<u8>),
}
#[derive(Clone)]
enum Value<'t> {
    Unknown,
    Nil,
    Number(f64),
    Bytes(Vec<u8>),
    Bool(bool),
    Table(Rc<BTreeMap<Key, Self>>),
    Function(Node<'t>, Rc<Env<'t>>),
    Native(String),
    Affine { symbol: String, mul: f64, add: f64 },
    Decoded(Vec<u8>),
}
type Env<'t> = HashMap<String, Value<'t>>;
#[derive(Default)]
struct BlockTrace {
    seed45: bool,
    seed255: bool,
    bytes: BTreeSet<u8>,
}
pub(super) struct Recovery {
    pub source: String,
    pub discovery: Discovery,
    pub decoded_strings: usize,
    pub decoded_bytes: usize,
    pub printable_bytes: usize,
}
struct Folder<'s> {
    source: &'s str,
    steps: usize,
    edits: BTreeMap<(usize, usize), String>,
    discovery: Discovery,
    cipher: Option<Cipher>,
    decoded_strings: usize,
    decoded_bytes: usize,
    printable_bytes: usize,
    folded_strings: usize,
    exhausted: bool,
}
fn children(n: Node<'_>) -> Vec<Node<'_>> {
    let mut c = n.walk();
    n.named_children(&mut c).collect()
}
fn child<'t>(n: Node<'t>, kind: &str) -> Option<Node<'t>> {
    children(n).into_iter().find(|n| n.kind() == kind)
}
fn text<'s>(n: Node<'_>, s: &'s str) -> &'s str {
    s.get(n.byte_range()).unwrap_or("")
}
fn key(v: &Value<'_>) -> Option<Key> {
    match v {
        Value::Number(n) => whole(*n).map(Key::Number),
        Value::Bytes(b) => Some(Key::Bytes(b.clone())),
        _ => None,
    }
}
fn number(v: &Value<'_>) -> Option<f64> {
    if let Value::Number(n) = v {
        Some(*n)
    } else {
        None
    }
}
enum Flow<'t> {
    Continue,
    Break,
    Return(Value<'t>),
}
fn truth(v: &Value<'_>) -> Option<bool> {
    match v {
        Value::Unknown | Value::Affine { .. } | Value::Decoded(_) => None,
        Value::Nil => Some(false),
        Value::Bool(b) => Some(*b),
        _ => Some(true),
    }
}
fn replace_aliases<'t>(
    env: &mut Env<'t>,
    old: &Rc<BTreeMap<Key, Value<'t>>>,
    new: &Rc<BTreeMap<Key, Value<'t>>>,
) {
    for value in env.values_mut() {
        if matches!(value,Value::Table(t) if Rc::ptr_eq(t,old)) {
            *value = Value::Table(new.clone());
        } else if let Value::Function(_, captured) = value {
            replace_aliases(Rc::make_mut(captured), old, new);
        }
    }
}
fn bounded_data(v: &Value<'_>) -> bool {
    let mut stack = vec![(v, 0)];
    let mut visited = 0;
    while let Some((v, depth)) = stack.pop() {
        visited += 1;
        if depth > MAX_DEPTH || visited > MAX_TABLE {
            return false;
        }
        if let Value::Table(t) = v {
            stack.extend(t.values().map(|v| (v, depth + 1)));
        }
    }
    true
}
fn invalidate_native(env: &mut Env<'_>, library: &str) {
    let prefix = format!("{library}.");
    for value in env.values_mut() {
        if matches!(value,Value::Native(n) if n==library || n.starts_with(&prefix)) {
            *value = Value::Unknown;
        }
    }
}
fn table_id<'t>(t: &Rc<BTreeMap<Key, Value<'t>>>) -> usize {
    Rc::as_ptr(t) as usize
}
fn table_ids<'t>(root: &Rc<BTreeMap<Key, Value<'t>>>) -> BTreeSet<usize> {
    let mut ids = BTreeSet::new();
    let mut pending = vec![root];
    while let Some(t) = pending.pop() {
        if !ids.insert(table_id(t)) {
            continue;
        }
        if ids.len() > MAX_TABLE {
            break;
        }
        pending.extend(t.values().filter_map(|v| {
            if let Value::Table(t) = v {
                Some(t)
            } else {
                None
            }
        }));
    }
    ids
}
fn invalidate_table<'t>(env: &mut Env<'t>, old: &Rc<BTreeMap<Key, Value<'t>>>) {
    let targets = table_ids(old);
    invalidate_tables(env, &targets);
}
fn invalidate_tables(env: &mut Env<'_>, targets: &BTreeSet<usize>) {
    for value in env.values_mut() {
        if let Value::Table(t) = value {
            if !table_ids(t).is_disjoint(targets) {
                *value = Value::Unknown;
            }
        } else if let Value::Function(_, captured) = value {
            invalidate_tables(Rc::make_mut(captured), targets);
        }
    }
}
// Only table captures are supported. Scalar captures can be reassigned across
// scopes; without lexical binding cells those must remain unknown.
fn captures<'t>(function: Node<'t>, env: &Env<'t>, source: &str) -> Rc<Env<'t>> {
    let params: BTreeSet<_> = function
        .child_by_field_name("parameters")
        .map(children)
        .unwrap_or_default()
        .iter()
        .map(|p| text(*p, source).to_owned())
        .collect();
    let mut names = BTreeSet::new();
    let mut stack = vec![function];
    let mut visited = 0;
    while let Some(node) = stack.pop() {
        visited += 1;
        if visited > 100_000 {
            return Rc::new(Env::new());
        }
        if node.kind() == "identifier" && !params.contains(text(node, source)) {
            names.insert(text(node, source).to_owned());
        }
        stack.extend(children(node));
    }
    Rc::new(
        env.iter()
            .filter(|(name, v)| names.contains(*name) && matches!(v, Value::Table(_)))
            .map(|(n, v)| (n.clone(), v.clone()))
            .collect(),
    )
}

fn quote(bytes: &[u8]) -> String {
    let mut s = String::from("\"");
    for b in bytes {
        match b {
            b'"' | b'\\' => {
                s.push('\\');
                s.push(char::from(*b));
            }
            32..=126 => s.push(char::from(*b)),
            _ => s.push_str(&format!("\\{b:03}")),
        }
    }
    s.push('"');
    s
}
fn string(raw: &str) -> Option<Vec<u8>> {
    let b = raw.as_bytes();
    if b.first() == Some(&b'[') {
        let start = raw.find('[')?;
        let rest = &raw[start + 1..];
        let end = rest.find('[')?;
        let eq = &rest[..end];
        if !eq.bytes().all(|c| c == b'=') {
            return None;
        }
        let tail = format!("]{eq}]");
        let body = rest[end + 1..].strip_suffix(&tail)?;
        return Some(body.strip_prefix('\n').unwrap_or(body).as_bytes().to_vec());
    }
    if b.len() < 2 || !matches!(b[0], b'\'' | b'"') || b.last() != Some(&b[0]) {
        return None;
    }
    let mut out = Vec::new();
    let mut i = 1;
    while i < b.len() - 1 {
        if b[i] != b'\\' {
            out.push(b[i]);
            i += 1;
            continue;
        }
        i += 1;
        let c = *b.get(i)?;
        i += 1;
        match c {
            b'0'..=b'9' => {
                let mut n = u16::from(c - b'0');
                for _ in 0..2 {
                    if i < b.len() - 1 && b[i].is_ascii_digit() {
                        n = n * 10 + u16::from(b[i] - b'0');
                        i += 1
                    } else {
                        break;
                    }
                }
                out.push(u8::try_from(n).ok()?);
            }
            b'x' => {
                let end = i.checked_add(2)?;
                out.push(u8::from_str_radix(raw.get(i..end)?, 16).ok()?);
                i = end;
            }
            b'n' | b'\n' => out.push(b'\n'),
            b'r' => out.push(b'\r'),
            b't' => out.push(b'\t'),
            b'a' => out.push(7),
            b'b' => out.push(8),
            b'f' => out.push(12),
            b'v' => out.push(11),
            b'z' => {
                while i < b.len() - 1 && b[i].is_ascii_whitespace() {
                    i += 1
                }
            }
            b'\r' => {
                if b.get(i) == Some(&b'\n') {
                    i += 1
                }
                out.push(b'\n')
            }
            b'\\' | b'"' | b'\'' => out.push(c),
            _ => return None,
        }
    }
    Some(out)
}
impl<'s> Folder<'s> {
    fn budget(&mut self, depth: usize) -> bool {
        self.steps += 1;
        let ok = self.steps <= MAX_STEPS && depth <= MAX_DEPTH;
        self.exhausted |= !ok;
        ok
    }
    fn patch(&mut self, n: Node<'_>, v: &Value<'_>, pure: bool) {
        if pure {
            return;
        }
        let rendered = match v {
            Value::Bytes(b) => {
                self.folded_strings += 1;
                Some(quote(b))
            }
            Value::Number(x) if x.is_finite() && x.abs() < 1e20 => Some(format!("({x})")),
            _ => None,
        };
        if let Some(s) = rendered {
            self.edits.insert((n.start_byte(), n.end_byte()), s);
        }
    }
    fn eval<'t>(
        &mut self,
        n: Node<'t>,
        env: &mut Env<'t>,
        depth: usize,
        pure: bool,
        trace: &mut BlockTrace,
    ) -> Value<'t> {
        if !self.budget(depth) {
            return Value::Unknown;
        }
        let mut v = match n.kind() {
            "number" => text(n, self.source)
                .parse::<f64>()
                .ok()
                .filter(|n| n.is_finite())
                .map_or(Value::Unknown, Value::Number),
            "string" => string(text(n, self.source)).map_or(Value::Unknown, Value::Bytes),
            "nil" => Value::Nil,
            "true" => Value::Bool(true),
            "false" => Value::Bool(false),
            "identifier" => env
                .get(text(n, self.source))
                .filter(|v| pure || !matches!(v, Value::Unknown))
                .cloned()
                .unwrap_or_else(|| {
                    if pure {
                        Value::Unknown
                    } else {
                        Value::Affine {
                            symbol: text(n, self.source).to_string(),
                            mul: 1.,
                            add: 0.,
                        }
                    }
                }),
            "parenthesized_expression" => children(n).first().map_or(Value::Unknown, |c| {
                self.eval(*c, env, depth + 1, pure, trace)
            }),
            "function_definition" => Value::Function(n, captures(n, env, self.source)),
            "table_constructor" => {
                let mut map = BTreeMap::new();
                let mut ix = 1;
                for f in children(n) {
                    let Some(value) = f.child_by_field_name("value") else {
                        continue;
                    };
                    let v = self.eval(value, env, depth + 1, pure, trace);
                    let k = if let Some(name) = f.child_by_field_name("name") {
                        if name.kind() == "identifier" && !text(f, self.source).starts_with('[') {
                            Some(Key::Bytes(text(name, self.source).as_bytes().to_vec()))
                        } else {
                            key(&self.eval(name, env, depth + 1, pure, trace))
                        }
                    } else {
                        let k = Some(Key::Number(ix));
                        ix += 1;
                        k
                    };
                    let Some(k) = k else { return Value::Unknown };
                    if !bounded_data(&v) {
                        return Value::Unknown;
                    }
                    map.insert(k, v);
                    if map.len() > MAX_TABLE {
                        return Value::Unknown;
                    }
                }
                Value::Table(Rc::new(map))
            }
            "dot_index_expression" | "bracket_index_expression" => {
                let Some(base) = n.child_by_field_name("table") else {
                    return Value::Unknown;
                };
                let Some(field) = n.child_by_field_name("field") else {
                    return Value::Unknown;
                };
                let b = self.eval(base, env, depth + 1, pure, trace);
                let f = if n.kind() == "dot_index_expression" {
                    Value::Bytes(text(field, self.source).as_bytes().to_vec())
                } else {
                    self.eval(field, env, depth + 1, pure, trace)
                };
                match (b, f) {
                    (Value::Native(lib), Value::Bytes(k)) => {
                        Value::Native(format!("{lib}.{}", String::from_utf8_lossy(&k)))
                    }
                    (_, Value::Decoded(b)) if !pure => {
                        self.decoded_strings += 1;
                        self.decoded_bytes += b.len();
                        self.printable_bytes += b
                            .iter()
                            .filter(|b| {
                                b.is_ascii_graphic() || matches!(**b, b' ' | b'\r' | b'\n' | b'\t')
                            })
                            .count();
                        self.edits.insert((n.start_byte(), n.end_byte()), quote(&b));
                        Value::Bytes(b)
                    }
                    (Value::Table(t), f) => {
                        key(&f).map_or(Value::Unknown, |k| t.get(&k).cloned().unwrap_or(Value::Nil))
                    }
                    _ if !pure => Value::Affine {
                        symbol: text(n, self.source).to_string(),
                        mul: 1.,
                        add: 0.,
                    },
                    _ => Value::Unknown,
                }
            }
            "unary_expression" => {
                let Some(a) = n.child_by_field_name("operand") else {
                    return Value::Unknown;
                };
                let a = self.eval(a, env, depth + 1, pure, trace);
                match (
                    n.child_by_field_name("operator")
                        .map(|x| text(x, self.source)),
                    a,
                ) {
                    (Some("-"), Value::Number(n)) => Value::Number(-n),
                    (Some("#"), Value::Bytes(b)) => Value::Number(b.len() as f64),
                    (Some("#"), Value::Table(t)) => Value::Number(
                        (1..=t.len())
                            .take_while(|i| t.contains_key(&Key::Number(*i as i64)))
                            .count() as f64,
                    ),
                    (Some("not"), v) => truth(&v).map_or(Value::Unknown, |v| Value::Bool(!v)),
                    _ => Value::Unknown,
                }
            }
            "binary_expression" => {
                let Some(l) = n.child_by_field_name("left") else {
                    return Value::Unknown;
                };
                let Some(r) = n.child_by_field_name("right") else {
                    return Value::Unknown;
                };
                let op = n
                    .child_by_field_name("operator")
                    .map(|n| text(n, self.source))
                    .unwrap_or("");
                let a = self.eval(l, env, depth + 1, pure, trace);
                let b = self.eval(r, env, depth + 1, pure, trace);
                self.binary(op, a, b, trace)
            }
            "function_call" => {
                let Some(name) = n.child_by_field_name("name") else {
                    return Value::Unknown;
                };
                let Some(args) = n.child_by_field_name("arguments") else {
                    return Value::Unknown;
                };
                let fnv = self.eval(name, env, depth + 1, pure, trace);
                let args: Vec<_> = children(args)
                    .into_iter()
                    .map(|a| self.eval(a, env, depth + 1, pure, trace))
                    .collect();
                match fnv {
                    Value::Function(f, captured) => {
                        let result = self.helper(f, &args, &captured, depth + 1);
                        if matches!(result, Value::Unknown) {
                            for v in captured.values().chain(args.iter()) {
                                if let Value::Table(t) = v {
                                    invalidate_table(env, t);
                                }
                            }
                        }
                        result
                    }
                    Value::Native(name) => self.native(&name, &args),
                    _ => {
                        // An unknown call can mutate any table it receives.
                        for a in &args {
                            if let Value::Table(t) = a {
                                invalidate_table(env, t);
                            }
                            if let Value::Native(lib) = a
                                && matches!(lib.as_str(), "math" | "string" | "table")
                            {
                                invalidate_native(env, lib);
                            }
                        }
                        if !pure
                            && args.len() == 2
                            && let (Value::Bytes(cipher), Value::Number(seed)) =
                                (&args[0], &args[1])
                            && seed.fract() == 0.
                            && *seed >= 0.
                            && *seed < super::prometheus::MOD45
                            && let Some(parameters) = self.cipher
                        {
                            Value::Decoded(parameters.decrypt(cipher, *seed))
                        } else {
                            Value::Unknown
                        }
                    }
                }
            }
            _ => Value::Unknown,
        };
        if let Value::Number(x) = v
            && (!x.is_finite() || x.abs() > 1e20)
        {
            v = Value::Unknown
        }
        if matches!(
            n.kind(),
            "binary_expression" | "unary_expression" | "function_call" | "identifier"
        ) {
            self.patch(n, &v, pure)
        }
        v
    }
    fn binary<'t>(
        &mut self,
        op: &str,
        a: Value<'t>,
        b: Value<'t>,
        trace: &mut BlockTrace,
    ) -> Value<'t> {
        self.discovery.operation(
            op,
            number(&a),
            number(&b),
            matches!(&b, Value::Affine { .. }),
        );
        if let (Value::Bytes(a), Value::Bytes(b)) = (&a, &b) {
            return match op {
                ".." if a.len() + b.len() <= MAX_BYTES => {
                    Value::Bytes([a.as_slice(), b.as_slice()].concat())
                }
                "==" => Value::Bool(a == b),
                "~=" => Value::Bool(a != b),
                _ => Value::Unknown,
            };
        }
        if let (Value::Number(a), Value::Number(b)) = (&a, &b) {
            return match op {
                "+" => Value::Number(a + b),
                "-" => Value::Number(a - b),
                "*" => Value::Number(a * b),
                "/" if *b != 0. => Value::Number(a / b),
                "%" if *b != 0. => Value::Number(a - (a / b).floor() * b),
                "^" if b.abs() < 64. => Value::Number(a.powf(*b)),
                "<" => Value::Bool(a < b),
                "<=" => Value::Bool(a <= b),
                ">" => Value::Bool(a > b),
                ">=" => Value::Bool(a >= b),
                "==" => Value::Bool(a == b),
                "~=" => Value::Bool(a != b),
                _ => Value::Unknown,
            };
        }
        if (op == "and" || op == "or")
            && let Some(t) = truth(&a)
        {
            return if (op == "and" && t) || (op == "or" && !t) {
                b
            } else {
                a
            };
        }
        if matches!(a, Value::Nil) || matches!(b, Value::Nil) {
            if matches!(a, Value::Unknown | Value::Affine { .. })
                || matches!(b, Value::Unknown | Value::Affine { .. })
            {
                return Value::Unknown;
            }
            return match op {
                "==" => Value::Bool(matches!(a, Value::Nil) && matches!(b, Value::Nil)),
                "~=" => Value::Bool(!(matches!(a, Value::Nil) && matches!(b, Value::Nil))),
                _ => Value::Unknown,
            };
        }
        if let (Value::Bool(a), Value::Bool(b)) = (&a, &b) {
            return match op {
                "and" => Value::Bool(*a && *b),
                "or" => Value::Bool(*a || *b),
                _ => Value::Unknown,
            };
        }
        let affine = |v: &Value<'t>| match v {
            Value::Number(n) => Some((String::new(), 0., *n)),
            Value::Affine { symbol, mul, add } => Some((symbol.clone(), *mul, *add)),
            _ => None,
        };
        let (Some((sa, ma, aa)), Some((sb, mb, ab))) = (affine(&a), affine(&b)) else {
            return Value::Unknown;
        };
        let sym = if sa.is_empty() {
            sb.clone()
        } else {
            sa.clone()
        };
        if !sa.is_empty() && !sb.is_empty() && sa != sb {
            return Value::Unknown;
        }
        if op == "%" && mb == 0. {
            if ab == super::prometheus::MOD45 {
                if ma == 1. && aa == 0. {
                    trace.seed45 = true
                } else {
                    self.discovery.lcg45(ma, aa)
                }
            }
            if ab == 255. && ma == 1. && aa == 0. {
                trace.seed255 = true
            }
            if ab == 257. && aa == 0. {
                self.discovery.lcg8(ma)
            }
            return Value::Unknown;
        }
        let (mul, add) = match op {
            "+" => (ma + mb, aa + ab),
            "-" => (ma - mb, aa - ab),
            "*" if ma == 0. => (aa * mb, aa * ab),
            "*" if mb == 0. => (ab * ma, ab * aa),
            _ => return Value::Unknown,
        };
        Value::Affine {
            symbol: sym,
            mul,
            add,
        }
    }
    fn native<'t>(&self, name: &str, a: &[Value<'t>]) -> Value<'t> {
        match (name, a) {
            ("math.floor", [Value::Number(n)]) => Value::Number(n.floor()),
            ("string.len", [Value::Bytes(b)]) => Value::Number(b.len() as f64),
            ("string.char", _) => {
                let mut b = Vec::new();
                for v in a {
                    let Some(byte) = number(v).and_then(whole).and_then(|n| u8::try_from(n).ok())
                    else {
                        return Value::Unknown;
                    };
                    b.push(byte)
                }
                Value::Bytes(b)
            }
            ("string.sub", [Value::Bytes(b), Value::Number(start), Value::Number(end)]) => {
                // Negative indices count from the end; both ends clamp to
                // 1..=len+1. Non-integer indices are not folded.
                let len = b.len() as f64;
                let norm = |x: f64| {
                    let x = if x < 0. { len + x + 1. } else { x };
                    whole(x.clamp(1., len + 1.)).and_then(|n| usize::try_from(n).ok())
                };
                let (Some(l), Some(r)) = (norm(*start), norm(*end)) else {
                    return Value::Unknown;
                };
                Value::Bytes(b.get(l - 1..r.min(b.len())).unwrap_or_default().to_vec())
            }
            ("type", [Value::Bytes(_)]) => Value::Bytes(b"string".to_vec()),
            ("type", [Value::Table(_)]) => Value::Bytes(b"table".to_vec()),
            ("type", [Value::Number(_)]) => Value::Bytes(b"number".to_vec()),
            ("type", [Value::Nil]) => Value::Bytes(b"nil".to_vec()),
            ("table.concat", [Value::Table(t)]) => {
                let mut out = Vec::new();
                for v in t.values() {
                    let Value::Bytes(b) = v else {
                        return Value::Unknown;
                    };
                    if out.len() + b.len() > MAX_BYTES {
                        return Value::Unknown;
                    }
                    out.extend_from_slice(b)
                }
                Value::Bytes(out)
            }
            _ => Value::Unknown,
        }
    }
    fn helper<'t>(
        &mut self,
        f: Node<'t>,
        args: &[Value<'t>],
        outer: &Env<'t>,
        depth: usize,
    ) -> Value<'t> {
        if depth > MAX_DEPTH {
            return Value::Unknown;
        }
        let Some(body) = f.child_by_field_name("body") else {
            return Value::Unknown;
        };
        // No calls, closures, conditionals or mutation through captured tables.
        // This recognises literal permutation/join and array lookup helpers.
        if !pure_shape(body, f.child_by_field_name("parameters"), self.source) {
            return Value::Unknown;
        }
        let mut env = outer.clone();
        let Some(params) = f.child_by_field_name("parameters") else {
            return Value::Unknown;
        };
        for (i, p) in children(params).into_iter().enumerate() {
            env.insert(
                text(p, self.source).to_string(),
                args.get(i).cloned().unwrap_or(Value::Nil),
            );
        }
        match self.pure_block(body, &mut env, depth) {
            Some(Flow::Return(v)) => v,
            _ => Value::Unknown,
        }
    }
    fn assign<'t>(
        &mut self,
        n: Node<'t>,
        env: &mut Env<'t>,
        depth: usize,
        pure: bool,
        trace: &mut BlockTrace,
    ) -> bool {
        let Some(vars) = child(n, "variable_list") else {
            return false;
        };
        let values = child(n, "expression_list")
            .map(children)
            .unwrap_or_default();
        let vals: Vec<_> = values
            .iter()
            .map(|n| self.eval(*n, env, depth + 1, pure, trace))
            .collect();
        for (i, v) in children(vars).iter().enumerate() {
            let value = vals.get(i).cloned().unwrap_or(Value::Nil);
            if pure
                && matches!(
                    value,
                    Value::Unknown | Value::Affine { .. } | Value::Decoded(_)
                )
            {
                return false;
            }
            if let Value::Number(n) = value
                && let Some(byte) = whole(n).and_then(|n| u8::try_from(n).ok())
                && (3..255).contains(&byte)
            {
                trace.bytes.insert(byte);
            }
            match v.kind() {
                "identifier" => {
                    let name = text(*v, self.source);
                    if let Some(Value::Table(old)) = env.get(name).cloned() {
                        for binding in env.values_mut() {
                            if let Value::Function(_, captured) = binding {
                                for v in Rc::make_mut(captured).values_mut() {
                                    if matches!(v,Value::Table(t) if Rc::ptr_eq(t,&old)) {
                                        *v = Value::Unknown;
                                    }
                                }
                            }
                        }
                    }
                    env.insert(name.to_string(), value);
                }
                "dot_index_expression" | "bracket_index_expression" => {
                    let Some(base) = v.child_by_field_name("table") else {
                        return false;
                    };
                    if base.kind() != "identifier" {
                        return false;
                    }
                    if let Some(Value::Native(lib)) = env.get(text(base, self.source)).cloned() {
                        invalidate_native(env, &lib);
                        return false;
                    }
                    let Some(ix) = v.child_by_field_name("field") else {
                        return false;
                    };
                    let ix = if v.kind() == "dot_index_expression" {
                        Value::Bytes(text(ix, self.source).as_bytes().to_vec())
                    } else {
                        self.eval(ix, env, depth + 1, pure, trace)
                    };
                    let Some(k) = key(&ix) else {
                        return false;
                    };
                    if !bounded_data(&value) {
                        return false;
                    }
                    let Some(Value::Table(t)) = env.get(text(base, self.source)).cloned() else {
                        return false;
                    };
                    if t.len() >= MAX_TABLE && !t.contains_key(&k) {
                        return false;
                    }
                    let mut updated = (*t).clone();
                    if matches!(value, Value::Nil) {
                        updated.remove(&k);
                    } else {
                        updated.insert(k, value);
                    }
                    replace_aliases(env, &t, &Rc::new(updated));
                }
                _ => return false,
            }
        }
        true
    }
    fn pure_block<'t>(&mut self, n: Node<'t>, env: &mut Env<'t>, depth: usize) -> Option<Flow<'t>> {
        self.pure_statements(&children(n), env, depth)
    }
    fn scoped<'t>(
        &mut self,
        body: Node<'t>,
        env: &mut Env<'t>,
        bindings: &[(String, Value<'t>)],
        depth: usize,
    ) -> Option<Flow<'t>> {
        let mut local = env.clone();
        let mut hidden: BTreeSet<_> = bindings.iter().map(|(n, _)| n.clone()).collect();
        for st in children(body) {
            if st.kind() == "variable_declaration" {
                let vars = child(st, "assignment_statement")
                    .and_then(|a| child(a, "variable_list"))
                    .or_else(|| child(st, "variable_list"));
                for v in vars.map(children).unwrap_or_default() {
                    hidden.insert(text(v, self.source).to_owned());
                }
            }
        }
        for (name, value) in bindings {
            local.insert(name.clone(), value.clone());
        }
        let flow = self.pure_block(body, &mut local, depth + 1)?;
        // Carry table mutations through aliases even when the loop iterator
        // shadows one alias. Branch snapshots retain their own old Rc values.
        let before = env.clone();
        for (name, old) in &before {
            if hidden.contains(name) {
                continue;
            }
            if let (Value::Table(old), Some(Value::Table(new))) = (old, local.get(name)) {
                replace_aliases(env, old, new);
            }
        }
        for name in before.keys() {
            if !hidden.contains(name)
                && let Some(v) = local.get(name)
            {
                env.insert(name.clone(), v.clone());
            }
        }
        Some(flow)
    }
    fn pure_statements<'t>(
        &mut self,
        statements: &[Node<'t>],
        env: &mut Env<'t>,
        depth: usize,
    ) -> Option<Flow<'t>> {
        let mut trace = BlockTrace::default();
        for &st in statements {
            if !self.budget(depth) {
                return None;
            }
            let flow = match st.kind() {
                "comment" | "empty_statement" => Flow::Continue,
                "variable_declaration" => {
                    if let Some(a) = child(st, "assignment_statement") {
                        if !self.assign(a, env, depth + 1, true, &mut trace) {
                            return None;
                        }
                    } else {
                        for v in child(st, "variable_list").map(children).unwrap_or_default() {
                            env.insert(text(v, self.source).to_owned(), Value::Nil);
                        }
                    }
                    Flow::Continue
                }
                "assignment_statement" => {
                    if !self.assign(st, env, depth + 1, true, &mut trace) {
                        return None;
                    }
                    Flow::Continue
                }
                "return_statement" => {
                    let v = child(st, "expression_list")
                        .and_then(|e| children(e).first().copied())
                        .map_or(Value::Nil, |e| {
                            self.eval(e, env, depth + 1, true, &mut trace)
                        });
                    if matches!(v, Value::Unknown) {
                        return None;
                    }
                    Flow::Return(v)
                }
                "break_statement" => Flow::Break,
                "do_statement" | "else_statement" => {
                    self.scoped(st.child_by_field_name("body")?, env, &[], depth + 1)?
                }
                "if_statement" | "elseif_statement" => {
                    let condition = self.eval(
                        st.child_by_field_name("condition")?,
                        env,
                        depth + 1,
                        true,
                        &mut trace,
                    );
                    if truth(&condition)? {
                        if let Some(body) = st.child_by_field_name("consequence") {
                            self.scoped(body, env, &[], depth + 1)?
                        } else {
                            Flow::Continue
                        }
                    } else {
                        let alts: Vec<_> = children(st)
                            .into_iter()
                            .filter(|n| matches!(n.kind(), "elseif_statement" | "else_statement"))
                            .collect();
                        let mut chosen = Flow::Continue;
                        for alt in alts {
                            if alt.kind() == "else_statement" {
                                chosen = self.pure_statements(&[alt], env, depth + 1)?;
                                break;
                            }
                            let c = self.eval(
                                alt.child_by_field_name("condition")?,
                                env,
                                depth + 1,
                                true,
                                &mut trace,
                            );
                            if truth(&c)? {
                                chosen = self.pure_statements(&[alt], env, depth + 1)?;
                                break;
                            }
                        }
                        chosen
                    }
                }
                "while_statement" => {
                    let mut count = 0;
                    loop {
                        let c = self.eval(
                            st.child_by_field_name("condition")?,
                            env,
                            depth + 1,
                            true,
                            &mut trace,
                        );
                        if !truth(&c)? {
                            break;
                        }
                        count += 1;
                        if count > MAX_LOOP {
                            return None;
                        }
                        match self.scoped(st.child_by_field_name("body")?, env, &[], depth + 1)? {
                            Flow::Continue => (),
                            Flow::Break => break,
                            f => return Some(f),
                        }
                    }
                    Flow::Continue
                }
                "for_statement" => {
                    let cl = st.child_by_field_name("clause")?;
                    let body = st.child_by_field_name("body")?;
                    if cl.kind() == "for_numeric_clause" {
                        let start = self.eval(
                            cl.child_by_field_name("start")?,
                            env,
                            depth + 1,
                            true,
                            &mut trace,
                        );
                        let end = self.eval(
                            cl.child_by_field_name("end")?,
                            env,
                            depth + 1,
                            true,
                            &mut trace,
                        );
                        let step = cl
                            .child_by_field_name("step")
                            .map_or(Value::Number(1.), |n| {
                                self.eval(n, env, depth + 1, true, &mut trace)
                            });
                        let (mut x, end, step) = (number(&start)?, number(&end)?, number(&step)?);
                        if step == 0. || (end - x).abs() / step.abs() > MAX_LOOP as f64 {
                            return None;
                        }
                        let name = text(cl.child_by_field_name("name")?, self.source).to_owned();
                        let mut count = 0;
                        while if step > 0. { x <= end } else { x >= end } {
                            count += 1;
                            if count > MAX_LOOP {
                                return None;
                            }
                            match self.scoped(
                                body,
                                env,
                                &[(name.clone(), Value::Number(x))],
                                depth + 1,
                            )? {
                                Flow::Continue => (),
                                Flow::Break => break,
                                f => return Some(f),
                            }
                            x += step;
                        }
                    } else {
                        let expr = child(cl, "expression_list")?;
                        let args = children(expr);
                        if args.len() != 1 || args[0].kind() != "function_call" {
                            return None;
                        }
                        let call = args[0];
                        let name = self.eval(
                            call.child_by_field_name("name")?,
                            env,
                            depth + 1,
                            true,
                            &mut trace,
                        );
                        if !matches!(name,Value::Native(ref n) if n=="ipairs") {
                            return None;
                        }
                        let args = children(call.child_by_field_name("arguments")?);
                        if args.len() != 1 {
                            return None;
                        }
                        let Value::Table(table) =
                            self.eval(args[0], env, depth + 1, true, &mut trace)
                        else {
                            return None;
                        };
                        let names: Vec<_> = children(child(cl, "variable_list")?)
                            .iter()
                            .map(|n| text(*n, self.source).to_owned())
                            .collect();
                        if names.is_empty() || names.len() > 2 {
                            return None;
                        }
                        for i in 1..=MAX_LOOP {
                            let Some(value) = table.get(&Key::Number(i as i64)) else {
                                break;
                            };
                            let mut bindings = vec![(names[0].clone(), Value::Number(i as f64))];
                            if names.len() == 2 {
                                bindings.push((names[1].clone(), value.clone()));
                            }
                            match self.scoped(body, env, &bindings, depth + 1)? {
                                Flow::Continue => (),
                                Flow::Break => break,
                                f => return Some(f),
                            }
                        }
                    }
                    Flow::Continue
                }
                "function_call" => {
                    let name = self.eval(
                        st.child_by_field_name("name")?,
                        env,
                        depth + 1,
                        true,
                        &mut trace,
                    );
                    if !matches!(name,Value::Native(ref n) if n=="table.insert") {
                        return None;
                    }
                    let args: Vec<_> = children(st.child_by_field_name("arguments")?)
                        .iter()
                        .map(|n| self.eval(*n, env, depth + 1, true, &mut trace))
                        .collect();
                    let [Value::Table(table), value] = args.as_slice() else {
                        return None;
                    };
                    if matches!(value, Value::Unknown) || table.len() >= MAX_TABLE {
                        return None;
                    }
                    let mut updated = (**table).clone();
                    let index =
                        (1..=MAX_TABLE).find(|i| !updated.contains_key(&Key::Number(*i as i64)))?;
                    updated.insert(Key::Number(index as i64), value.clone());
                    replace_aliases(env, table, &Rc::new(updated));
                    Flow::Continue
                }
                _ => {
                    return None;
                }
            };
            if !matches!(flow, Flow::Continue) {
                return Some(flow);
            }
        }
        Some(Flow::Continue)
    }
    fn walk<'t>(&mut self, n: Node<'t>, env: &mut Env<'t>, depth: usize) {
        if !self.budget(depth) {
            return;
        }
        match n.kind() {
            "return_statement" => {
                let mut trace = BlockTrace::default();
                if let Some(expressions) = child(n, "expression_list") {
                    for expression in children(expressions) {
                        self.eval(expression, env, depth + 1, false, &mut trace);
                    }
                }
            }
            "chunk" | "block" => {
                let mut trace = BlockTrace::default();
                for st in children(n) {
                    if st.kind() == "variable_declaration" {
                        if let Some(a) = child(st, "assignment_statement") {
                            self.assign(a, env, depth + 1, false, &mut trace);
                        } else if let Some(f) = child(st, "function_declaration") {
                            self.walk(f, env, depth + 1);
                        } else {
                            for v in child(st, "variable_list").map(children).unwrap_or_default() {
                                env.insert(text(v, self.source).to_string(), Value::Unknown);
                            }
                        }
                    } else if st.kind() == "assignment_statement" {
                        self.assign(st, env, depth + 1, false, &mut trace);
                    } else {
                        self.walk(st, env, depth + 1)
                    }
                    // Function bodies are inspected independently, never called.
                    for c in descendants_shallow_functions(st) {
                        let mut local = env.clone();
                        if let Some(params) = c.child_by_field_name("parameters") {
                            for p in children(params) {
                                local.remove(text(p, self.source));
                            }
                        }
                        if let Some(body) = c.child_by_field_name("body") {
                            self.walk(body, &mut local, depth + 1)
                        }
                    }
                }
                if trace.seed45
                    && trace.seed255
                    && trace.bytes.len() == 1
                    && let Some(key) = trace.bytes.first()
                {
                    self.discovery.key(*key)
                }
            }
            "function_definition" | "function_declaration" => {
                let mut local = env.clone();
                if let Some(p) = n.child_by_field_name("parameters") {
                    for p in children(p) {
                        local.remove(text(p, self.source));
                    }
                }
                if let Some(body) = n.child_by_field_name("body") {
                    self.walk(body, &mut local, depth + 1)
                }
                if n.kind() == "function_declaration"
                    && let Some(name) = n.child_by_field_name("name")
                {
                    env.insert(
                        text(name, self.source).to_string(),
                        Value::Function(n, captures(n, env, self.source)),
                    );
                }
            }
            "if_statement" | "elseif_statement" | "else_statement" | "while_statement"
            | "for_statement" | "do_statement" => {
                let mut candidate = env.clone();
                if self
                    .pure_statements(&[n], &mut candidate, depth + 1)
                    .is_some()
                {
                    *env = candidate;
                    return;
                }
                let mut written = BTreeSet::new();
                assigned_names(n, self.source, &mut written, 0);
                for name in written {
                    if let Some(Value::Table(table)) = env.get(&name).cloned() {
                        invalidate_table(env, &table);
                    }
                    env.insert(name, Value::Unknown);
                }
                for c in children(n) {
                    let mut local = env.clone();
                    self.walk(c, &mut local, depth + 1)
                } // Do not carry branch-dependent values beyond the branch.
            }
            _ => {
                let mut trace = BlockTrace::default();
                self.eval(n, env, depth + 1, false, &mut trace);
                for c in children(n) {
                    if matches!(
                        c.kind(),
                        "block" | "function_definition" | "function_declaration"
                    ) {
                        self.walk(c, env, depth + 1)
                    }
                }
            }
        }
    }
}
fn pure_shape(n: Node<'_>, params: Option<Node<'_>>, source: &str) -> bool {
    let mut locals: BTreeSet<String> = params
        .map(children)
        .unwrap_or_default()
        .iter()
        .map(|n| text(*n, source).to_owned())
        .collect();
    let mut declarations = vec![n];
    let mut visited = 0;
    while let Some(node) = declarations.pop() {
        visited += 1;
        if visited > 2000 {
            return false;
        }
        if node.kind() == "variable_declaration" {
            let vars = child(node, "assignment_statement")
                .and_then(|a| child(a, "variable_list"))
                .or_else(|| child(node, "variable_list"));
            locals.extend(
                vars.map(children)
                    .unwrap_or_default()
                    .iter()
                    .map(|v| text(*v, source).to_owned()),
            );
        }
        if node.kind() == "for_numeric_clause"
            && let Some(v) = node.child_by_field_name("name")
        {
            locals.insert(text(v, source).to_owned());
        }
        declarations.extend(children(node));
        if declarations.len() > 2000 {
            return false;
        }
    }
    let mut stack = vec![n];
    let mut count = 0;
    while let Some(n) = stack.pop() {
        count += 1;
        if count > 2000 {
            return false;
        }
        if matches!(
            n.kind(),
            "function_call"
                | "function_definition"
                | "function_declaration"
                | "if_statement"
                | "while_statement"
                | "do_statement"
                | "goto_statement"
        ) {
            return false;
        }
        if n.kind() == "assignment_statement"
            && let Some(vars) = child(n, "variable_list")
            && children(vars)
                .iter()
                .any(|n| n.kind() != "identifier" || !locals.contains(text(*n, source)))
        {
            return false;
        }
        stack.extend(children(n));
    }
    true
}
fn descendants_shallow_functions(n: Node<'_>) -> Vec<Node<'_>> {
    let mut out = Vec::new();
    let mut stack = children(n);
    while let Some(n) = stack.pop() {
        if matches!(n.kind(), "function_definition" | "function_declaration") {
            out.push(n)
        } else {
            stack.extend(children(n));
        }
    }
    out
}
fn assigned_names(n: Node<'_>, source: &str, out: &mut BTreeSet<String>, depth: usize) {
    if depth > MAX_DEPTH {
        return;
    }
    if matches!(n.kind(), "function_definition" | "function_declaration") {
        return;
    }
    if n.kind() == "assignment_statement"
        && let Some(v) = child(n, "variable_list")
    {
        for v in children(v) {
            if v.kind() == "identifier" {
                out.insert(text(v, source).to_string());
            } else if matches!(
                v.kind(),
                "bracket_index_expression" | "dot_index_expression"
            ) && let Some(base) = v.child_by_field_name("table")
                && base.kind() == "identifier"
            {
                out.insert(text(base, source).to_owned());
            }
        }
    }
    for c in children(n) {
        assigned_names(c, source, out, depth + 1)
    }
}
pub(super) fn recover(tree: &tree_sitter::Tree, source: &str, cipher: Option<Cipher>) -> Recovery {
    let mut f = Folder {
        source,
        steps: 0,
        edits: BTreeMap::new(),
        discovery: Discovery::default(),
        cipher,
        decoded_strings: 0,
        decoded_bytes: 0,
        printable_bytes: 0,
        folded_strings: 0,
        exhausted: false,
    };
    let mut env = Env::new();
    for name in ["math", "string", "table", "type", "ipairs"] {
        env.insert(name.to_string(), Value::Native(name.to_string()));
    }
    f.walk(tree.root_node(), &mut env, 0);
    let mut result = String::with_capacity(source.len());
    let mut offset = 0;
    let mut edits: Vec<_> = f.edits.iter().collect();
    edits.sort_unstable_by_key(|((start, end), _)| (*start, std::cmp::Reverse(*end)));
    for ((start, end), replacement) in edits {
        if *start < offset {
            continue;
        }
        result.push_str(&source[offset..*start]);
        result.push_str(replacement);
        offset = *end;
        if result.len() > MAX_BYTES {
            f.exhausted = true;
            break;
        }
    }
    result.push_str(&source[offset..]);
    if result.len() > MAX_BYTES || f.exhausted {
        return Recovery {
            source: source.to_owned(),
            discovery: Discovery::default(),
            decoded_strings: 0,
            decoded_bytes: 0,
            printable_bytes: 0,
        };
    }
    Recovery {
        source: result,
        discovery: f.discovery,
        decoded_strings: f.decoded_strings,
        decoded_bytes: f.decoded_bytes,
        printable_bytes: f.printable_bytes,
    }
}
