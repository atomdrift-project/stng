//! Pure helper functions run at fold time: a function whose body only
//! computes on its arguments and constants is evaluated, statement by
//! statement, with loops unrolled up to `MAX_LOOP`.

use super::{
    BlockTrace, Env, Flow, Folder, Key, MAX_DEPTH, MAX_LOOP, MAX_TABLE, Value, child, children,
    number, replace_aliases, text, truth,
};
use std::collections::BTreeSet;
use std::rc::Rc;
use tree_sitter::Node;

impl Folder<'_> {
    pub(super) fn helper<'t>(
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
    pub(super) fn pure_block<'t>(
        &mut self,
        n: Node<'t>,
        env: &mut Env<'t>,
        depth: usize,
    ) -> Option<Flow<'t>> {
        self.pure_statements(&children(n), env, depth)
    }
    pub(super) fn scoped<'t>(
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
    /// The branch an `if` or `elseif` takes, run to completion.
    pub(super) fn pure_if<'t>(
        &mut self,
        st: Node<'t>,
        env: &mut Env<'t>,
        depth: usize,
        trace: &mut BlockTrace,
    ) -> Option<Flow<'t>> {
        let condition = self.eval(
            st.child_by_field_name("condition")?,
            env,
            depth + 1,
            true,
            trace,
        );
        if truth(&condition)? {
            return match st.child_by_field_name("consequence") {
                Some(body) => self.scoped(body, env, &[], depth + 1),
                None => Some(Flow::Continue),
            };
        }
        for alt in children(st) {
            match alt.kind() {
                "else_statement" => return self.pure_statements(&[alt], env, depth + 1),
                "elseif_statement" => {
                    let c = self.eval(
                        alt.child_by_field_name("condition")?,
                        env,
                        depth + 1,
                        true,
                        trace,
                    );
                    if truth(&c)? {
                        return self.pure_statements(&[alt], env, depth + 1);
                    }
                }
                _ => {}
            }
        }
        Some(Flow::Continue)
    }
    /// A numeric `for`, or a `for` over `ipairs(t)`, unrolled up to `MAX_LOOP`
    /// iterations.
    pub(super) fn pure_for<'t>(
        &mut self,
        st: Node<'t>,
        env: &mut Env<'t>,
        depth: usize,
        trace: &mut BlockTrace,
    ) -> Option<Flow<'t>> {
        let cl = st.child_by_field_name("clause")?;
        let body = st.child_by_field_name("body")?;
        if cl.kind() == "for_numeric_clause" {
            let start = self.eval(
                cl.child_by_field_name("start")?,
                env,
                depth + 1,
                true,
                trace,
            );
            let end = self.eval(cl.child_by_field_name("end")?, env, depth + 1, true, trace);
            let step = cl
                .child_by_field_name("step")
                .map_or(Value::Number(1.), |n| {
                    self.eval(n, env, depth + 1, true, trace)
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
                match self.scoped(body, env, &[(name.clone(), Value::Number(x))], depth + 1)? {
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
                trace,
            );
            if !matches!(name,Value::Native(ref n) if n=="ipairs") {
                return None;
            }
            let args = children(call.child_by_field_name("arguments")?);
            if args.len() != 1 {
                return None;
            }
            let Value::Table(table) = self.eval(args[0], env, depth + 1, true, trace) else {
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
        Some(Flow::Continue)
    }
    pub(super) fn pure_statements<'t>(
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
                "if_statement" | "elseif_statement" => self.pure_if(st, env, depth, &mut trace)?,
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
                "for_statement" => self.pure_for(st, env, depth, &mut trace)?,
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
}

pub(super) fn pure_shape(n: Node<'_>, params: Option<Node<'_>>, source: &str) -> bool {
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
