use std::collections::{HashMap, HashSet};

use rustpython_ast::*;

use crate::file_access::{self, AccessKind, FileAccess};

use super::builtins;
use super::PythonAnalysis;

// Modules whose mere import makes the script unanalyzable.
const UNSAFE_IMPORT_MODULES: &[&str] = &[
    "subprocess",
    "ctypes",
    "socket",
    "importlib",
    "shutil",
];

pub(super) struct PythonVisitor {
    cwd: String,
    /// Maps local names to qualified module paths.
    /// e.g. "os" -> "os", "sp" -> "subprocess", "remove" -> "os.remove"
    imports: HashMap<String, String>,
    /// Builtins that have been shadowed by assignment, def, or import.
    shadowed_builtins: HashSet<String>,
    /// Accumulated file accesses.
    accesses: Vec<FileAccess>,
    /// If set, the script is unanalyzable.
    unanalyzable: Option<String>,
}

impl PythonVisitor {
    pub fn new(cwd: &str) -> Self {
        Self {
            cwd: cwd.to_string(),
            imports: HashMap::new(),
            shadowed_builtins: HashSet::new(),
            accesses: Vec::new(),
            unanalyzable: None,
        }
    }

    pub fn into_result(self) -> PythonAnalysis {
        if let Some(reason) = self.unanalyzable {
            PythonAnalysis::Unanalyzable(reason)
        } else {
            PythonAnalysis::Analyzed {
                accesses: self.accesses,
            }
        }
    }

    fn mark_unanalyzable(&mut self, reason: String) {
        if self.unanalyzable.is_none() {
            self.unanalyzable = Some(reason);
        }
    }

    fn is_unanalyzable(&self) -> bool {
        self.unanalyzable.is_some()
    }

    fn add_access(&mut self, path: &str, kind: AccessKind) {
        let resolved = file_access::resolve_path(path, &self.cwd);
        self.accesses.push(FileAccess {
            path: resolved,
            kind,
        });
    }

    /// Resolve a local name to its qualified module path.
    fn resolve_name(&self, name: &str) -> Option<&str> {
        self.imports.get(name).map(|s| s.as_str())
    }

    /// Check if a builtin name is shadowed by user code.
    fn is_builtin_shadowed(&self, name: &str) -> bool {
        self.shadowed_builtins.contains(name)
    }

    /// Record that a name shadows a builtin.
    fn shadow_if_builtin(&mut self, name: &str) {
        if builtins::is_tracked_builtin(name) {
            self.shadowed_builtins.insert(name.to_string());
        }
    }

    // Walk methods =====

    pub fn walk_module(&mut self, module: &ModModule) {
        self.walk_body(&module.body);
    }

    fn walk_body(&mut self, stmts: &[Stmt]) {
        for stmt in stmts {
            if self.is_unanalyzable() {
                return;
            }
            self.walk_stmt(stmt);
        }
    }

    fn walk_stmt(&mut self, stmt: &Stmt) {
        if self.is_unanalyzable() {
            return;
        }
        match stmt {
            Stmt::Import(s) => self.walk_import(s),
            Stmt::ImportFrom(s) => self.walk_import_from(s),
            Stmt::Assign(s) => self.walk_assign(s),
            Stmt::AugAssign(s) => self.walk_aug_assign(s),
            Stmt::AnnAssign(s) => self.walk_ann_assign(s),
            Stmt::Expr(s) => self.walk_expr(&s.value),
            Stmt::FunctionDef(s) => self.walk_function_def(s),
            Stmt::AsyncFunctionDef(s) => self.walk_async_function_def(s),
            Stmt::ClassDef(s) => self.walk_class_def(s),
            Stmt::Return(s) => {
                if let Some(value) = &s.value {
                    self.walk_expr(value);
                }
            }
            Stmt::Delete(s) => {
                for target in &s.targets {
                    self.walk_expr(target);
                }
            }
            Stmt::For(s) => {
                self.check_assignment_target(&s.target);
                self.walk_expr(&s.iter);
                self.walk_body(&s.body);
                self.walk_body(&s.orelse);
            }
            Stmt::AsyncFor(s) => {
                self.check_assignment_target(&s.target);
                self.walk_expr(&s.iter);
                self.walk_body(&s.body);
                self.walk_body(&s.orelse);
            }
            Stmt::While(s) => {
                self.walk_expr(&s.test);
                self.walk_body(&s.body);
                self.walk_body(&s.orelse);
            }
            Stmt::If(s) => {
                self.walk_expr(&s.test);
                self.walk_body(&s.body);
                self.walk_body(&s.orelse);
            }
            Stmt::With(s) => self.walk_with(s),
            Stmt::AsyncWith(s) => {
                for item in &s.items {
                    self.walk_expr(&item.context_expr);
                    if let Some(vars) = &item.optional_vars {
                        self.check_assignment_target(vars);
                    }
                }
                self.walk_body(&s.body);
            }
            Stmt::Raise(s) => {
                if let Some(exc) = &s.exc {
                    self.walk_expr(exc);
                }
                if let Some(cause) = &s.cause {
                    self.walk_expr(cause);
                }
            }
            Stmt::Try(s) => {
                self.walk_body(&s.body);
                for handler in &s.handlers {
                    let ExceptHandler::ExceptHandler(h) = handler;
                    if let Some(name) = &h.name {
                        self.shadow_if_builtin(name.as_str());
                    }
                    self.walk_body(&h.body);
                }
                self.walk_body(&s.orelse);
                self.walk_body(&s.finalbody);
            }
            Stmt::TryStar(s) => {
                self.walk_body(&s.body);
                for handler in &s.handlers {
                    let ExceptHandler::ExceptHandler(h) = handler;
                    if let Some(name) = &h.name {
                        self.shadow_if_builtin(name.as_str());
                    }
                    self.walk_body(&h.body);
                }
                self.walk_body(&s.orelse);
                self.walk_body(&s.finalbody);
            }
            Stmt::Assert(s) => {
                self.walk_expr(&s.test);
                if let Some(msg) = &s.msg {
                    self.walk_expr(msg);
                }
            }
            Stmt::Match(s) => {
                self.walk_expr(&s.subject);
                for case in &s.cases {
                    if let Some(guard) = &case.guard {
                        self.walk_expr(guard);
                    }
                    self.walk_body(&case.body);
                }
            }
            // No expressions to walk in these:
            Stmt::Global(_)
            | Stmt::Nonlocal(_)
            | Stmt::Pass(_)
            | Stmt::Break(_)
            | Stmt::Continue(_)
            | Stmt::TypeAlias(_) => {}
        }
    }

    fn walk_expr(&mut self, expr: &Expr) {
        if self.is_unanalyzable() {
            return;
        }
        match expr {
            Expr::Call(call) => self.walk_call(call),
            Expr::BoolOp(e) => {
                for value in &e.values {
                    self.walk_expr(value);
                }
            }
            Expr::NamedExpr(e) => {
                // walrus operator: target := value
                self.check_assignment_target(&e.target);
                self.walk_expr(&e.value);
            }
            Expr::BinOp(e) => {
                self.walk_expr(&e.left);
                self.walk_expr(&e.right);
            }
            Expr::UnaryOp(e) => self.walk_expr(&e.operand),
            Expr::Lambda(e) => self.walk_expr(&e.body),
            Expr::IfExp(e) => {
                self.walk_expr(&e.test);
                self.walk_expr(&e.body);
                self.walk_expr(&e.orelse);
            }
            Expr::Dict(e) => {
                for key in e.keys.iter().flatten() {
                    self.walk_expr(key);
                }
                for value in &e.values {
                    self.walk_expr(value);
                }
            }
            Expr::Set(e) => {
                for elt in &e.elts {
                    self.walk_expr(elt);
                }
            }
            Expr::ListComp(e) => {
                // Walk generators first so targets shadow builtins before elt is processed
                for comp in &e.generators {
                    self.walk_comprehension(comp);
                }
                self.walk_expr(&e.elt);
            }
            Expr::SetComp(e) => {
                for comp in &e.generators {
                    self.walk_comprehension(comp);
                }
                self.walk_expr(&e.elt);
            }
            Expr::DictComp(e) => {
                for comp in &e.generators {
                    self.walk_comprehension(comp);
                }
                self.walk_expr(&e.key);
                self.walk_expr(&e.value);
            }
            Expr::GeneratorExp(e) => {
                for comp in &e.generators {
                    self.walk_comprehension(comp);
                }
                self.walk_expr(&e.elt);
            }
            Expr::Await(e) => self.walk_expr(&e.value),
            Expr::Yield(e) => {
                if let Some(value) = &e.value {
                    self.walk_expr(value);
                }
            }
            Expr::YieldFrom(e) => self.walk_expr(&e.value),
            Expr::Compare(e) => {
                self.walk_expr(&e.left);
                for comp in &e.comparators {
                    self.walk_expr(comp);
                }
            }
            Expr::FormattedValue(e) => self.walk_expr(&e.value),
            Expr::JoinedStr(e) => {
                for value in &e.values {
                    self.walk_expr(value);
                }
            }
            Expr::Attribute(_) => {} // Attribute access alone is not a side effect
            Expr::Subscript(e) => {
                self.walk_expr(&e.value);
                self.walk_expr(&e.slice);
            }
            Expr::Starred(e) => self.walk_expr(&e.value),
            Expr::List(e) => {
                for elt in &e.elts {
                    self.walk_expr(elt);
                }
            }
            Expr::Tuple(e) => {
                for elt in &e.elts {
                    self.walk_expr(elt);
                }
            }
            Expr::Slice(e) => {
                if let Some(lower) = &e.lower {
                    self.walk_expr(lower);
                }
                if let Some(upper) = &e.upper {
                    self.walk_expr(upper);
                }
                if let Some(step) = &e.step {
                    self.walk_expr(step);
                }
            }
            // Leaf nodes with no sub-expressions:
            Expr::Constant(_) | Expr::Name(_) => {}
        }
    }

    fn walk_comprehension(&mut self, comp: &Comprehension) {
        self.check_assignment_target(&comp.target);
        self.walk_expr(&comp.iter);
        for cond in &comp.ifs {
            self.walk_expr(cond);
        }
    }

    // Import handling =====

    fn walk_import(&mut self, stmt: &StmtImport) {
        for alias in &stmt.names {
            let module_name = alias.name.as_str();

            // Check for unsafe module imports
            let top_level = module_name.split('.').next().unwrap_or(module_name);
            if UNSAFE_IMPORT_MODULES.contains(&top_level) {
                self.mark_unanalyzable(format!("import of unsafe module '{module_name}'"));
                return;
            }

            let local_name = alias
                .asname
                .as_ref()
                .map(|id| id.as_str())
                .unwrap_or(module_name);
            self.imports.insert(local_name.to_string(), module_name.to_string());

            // Check if this shadows a builtin
            self.shadow_if_builtin(local_name);
        }
    }

    fn walk_import_from(&mut self, stmt: &StmtImportFrom) {
        let module_name = stmt.module.as_ref().map(|id| id.as_str()).unwrap_or("");

        // Check for star import
        if stmt.names.iter().any(|a| a.name.as_str() == "*") {
            self.mark_unanalyzable(format!("star import from '{module_name}'"));
            return;
        }

        // Check for unsafe module import
        let top_level = module_name.split('.').next().unwrap_or(module_name);
        if UNSAFE_IMPORT_MODULES.contains(&top_level) {
            self.mark_unanalyzable(format!("import from unsafe module '{module_name}'"));
            return;
        }

        for alias in &stmt.names {
            let imported_name = alias.name.as_str();
            let local_name = alias
                .asname
                .as_ref()
                .map(|id| id.as_str())
                .unwrap_or(imported_name);
            let qualified = if module_name.is_empty() {
                imported_name.to_string()
            } else {
                format!("{module_name}.{imported_name}")
            };
            self.imports.insert(local_name.to_string(), qualified);

            // Check if this shadows a builtin
            self.shadow_if_builtin(local_name);
        }
    }

    // Assignment handling =====

    fn walk_assign(&mut self, stmt: &StmtAssign) {
        for target in &stmt.targets {
            self.check_assignment_target(target);
        }
        self.walk_expr(&stmt.value);
    }

    fn walk_aug_assign(&mut self, stmt: &StmtAugAssign) {
        self.check_assignment_target(&stmt.target);
        self.walk_expr(&stmt.value);
    }

    fn walk_ann_assign(&mut self, stmt: &StmtAnnAssign) {
        self.check_assignment_target(&stmt.target);
        if let Some(value) = &stmt.value {
            self.walk_expr(value);
        }
    }

    /// Check if an assignment target shadows a tracked builtin.
    fn check_assignment_target(&mut self, target: &Expr) {
        if let Expr::Name(name) = target {
            self.shadow_if_builtin(name.id.as_str());
        }
    }

    // Function/class def handling =====

    fn walk_function_def(&mut self, stmt: &StmtFunctionDef) {
        self.shadow_if_builtin(stmt.name.as_str());
        for decorator in &stmt.decorator_list {
            self.walk_expr(decorator);
        }
        self.walk_body(&stmt.body);
    }

    fn walk_async_function_def(&mut self, stmt: &StmtAsyncFunctionDef) {
        self.shadow_if_builtin(stmt.name.as_str());
        for decorator in &stmt.decorator_list {
            self.walk_expr(decorator);
        }
        self.walk_body(&stmt.body);
    }

    fn walk_class_def(&mut self, stmt: &StmtClassDef) {
        for base in &stmt.bases {
            self.walk_expr(base);
        }
        for keyword in &stmt.keywords {
            self.walk_expr(&keyword.value);
        }
        for decorator in &stmt.decorator_list {
            self.walk_expr(decorator);
        }
        self.walk_body(&stmt.body);
    }

    // With statement handling =====

    fn walk_with(&mut self, stmt: &StmtWith) {
        for item in &stmt.items {
            self.walk_expr(&item.context_expr);
            if let Some(vars) = &item.optional_vars {
                self.check_assignment_target(vars);
            }
        }
        self.walk_body(&stmt.body);
    }

    // Call handling =====

    fn walk_call(&mut self, call: &ExprCall) {
        // First, walk all arguments (they may contain nested calls like open())
        for arg in &call.args {
            self.walk_expr(arg);
        }
        for kw in &call.keywords {
            self.walk_expr(&kw.value);
        }

        if self.is_unanalyzable() {
            return;
        }

        // Now analyze the call itself
        match &*call.func {
            // Bare function call: open(...), exec(...), etc.
            Expr::Name(name) => {
                let func_name = name.id.as_str();

                // Check if it's a resolved import (e.g. `from os import system; system(...)`)
                if let Some(qualified) = self.resolve_name(func_name).map(|s| s.to_string()) {
                    self.analyze_qualified_call(&qualified, call);
                    return;
                }

                // Check unsafe builtins
                if builtins::is_unsafe_builtin(func_name) && !self.is_builtin_shadowed(func_name) {
                    self.mark_unanalyzable(format!("call to unsafe builtin '{func_name}'"));
                    return;
                }

                // Check open()
                if func_name == "open" && !self.is_builtin_shadowed("open") {
                    self.analyze_open_call(call);
                }
            }
            // Attribute call: os.remove(...), pathlib.Path(...).read_text(), etc.
            Expr::Attribute(attr) => {
                let method_name = attr.attr.as_str();

                // Resolve the object to a module if possible
                if let Expr::Name(obj_name) = &*attr.value {
                    let obj = obj_name.id.as_str();
                    if let Some(qualified) = self.resolve_name(obj).map(|s| s.to_string()) {
                        let full = format!("{qualified}.{method_name}");
                        self.analyze_qualified_call(&full, call);
                    }
                }
                // Also walk the object expression (might contain calls)
                self.walk_expr(&attr.value);
            }
            // Any other callable expression (subscript, another call, etc.)
            other => {
                self.walk_expr(other);
            }
        }
    }

    /// Analyze a call to a qualified name (e.g. "os.system", "io.open", "builtins.open").
    fn analyze_qualified_call(&mut self, qualified: &str, call: &ExprCall) {
        // Check unsafe qualified calls
        if builtins::is_unsafe_qualified(qualified) {
            self.mark_unanalyzable(format!("call to unsafe function '{qualified}'"));
            return;
        }

        // Check io.open / builtins.open (aliases for builtin open)
        if qualified == "io.open" || qualified == "builtins.open" {
            self.analyze_open_call(call);
        }
    }

    /// Analyze an `open(path, mode)` call and extract file access.
    fn analyze_open_call(&mut self, call: &ExprCall) {
        // Reject *args / **kwargs -- cannot statically determine arguments
        if call.args.iter().any(|a| matches!(a, Expr::Starred(_)))
            || call.keywords.iter().any(|k| k.arg.is_none())
        {
            self.mark_unanalyzable("open() with *args or **kwargs".to_string());
            return;
        }

        // Extract path (first positional arg)
        let path = match call.args.first() {
            Some(expr) => match try_extract_string(expr) {
                Some(s) => s,
                None => {
                    self.mark_unanalyzable("open() with dynamic path".to_string());
                    return;
                }
            },
            None => {
                // open() with no args -- will fail at runtime, but not a file access
                return;
            }
        };

        // Extract mode (second positional arg, or mode= keyword, or default 'r')
        let mode = if let Some(mode_expr) = call.args.get(1) {
            match try_extract_string(mode_expr) {
                Some(s) => s,
                None => {
                    self.mark_unanalyzable("open() with dynamic mode".to_string());
                    return;
                }
            }
        } else if let Some(kw) = call.keywords.iter().find(|k| {
            k.arg.as_ref().is_some_and(|id| id.as_str() == "mode")
        }) {
            match try_extract_string(&kw.value) {
                Some(s) => s,
                None => {
                    self.mark_unanalyzable("open() with dynamic mode".to_string());
                    return;
                }
            }
        } else {
            "r".to_string()
        };

        let kind = builtins::classify_open_mode(&mode);
        self.add_access(&path, kind);
    }
}

/// Try to extract a static string value from an expression.
fn try_extract_string(expr: &Expr) -> Option<String> {
    if let Expr::Constant(c) = expr {
        if let Constant::Str(s) = &c.value {
            return Some(s.clone());
        }
    }
    None
}
