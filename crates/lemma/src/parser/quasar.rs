use crate::{
    parser::Parser,
    types::{AccountDecl, ArithmeticOp, CpiCall, InstructionHandler},
};

pub struct QuasarParser;

impl Parser for QuasarParser {
    fn parse(&self, source: &str, source_path: &str) -> Vec<InstructionHandler> {
        let accounts_map = extract_accounts_structs(source);
        extract_handlers(source, source_path, &accounts_map)
    }
}

type AccountsMap = std::collections::HashMap<String, Vec<AccountDecl>>;

fn extract_accounts_structs(source: &str) -> AccountsMap {
    let mut map = AccountsMap::new();
    let lines: Vec<&str> = source.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let trimmed = lines[i].trim();
        if trimmed.contains("derive") && trimmed.contains("Accounts") {
            if let Some(name) = find_struct_name(&lines, i + 1) {
                let accounts = extract_struct_fields(&lines, i + 1);
                map.insert(name, accounts);
            }
        }
        i += 1;
    }
    map
}

fn find_struct_name(lines: &[&str], start: usize) -> Option<String> {
    for line in lines.iter().skip(start).take(5) {
        let t = line.trim();
        let rest = t
            .strip_prefix("pub struct ")
            .or_else(|| t.strip_prefix("struct "))?;
        let name = rest
            .split(['<', '{', ' '])
            .next()?
            .trim()
            .to_string();
        if !name.is_empty() {
            return Some(name);
        }
    }
    None
}

fn extract_struct_fields(lines: &[&str], start: usize) -> Vec<AccountDecl> {
    let mut accounts = Vec::new();
    let body_start = lines
        .iter()
        .skip(start)
        .position(|l| l.contains('{'))
        .map(|p| start + p)
        .unwrap_or(start);

    let mut depth = 0i32;
    let mut in_body = false;
    let mut pending: Option<String> = None;

    for line in lines.iter().skip(body_start) {
        let trimmed = line.trim();
        for ch in trimmed.chars() {
            match ch {
                '{' => { depth += 1; in_body = true; }
                '}' => { depth -= 1; }
                _   => {}
            }
        }
        if !in_body || depth <= 0 { break; }

        if trimmed.starts_with("#[account(") {
            pending = Some(trimmed.to_string());
            continue;
        }

        if let Some(decl) = parse_quasar_field(trimmed, pending.take()) {
            accounts.push(decl);
        }
    }
    accounts
}

fn parse_quasar_field(line: &str, constraint: Option<String>) -> Option<AccountDecl> {
    let line = line.trim_start_matches("pub ").trim();
    let colon = line.find(':')?;
    let name     = line[..colon].trim().to_string();
    let type_str = line[colon + 1..].trim().trim_end_matches(',').to_string();
    if name.is_empty() || type_str.is_empty() { return None; }

    let c = constraint.as_deref().unwrap_or("");

    let has_auth = c.contains("auth ");
    let has_has_one = c.contains("has_one") || has_auth;
    let has_one_field = if has_auth {
        extract_auth_field(c)
    } else if has_has_one {
        extract_has_one_field(c)
    } else {
        None
    };

    let is_signer = type_str.contains("Signer<")
        || c.contains("signer")
        || is_authority_name(&name);

    let is_unchecked = type_str.contains("UncheckedAccount<")
        || type_str.contains("AccountInfo<");

    let has_owner = type_str.contains("Account<") || !is_unchecked;

    Some(AccountDecl {
        name:           name.into_boxed_str(),
        type_str:       type_str.into_boxed_str(),
        is_mutable:     c.contains("mut"),
        has_signer:     is_signer,
        has_owner,
        has_has_one,
        has_one_field:  has_one_field.map(|s| s.into_boxed_str()),
        is_pda:         c.contains("seeds"),
        has_bump:       c.contains("bump"),
        is_unchecked,
        raw_constraint: constraint.map(|s| s.into_boxed_str()),
    })
}

fn extract_auth_field(constraint: &str) -> Option<String> {
    let start = constraint.find("auth ")? + 5;
    let field = constraint[start..]
        .split_whitespace()
        .next()?
        .trim_end_matches(',')
        .to_string();
    Some(field)
}

fn extract_has_one_field(constraint: &str) -> Option<String> {
    let start = constraint.find("has_one")? + "has_one".len();
    let rest  = constraint[start..].trim().strip_prefix('=')?;
    let field = rest.trim().split_whitespace().next()?.trim_end_matches(',').to_string();
    Some(field)
}

fn is_authority_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.contains("authority") || n.contains("admin") || n.contains("owner")
}

fn extract_handlers(
    source:       &str,
    source_path:  &str,
    accounts_map: &AccountsMap,
) -> Vec<InstructionHandler> {
    let lines: Vec<&str> = source.lines().collect();
    let mut handlers = Vec::new();
    let mut i = 0;

    while i < lines.len() {
        let trimmed = lines[i].trim();
        if (trimmed.starts_with("pub fn ") || trimmed.starts_with("pub async fn "))
            && (trimmed.contains("Ctx<") || trimmed.contains("&Ctx<"))
        {
            if let Some(h) = parse_handler(&lines, i, source_path, accounts_map) {
                handlers.push(h);
            }
        }
        i += 1;
    }
    handlers
}

fn parse_handler(
    lines:        &[&str],
    sig_line:     usize,
    source_path:  &str,
    accounts_map: &AccountsMap,
) -> Option<InstructionHandler> {
    let sig = lines[sig_line].trim();
    let name = extract_fn_name(sig)?;
    let ctx_type = extract_ctx_type(sig)?;
    let accounts = accounts_map.get(&ctx_type).cloned().unwrap_or_default();
    let args = extract_fn_args(sig);

    let body_end = find_body_end(lines, sig_line);
    let body_text = lines[sig_line..body_end.min(lines.len())].join("\n");

    Some(InstructionHandler {
        name:        name.into_boxed_str(),
        accounts,
        args,
        arithmetic:  extract_arithmetic(&body_text),
        cpi_calls:   extract_cpi_calls(&body_text),
        doc_comment: extract_doc_comment(lines, sig_line).map(|s| s.into_boxed_str()),
        source_file: source_path.into(),
    })
}

fn extract_fn_name(sig: &str) -> Option<String> {
    let after = sig.split_once("fn ")?.1;
    let name = after.split('(').next()?.trim().to_string();
    if name.is_empty() { None } else { Some(name) }
}

fn extract_ctx_type(sig: &str) -> Option<String> {
    let pattern = "Ctx<";
    let start = sig.find(pattern)? + pattern.len();
    let ty = sig[start..].split('>').next()?.trim().to_string();
    Some(ty)
}

fn extract_fn_args(sig: &str) -> Vec<(Box<str>, Box<str>)> {
    let Some(open)  = sig.find('(')  else { return Vec::new() };
    let Some(close) = sig.rfind(')') else { return Vec::new() };
    sig[open + 1..close]
        .split(',')
        .filter_map(|p| {
            let p = p.trim();
            if p.starts_with("ctx") { return None; }
            let colon = p.find(':')?;
            let name  = p[..colon].trim().to_string();
            let ty    = p[colon + 1..].trim().to_string();
            if name.is_empty() || ty.is_empty() { return None; }
            Some((name.into_boxed_str(), ty.into_boxed_str()))
        })
        .collect()
}

fn find_body_end(lines: &[&str], start: usize) -> usize {
    let mut depth = 0i32;
    let mut found = false;
    for (i, line) in lines.iter().enumerate().skip(start) {
        for ch in line.chars() {
            match ch {
                '{' => { depth += 1; found = true; }
                '}' => { depth -= 1; }
                _   => {}
            }
        }
        if found && depth == 0 { return i + 1; }
    }
    lines.len()
}

fn extract_doc_comment(lines: &[&str], fn_line: usize) -> Option<String> {
    let mut docs: Vec<&str> = Vec::new();
    for i in (fn_line.saturating_sub(10)..fn_line).rev() {
        let t = lines[i].trim();
        if let Some(c) = t.strip_prefix("///") {
            docs.push(c.trim());
        } else if t.starts_with("#[") || t.is_empty() {
            continue;
        } else {
            break;
        }
    }
    if docs.is_empty() { return None; }
    docs.reverse();
    Some(docs.join(" "))
}

fn extract_arithmetic(body: &str) -> Vec<ArithmeticOp> {
    let mut ops = Vec::new();
    for (ln, line) in body.lines().enumerate() {
        let t = line.trim();
        if t.starts_with("//") { continue; }
        for method in &["checked_add", "checked_sub", "checked_mul", "checked_div",
                        "saturating_add", "saturating_sub"] {
            if t.contains(method) {
                let op_char = match *method {
                    "checked_add" | "saturating_add" => '+',
                    "checked_sub" | "saturating_sub" => '-',
                    "checked_mul"                    => '*',
                    _                                => '/',
                };
                let dot = t.find('.').unwrap_or(0);
                let lhs = t[..dot].trim();
                let rhs = t.find('(')
                    .and_then(|s| t[s+1..].find(')').map(|e| t[s+1..s+1+e].trim()))
                    .unwrap_or("");
                ops.push(ArithmeticOp {
                    op: op_char, lhs: lhs.into(), rhs: rhs.into(),
                    is_checked: true, line: Some(ln as u32 + 1),
                });
            }
        }
    }
    ops
}

fn extract_cpi_calls(body: &str) -> Vec<CpiCall> {
    let mut calls = Vec::new();
    for (ln, line) in body.lines().enumerate() {
        let t = line.trim();
        if t.starts_with("//") { continue; }
        if t.contains("invoke(") || t.contains("invoke_signed(") || t.contains("CpiContext::new(") {
            let program_account = t.find('(')
                .map(|i| t[i+1..].trim().trim_start_matches('&').split_whitespace().next().unwrap_or("unknown").trim_end_matches(',').to_string())
                .unwrap_or_else(|| "unknown".to_string());
            let verified = body.contains("Program<") || body.contains(&format!("{}.key()", program_account));
            calls.push(CpiCall {
                program_account: program_account.into_boxed_str(),
                program_verified: verified,
                line: Some(ln as u32 + 1),
            });
        }
    }
    calls
}