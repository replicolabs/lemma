use crate::{
    parser::Parser,
    types::{AccountDecl, ArithmeticOp, CpiCall, InstructionHandler},
};

pub struct NativeParser;

impl Parser for NativeParser {
    fn parse(&self, source: &str, source_path: &str) -> Vec<InstructionHandler> {
        let lines: Vec<&str> = source.lines().collect();
        let mut handlers = Vec::new();
        let mut i = 0;
        while i < lines.len() {
            let trimmed = lines[i].trim();
            if trimmed.starts_with("pub fn ") || trimmed.starts_with("fn ") {
                let sig = crate::parser::gather_signature(&lines, i);
                if is_handler_signature(&sig)
                    && let Some(h) = parse_handler(&lines, i, &sig, source_path) {
                        handlers.push(h);
                    }
            }
            i += 1;
        }
        handlers
    }
}

fn is_handler_signature(sig: &str) -> bool {
    (sig.starts_with("pub fn ") || sig.starts_with("fn ")) && sig.contains("&[AccountInfo")
}

fn parse_handler(lines: &[&str], sig_line: usize, sig: &str, source_path: &str)
    -> Option<InstructionHandler>
{
    let name = extract_fn_name(sig)?;
    let body_end = find_body_end(lines, sig_line);
    let body_text = lines[sig_line..body_end.min(lines.len())].join("\n");
    let accounts = extract_accounts_from_body(&body_text);
    let args = extract_fn_args(sig);
    let arithmetic = extract_arithmetic(&body_text);
    let cpi_calls = extract_cpi_calls(&body_text);
    let doc_comment = extract_doc_comment(lines, sig_line);
    Some(InstructionHandler {
        name: name.into_boxed_str(), accounts, args, arithmetic, cpi_calls,
        doc_comment: doc_comment.map(|s| s.into_boxed_str()),
        source_file: source_path.into(),
    })
}

fn extract_accounts_from_body(body: &str) -> Vec<AccountDecl> {
    let mut accounts: Vec<AccountDecl> = Vec::new();
    let mut seen_names = std::collections::HashSet::new();

    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") { continue; }
        if let Some(name) = extract_account_let(trimmed)
            && seen_names.insert(name.clone()) {
                let has_signer = body.contains(&format!("{}.is_signer", name))
                    && body.contains(&format!("!{}.is_signer", name));
                let has_owner = body.contains(&format!("{}.owner", name));
                let is_authority = is_authority_name(&name);

                accounts.push(AccountDecl {
                    name:           name.into_boxed_str(),
                    type_str:       "AccountInfo".into(),
                    is_mutable:     body.contains(&format!("{}.try_borrow_mut_data", ""))
                                    || trimmed.contains("mut"),
                    has_signer:     has_signer || is_authority,
                    has_owner,
                    has_has_one:    false,
                    has_one_field:  None,
                    is_pda:         body.contains("create_program_address")
                                    || body.contains("find_program_address"),
                    has_bump:       body.contains("canonical_bump") || body.contains("bump"),
                    is_unchecked:   true, 
                    raw_constraint: None,
                });
            }
    }

    accounts
}

fn extract_account_let(line: &str) -> Option<String> {
    if line.contains("next_account_info") {
        let rest = line.strip_prefix("let ")?;
        let name = rest.split('=').next()?.trim().trim_start_matches("mut ").trim().to_string();
        if !name.is_empty() { return Some(name); }
    }
    if line.contains("accounts[")
        && let Some(rest) = line.strip_prefix("let ") {
            let name = rest.split('=').next()?.trim().trim_start_matches("mut ").trim().to_string();
            if !name.is_empty() { return Some(name); }
        }
    None
}

fn is_authority_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.contains("authority") || n.contains("admin") || n.contains("owner") || n.contains("signer")
}

fn extract_fn_name(sig: &str) -> Option<String> {
    let after = sig.split_once("fn ")?.1;
    let name = after.split('(').next()?.trim().to_string();
    if name.is_empty() { None } else { Some(name) }
}

fn extract_fn_args(sig: &str) -> Vec<(Box<str>, Box<str>)> {
    let Some(open)  = sig.find('(')  else { return Vec::new() };
    let Some(close) = sig.rfind(')') else { return Vec::new() };
    sig[open + 1..close]
        .split(',')
        .filter_map(|p| {
            let p = p.trim();
            if p.contains("AccountInfo") || p.contains("program_id") { return None; }
            let colon = p.find(':')?;
            let name  = p[..colon].trim().trim_start_matches("mut ").to_string();
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
    let mut docs = Vec::new();
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
            if !t.contains(method) { continue; }
            let op_char = match *method {
                "checked_add" | "saturating_add" => '+',
                "checked_sub" | "saturating_sub" => '-',
                "checked_mul"                    => '*',
                _                                => '/',
            };
            let dot = t.find('.').unwrap_or(0);
            let lhs = t[..dot].trim();
            let rhs = t.find('(').and_then(|s| t[s+1..].find(')').map(|e| &t[s+1..s+1+e])).unwrap_or("").trim();
            ops.push(ArithmeticOp { op: op_char, lhs: lhs.into(), rhs: rhs.into(), is_checked: true, line: Some(ln as u32 + 1) });
        }
    }
    ops
}

fn extract_cpi_calls(body: &str) -> Vec<CpiCall> {
    let mut calls = Vec::new();
    for (ln, line) in body.lines().enumerate() {
        let t = line.trim();
        if t.starts_with("//") { continue; }
        if !t.contains("invoke(") && !t.contains("invoke_signed(") { continue; }
        let program_account = t.find('(')
            .map(|i| t[i+1..].trim().trim_start_matches('&').split_whitespace().next().unwrap_or("unknown").trim_end_matches(',').to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let verified = body.contains(&format!("{}.key != &", program_account))
            || body.contains(&format!("{} != &", program_account));
        calls.push(CpiCall {
            program_account: program_account.into_boxed_str(),
            program_verified: verified,
            line: Some(ln as u32 + 1),
        });
    }
    calls
}