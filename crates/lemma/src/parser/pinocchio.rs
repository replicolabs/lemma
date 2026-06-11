use crate::{
    parser::Parser,
    types::{AccountDecl, ArithmeticOp, CpiCall, InstructionHandler},
};

pub struct PinocchioParser;

impl Parser for PinocchioParser {
    fn parse(&self, source: &str, source_path: &str) -> Vec<InstructionHandler> {
        let lines: Vec<&str> = source.lines().collect();
        let mut handlers = Vec::new();
        let mut i = 0;
        while i < lines.len() {
            let trimmed = lines[i].trim();
            if (trimmed.contains("fn process(") || trimmed.contains("fn process<"))
                && let Some(h) = parse_process_method(&lines, i, source_path)
            {
                handlers.push(h);
            } else if trimmed.starts_with("pub fn process") || trimmed.starts_with("fn process") {
                let sig = crate::parser::gather_signature(&lines, i);
                if (sig.contains("AccountView") || sig.contains("AccountInfo"))
                    && let Some(h) = parse_process_fn(&lines, i, &sig, source_path)
                {
                    handlers.push(h);
                }
            }
            i += 1;
        }
        handlers
    }
}

// accept the gathered sig; delete the old `let sig = lines[sig_line].trim();`
fn parse_process_fn(
    lines: &[&str],
    sig_line: usize,
    sig: &str,
    source_path: &str,
) -> Option<InstructionHandler> {
    let name = extract_fn_name(sig)?;
    let body_end = find_body_end(lines, sig_line);
    let body_text = lines[sig_line..body_end.min(lines.len())].join("\n");
    let accounts = extract_accounts_from_body(&body_text);
    let doc_comment = extract_doc_comment(lines, sig_line);
    Some(InstructionHandler {
        name: name.into_boxed_str(),
        accounts,
        args: Vec::new(),
        arithmetic: extract_arithmetic(&body_text),
        cpi_calls: extract_cpi_calls(&body_text),
        doc_comment: doc_comment.map(|s| s.into_boxed_str()),
        source_file: source_path.into(),
    })
}

fn parse_process_method(
    lines: &[&str],
    sig_line: usize,
    source_path: &str,
) -> Option<InstructionHandler> {
    let name =
        find_enclosing_instruction_name(lines, sig_line).unwrap_or_else(|| "process".to_string());

    let body_end = find_body_end(lines, sig_line);
    let body_text = lines[sig_line..body_end.min(lines.len())].join("\n");
    let try_from_accounts = extract_try_from_accounts(lines, sig_line);

    let doc_comment = extract_doc_comment(lines, sig_line);

    Some(InstructionHandler {
        name: name.into_boxed_str(),
        accounts: try_from_accounts,
        args: Vec::new(),
        arithmetic: extract_arithmetic(&body_text),
        cpi_calls: extract_cpi_calls(&body_text),
        doc_comment: doc_comment.map(|s| s.into_boxed_str()),
        source_file: source_path.into(),
    })
}

fn find_enclosing_instruction_name(lines: &[&str], from: usize) -> Option<String> {
    for i in (0..from.min(lines.len())).rev() {
        let t = lines[i].trim();
        if t.starts_with("impl") {
            let name = t
                .split_whitespace()
                .nth(1)?
                .split('<')
                .next()?
                .trim()
                .to_string();
            if !name.is_empty() {
                return Some(name);
            }
        }
        if t.starts_with("pub struct ") || t.starts_with("struct ") {
            let rest = t
                .trim_start_matches("pub ")
                .trim_start_matches("struct ")
                .trim();
            let name = rest.split(['<', '{']).next()?.trim().to_string();
            if !name.is_empty() {
                return Some(name);
            }
        }
    }
    None
}

fn extract_try_from_accounts(lines: &[&str], from: usize) -> Vec<AccountDecl> {
    let search_start = from.saturating_sub(200);
    let try_from_line = lines[search_start..from]
        .iter()
        .rposition(|l| l.contains("TryFrom") && l.contains("AccountInfo"))
        .map(|p| search_start + p);

    let Some(tf_line) = try_from_line else {
        return Vec::new();
    };

    let tf_end = find_body_end(lines, tf_line);
    let tf_body = lines[tf_line..tf_end.min(lines.len())].join("\n");
    extract_accounts_from_body(&tf_body)
}

fn extract_accounts_from_body(body: &str) -> Vec<AccountDecl> {
    let mut accounts: Vec<AccountDecl> = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for line in body.lines() {
        let t = line.trim();
        if t.starts_with("//") {
            continue;
        }

        if let Some(name) = extract_account_let(t)
            && seen.insert(name.clone())
        {
            let has_signer_check = body.contains(&format!("{}.is_signer()", name))
                || body.contains(&format!("!{}.is_signer()", name));
            let has_owner_check = body.contains(&format!("{}.owner()", name))
                || body.contains(&format!("{}.is_owned_by", name));
            let is_unchecked = !has_signer_check && !has_owner_check;
            let is_authority = is_authority_name_in_body(&name, body);

            accounts.push(AccountDecl {
                name: name.into_boxed_str(),
                type_str: "AccountInfo".into(),
                is_mutable: body.contains(&format!("{}.try_borrow_mut", "")),
                has_signer: has_signer_check || is_authority,
                has_owner: has_owner_check,
                has_has_one: false,
                has_one_field: None,
                is_pda: body.contains("create_program_address")
                    || body.contains("find_program_address"),
                has_bump: body.contains("canonical_bump"),
                is_unchecked,
                raw_constraint: None,
            });
        }
    }

    accounts
}

fn extract_account_let(line: &str) -> Option<String> {
    if !line.starts_with("let ") {
        return None;
    }
    let rest = &line[4..];
    let name = rest
        .split('=')
        .next()?
        .trim()
        .trim_start_matches("mut ")
        .trim()
        .to_string();
    if (line.contains("account") || line.contains("iter") || line.contains("accounts["))
        && !name.is_empty()
        && !name.contains(':')
    {
        return Some(name);
    }
    None
}

fn is_authority_name_in_body(name: &str, body: &str) -> bool {
    let n = name.to_ascii_lowercase();
    let is_authority_name = n.contains("authority") || n.contains("admin") || n.contains("owner");
    is_authority_name && body.contains(&format!("{}.is_signer()", name))
}

fn extract_fn_name(sig: &str) -> Option<String> {
    let after = sig.split_once("fn ")?.1;
    let name = after.split('(').next()?.trim().to_string();
    if name.is_empty() { None } else { Some(name) }
}

fn find_body_end(lines: &[&str], start: usize) -> usize {
    let mut depth = 0i32;
    let mut found = false;
    for (i, line) in lines.iter().enumerate().skip(start) {
        for ch in line.chars() {
            match ch {
                '{' => {
                    depth += 1;
                    found = true;
                }
                '}' => {
                    depth -= 1;
                }
                _ => {}
            }
        }
        if found && depth == 0 {
            return i + 1;
        }
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
    if docs.is_empty() {
        return None;
    }
    docs.reverse();
    Some(docs.join(" "))
}

fn extract_arithmetic(body: &str) -> Vec<ArithmeticOp> {
    let mut ops = Vec::new();
    for (ln, line) in body.lines().enumerate() {
        let t = line.trim();
        if t.starts_with("//") {
            continue;
        }
        for method in &["checked_add", "checked_sub", "checked_mul", "checked_div"] {
            if !t.contains(method) {
                continue;
            }
            let op_char = match *method {
                "checked_add" => '+',
                "checked_sub" => '-',
                "checked_mul" => '*',
                _ => '/',
            };
            let dot = t.find('.').unwrap_or(0);
            let lhs = t[..dot].trim();
            let rhs = t
                .find('(')
                .and_then(|s| t[s + 1..].find(')').map(|e| &t[s + 1..s + 1 + e]))
                .unwrap_or("")
                .trim();
            ops.push(ArithmeticOp {
                op: op_char,
                lhs: lhs.into(),
                rhs: rhs.into(),
                is_checked: true,
                line: Some(ln as u32 + 1),
            });
        }
    }
    ops
}

fn extract_cpi_calls(body: &str) -> Vec<CpiCall> {
    let mut calls = Vec::new();
    for (ln, line) in body.lines().enumerate() {
        let t = line.trim();
        if t.starts_with("//") {
            continue;
        }
        if !t.contains("invoke(") && !t.contains("invoke_signed(") {
            continue;
        }
        let program_account = t
            .find('(')
            .map(|i| {
                t[i + 1..]
                    .trim()
                    .trim_start_matches('&')
                    .split_whitespace()
                    .next()
                    .unwrap_or("unknown")
                    .trim_end_matches(',')
                    .to_string()
            })
            .unwrap_or_else(|| "unknown".to_string());
        let verified = body.contains(&format!("{}.key()", program_account))
            || body.contains(&"pinocchio_token::ID".to_string());
        calls.push(CpiCall {
            program_account: program_account.into_boxed_str(),
            program_verified: verified,
            line: Some(ln as u32 + 1),
        });
    }
    calls
}
