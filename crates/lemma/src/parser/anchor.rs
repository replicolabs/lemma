use std::collections::HashMap;

use crate::{
    parser::{Parser, gather_signature},
    types::{AccountDecl, ArithmeticOp, CpiCall, InstructionHandler},
};

pub struct AnchorParser;

impl Parser for AnchorParser {
    fn parse(&self, source: &str, source_path: &str) -> Vec<InstructionHandler> {
        let accounts_map = extract_accounts_structs(source);
        extract_handlers(source, source_path, &accounts_map)
    }
}

type AccountsMap = HashMap<String, Vec<AccountDecl>>;

fn extract_accounts_structs(source: &str) -> AccountsMap {
    let mut map: AccountsMap = HashMap::new();
    let lines: Vec<&str> = source.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i].trim();
        if line.contains("derive") && line.contains("Accounts") {
            let struct_name = find_struct_name(&lines, i + 1);
            if let Some(name) = struct_name {
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
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("pub struct ") {
            let name = rest
                .split('<')
                .next()?
                .split('{')
                .next()?
                .trim()
                .to_string();
            if !name.is_empty() {
                return Some(name);
            }
        }
        if let Some(rest) = trimmed.strip_prefix("struct ") {
            let name = rest
                .split('<')
                .next()?
                .split('{')
                .next()?
                .trim()
                .to_string();
            if !name.is_empty() {
                return Some(name);
            }
        }
    }
    None
}

fn extract_struct_fields(lines: &[&str], start: usize) -> Vec<AccountDecl> {
    let mut accounts: Vec<AccountDecl> = Vec::new();
    let body_start = lines
        .iter()
        .skip(start)
        .position(|l| l.contains('{'))
        .map(|p| start + p)
        .unwrap_or(start);

    let mut depth = 0i32;
    let mut in_body = false;
    let mut pending_constraint: Option<String> = None;

    for line in lines.iter().skip(body_start) {
        let trimmed = line.trim();
        for ch in trimmed.chars() {
            match ch {
                '{' => {
                    depth += 1;
                    in_body = true;
                }
                '}' => {
                    depth -= 1;
                }
                _ => {}
            }
        }

        if !in_body {
            continue;
        }
        if depth <= 0 {
            break;
        }
        if trimmed.starts_with("#[account(") {
            pending_constraint = Some(trimmed.to_string());
            continue;
        }
        if pending_constraint.is_some() && !trimmed.starts_with("pub ") {
            if let Some(ref mut c) = pending_constraint {
                c.push(' ');
                c.push_str(trimmed);
            }
            continue;
        }
        if let Some(field) = parse_field_line(trimmed, pending_constraint.take()) {
            accounts.push(field);
        }
    }

    accounts
}

fn parse_field_line(line: &str, constraint: Option<String>) -> Option<AccountDecl> {
    let line = line.trim_start_matches("pub ").trim();
    let colon_pos = line.find(':')?;
    let name = line[..colon_pos].trim().to_string();
    let type_str = line[colon_pos + 1..]
        .trim()
        .trim_end_matches(',')
        .to_string();
    if name.is_empty() || type_str.is_empty() {
        return None;
    }

    let constraint_str = constraint.as_deref().unwrap_or("");

    // let is_signer = type_str.contains("Signer<")
    //     || constraint_str.contains("signer")
    //     || is_authority_name(&name);

    let is_signer = type_str.contains("Signer<") || constraint_str.contains("signer");

    let is_unchecked = type_str.contains("UncheckedAccount<") || type_str.contains("AccountInfo<");

    let has_owner = (!is_unchecked
        && (type_str.contains("Account<")
            || type_str.contains("Program<")
            || type_str.contains("TokenAccount")))
        || constraint_str.contains("owner =")
        || constraint_str.contains("owner=");

    let is_mutable = constraint_str.contains("mut") || constraint_str.contains("#[account(mut");

    let has_has_one = constraint_str.contains("has_one");
    let has_one_field = if has_has_one {
        extract_has_one_field(constraint_str)
    } else {
        None
    };

    let is_pda = constraint_str.contains("seeds");
    let has_bump = constraint_str.contains("bump");

    Some(AccountDecl {
        name: name.into_boxed_str(),
        type_str: type_str.into_boxed_str(),
        is_mutable,
        has_signer: is_signer,
        has_owner,
        has_has_one,
        has_one_field: has_one_field.map(|s| s.into_boxed_str()),
        is_pda,
        has_bump,
        is_unchecked,
        raw_constraint: constraint.map(|s| s.into_boxed_str()),
    })
}

fn extract_has_one_field(constraint: &str) -> Option<String> {
    let start = constraint.find("has_one")? + "has_one".len();
    let rest = constraint[start..].trim().strip_prefix('=')?;
    let field = rest
        .split_whitespace()
        .next()?
        .trim_end_matches('@')
        .trim_end_matches(',')
        .to_string();
    Some(field)
}

// fn is_authority_name(name: &str) -> bool {
//     let n = name.to_ascii_lowercase();
//     n.contains("authority")
//         || n.contains("admin")
//         || n.contains("owner")
//         || n.contains("signer")
//         || n.contains("manager")
//         || n.contains("operator")
// }

fn extract_handlers(
    source: &str,
    source_path: &str,
    accounts_map: &AccountsMap,
) -> Vec<InstructionHandler> {
    let lines: Vec<&str> = source.lines().collect();
    let mut handlers = Vec::new();
    let mut in_program_module = false;
    let mut module_depth = 0i32;

    let mut i = 0;
    while i < lines.len() {
        let trimmed = lines[i].trim();
        if trimmed == "#[program]" {
            in_program_module = true;
            i += 1;
            continue;
        }

        if in_program_module {
            for ch in trimmed.chars() {
                match ch {
                    '{' => module_depth += 1,
                    '}' => module_depth -= 1,
                    _ => {}
                }
            }
            if module_depth < 0 {
                in_program_module = false;
                module_depth = 0;
            }
        }

        if (in_program_module || source.contains("#[program]"))
            && (trimmed.starts_with("pub fn ") || trimmed.starts_with("pub async fn "))
        {
            let sig = gather_signature(&lines, i);
            if sig.contains("ctx: Context<")
                && let Some(handler) = parse_handler(&lines, i, &sig, source_path, accounts_map)
            {
                handlers.push(handler);
            }
        }

        i += 1;
    }

    handlers
}

fn parse_handler(
    lines: &[&str],
    sig_line: usize,
    sig: &str,
    source_path: &str,
    accounts_map: &AccountsMap,
) -> Option<InstructionHandler> {
    let name = extract_fn_name(sig)?;
    let ctx_type = extract_context_type(sig)?;
    let accounts = accounts_map.get(&ctx_type).cloned().unwrap_or_default();
    let args = extract_fn_args(sig);
    let body_end = find_body_end(lines, sig_line);
    let body_text = lines[sig_line..body_end.min(lines.len())].join("\n");
    let doc_comment = extract_doc_comment(lines, sig_line);
    let arithmetic = extract_arithmetic(&body_text);
    let cpi_calls = extract_cpi_calls(&body_text, &accounts); // note: now takes accounts
    Some(InstructionHandler {
        name: name.into_boxed_str(),
        accounts,
        args,
        arithmetic,
        cpi_calls,
        doc_comment: doc_comment.map(|s| s.into_boxed_str()),
        source_file: source_path.into(),
    })
}

fn extract_fn_name(sig: &str) -> Option<String> {
    let after_fn = sig.split_once("fn ")?.1;
    let name = after_fn.split('(').next()?.trim().to_string();
    if name.is_empty() { None } else { Some(name) }
}

fn extract_context_type(sig: &str) -> Option<String> {
    let start = sig.find("Context<")? + "Context<".len();
    let rest = &sig[start..];
    let mut depth = 1;
    let mut end = 0;
    for (i, ch) in rest.char_indices() {
        match ch {
            '<' => depth += 1,
            '>' => {
                depth -= 1;
                if depth == 0 {
                    end = i;
                    break;
                }
            }
            _ => {}
        }
    }
    if end == 0 {
        return None;
    }
    let ty = rest[..end].split('<').next()?.trim().to_string();
    Some(ty)
}

fn extract_fn_args(sig: &str) -> Vec<(Box<str>, Box<str>)> {
    let Some(open) = sig.find('(') else {
        return Vec::new();
    };
    let Some(close) = sig.rfind(')') else {
        return Vec::new();
    };
    let params = &sig[open + 1..close];

    params
        .split(',')
        .filter_map(|param| {
            let param = param.trim();
            if param.starts_with("ctx") {
                return None;
            }
            let colon = param.find(':')?;
            let name = param[..colon].trim().to_string();
            let ty = param[colon + 1..].trim().to_string();
            if name.is_empty() || ty.is_empty() {
                return None;
            }
            Some((name.into_boxed_str(), ty.into_boxed_str()))
        })
        .collect()
}

fn find_body_end(lines: &[&str], start: usize) -> usize {
    let mut depth = 0i32;
    let mut found_open = false;

    for (i, line) in lines.iter().enumerate().skip(start) {
        for ch in line.chars() {
            match ch {
                '{' => {
                    depth += 1;
                    found_open = true;
                }
                '}' => {
                    depth -= 1;
                    if found_open && depth == 0 {
                        return i + 1;
                    }
                }
                _ => {}
            }
        }
    }
    lines.len()
}

fn extract_doc_comment(lines: &[&str], fn_line: usize) -> Option<String> {
    let mut doc_lines: Vec<&str> = Vec::new();
    let start = fn_line.saturating_sub(20);

    for i in (start..fn_line).rev() {
        let trimmed = lines[i].trim();
        if let Some(content) = trimmed.strip_prefix("///") {
            doc_lines.push(content.trim());
        } else if trimmed.starts_with("#[") || trimmed.is_empty() {
            continue;
        } else {
            break;
        }
    }

    if doc_lines.is_empty() {
        return None;
    }
    doc_lines.reverse();
    Some(doc_lines.join(" "))
}

fn extract_arithmetic(body: &str) -> Vec<ArithmeticOp> {
    let mut ops: Vec<ArithmeticOp> = Vec::new();

    for (line_num, line) in body.lines().enumerate() {
        let trimmed = line.trim();

        if trimmed.starts_with("//") {
            continue;
        }

        for method in &[
            "checked_add",
            "checked_sub",
            "checked_mul",
            "checked_div",
            "saturating_add",
            "saturating_sub",
            "saturating_mul",
        ] {
            if trimmed.contains(method)
                && let Some(op) = parse_checked_op(trimmed, method, line_num as u32 + 1)
            {
                ops.push(op);
            }
        }
        for op_char in &['+', '-', '*'] {
            if trimmed.contains(*op_char)
                && !trimmed.contains("checked")
                && involves_token_variable(trimmed)
                && let Some(op) = parse_raw_op(trimmed, *op_char, line_num as u32 + 1)
            {
                ops.push(op);
            }
        }
    }

    ops
}

fn involves_token_variable(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    [
        "amount",
        "balance",
        "fee",
        "collateral",
        "reserve",
        "debt",
        "lamport",
        "token",
        "liquidity",
        "price",
    ]
    .iter()
    .any(|kw| lower.contains(kw))
}

fn parse_checked_op(line: &str, method: &str, line_num: u32) -> Option<ArithmeticOp> {
    let op_char = match method {
        "checked_add" | "saturating_add" => '+',
        "checked_sub" | "saturating_sub" => '-',
        "checked_mul" | "saturating_mul" => '*',
        "checked_div" => '/',
        _ => return None,
    };

    let dot_pos = line.find('.')?;
    let lhs = line[..dot_pos].trim();
    let arg_start = line.find('(')? + 1;
    let arg_end = line.find(')')?;
    let rhs = line[arg_start..arg_end].trim();

    Some(ArithmeticOp {
        op: op_char,
        lhs: lhs.into(),
        rhs: rhs.into(),
        is_checked: true,
        line: Some(line_num),
    })
}

fn parse_raw_op(line: &str, op_char: char, line_num: u32) -> Option<ArithmeticOp> {
    let op_pos = line.find(op_char)?;
    // Skip only `->`. Keep `-=`, `+=`, `*=` — those are unchecked arithmetic.
    if op_char == '-' && line[op_pos + 1..].starts_with('>') {
        return None;
    }
    let lhs = line[..op_pos].trim();
    let rhs = line[op_pos + op_char.len_utf8()..].trim();
    if lhs.is_empty() || rhs.is_empty() {
        return None;
    }
    Some(ArithmeticOp {
        op: op_char,
        lhs: lhs.into(),
        rhs: rhs.into(),
        is_checked: false,
        line: Some(line_num),
    })
}

fn extract_cpi_program_account(text: &str) -> Option<String> {
    // Anchor names the program in the FIRST arg of CpiContext::new(...).
    // Anchor on that substring, not the first '(' in the line (which may
    // belong to an outer wrapper like create_account(CpiContext::new(...))).
    let start = ["CpiContext::new_with_signer(", "CpiContext::new("]
        .iter()
        .find_map(|m| text.find(m).map(|i| i + m.len()))?;
    let inner = text[start..].trim().trim_start_matches('&').trim();
    let token: String = inner
        .split(|c: char| !c.is_alphanumeric() && c != '_' && c != '.')
        .next()?
        .to_string();
    if token.is_empty() {
        return None;
    }
    if let Some(rest) = token.strip_prefix("ctx.accounts.") {
        return rest.split('.').next().map(str::to_string);
    }
    token.split('.').next().map(str::to_string)
}

fn extract_cpi_calls(body: &str, accounts: &[AccountDecl]) -> Vec<CpiCall> {
    let lines: Vec<&str> = body.lines().collect();
    let mut calls = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let t = line.trim();
        if t.starts_with("//") {
            continue;
        }
        if !(t.contains("CpiContext::new(") || t.contains("CpiContext::new_with_signer(")) {
            continue; // raw invoke handled separately; skip to avoid false flags
        }
        let window = lines[i..(i + 4).min(lines.len())].join(" ");
        let prog = extract_cpi_program_account(&window).unwrap_or_else(|| "unknown".into());
        // A typed Program<T> account is identity-checked by Anchor → verified.
        let verified = accounts
            .iter()
            .any(|a| a.name.as_ref() == prog && a.type_str.contains("Program<"))
            || body.contains(&format!("require_keys_eq!({}", prog));
        calls.push(CpiCall {
            program_account: prog.into_boxed_str(),
            program_verified: verified,
            line: Some(i as u32 + 1),
        });
    }
    calls
}
