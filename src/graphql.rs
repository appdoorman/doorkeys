//! GraphQL ops: what the Keyhole needs to know about a signed GraphQL document before it sends it.
//!
//! A GraphQL admin API (Linear's, for one) answers every call on one `POST` endpoint, so the
//! method-and-path allowlist cannot tell a member list from a billing change. The document is part
//! of the signed spec and never templated, so the Keyhole reads it once, strictly: exactly one
//! operation, with an explicit `query` or `mutation` keyword, and no fragments, spreads or
//! directives (which could hide or skip a field). What comes out is the operation's kind (a
//! `query` is a read, a `mutation` a change that needs a read-back), its root fields, which the
//! allowlist names, and the variables it declares, the only values a Doorkey may fill in.

use anyhow::{bail, Result};

/// Whether a GraphQL document reads or changes state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Query,
    Mutation,
}

/// What the Keyhole checks a GraphQL document by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Operation {
    pub kind: Kind,
    /// The fields selected at the top of the operation (`users`, `deactivate_users`), aliases
    /// resolved to the real field.
    pub root_fields: Vec<String>,
    /// The variables the operation declares, without `$`.
    pub variables: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Name(String),
    Var(String),
    Punct(char),
    /// A string, number or other literal value; only its place matters here.
    Value,
}

/// Read a document into an [`Operation`], or refuse it.
pub fn parse(document: &str) -> Result<Operation> {
    let tokens = tokenize(document)?;
    let mut at = 0;
    let kind = match tokens.first() {
        Some(Token::Name(k)) if k == "query" => Kind::Query,
        Some(Token::Name(k)) if k == "mutation" => Kind::Mutation,
        Some(Token::Punct('{')) => bail!(
            "the GraphQL document must start with `query` or `mutation`, not the `{{` shorthand"
        ),
        _ => bail!("the GraphQL document must be one `query` or `mutation` operation"),
    };
    at += 1;
    if let Some(Token::Name(_)) = tokens.get(at) {
        at += 1;
    }
    let mut variables = Vec::new();
    if tokens.get(at) == Some(&Token::Punct('(')) {
        let end = closing(&tokens, at, '(', ')')?;
        // `$name:` declares a variable; any other `$name` in the header is a default's reference,
        // which GraphQL does not allow either.
        for pair in tokens[at + 1..end].windows(2) {
            if let [Token::Var(name), Token::Punct(':')] = pair {
                if variables.contains(name) {
                    bail!("the GraphQL variable `${name}` is declared twice");
                }
                variables.push(name.clone());
            }
        }
        at = end + 1;
    }
    if tokens.get(at) != Some(&Token::Punct('{')) {
        bail!("the GraphQL operation must have a selection set");
    }
    let end = closing(&tokens, at, '{', '}')?;
    if end + 1 != tokens.len() {
        bail!("the GraphQL document must hold exactly one operation and nothing after it");
    }

    // The root selection: `field`, or `alias: field`, each with optional arguments and an optional
    // selection of its own.
    let mut root_fields = Vec::new();
    let mut i = at + 1;
    while i < end {
        let Token::Name(first) = &tokens[i] else {
            bail!("the GraphQL operation's top level may only select fields");
        };
        let mut field = first.clone();
        i += 1;
        if tokens.get(i) == Some(&Token::Punct(':')) {
            let Some(Token::Name(real)) = tokens.get(i + 1) else {
                bail!("a GraphQL alias must name a field");
            };
            field = real.clone();
            i += 2;
        }
        if tokens.get(i) == Some(&Token::Punct('(')) {
            i = closing(&tokens, i, '(', ')')? + 1;
        }
        if tokens.get(i) == Some(&Token::Punct('{')) {
            i = closing(&tokens, i, '{', '}')? + 1;
        }
        root_fields.push(field);
    }
    if root_fields.is_empty() {
        bail!("the GraphQL operation selects nothing");
    }

    // Every variable the document uses must be one it declares.
    for token in &tokens {
        if let Token::Var(name) = token {
            if !variables.contains(name) {
                bail!("the GraphQL document uses `${name}` without declaring it");
            }
        }
    }
    Ok(Operation {
        kind,
        root_fields,
        variables,
    })
}

/// The index of the token that closes the bracket opened at `open`.
fn closing(tokens: &[Token], open: usize, left: char, right: char) -> Result<usize> {
    let mut depth = 0usize;
    for (i, token) in tokens.iter().enumerate().skip(open) {
        match token {
            Token::Punct(c) if *c == left => depth += 1,
            Token::Punct(c) if *c == right => {
                depth -= 1;
                if depth == 0 {
                    return Ok(i);
                }
            }
            _ => {}
        }
    }
    bail!("the GraphQL document has an unclosed `{left}`")
}

fn tokenize(document: &str) -> Result<Vec<Token>> {
    let chars: Vec<char> = document.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0;
    let name_start = |c: char| c.is_ascii_alphabetic() || c == '_';
    let name_char = |c: char| c.is_ascii_alphanumeric() || c == '_';
    while i < chars.len() {
        let c = chars[i];
        match c {
            // Whitespace, commas and the byte-order mark are insignificant in GraphQL.
            _ if c.is_whitespace() || c == ',' || c == '\u{feff}' => i += 1,
            '#' => {
                while i < chars.len() && chars[i] != '\n' && chars[i] != '\r' {
                    i += 1;
                }
            }
            '"' => {
                if chars[i..].starts_with(&['"', '"', '"']) {
                    i += 3;
                    loop {
                        if i >= chars.len() {
                            bail!("the GraphQL document has an unterminated block string");
                        }
                        if chars[i..].starts_with(&['\\', '"', '"', '"']) {
                            i += 4;
                        } else if chars[i..].starts_with(&['"', '"', '"']) {
                            i += 3;
                            break;
                        } else {
                            i += 1;
                        }
                    }
                } else {
                    i += 1;
                    loop {
                        match chars.get(i) {
                            None | Some('\n') | Some('\r') => {
                                bail!("the GraphQL document has an unterminated string")
                            }
                            Some('\\') => i += 2,
                            Some('"') => {
                                i += 1;
                                break;
                            }
                            Some(_) => i += 1,
                        }
                    }
                }
                tokens.push(Token::Value);
            }
            '$' => {
                i += 1;
                let start = i;
                if !chars.get(i).copied().is_some_and(name_start) {
                    bail!("the GraphQL document has a `$` without a variable name");
                }
                while chars.get(i).copied().is_some_and(name_char) {
                    i += 1;
                }
                tokens.push(Token::Var(chars[start..i].iter().collect()));
            }
            '.' => bail!("the GraphQL document may not use fragments or `...` spreads"),
            '@' => bail!("the GraphQL document may not use directives"),
            '{' | '}' | '(' | ')' | '[' | ']' | ':' | '!' | '=' | '|' | '&' => {
                tokens.push(Token::Punct(c));
                i += 1;
            }
            _ if name_start(c) => {
                let start = i;
                while chars.get(i).copied().is_some_and(name_char) {
                    i += 1;
                }
                let name: String = chars[start..i].iter().collect();
                if matches!(name.as_str(), "fragment" | "subscription") && tokens.is_empty() {
                    bail!("the GraphQL document must be one `query` or `mutation` operation");
                }
                tokens.push(Token::Name(name));
            }
            _ if c == '-' || c.is_ascii_digit() => {
                i += 1;
                while chars
                    .get(i)
                    .copied()
                    .is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '-'))
                {
                    i += 1;
                }
                tokens.push(Token::Value);
            }
            _ => bail!("the GraphQL document has an unexpected character `{c}`"),
        }
    }
    Ok(tokens)
}
