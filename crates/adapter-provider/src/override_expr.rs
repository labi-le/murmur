//! `OverrideExpr` is an update-oriented subset of yq expressions for modifying a single proxy
//! provider mapping.
//!
//! Configure it as an ordered string array; each item observes the result of
//! all previous items:
//!
//! ```yaml
//! proxy-providers:
//!   provider-name:
//!     override:
//!       override-expr:
//!         - '.name = "[provider] " + .name'
//!         - '.udp = true'
//!         - '.skip-cert-verify = false'
//!         - '.plugin-opts.mode = "tls"'
//!         - '.alpn[] |= upcase'
//!         - 'del(.password)'
//! ```
//!
//! Supported paths:
//!   - Root and mapping fields: `.`, `.name`, `.plugin-opts.mode`.
//!   - Quoted fields: `."field.with.dots"` and `.["field.with.dots"]`.
//!   - Array indexes, including negative indexes: `.servers[0]`, `.servers[-1]`.
//!   - Array or mapping wildcards: `.alpn[]` and `.servers[].password`.
//!   - Missing mappings and non-negative array indexes are created on assignment.
//!   - Reading through a scalar produces null; updating through one is a no-op.
//!
//! Supported update statements:
//!   - Assignment: `=`. Its right side uses the root mapping as dot context.
//!   - Update assignment: `|=`. The right side receives the selected old value as its dot
//!     context, for example `.name |= upcase`.
//!   - Compound assignment: `+=`, `-=`, and `*=`.
//!   - Deletion: `del(.field)`, `del(.a, .b)`, and `del(.items[].secret)`. `del(.)` is rejected
//!     because deleting the complete input cannot produce a mapping.
//!   - Conditional paths: `(select(.score > 5) | .tier) = "fast"`. A select that is false
//!     produces no match, so the assignment is skipped.
//!   - Statement pipelines: `.name |= trim | .name |= upcase`. A pipeline used as an assignment
//!     value must be parenthesized, for example `.name = (.name | upcase)` or
//!     `.name |= (trim | upcase)`. The same rule applies to `and`/`or` values.
//!   - Multi-result value pipelines. Wildcards, `select`, and comma unions may produce zero or
//!     more results; collect them with brackets, for example
//!     `.names = [.servers[] | select(.enabled) | .name]`. An assignment value that still has
//!     multiple uncollected results is rejected because a proxy provider override must produce
//!     one mapping.
//!   - A complete override-expr item may itself be a filter pipeline, for example
//!     `. | with_entries(.key |= upcase)`. Its final result must be exactly one mapping.
//!
//! Supported value expressions:
//!   - null (`null` or `~`), booleans, decimal/hex integers, floats, double-quoted strings,
//!     arrays, and mappings with double-quoted keys. String escapes follow yq: `\n`, `\"`, and
//!     `\\` are decoded; other backslash sequences remain literal. Arrays collect all item
//!     results; mapping values omit their key on zero results and keep the last of multiple
//!     results.
//!   - Path references, parentheses, and negative decimal integer/float literals.
//!   - Comma unions, for example `(.name, .port)`. A union after a wildcard follows yq stream
//!     ordering: each union branch processes all inputs.
//!   - yq string interpolation, for example `"[\(.type)] \(.name)"`. An interpolation expression
//!     with multiple results uses its first result.
//!   - A `#` outside a string starts a comment through the end of the expression item.
//!   - Arithmetic and collection operators: `+`, `-`, `*`, `/`, and `%`. `+` concatenates
//!     strings/arrays and shallow-merges mappings. `*` multiplies numbers, repeats strings,
//!     replaces arrays, and deep-merges mappings. `/` splits strings when both operands are
//!     strings.
//!   - Comparisons: `==`, `!=`, `<`, `<=`, `>`, and `>=`. Equality follows yq scalar-value
//!     semantics and does not structurally compare arrays or mappings. Ordered comparisons
//!     support numbers, strings, and null.
//!   - Boolean/default operators: `and`, `or`, and `//`. Only `false` and `null` are falsey.
//!
//! Supported functions use the current dot value as input:
//!   - Collection queries: `length`, `keys`, `has`, `contains`, and `select`. String length is
//!     measured in UTF-8 bytes. `keys` supports arrays/mappings; `has` accepts string mapping
//!     keys or positive/negative array indexes.
//!   - Array operations: `reverse`, `sort`, `unique`, `flatten`, `any`, and `all`. `sort` is
//!     limited to scalar arrays. `flatten` accepts an optional non-negative depth. `any`/`all`
//!     implement their zero-arg forms.
//!   - Stream/collection transforms: `map`, `map_values`, `filter`, `to_entries`,
//!     `from_entries`, `with_entries`, `any_c`, and `all_c`. `map`/`filter`/`map_values` accept
//!     arrays or mappings and operate on their values. `map`/`filter` return arrays;
//!     `map_values` preserves the input collection shape. `to_entries` accepts arrays/mappings
//!     and produces no result for null; `from_entries` accepts arrays of entries. `from_entries`
//!     requires string keys because the target configuration is `map[string]any`.
//!     `with_entries` therefore supports mappings only; `any_c`/`all_c` support arrays only.
//!   - String checks: `test(pattern)` and `test(pattern, "g")`.
//!   - String transforms: `sub`, `split`, `join`, `upcase`, `downcase`, and `trim`. Like yq,
//!     `sub` replaces every regular-expression match. `split` produces no result for null;
//!     `join` accepts arrays.
//!   - Conversion/introspection: `tostring`, `tonumber`, `type`, and `not`.
//!
//! Function arguments use yq-style comma separators. A semicolon is also accepted as an argument
//! separator for compatibility with older expressions. Ordinary function arguments must not
//! produce multiple results; `map`/`filter`-style expression arguments may produce streams. For
//! example:
//!
//! ```yaml
//! .name |= sub("^HK-(.*)$", "Hong Kong $1")
//! .tags |= split(",")
//! .options *= {"tls": {"enabled": true}, "retries": 3}
//! ```
//!
//! This intentionally does not implement the complete yq language. Variables, reduce, dynamic
//! paths, recursive descent, document streams, file/environment access, custom tags, and yq CLI
//! flags are not supported. Evaluation uses values instead of yq's mutable node references.
//! Out-of-range reads do not extend source arrays, and `flatten`/`map_values` in a right-side
//! filter do not mutate their source path; use `|=` to request an update. A right-side expression
//! with no result leaves its target untouched instead of auto-creating a null value. Mapping
//! streams, keys, and entry transforms use sorted keys because `map[string]any` does not retain
//! YAML key order. Expressions are parsed while the schema field is decoded through the text
//! unmarshaler path, so syntax errors are reported before providers run.
//!
//! Expression text is a raw byte sequence: identifiers are classified byte-by-byte through the
//! `unicode` classifiers, so only Latin-1 code points classify correctly; lexing over bytes with
//! a lossy UTF-8 reassembly leaves documented (effectively ASCII) syntax unchanged. The
//! `map[string]any` graph is represented here as `serde_yaml::Value` / `serde_yaml::Mapping`,
//! which (unlike `serde_json::Value`) can hold the `+Inf`/`-Inf`/`NaN` floats that
//! `evaluate_override_numbers` can legitimately produce, matching the `float64`.

use std::collections::HashSet;
use std::fmt::Write as _;

use anyhow::{anyhow, bail, Result};
use serde::de::Visitor;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_yaml::value::{Tag, TaggedValue};
use serde_yaml::{Mapping, Value};

use murmur_common::structure::structure::TEXT_UNMARSHALER;
use murmur_common::yaml::yaml;

#[derive(Clone, Debug, Default)]
pub struct OverrideExpr {
    source: String,
    statements: Vec<Statement>,
}

impl OverrideExpr {
    pub fn new(source: &str) -> Result<Self> {
        let tokens = lex_override_expr(source)?;
        let parser = Parser { tokens, pos: 0 };
        let mut expr = parser.parse()?;
        source.clone_into(&mut expr.source);
        Ok(expr)
    }

    pub fn unmarshal_text(&mut self, text: &[u8]) -> Result<()> {
        *self = Self::new(std::str::from_utf8(text)?)?;
        Ok(())
    }

    pub fn marshal_text(&self) -> Result<Vec<u8>> {
        Ok(self.source.clone().into_bytes())
    }

    pub fn apply(&self, mapping: &mut Mapping) -> Result<()> {
        for statement in &self.statements {
            statement.apply(mapping)?;
        }
        Ok(())
    }
}

impl std::fmt::Display for OverrideExpr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.source)
    }
}

impl Serialize for OverrideExpr {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.source)
    }
}

impl<'de> Deserialize<'de> for OverrideExpr {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct OverrideExprVisitor;

        impl Visitor<'_> for OverrideExprVisitor {
            type Value = OverrideExpr;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an override-expr string")
            }

            fn visit_str<E: serde::de::Error>(self, text: &str) -> Result<OverrideExpr, E> {
                OverrideExpr::new(text).map_err(E::custom)
            }
        }

        deserializer.deserialize_newtype_struct(TEXT_UNMARSHALER, OverrideExprVisitor)
    }
}

#[derive(Clone, Debug)]
enum Statement {
    Assign(AssignStatement),
    Filter(FilterStatement),
    Delete(DeleteStatement),
}

impl Statement {
    fn apply(&self, mapping: &mut Mapping) -> Result<()> {
        match self {
            Self::Assign(s) => s.apply(mapping),
            Self::Filter(s) => s.apply(mapping),
            Self::Delete(s) => s.apply(mapping),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TokenKind {
    Eof,
    Dot,
    Identifier,
    String,
    Number,
    LeftParen,
    RightParen,
    LeftBracket,
    RightBracket,
    LeftBrace,
    RightBrace,
    Comma,
    Semicolon,
    Colon,
    Pipe,
    Assign,
    UpdateAssign,
    AddAssign,
    SubtractAssign,
    MultiplyAssign,
    Plus,
    Minus,
    Multiply,
    Divide,
    Modulo,
    Alternative,
    Equal,
    NotEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
}

#[derive(Clone, Debug)]
struct Token {
    kind: TokenKind,
    text: String,
    pos: usize,
}

fn text_of(bytes: &[u8], range: std::ops::Range<usize>) -> String {
    bytes.get(range).map_or_else(String::new, |slice| String::from_utf8_lossy(slice).into_owned())
}

/// Token kinds whose text is exactly the byte that produced them.
const fn single_byte_token(ch: u8) -> Option<TokenKind> {
    Some(match ch {
        b'.' => TokenKind::Dot,
        b'(' => TokenKind::LeftParen,
        b')' => TokenKind::RightParen,
        b'[' => TokenKind::LeftBracket,
        b']' => TokenKind::RightBracket,
        b'{' => TokenKind::LeftBrace,
        b'}' => TokenKind::RightBrace,
        b',' => TokenKind::Comma,
        b';' => TokenKind::Semicolon,
        b':' => TokenKind::Colon,
        b'%' => TokenKind::Modulo,
        _ => return None,
    })
}

/// Operators that become a two-character token when followed by the returned byte, paired with
/// the one-character token they fall back to.
const fn doubled_token(ch: u8) -> Option<(u8, TokenKind, TokenKind)> {
    Some(match ch {
        b'|' => (b'=', TokenKind::UpdateAssign, TokenKind::Pipe),
        b'+' => (b'=', TokenKind::AddAssign, TokenKind::Plus),
        b'-' => (b'=', TokenKind::SubtractAssign, TokenKind::Minus),
        b'*' => (b'=', TokenKind::MultiplyAssign, TokenKind::Multiply),
        b'/' => (b'/', TokenKind::Alternative, TokenKind::Divide),
        b'=' => (b'=', TokenKind::Equal, TokenKind::Assign),
        b'<' => (b'=', TokenKind::LessEqual, TokenKind::Less),
        b'>' => (b'=', TokenKind::GreaterEqual, TokenKind::Greater),
        _ => return None,
    })
}

fn lex_override_expr(source: &str) -> Result<Vec<Token>> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::with_capacity(16);
    let mut pos = 0usize;
    while let Some(&ch) = bytes.get(pos) {
        if (ch as char).is_whitespace() {
            pos += 1;
            continue;
        }
        if ch == b'#' {
            break;
        }
        let start = pos;
        if let Some(kind) = single_byte_token(ch) {
            tokens.push(Token { kind, text: char::from(ch).to_string(), pos });
            pos += 1;
            continue;
        }
        if let Some((follower, doubled, single)) = doubled_token(ch) {
            let (kind, width) = if bytes.get(pos + 1) == Some(&follower) { (doubled, 2) } else { (single, 1) };
            tokens.push(Token { kind, text: text_of(bytes, pos..pos + width), pos });
            pos += width;
            continue;
        }
        match ch {
            b'!' => {
                if bytes.get(pos + 1) != Some(&b'=') {
                    bail!("unexpected {:?} at column {}", ch as char, pos + 1);
                }
                tokens.push(Token { kind: TokenKind::NotEqual, text: "!=".to_owned(), pos });
                pos += 2;
            }
            b'"' => {
                let (value, next) = scan_override_string(bytes, pos)?;
                tokens.push(Token { kind: TokenKind::String, text: value, pos });
                pos = next;
            }
            b'~' => {
                tokens.push(Token { kind: TokenKind::Identifier, text: "~".to_owned(), pos });
                pos += 1;
            }
            _ => {
                if ch.is_ascii_digit() {
                    pos = scan_override_number(bytes, pos);
                    tokens.push(Token { kind: TokenKind::Number, text: text_of(bytes, start..pos), pos: start });
                } else if is_override_identifier_start(char::from(ch)) {
                    pos += 1;
                    while bytes.get(pos).is_some_and(|b| is_override_identifier_part(char::from(*b))) {
                        pos += 1;
                    }
                    tokens.push(Token { kind: TokenKind::Identifier, text: text_of(bytes, start..pos), pos: start });
                } else {
                    bail!("unexpected {:?} at column {}", ch as char, pos + 1);
                }
            }
        }
    }
    tokens.push(Token { kind: TokenKind::Eof, text: String::new(), pos: bytes.len() });
    Ok(tokens)
}

fn scan_override_string(bytes: &[u8], start: usize) -> Result<(String, usize)> {
    let mut pos = start + 1;
    while let Some(&ch) = bytes.get(pos) {
        if ch == b'\\' {
            pos += 2;
            continue;
        }
        if ch != b'"' {
            pos += 1;
            continue;
        }
        return Ok((text_of(bytes, start + 1..pos), pos + 1));
    }
    bail!("unterminated string at column {}", start + 1);
}

fn decode_override_string(raw: &[u8], column: usize) -> Result<String> {
    let mut result: Vec<u8> = Vec::with_capacity(raw.len());
    let mut pos = 0usize;
    while let Some(&ch) = raw.get(pos) {
        if ch != b'\\' {
            result.push(ch);
            pos += 1;
            continue;
        }
        let Some(&escaped) = raw.get(pos + 1) else {
            bail!("invalid string escape at column {}", column + pos);
        };
        pos += 1;
        match escaped {
            b'"' => result.push(b'"'),
            b'n' => result.push(b'\n'),
            b'\\' => result.push(b'\\'),
            other => {
                result.push(b'\\');
                result.push(other);
            }
        }
        pos += 1;
    }
    Ok(String::from_utf8_lossy(&result).into_owned())
}

fn scan_override_number(bytes: &[u8], mut pos: usize) -> usize {
    if bytes.get(pos) == Some(&b'0') && matches!(bytes.get(pos + 1), Some(b'x' | b'X')) {
        pos += 2;
        while bytes.get(pos).is_some_and(u8::is_ascii_hexdigit) {
            pos += 1;
        }
        return pos;
    }
    while bytes.get(pos).is_some_and(u8::is_ascii_digit) {
        pos += 1;
    }
    if bytes.get(pos) == Some(&b'.') {
        pos += 1;
        while bytes.get(pos).is_some_and(u8::is_ascii_digit) {
            pos += 1;
        }
    }
    if matches!(bytes.get(pos), Some(b'e' | b'E')) {
        pos += 1;
        if matches!(bytes.get(pos), Some(b'+' | b'-')) {
            pos += 1;
        }
        while bytes.get(pos).is_some_and(u8::is_ascii_digit) {
            pos += 1;
        }
    }
    pos
}

fn is_override_identifier_start(ch: char) -> bool {
    ch == '_' || ch.is_alphabetic()
}

fn is_override_identifier_part(ch: char) -> bool {
    ch == '_' || ch == '-' || ch.is_alphabetic() || ch.is_numeric()
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

fn parser_error(token: &Token, message: impl Into<String>) -> anyhow::Error {
    anyhow!("column {}: {}", token.pos + 1, message.into())
}

/// Returned by `Parser::peek` when the cursor sits past the last token, which `next` prevents by
/// stopping on the trailing `Eof`.
static EOF_TOKEN: Token = Token { kind: TokenKind::Eof, text: String::new(), pos: 0 };

impl Parser {
    fn peek(&self) -> &Token {
        self.tokens.get(self.pos).unwrap_or(&EOF_TOKEN)
    }

    fn next(&mut self) -> Token {
        let token = self.peek().clone();
        if token.kind != TokenKind::Eof {
            self.pos += 1;
        }
        token
    }

    fn match_kind(&mut self, kind: TokenKind) -> bool {
        if self.peek().kind != kind {
            return false;
        }
        self.next();
        true
    }

    fn expect(&mut self, kind: TokenKind, message: &str) -> Result<Token> {
        let token = self.next();
        if token.kind != kind {
            return Err(parser_error(&token, message));
        }
        Ok(token)
    }

    fn peek_identifier(&self, value: &str) -> bool {
        let token = self.peek();
        token.kind == TokenKind::Identifier && token.text == value
    }

    fn parse(mut self) -> Result<OverrideExpr> {
        let mut result = OverrideExpr::default();
        if self.peek().kind == TokenKind::Eof {
            bail!("expression is empty");
        }
        loop {
            let statement = self.parse_statement()?;
            result.statements.push(statement);
            if !self.match_kind(TokenKind::Pipe) {
                break;
            }
            if self.peek().kind == TokenKind::Eof {
                return Err(parser_error(self.peek(), "expected expression after pipe"));
            }
        }
        let token = self.peek();
        if token.kind != TokenKind::Eof {
            return Err(parser_error(token, format!("unexpected {:?}", token.text)));
        }
        Ok(result)
    }

    fn parse_statement(&mut self) -> Result<Statement> {
        if self.peek_identifier("del") {
            self.next();
            self.expect(TokenKind::LeftParen, "expected '(' after del")?;
            let mut paths = Vec::new();
            loop {
                paths.push(self.parse_path()?);
                if !self.match_kind(TokenKind::Comma) {
                    break;
                }
            }
            self.expect(TokenKind::RightParen, "expected ')' after del arguments")?;
            for path in &paths {
                if path.segments.is_empty() {
                    return Err(parser_error(self.peek(), "del(.) cannot be represented by a mapping override"));
                }
            }
            return Ok(Statement::Delete(DeleteStatement { paths }));
        }
        if !self.starts_assignment_statement() {
            let expression = self.parse_union_expression(true)?;
            return Ok(Statement::Filter(FilterStatement { expression }));
        }

        let (path, target) = if self.peek().kind == TokenKind::LeftParen {
            (Path::default(), Some(self.parse_assignment_target()?))
        } else {
            (self.parse_path()?, None)
        };
        let op = self.next();
        if !is_override_assignment_token(op.kind) {
            return Err(parser_error(&op, "expected assignment operator after path"));
        }
        let value = self.parse_value_expression(false)?;
        Ok(Statement::Assign(AssignStatement { path, target, operator: op.kind, value }))
    }

    fn starts_assignment_statement(&mut self) -> bool {
        let start = self.pos;
        if self.peek().kind == TokenKind::Dot {
            let result = match self.parse_path() {
                Ok(_) => is_override_assignment_token(self.peek().kind),
                Err(_) => false,
            };
            self.pos = start;
            return result;
        }
        if self.peek().kind != TokenKind::LeftParen {
            return false;
        }
        let mut depth = 0i32;
        for (offset, token) in self.tokens.iter().enumerate().skip(start) {
            if token.kind == TokenKind::LeftParen {
                depth += 1;
                continue;
            }
            if token.kind == TokenKind::RightParen {
                depth -= 1;
                if depth == 0 {
                    return self.tokens.get(offset + 1).is_some_and(|next| is_override_assignment_token(next.kind));
                }
            }
        }
        false
    }

    fn parse_assignment_target(&mut self) -> Result<AssignmentTarget> {
        self.expect(TokenKind::LeftParen, "expected '('")?;
        let mut target = AssignmentTarget { stages: Vec::new() };
        loop {
            if self.peek_identifier("select") {
                self.next();
                self.expect(TokenKind::LeftParen, "expected '(' after select")?;
                let condition = self.parse_value_expression(true)?;
                self.expect(TokenKind::RightParen, "expected ')' after select condition")?;
                target.stages.push(TargetStage::Select(condition));
            } else {
                let path = self.parse_path()?;
                target.stages.push(TargetStage::Path(path));
            }
            if !self.match_kind(TokenKind::Pipe) {
                break;
            }
        }
        self.expect(TokenKind::RightParen, "expected ')' after assignment path")?;
        if target.stages.iter().any(|stage| matches!(stage, TargetStage::Path(_))) {
            return Ok(target);
        }
        Err(parser_error(self.peek(), "conditional assignment must select a path"))
    }

    fn parse_path(&mut self) -> Result<Path> {
        self.expect(TokenKind::Dot, "expected path starting with '.'")?;
        let mut path = Path::default();
        if matches!(self.peek().kind, TokenKind::Identifier | TokenKind::String) {
            let token = self.next();
            let key = Self::path_field(&token)?;
            path.segments.push(PathSegment { kind: PathSegmentKind::Field, key, index: 0 });
        }
        loop {
            if self.peek().kind == TokenKind::Dot {
                self.next();
                let token = self.next();
                if token.kind != TokenKind::Identifier && token.kind != TokenKind::String {
                    return Err(parser_error(&token, "expected field name after '.'"));
                }
                let key = Self::path_field(&token)?;
                path.segments.push(PathSegment { kind: PathSegmentKind::Field, key, index: 0 });
                continue;
            }
            if self.peek().kind != TokenKind::LeftBracket {
                return Ok(path);
            }
            self.next();
            if self.match_kind(TokenKind::RightBracket) {
                path.segments.push(PathSegment { kind: PathSegmentKind::Wildcard, key: String::new(), index: 0 });
                continue;
            }
            let token = self.next();
            if matches!(token.kind, TokenKind::String | TokenKind::Identifier) {
                let key = Self::path_field(&token)?;
                path.segments.push(PathSegment { kind: PathSegmentKind::Field, key, index: 0 });
            } else if matches!(token.kind, TokenKind::Number | TokenKind::Minus) {
                let mut text = token.text.clone();
                if token.kind == TokenKind::Minus {
                    let number = self.expect(TokenKind::Number, "expected array index after '-'")?;
                    text.push_str(&number.text);
                }
                let index: i64 =
                    text.parse().map_err(|_| parser_error(&token, format!("invalid array index {text:?}")))?;
                path.segments.push(PathSegment { kind: PathSegmentKind::Index, key: String::new(), index });
            } else {
                return Err(parser_error(&token, "expected field name or array index"));
            }
            self.expect(TokenKind::RightBracket, "expected ']' after path index")?;
        }
    }

    fn path_field(token: &Token) -> Result<String> {
        if token.kind == TokenKind::Identifier {
            return Ok(token.text.clone());
        }
        decode_override_string(token.text.as_bytes(), token.pos + 1).map_err(|e| parser_error(token, format!("{e}")))
    }

    fn parse_value_expression(&mut self, allow_low_precedence: bool) -> Result<ValueExpr> {
        let first = match self.parse_value_update_expression()? {
            Some(expr) => expr,
            None if allow_low_precedence => self.parse_or()?,
            None => self.parse_alternative()?,
        };
        if !allow_low_precedence {
            return Ok(first);
        }
        let mut stages = vec![first];
        while self.peek().kind == TokenKind::Pipe {
            self.next();
            let stage = match self.parse_value_update_expression()? {
                Some(expr) => expr,
                None => self.parse_or()?,
            };
            stages.push(stage);
        }
        if let [stage] = stages.as_slice() {
            return Ok(stage.clone());
        }
        Ok(ValueExpr::Pipeline(PipelineExpr { stages }))
    }

    fn parse_value_update_expression(&mut self) -> Result<Option<ValueExpr>> {
        if self.peek().kind != TokenKind::Dot {
            return Ok(None);
        }
        let start = self.pos;
        let Ok(path) = self.parse_path() else {
            self.pos = start;
            return Ok(None);
        };
        if !is_override_assignment_token(self.peek().kind) {
            self.pos = start;
            return Ok(None);
        }
        let operator = self.next();
        let value = self.parse_value_expression(false)?;
        Ok(Some(ValueExpr::ValueUpdate(ValueUpdateExpr { path, operator: operator.kind, value: Box::new(value) })))
    }

    fn parse_union_expression(&mut self, allow_low_precedence: bool) -> Result<ValueExpr> {
        let first = self.parse_value_expression(allow_low_precedence)?;
        let mut values = vec![first];
        while self.match_kind(TokenKind::Comma) {
            values.push(self.parse_value_expression(allow_low_precedence)?);
        }
        if let [value] = values.as_slice() {
            return Ok(value.clone());
        }
        Ok(ValueExpr::Union(UnionExpr { values }))
    }

    fn parse_or(&mut self) -> Result<ValueExpr> {
        let mut left = self.parse_and()?;
        while self.peek_identifier("or") {
            let op = self.next();
            let right = self.parse_and()?;
            left = ValueExpr::Binary(BinaryExpr { operator: op.text, left: Box::new(left), right: Box::new(right) });
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<ValueExpr> {
        let mut left = self.parse_alternative()?;
        while self.peek_identifier("and") {
            let op = self.next();
            let right = self.parse_alternative()?;
            left = ValueExpr::Binary(BinaryExpr { operator: op.text, left: Box::new(left), right: Box::new(right) });
        }
        Ok(left)
    }

    fn parse_alternative(&mut self) -> Result<ValueExpr> {
        let mut left = self.parse_comparison()?;
        while self.match_kind(TokenKind::Alternative) {
            let right = self.parse_comparison()?;
            left = ValueExpr::Binary(BinaryExpr {
                operator: "//".to_owned(),
                left: Box::new(left),
                right: Box::new(right),
            });
        }
        Ok(left)
    }

    fn parse_comparison(&mut self) -> Result<ValueExpr> {
        let mut left = self.parse_additive()?;
        loop {
            let token = self.peek().clone();
            if !is_override_comparison_token(token.kind) {
                return Ok(left);
            }
            self.next();
            let right = self.parse_additive()?;
            left = ValueExpr::Binary(BinaryExpr { operator: token.text, left: Box::new(left), right: Box::new(right) });
        }
    }

    fn parse_additive(&mut self) -> Result<ValueExpr> {
        let mut left = self.parse_multiplicative()?;
        loop {
            let token = self.peek().clone();
            if token.kind != TokenKind::Plus && token.kind != TokenKind::Minus {
                return Ok(left);
            }
            self.next();
            let right = self.parse_multiplicative()?;
            left = ValueExpr::Binary(BinaryExpr { operator: token.text, left: Box::new(left), right: Box::new(right) });
        }
    }

    fn parse_multiplicative(&mut self) -> Result<ValueExpr> {
        let mut left = self.parse_unary()?;
        loop {
            let token = self.peek().clone();
            if token.kind != TokenKind::Multiply && token.kind != TokenKind::Divide && token.kind != TokenKind::Modulo {
                return Ok(left);
            }
            self.next();
            let right = self.parse_unary()?;
            left = ValueExpr::Binary(BinaryExpr { operator: token.text, left: Box::new(left), right: Box::new(right) });
        }
    }

    fn parse_unary(&mut self) -> Result<ValueExpr> {
        if self.peek().kind == TokenKind::Minus {
            let minus = self.next();
            let mut number = self.next();
            if number.kind != TokenKind::Number {
                return Err(parser_error(&minus, "unary '-' is only supported for number literals"));
            }
            number.text = format!("-{}", number.text);
            return Self::parse_number(&number);
        }
        self.parse_primary()
    }

    fn parse_number(token: &Token) -> Result<ValueExpr> {
        if token.text.contains(['.', 'e', 'E']) {
            let value: f64 =
                token.text.parse().map_err(|_| parser_error(token, format!("invalid number {:?}", token.text)))?;
            return Ok(ValueExpr::Literal(LiteralExpr { value: Value::from(value) }));
        }
        let (base, digits) = if let Some(rest) = token.text.strip_prefix("0x").or_else(|| token.text.strip_prefix("0X"))
        {
            (16, rest)
        } else {
            (10, token.text.as_str())
        };
        let value = i64::from_str_radix(digits, base)
            .map_err(|_| parser_error(token, format!("invalid number {:?}", token.text)))?;
        Ok(ValueExpr::Literal(LiteralExpr { value: Value::from(value) }))
    }

    fn parse_string(token: &Token) -> Result<ValueExpr> {
        let bytes = token.text.as_bytes();
        let mut parts = Vec::with_capacity(1);
        let mut literal_start = 0usize;
        let mut pos = 0usize;
        while let Some(&ch) = bytes.get(pos) {
            let Some(&next) = bytes.get(pos + 1) else {
                break;
            };
            if ch != b'\\' {
                pos += 1;
                continue;
            }
            if next == b'\\' {
                pos += 2;
                continue;
            }
            if next != b'(' {
                pos += 2;
                continue;
            }
            let literal = decode_override_string(
                bytes.get(literal_start..pos).unwrap_or_default(),
                token.pos + 1 + literal_start,
            )?;
            if !literal.is_empty() {
                parts.push(StringPart { literal, expression: None });
            }
            let expression_start = pos + 2;
            let expression_end = find_override_interpolation_end(bytes, expression_start)
                .map_err(|e| parser_error(token, format!("{e}")))?;
            let expression_source = text_of(bytes, expression_start..expression_end).replace("\\\"", "\"");
            let expression = parse_override_value_expr(&expression_source)
                .map_err(|e| parser_error(token, format!("invalid interpolation: {e}")))?;
            parts.push(StringPart { literal: String::new(), expression: Some(Box::new(expression)) });
            pos = expression_end + 1;
            literal_start = pos;
        }
        let literal =
            decode_override_string(bytes.get(literal_start..).unwrap_or_default(), token.pos + 1 + literal_start)?;
        if parts.is_empty() {
            return Ok(ValueExpr::Literal(LiteralExpr { value: Value::String(literal) }));
        }
        if !literal.is_empty() {
            parts.push(StringPart { literal, expression: None });
        }
        Ok(ValueExpr::StringExpr(StringExpr { parts }))
    }

    fn parse_identifier(&mut self, token: &Token) -> Result<ValueExpr> {
        match token.text.as_str() {
            "true" => return Ok(ValueExpr::Literal(LiteralExpr { value: Value::Bool(true) })),
            "false" => return Ok(ValueExpr::Literal(LiteralExpr { value: Value::Bool(false) })),
            "null" | "~" => return Ok(ValueExpr::Literal(LiteralExpr { value: Value::Null })),
            _ => {}
        }
        let mut args = Vec::new();
        if self.match_kind(TokenKind::LeftParen) && !self.match_kind(TokenKind::RightParen) {
            loop {
                args.push(self.parse_value_expression(true)?);
                if !self.match_kind(TokenKind::Comma) && !self.match_kind(TokenKind::Semicolon) {
                    break;
                }
            }
            self.expect(TokenKind::RightParen, "expected ')' after function arguments")?;
        }
        if !is_override_function(&token.text) {
            return Err(parser_error(token, format!("unknown function {:?}", token.text)));
        }
        if is_override_stream_function(&token.text) {
            Ok(ValueExpr::StreamFunction(StreamFunctionExpr { name: token.text.clone(), args }))
        } else {
            Ok(ValueExpr::Function(FunctionExpr { name: token.text.clone(), args }))
        }
    }

    fn parse_primary(&mut self) -> Result<ValueExpr> {
        let token = self.next();
        match token.kind {
            TokenKind::Dot => {
                self.pos -= 1;
                let path = self.parse_path()?;
                Ok(ValueExpr::Path(PathExpr { path }))
            }
            TokenKind::String => Self::parse_string(&token),
            TokenKind::Number => Self::parse_number(&token),
            TokenKind::LeftParen => {
                let value = self.parse_union_expression(true)?;
                self.expect(TokenKind::RightParen, "expected ')'")?;
                Ok(value)
            }
            TokenKind::LeftBracket => {
                let mut values = Vec::new();
                if self.match_kind(TokenKind::RightBracket) {
                    return Ok(ValueExpr::Array(ArrayExpr { values }));
                }
                loop {
                    values.push(self.parse_value_expression(true)?);
                    if !self.match_kind(TokenKind::Comma) {
                        break;
                    }
                }
                self.expect(TokenKind::RightBracket, "expected ']' after array")?;
                Ok(ValueExpr::Array(ArrayExpr { values }))
            }
            TokenKind::LeftBrace => {
                let mut entries = Vec::new();
                if self.match_kind(TokenKind::RightBrace) {
                    return Ok(ValueExpr::Map(MapExpr { entries }));
                }
                loop {
                    let key = self.next();
                    if key.kind != TokenKind::String {
                        return Err(parser_error(&key, "expected quoted map key"));
                    }
                    self.expect(TokenKind::Colon, "expected ':' after map key")?;
                    let key_value = decode_override_string(key.text.as_bytes(), key.pos + 1)?;
                    let value = self.parse_value_expression(true)?;
                    entries.push(MapEntry { key: key_value, value });
                    if !self.match_kind(TokenKind::Comma) {
                        break;
                    }
                }
                self.expect(TokenKind::RightBrace, "expected '}' after map")?;
                Ok(ValueExpr::Map(MapExpr { entries }))
            }
            TokenKind::Identifier => self.parse_identifier(&token),
            TokenKind::Eof
            | TokenKind::RightParen
            | TokenKind::RightBracket
            | TokenKind::RightBrace
            | TokenKind::Comma
            | TokenKind::Semicolon
            | TokenKind::Colon
            | TokenKind::Pipe
            | TokenKind::Assign
            | TokenKind::UpdateAssign
            | TokenKind::AddAssign
            | TokenKind::SubtractAssign
            | TokenKind::MultiplyAssign
            | TokenKind::Plus
            | TokenKind::Minus
            | TokenKind::Multiply
            | TokenKind::Divide
            | TokenKind::Modulo
            | TokenKind::Alternative
            | TokenKind::Equal
            | TokenKind::NotEqual
            | TokenKind::Less
            | TokenKind::LessEqual
            | TokenKind::Greater
            | TokenKind::GreaterEqual => Err(parser_error(&token, "expected value")),
        }
    }
}

fn find_override_interpolation_end(bytes: &[u8], start: usize) -> Result<usize> {
    let mut depth = 0i32;
    let mut pos = start;
    while let Some(&ch) = bytes.get(pos) {
        match ch {
            b'\\' => pos += 1,
            b'"' => {
                pos += 1;
                while let Some(&quoted) = bytes.get(pos) {
                    if quoted == b'\\' {
                        pos += 2;
                        continue;
                    }
                    if quoted == b'"' {
                        break;
                    }
                    pos += 1;
                }
            }
            b'(' => depth += 1,
            b')' => {
                if depth == 0 {
                    return Ok(pos);
                }
                depth -= 1;
            }
            _ => {}
        }
        pos += 1;
    }
    bail!("unterminated interpolation");
}

fn parse_override_value_expr(source: &str) -> Result<ValueExpr> {
    let tokens = lex_override_expr(source)?;
    let mut parser = Parser { tokens, pos: 0 };
    let expression = parser.parse_union_expression(true)?;
    let token = parser.peek();
    if token.kind != TokenKind::Eof {
        return Err(parser_error(token, format!("unexpected {:?}", token.text)));
    }
    Ok(expression)
}

const fn is_override_comparison_token(kind: TokenKind) -> bool {
    matches!(
        kind,
        TokenKind::Equal
            | TokenKind::NotEqual
            | TokenKind::Less
            | TokenKind::LessEqual
            | TokenKind::Greater
            | TokenKind::GreaterEqual
    )
}

const fn is_override_assignment_token(kind: TokenKind) -> bool {
    matches!(
        kind,
        TokenKind::Assign
            | TokenKind::UpdateAssign
            | TokenKind::AddAssign
            | TokenKind::SubtractAssign
            | TokenKind::MultiplyAssign
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PathSegmentKind {
    Field,
    Index,
    Wildcard,
}

#[derive(Clone, Debug)]
struct PathSegment {
    kind: PathSegmentKind,
    key: String,
    index: i64,
}

#[derive(Clone, Debug, Default)]
struct Path {
    segments: Vec<PathSegment>,
}

impl std::fmt::Display for Path {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, ".")?;
        for (idx, segment) in self.segments.iter().enumerate() {
            match segment.kind {
                PathSegmentKind::Field => {
                    if idx > 0 {
                        write!(f, ".")?;
                    }
                    write!(f, "{}", segment.key)?;
                }
                PathSegmentKind::Index => write!(f, "[{}]", segment.index)?,
                PathSegmentKind::Wildcard => write!(f, "[]")?,
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
enum TargetStage {
    Path(Path),
    Select(ValueExpr),
}

#[derive(Clone, Debug)]
struct AssignmentTarget {
    stages: Vec<TargetStage>,
}

struct TargetSelection {
    value: Value,
    path: Vec<PathSegment>,
}

impl AssignmentTarget {
    fn resolve(&self, root: &Value) -> Result<Vec<TargetSelection>> {
        let mut selections = vec![TargetSelection { value: root.clone(), path: Vec::new() }];
        for stage in &self.stages {
            match stage {
                TargetStage::Path(path) => {
                    let mut next = Vec::with_capacity(selections.len());
                    for selection in selections {
                        next.extend(expand_override_target_path(selection, &path.segments)?);
                    }
                    selections = next;
                }
                TargetStage::Select(condition) => {
                    let mut next = Vec::new();
                    for selection in selections {
                        let matches = eval_stream(condition, &selection.value)?;
                        if matches.iter().any(override_truthy) {
                            next.push(selection);
                        }
                    }
                    selections = next;
                }
            }
        }
        Ok(selections)
    }
}

/// An array length as the `i64` domain `PathSegment` indexes live in.
fn override_len_i64(len: usize) -> i64 {
    i64::try_from(len).unwrap_or(i64::MAX)
}

fn expand_override_target_path(selection: TargetSelection, path: &[PathSegment]) -> Result<Vec<TargetSelection>> {
    let Some((segment, rest)) = path.split_first() else {
        return Ok(vec![selection]);
    };
    let append_path = |seg: PathSegment| {
        let mut p = selection.path.clone();
        p.push(seg);
        p
    };
    match segment.kind {
        PathSegmentKind::Field => {
            if selection.value.is_null() {
                return expand_override_target_path(
                    TargetSelection { value: Value::Null, path: append_path(segment.clone()) },
                    rest,
                );
            }
            let Value::Mapping(mapping) = &selection.value else {
                return Ok(Vec::new());
            };
            let child = mapping.get(segment.key.as_str()).cloned().unwrap_or(Value::Null);
            expand_override_target_path(TargetSelection { value: child, path: append_path(segment.clone()) }, rest)
        }
        PathSegmentKind::Index => {
            if selection.value.is_null() {
                return expand_override_target_path(
                    TargetSelection { value: Value::Null, path: append_path(segment.clone()) },
                    rest,
                );
            }
            let Value::Sequence(array) = &selection.value else {
                return Ok(Vec::new());
            };
            let mut index = segment.index;
            if index < 0 {
                index += override_len_i64(array.len());
            }
            if index < 0 {
                return Ok(Vec::new());
            }
            let concrete = PathSegment { kind: PathSegmentKind::Index, key: String::new(), index };
            let value = usize::try_from(index).ok().and_then(|i| array.get(i)).cloned().unwrap_or(Value::Null);
            expand_override_target_path(TargetSelection { value, path: append_path(concrete) }, rest)
        }
        PathSegmentKind::Wildcard => {
            let mut result = Vec::new();
            match &selection.value {
                Value::Sequence(array) => {
                    for (index, item) in array.iter().enumerate() {
                        let concrete = PathSegment {
                            kind: PathSegmentKind::Index,
                            key: String::new(),
                            index: override_len_i64(index),
                        };
                        let expanded = expand_override_target_path(
                            TargetSelection { value: item.clone(), path: append_path(concrete) },
                            rest,
                        )?;
                        result.extend(expanded);
                    }
                }
                Value::Mapping(mapping) => {
                    let mut keys: Vec<String> = mapping.keys().filter_map(|k| k.as_str().map(str::to_owned)).collect();
                    keys.sort();
                    for key in keys {
                        let value = mapping.get(key.as_str()).cloned().unwrap_or(Value::Null);
                        let concrete = PathSegment { kind: PathSegmentKind::Field, key: key.clone(), index: 0 };
                        let expanded =
                            expand_override_target_path(TargetSelection { value, path: append_path(concrete) }, rest)?;
                        result.extend(expanded);
                    }
                }
                Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) | Value::Tagged(_) => {}
            }
            Ok(result)
        }
    }
}

#[derive(Clone, Debug)]
struct AssignStatement {
    path: Path,
    target: Option<AssignmentTarget>,
    operator: TokenKind,
    value: ValueExpr,
}

#[derive(Clone, Debug)]
struct FilterStatement {
    expression: ValueExpr,
}

impl FilterStatement {
    fn apply(&self, mapping: &mut Mapping) -> Result<()> {
        let root = Value::Mapping(mapping.clone());
        let value = eval_single(&self.expression, &root)?;
        if is_no_match(&value) {
            bail!("filter expression produced no result; a mapping is required");
        }
        let Value::Mapping(result) = value else {
            bail!("filter expression must produce a mapping, got {}", override_type(&value));
        };
        *mapping = result;
        Ok(())
    }
}

/// The symbol of a compound assignment operator (`+=`, `-=`, `*=`), `None` for every other token.
const fn compound_operator_symbol(op: TokenKind) -> Option<&'static str> {
    if matches!(op, TokenKind::AddAssign) {
        Some("+")
    } else if matches!(op, TokenKind::SubtractAssign) {
        Some("-")
    } else if matches!(op, TokenKind::MultiplyAssign) {
        Some("*")
    } else {
        None
    }
}

impl AssignStatement {
    fn apply(&self, mapping: &mut Mapping) -> Result<()> {
        let root = Value::Mapping(mapping.clone());
        let updater: Box<dyn Fn(Value) -> Result<Value>> = if self.operator == TokenKind::Assign {
            let value = eval_single(&self.value, &root)?;
            if is_no_match(&value) {
                return Ok(());
            }
            Box::new(move |_old: Value| Ok(value.clone()))
        } else if self.operator == TokenKind::UpdateAssign {
            let expr = self.value.clone();
            Box::new(move |old: Value| {
                let value = eval_single(&expr, &old)?;
                if is_no_match(&value) {
                    Ok(old)
                } else {
                    Ok(value)
                }
            })
        } else {
            let value = eval_single(&self.value, &root)?;
            if is_no_match(&value) {
                return Ok(());
            }
            let Some(operator) = compound_operator_symbol(self.operator) else {
                bail!("{:?} is not a compound assignment operator", self.operator);
            };
            Box::new(move |old: Value| evaluate_override_binary(operator, &old, &value))
        };

        if let Some(target) = &self.target {
            let selections = target.resolve(&root)?;
            let mut current = root;
            for selection in &selections {
                let next = update_override_path(current, &selection.path, updater.as_ref())
                    .map_err(|e| anyhow!("update selected path: {e}"))?;
                match next {
                    Value::Mapping(_) => current = next,
                    other @ (Value::Null
                    | Value::Bool(_)
                    | Value::Number(_)
                    | Value::String(_)
                    | Value::Sequence(_)
                    | Value::Tagged(_)) => {
                        bail!("root expression must produce a mapping, got {}", override_type(&other));
                    }
                }
            }
            let Value::Mapping(final_map) = current else {
                bail!("root expression must produce a mapping");
            };
            *mapping = final_map;
            return Ok(());
        }

        let next = update_override_path(root, &self.path.segments, updater.as_ref())
            .map_err(|e| anyhow!("update {}: {e}", self.path))?;
        match next {
            Value::Mapping(final_map) => {
                *mapping = final_map;
                Ok(())
            }
            other @ (Value::Null
            | Value::Bool(_)
            | Value::Number(_)
            | Value::String(_)
            | Value::Sequence(_)
            | Value::Tagged(_)) => {
                bail!("root expression must produce a mapping, got {}", override_type(&other));
            }
        }
    }
}

#[derive(Clone, Debug)]
struct DeleteStatement {
    paths: Vec<Path>,
}

impl DeleteStatement {
    fn apply(&self, mapping: &mut Mapping) -> Result<()> {
        let paths: Vec<&[PathSegment]> = self.paths.iter().map(|path| path.segments.as_slice()).collect();
        let node = Value::Mapping(std::mem::take(mapping));
        match delete_override_paths(node, &paths)? {
            Value::Mapping(result) => {
                *mapping = result;
                Ok(())
            }
            Value::Null
            | Value::Bool(_)
            | Value::Number(_)
            | Value::String(_)
            | Value::Sequence(_)
            | Value::Tagged(_) => bail!("root expression must produce a mapping"),
        }
    }
}

fn delete_override_paths(node: Value, paths: &[&[PathSegment]]) -> Result<Value> {
    match node {
        Value::Mapping(mut mapping) => {
            let keys: Vec<String> = mapping.keys().filter_map(|k| k.as_str().map(str::to_owned)).collect();
            for key in keys {
                let mut remove = false;
                let mut tails: Vec<&[PathSegment]> = Vec::new();
                for path in paths {
                    let Some((segment, rest)) = path.split_first() else { continue };
                    let matches = segment.kind == PathSegmentKind::Wildcard
                        || (segment.kind == PathSegmentKind::Field && segment.key == key);
                    if !matches {
                        continue;
                    }
                    if rest.is_empty() {
                        remove = true;
                        break;
                    }
                    tails.push(rest);
                }
                if remove {
                    mapping.shift_remove(key.as_str());
                    continue;
                }
                if tails.is_empty() {
                    continue;
                }
                let child = mapping.get(key.as_str()).cloned().unwrap_or(Value::Null);
                let updated = delete_override_paths(child, &tails)?;
                mapping.insert(Value::String(key), updated);
            }
            Ok(Value::Mapping(mapping))
        }
        Value::Sequence(value) => {
            let mut remove = vec![false; value.len()];
            let mut tails: Vec<Vec<&[PathSegment]>> = vec![Vec::new(); value.len()];
            for path in paths {
                let Some((segment, rest)) = path.split_first() else { continue };
                let indexes: Vec<usize> = match segment.kind {
                    PathSegmentKind::Wildcard => (0..value.len()).collect(),
                    PathSegmentKind::Index => {
                        let mut index = segment.index;
                        if index < 0 {
                            index += override_len_i64(value.len());
                        }
                        usize::try_from(index).map_or_else(
                            |_| Vec::new(),
                            |index| if index < value.len() { vec![index] } else { Vec::new() },
                        )
                    }
                    PathSegmentKind::Field => continue,
                };
                for index in indexes {
                    if rest.is_empty() {
                        if let Some(flag) = remove.get_mut(index) {
                            *flag = true;
                        }
                        continue;
                    }
                    if let Some(tail) = tails.get_mut(index) {
                        tail.push(rest);
                    }
                }
            }
            let mut result = Vec::with_capacity(value.len());
            for ((mut child, removed), tail) in value.into_iter().zip(remove).zip(tails) {
                if removed {
                    continue;
                }
                if !tail.is_empty() {
                    child = delete_override_paths(child, &tail)?;
                }
                result.push(child);
            }
            Ok(Value::Sequence(result))
        }
        other @ (Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) | Value::Tagged(_)) => Ok(other),
    }
}

fn update_override_path(node: Value, path: &[PathSegment], updater: &dyn Fn(Value) -> Result<Value>) -> Result<Value> {
    let Some((segment, rest)) = path.split_first() else {
        return updater(node);
    };
    match segment.kind {
        PathSegmentKind::Field => {
            let node = if node.is_null() { Value::Mapping(Mapping::new()) } else { node };
            match node {
                Value::Mapping(mut mapping) => {
                    let child = mapping.get(segment.key.as_str()).cloned().unwrap_or(Value::Null);
                    let value = update_override_path(child, rest, updater)?;
                    mapping.insert(Value::String(segment.key.clone()), value);
                    Ok(Value::Mapping(mapping))
                }
                other @ (Value::Null
                | Value::Bool(_)
                | Value::Number(_)
                | Value::String(_)
                | Value::Sequence(_)
                | Value::Tagged(_)) => Ok(other),
            }
        }
        PathSegmentKind::Index => {
            let node = if node.is_null() { Value::Sequence(Vec::new()) } else { node };
            match node {
                Value::Sequence(mut array) => {
                    let mut index = segment.index;
                    if index < 0 {
                        index += override_len_i64(array.len());
                    }
                    let Ok(index) = usize::try_from(index) else {
                        bail!("array index {} is out of range", segment.index);
                    };
                    while array.len() <= index {
                        array.push(Value::Null);
                    }
                    let child = array.get_mut(index).map_or(Value::Null, |slot| std::mem::replace(slot, Value::Null));
                    let value = update_override_path(child, rest, updater)?;
                    if let Some(slot) = array.get_mut(index) {
                        *slot = value;
                    }
                    Ok(Value::Sequence(array))
                }
                other @ (Value::Null
                | Value::Bool(_)
                | Value::Number(_)
                | Value::String(_)
                | Value::Mapping(_)
                | Value::Tagged(_)) => Ok(other),
            }
        }
        PathSegmentKind::Wildcard => match node {
            Value::Sequence(mut array) => {
                for item in &mut array {
                    let taken = std::mem::replace(item, Value::Null);
                    *item = update_override_path(taken, rest, updater)?;
                }
                Ok(Value::Sequence(array))
            }
            Value::Mapping(mut mapping) => {
                let keys: Vec<Value> = mapping.keys().cloned().collect();
                for key in keys {
                    if let Some(item) = mapping.get_mut(&key) {
                        let taken = std::mem::replace(item, Value::Null);
                        let next = update_override_path(taken, rest, updater)?;
                        mapping.insert(key, next);
                    }
                }
                Ok(Value::Mapping(mapping))
            }
            other @ (Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) | Value::Tagged(_)) => {
                Ok(other)
            }
        },
    }
}

const NO_MATCH_TAG: &str = "murmur:override-no-match";

fn no_match_value() -> Value {
    Value::Tagged(Box::new(TaggedValue { tag: Tag::new(NO_MATCH_TAG), value: Value::Null }))
}

fn is_no_match(value: &Value) -> bool {
    matches!(value, Value::Tagged(tagged) if tagged.tag == NO_MATCH_TAG)
}

#[derive(Clone, Debug)]
enum ValueExpr {
    Pipeline(PipelineExpr),
    Union(UnionExpr),
    Literal(LiteralExpr),
    StringExpr(StringExpr),
    Path(PathExpr),
    Array(ArrayExpr),
    Map(MapExpr),
    ValueUpdate(ValueUpdateExpr),
    Binary(BinaryExpr),
    Function(FunctionExpr),
    StreamFunction(StreamFunctionExpr),
}

impl ValueExpr {
    fn eval(&self, input: &Value) -> Result<Value> {
        eval_single(self, input)
    }
}

fn single_result(value: Value) -> Vec<Value> {
    if is_no_match(&value) {
        Vec::new()
    } else {
        vec![value]
    }
}

fn eval_stream(expr: &ValueExpr, input: &Value) -> Result<Vec<Value>> {
    match expr {
        ValueExpr::Pipeline(e) => e.eval_all(input),
        ValueExpr::Union(e) => e.eval_all(input),
        ValueExpr::Path(e) => e.eval_all(input),
        ValueExpr::Binary(e) => e.eval_all(input),
        ValueExpr::StreamFunction(e) => e.eval_all(input),
        ValueExpr::Literal(e) => Ok(single_result(e.eval(input))),
        ValueExpr::StringExpr(e) => Ok(single_result(e.eval(input)?)),
        ValueExpr::Array(e) => Ok(single_result(e.eval(input)?)),
        ValueExpr::Map(e) => Ok(single_result(e.eval(input)?)),
        ValueExpr::ValueUpdate(e) => Ok(single_result(e.eval(input)?)),
        ValueExpr::Function(e) => Ok(single_result(e.eval(input)?)),
    }
}

fn eval_single(expr: &ValueExpr, input: &Value) -> Result<Value> {
    let values = eval_stream(expr, input)?;
    match values.as_slice() {
        [] => Ok(no_match_value()),
        [value] => Ok(value.clone()),
        values => bail!("expression produced {} results; collect them with [...]", values.len()),
    }
}

fn eval_stream_inputs(expr: &ValueExpr, inputs: &[Value]) -> Result<Vec<Value>> {
    if let ValueExpr::Union(union_expr) = expr {
        return union_expr.eval_all_inputs(inputs);
    }
    let mut results = Vec::with_capacity(inputs.len());
    for input in inputs {
        results.extend(eval_stream(expr, input)?);
    }
    Ok(results)
}

fn eval_override_expression_list(expressions: &[ValueExpr], input: &Value) -> Result<Vec<Value>> {
    let mut results = Vec::with_capacity(expressions.len());
    for expression in expressions {
        results.extend(eval_stream(expression, input)?);
    }
    Ok(results)
}

#[derive(Clone, Debug)]
struct PipelineExpr {
    stages: Vec<ValueExpr>,
}

impl PipelineExpr {
    fn eval_all(&self, input: &Value) -> Result<Vec<Value>> {
        let mut values = vec![input.clone()];
        for stage in &self.stages {
            values = eval_stream_inputs(stage, &values)?;
        }
        Ok(values)
    }
}

#[derive(Clone, Debug)]
struct UnionExpr {
    values: Vec<ValueExpr>,
}

impl UnionExpr {
    fn eval_all(&self, input: &Value) -> Result<Vec<Value>> {
        self.eval_all_inputs(std::slice::from_ref(input))
    }

    fn eval_all_inputs(&self, inputs: &[Value]) -> Result<Vec<Value>> {
        let mut results = Vec::with_capacity(self.values.len());
        for value_expr in &self.values {
            results.extend(eval_stream_inputs(value_expr, inputs)?);
        }
        Ok(results)
    }
}

#[derive(Clone, Debug)]
struct LiteralExpr {
    value: Value,
}

impl LiteralExpr {
    fn eval(&self, _input: &Value) -> Value {
        self.value.clone()
    }
}

#[derive(Clone, Debug)]
struct StringPart {
    literal: String,
    expression: Option<Box<ValueExpr>>,
}

#[derive(Clone, Debug)]
struct StringExpr {
    parts: Vec<StringPart>,
}

impl StringExpr {
    fn eval(&self, input: &Value) -> Result<Value> {
        let mut out = String::new();
        for part in &self.parts {
            let Some(expression) = &part.expression else {
                out.push_str(&part.literal);
                continue;
            };
            let values = eval_stream(expression, input)?;
            let Some(value) = values.into_iter().next() else {
                continue;
            };
            if let Value::String(s) = &value {
                out.push_str(s);
            } else if is_override_scalar(&value) {
                if value.is_null() {
                    out.push_str("null");
                } else {
                    out.push_str(&format_scalar(&value));
                }
            } else {
                let encoded = yaml::marshal(&sorted_for_marshal(&value))?;
                let encoded = String::from_utf8(encoded)?;
                out.push_str(encoded.trim_end_matches('\n'));
            }
        }
        Ok(Value::String(out))
    }
}

/// A YAML mapping has no defined iteration order, and the output this module must match sorts a
/// map's keys when serializing it. `serde_yaml::Mapping` preserves insertion order instead, so
/// every `yaml::marshal` call in this module marshals this sorted copy to match the output text.
fn sorted_for_marshal(value: &Value) -> Value {
    match value {
        Value::Mapping(map) => {
            let mut keys: Vec<String> = map.keys().filter_map(|k| k.as_str().map(str::to_owned)).collect();
            keys.sort();
            let mut sorted = Mapping::new();
            for key in keys {
                let child = map.get(key.as_str()).cloned().unwrap_or(Value::Null);
                sorted.insert(Value::String(key), sorted_for_marshal(&child));
            }
            Value::Mapping(sorted)
        }
        Value::Sequence(values) => Value::Sequence(values.iter().map(sorted_for_marshal).collect()),
        other @ (Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) | Value::Tagged(_)) => {
            other.clone()
        }
    }
}

#[derive(Clone, Debug)]
struct PathExpr {
    path: Path,
}

impl PathExpr {
    fn eval_all(&self, input: &Value) -> Result<Vec<Value>> {
        lookup_override_path_stream(input, &self.path.segments)
    }
}

fn lookup_override_path_stream(value: &Value, path: &[PathSegment]) -> Result<Vec<Value>> {
    let Some((segment, rest)) = path.split_first() else {
        return Ok(vec![value.clone()]);
    };
    match segment.kind {
        PathSegmentKind::Field => {
            let Value::Mapping(mapping) = value else {
                return Ok(vec![Value::Null]);
            };
            let child = mapping.get(segment.key.as_str()).cloned().unwrap_or(Value::Null);
            lookup_override_path_stream(&child, rest)
        }
        PathSegmentKind::Index => {
            let Value::Sequence(array) = value else {
                return Ok(vec![Value::Null]);
            };
            let mut index = segment.index;
            if index < 0 {
                index += override_len_i64(array.len());
            }
            let Ok(index) = usize::try_from(index) else {
                return Ok(vec![Value::Null]);
            };
            let Some(item) = array.get(index) else {
                return Ok(vec![Value::Null]);
            };
            lookup_override_path_stream(item, rest)
        }
        PathSegmentKind::Wildcard => {
            let mut results = Vec::new();
            match value {
                Value::Sequence(items) => {
                    for item in items {
                        results.extend(lookup_override_path_stream(item, rest)?);
                    }
                }
                Value::Mapping(map) => {
                    let mut keys: Vec<String> = map.keys().filter_map(|k| k.as_str().map(str::to_owned)).collect();
                    keys.sort();
                    for key in keys {
                        let child = map.get(key.as_str()).cloned().unwrap_or(Value::Null);
                        results.extend(lookup_override_path_stream(&child, rest)?);
                    }
                }
                Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) | Value::Tagged(_) => {}
            }
            Ok(results)
        }
    }
}

#[derive(Clone, Debug)]
struct ArrayExpr {
    values: Vec<ValueExpr>,
}

impl ArrayExpr {
    fn eval(&self, input: &Value) -> Result<Value> {
        let mut result = Vec::with_capacity(self.values.len());
        for value_expr in &self.values {
            result.extend(eval_stream(value_expr, input)?);
        }
        Ok(Value::Sequence(result))
    }
}

#[derive(Clone, Debug)]
struct MapEntry {
    key: String,
    value: ValueExpr,
}

#[derive(Clone, Debug)]
struct MapExpr {
    entries: Vec<MapEntry>,
}

impl MapExpr {
    fn eval(&self, input: &Value) -> Result<Value> {
        let mut result = Mapping::new();
        for entry in &self.entries {
            let values = eval_stream(&entry.value, input)?;
            if let Some(value) = values.into_iter().last() {
                result.insert(Value::String(entry.key.clone()), value);
            }
        }
        Ok(Value::Mapping(result))
    }
}

#[derive(Clone, Debug)]
struct ValueUpdateExpr {
    path: Path,
    operator: TokenKind,
    value: Box<ValueExpr>,
}

impl ValueUpdateExpr {
    fn eval(&self, input: &Value) -> Result<Value> {
        let root = input.clone();
        let updater: Box<dyn Fn(Value) -> Result<Value>> = if self.operator == TokenKind::Assign {
            let value = eval_single(&self.value, &root)?;
            if is_no_match(&value) {
                return Ok(root);
            }
            Box::new(move |_old: Value| Ok(value.clone()))
        } else if self.operator == TokenKind::UpdateAssign {
            let expr = (*self.value).clone();
            Box::new(move |old: Value| {
                let value = eval_single(&expr, &old)?;
                if is_no_match(&value) {
                    Ok(old)
                } else {
                    Ok(value)
                }
            })
        } else {
            let value = eval_single(&self.value, &root)?;
            let Some(operator) = compound_operator_symbol(self.operator) else {
                bail!("{:?} is not a compound assignment operator", self.operator);
            };
            Box::new(move |old: Value| evaluate_override_binary(operator, &old, &value))
        };
        update_override_path(root, &self.path.segments, updater.as_ref())
            .map_err(|e| anyhow!("update {}: {e}", self.path))
    }
}

#[derive(Clone, Debug)]
struct BinaryExpr {
    operator: String,
    left: Box<ValueExpr>,
    right: Box<ValueExpr>,
}

impl BinaryExpr {
    fn eval_all(&self, input: &Value) -> Result<Vec<Value>> {
        let left_values = eval_stream(&self.left, input)?;
        if self.operator == "//" {
            let mut results = Vec::with_capacity(left_values.len());
            for left in &left_values {
                if override_truthy(left) {
                    results.push(left.clone());
                    continue;
                }
                results.extend(eval_stream(&self.right, input)?);
            }
            if left_values.is_empty() {
                return eval_stream(&self.right, input);
            }
            return Ok(results);
        }
        let mut needs_right = self.operator != "and" && self.operator != "or";
        if !needs_right {
            for left in &left_values {
                if (self.operator == "and" && override_truthy(left))
                    || (self.operator == "or" && !override_truthy(left))
                {
                    needs_right = true;
                    break;
                }
            }
        }
        if !needs_right {
            return Ok(left_values
                .iter()
                .map(|left| Value::Bool(self.operator == "or" && override_truthy(left)))
                .collect());
        }
        let right_values = eval_stream(&self.right, input)?;
        let mut results = Vec::with_capacity(left_values.len() * right_values.len().max(1));
        for left in &left_values {
            if self.operator == "and" && !override_truthy(left) {
                results.push(Value::Bool(false));
                continue;
            }
            if self.operator == "or" && override_truthy(left) {
                results.push(Value::Bool(true));
                continue;
            }
            for right in &right_values {
                results.push(evaluate_override_binary(&self.operator, left, right)?);
            }
        }
        Ok(results)
    }
}

#[derive(Clone, Debug)]
struct FunctionExpr {
    name: String,
    args: Vec<ValueExpr>,
}

#[derive(Clone, Debug)]
struct StreamFunctionExpr {
    name: String,
    args: Vec<ValueExpr>,
}

impl StreamFunctionExpr {
    fn eval_all(&self, input: &Value) -> Result<Vec<Value>> {
        match self.name.as_str() {
            "map" | "filter" => self.eval_map_filter(input),
            "map_values" => self.eval_map_values(input),
            "to_entries" | "from_entries" | "with_entries" => self.eval_entries(input),
            "any_c" | "all_c" => self.eval_condition(input),
            other => bail!("unsupported stream function {other:?}"),
        }
    }

    fn eval_map_filter(&self, input: &Value) -> Result<Vec<Value>> {
        match self.name.as_str() {
            "map" | "filter" => {
                if self.args.is_empty() {
                    bail!("{} expects an expression", self.name);
                }
                let values = override_collection_values(input).map_err(|e| anyhow!("{}: {e}", self.name))?;
                let mut result = Vec::with_capacity(values.len());
                if self.name == "map" {
                    for expression in &self.args {
                        result.extend(eval_stream_inputs(expression, &values)?);
                    }
                    return Ok(vec![Value::Sequence(result)]);
                }
                for value in &values {
                    let items = eval_override_expression_list(&self.args, value)?;
                    if items.iter().any(override_truthy) {
                        result.push(value.clone());
                    }
                }
                Ok(vec![Value::Sequence(result)])
            }
            other => bail!("unsupported stream function {other:?}"),
        }
    }

    fn eval_map_values(&self, input: &Value) -> Result<Vec<Value>> {
        match self.name.as_str() {
            "map_values" => {
                if self.args.is_empty() {
                    bail!("map_values expects an expression");
                }
                match input {
                    Value::Sequence(seq) => {
                        let mut result = seq.clone();
                        for item in &mut result {
                            let items = eval_override_expression_list(&self.args, item)?;
                            if let Some(first) = items.into_iter().next() {
                                *item = first;
                            }
                        }
                        Ok(vec![Value::Sequence(result)])
                    }
                    Value::Mapping(map) => {
                        let mut result = map.clone();
                        let keys: Vec<Value> = result.keys().cloned().collect();
                        for key in keys {
                            let current = result.get(&key).cloned().unwrap_or(Value::Null);
                            let items = eval_override_expression_list(&self.args, &current)?;
                            if let Some(first) = items.into_iter().next() {
                                result.insert(key, first);
                            }
                        }
                        Ok(vec![Value::Mapping(result)])
                    }
                    other @ (Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) | Value::Tagged(_)) => {
                        bail!("map_values only supports arrays and mappings, got {}", override_type(other));
                    }
                }
            }
            other => bail!("unsupported stream function {other:?}"),
        }
    }

    fn eval_entries(&self, input: &Value) -> Result<Vec<Value>> {
        match self.name.as_str() {
            "to_entries" => {
                if !self.args.is_empty() {
                    bail!("to_entries expects no arguments");
                }
                match to_override_entries(input)? {
                    None => Ok(Vec::new()),
                    Some(entries) => Ok(vec![Value::Sequence(entries)]),
                }
            }
            "from_entries" => {
                if !self.args.is_empty() {
                    bail!("from_entries expects no arguments");
                }
                Ok(vec![Value::Mapping(from_override_entries(input)?)])
            }
            "with_entries" => {
                if self.args.is_empty() {
                    bail!("with_entries expects an expression");
                }
                if !matches!(input, Value::Mapping(_)) {
                    bail!("with_entries only supports mappings, got {}", override_type(input));
                }
                let Some(entries) = to_override_entries(input)? else {
                    return Ok(Vec::new());
                };
                let mut transformed = Vec::with_capacity(entries.len());
                for entry in &entries {
                    transformed.extend(eval_override_expression_list(&self.args, entry)?);
                }
                let value = from_override_entries(&Value::Sequence(transformed))?;
                Ok(vec![Value::Mapping(value)])
            }
            other => bail!("unsupported stream function {other:?}"),
        }
    }

    fn eval_condition(&self, input: &Value) -> Result<Vec<Value>> {
        match self.name.as_str() {
            "any_c" | "all_c" => {
                if self.args.is_empty() {
                    bail!("{} expects a condition", self.name);
                }
                let Value::Sequence(values) = input else {
                    bail!("{} only supports arrays, got {}", self.name, override_type(input));
                };
                let result = self.name == "all_c";
                for value in values {
                    let items = eval_override_expression_list(&self.args, value)?;
                    let Some(first) = items.into_iter().next() else { continue };
                    let matched = override_truthy(&first);
                    if self.name == "any_c" && matched {
                        return Ok(vec![Value::Bool(true)]);
                    }
                    if self.name == "all_c" && !matched {
                        return Ok(vec![Value::Bool(false)]);
                    }
                }
                Ok(vec![Value::Bool(result)])
            }
            other => bail!("unsupported stream function {other:?}"),
        }
    }
}

fn override_collection_values(input: &Value) -> Result<Vec<Value>> {
    match input {
        Value::Sequence(values) => Ok(values.clone()),
        Value::Mapping(map) => {
            let mut keys: Vec<String> = map.keys().filter_map(|k| k.as_str().map(str::to_owned)).collect();
            keys.sort();
            Ok(keys.into_iter().filter_map(|k| map.get(k.as_str()).cloned()).collect())
        }
        other @ (Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) | Value::Tagged(_)) => {
            bail!("expected array or mapping, got {}", override_type(other))
        }
    }
}

fn to_override_entries(input: &Value) -> Result<Option<Vec<Value>>> {
    match input {
        Value::Null => Ok(None),
        Value::Sequence(values) => {
            let result = values
                .iter()
                .enumerate()
                .map(|(idx, item)| {
                    let mut entry = Mapping::new();
                    entry.insert(Value::String("key".to_owned()), Value::from(override_len_i64(idx)));
                    entry.insert(Value::String("value".to_owned()), item.clone());
                    Value::Mapping(entry)
                })
                .collect();
            Ok(Some(result))
        }
        Value::Mapping(map) => {
            let mut keys: Vec<String> = map.keys().filter_map(|k| k.as_str().map(str::to_owned)).collect();
            keys.sort();
            let result = keys
                .into_iter()
                .map(|key| {
                    let value = map.get(key.as_str()).cloned().unwrap_or(Value::Null);
                    let mut entry = Mapping::new();
                    entry.insert(Value::String("key".to_owned()), Value::String(key));
                    entry.insert(Value::String("value".to_owned()), value);
                    Value::Mapping(entry)
                })
                .collect();
            Ok(Some(result))
        }
        other @ (Value::Bool(_) | Value::Number(_) | Value::String(_) | Value::Tagged(_)) => {
            bail!("{} has no keys", override_type(other));
        }
    }
}

fn from_override_entries(input: &Value) -> Result<Mapping> {
    let Value::Sequence(entries) = input else {
        bail!("from_entries only supports arrays");
    };
    let mut result = Mapping::new();
    for (idx, item) in entries.iter().enumerate() {
        let Value::Mapping(entry) = item else {
            bail!("entry {idx} must be a mapping");
        };
        let Some(key) = entry.get("key") else {
            bail!("entry {idx} has no key");
        };
        let Some(value) = entry.get("value") else {
            bail!("entry {idx} has no value");
        };
        let Value::String(key_string) = key else {
            bail!("entry {idx} key must be a string in override-expr");
        };
        result.insert(Value::String(key_string.clone()), value.clone());
    }
    Ok(result)
}

fn is_override_function(name: &str) -> bool {
    matches!(
        name,
        "length"
            | "type"
            | "keys"
            | "has"
            | "contains"
            | "select"
            | "sub"
            | "test"
            | "split"
            | "join"
            | "upcase"
            | "downcase"
            | "trim"
            | "tostring"
            | "tonumber"
            | "not"
            | "reverse"
            | "sort"
            | "unique"
            | "flatten"
            | "any"
            | "all"
            | "map"
            | "map_values"
            | "filter"
            | "to_entries"
            | "from_entries"
            | "with_entries"
            | "any_c"
            | "all_c"
    )
}

fn is_override_stream_function(name: &str) -> bool {
    matches!(name, "map" | "map_values" | "filter" | "to_entries" | "from_entries" | "with_entries" | "any_c" | "all_c")
}

impl FunctionExpr {
    fn eval(&self, input: &Value) -> Result<Value> {
        if is_no_match(input) {
            return Ok(input.clone());
        }
        let mut args = Vec::with_capacity(self.args.len());
        for arg in &self.args {
            args.push(arg.eval(input)?);
        }
        match self.name.as_str() {
            "select" | "not" | "type" | "length" => self.eval_scalar_query(input, &args),
            "keys" | "has" | "contains" => self.eval_collection_query(input, &args),
            "reverse" | "sort" | "unique" => self.eval_array_transform(input, &args),
            "flatten" | "any" | "all" => self.eval_array_reduce(input, &args),
            "sub" | "test" | "split" | "join" | "upcase" | "downcase" | "trim" => self.eval_string_query(input, &args),
            "tostring" | "tonumber" => self.eval_conversion(input, &args),
            other => bail!("unsupported function {other:?}"),
        }
    }

    fn arg_count(&self, args: &[Value], want: &[usize]) -> Result<()> {
        if want.contains(&args.len()) {
            Ok(())
        } else {
            bail!("{} expects {:?} arguments, got {}", self.name, want, args.len());
        }
    }

    fn string_arg(&self, args: &[Value], index: usize) -> Result<String> {
        match args.get(index) {
            Some(Value::String(s)) => Ok(s.clone()),
            _ => bail!("{} argument {} must be a string", self.name, index + 1),
        }
    }

    fn required_arg<'a>(&self, args: &'a [Value], index: usize) -> Result<&'a Value> {
        args.get(index).ok_or_else(|| anyhow!("{} argument {} is missing", self.name, index + 1))
    }

    fn eval_scalar_query(&self, input: &Value, args: &[Value]) -> Result<Value> {
        match self.name.as_str() {
            "select" => {
                self.arg_count(args, &[1])?;
                let argument = self.required_arg(args, 0)?;
                if is_no_match(argument) || !override_truthy(argument) {
                    return Ok(no_match_value());
                }
                Ok(input.clone())
            }
            "not" => {
                self.arg_count(args, &[0])?;
                Ok(Value::Bool(!override_truthy(input)))
            }
            "type" => {
                self.arg_count(args, &[0])?;
                Ok(Value::String(override_type(input).to_owned()))
            }
            "length" => {
                self.arg_count(args, &[0])?;
                match input {
                    Value::Null => Ok(Value::from(0i64)),
                    Value::String(s) => Ok(Value::from(override_len_i64(s.len()))),
                    Value::Sequence(v) => Ok(Value::from(override_len_i64(v.len()))),
                    Value::Mapping(m) => Ok(Value::from(override_len_i64(m.len()))),
                    other @ (Value::Bool(_) | Value::Number(_) | Value::Tagged(_)) => {
                        let (_, _, numeric) = override_number(other);
                        if numeric || matches!(other, Value::Bool(_)) {
                            Ok(Value::from(override_len_i64(format_scalar(other).len())))
                        } else {
                            bail!("length cannot be used with {}", override_type(other));
                        }
                    }
                }
            }
            other => bail!("unsupported function {other:?}"),
        }
    }

    fn eval_collection_query(&self, input: &Value, args: &[Value]) -> Result<Value> {
        match self.name.as_str() {
            "keys" => {
                self.arg_count(args, &[0])?;
                match input {
                    Value::Mapping(map) => {
                        let mut keys: Vec<String> = map.keys().filter_map(|k| k.as_str().map(str::to_owned)).collect();
                        keys.sort();
                        Ok(Value::Sequence(keys.into_iter().map(Value::String).collect()))
                    }
                    Value::Sequence(values) => {
                        Ok(Value::Sequence((0..override_len_i64(values.len())).map(Value::from).collect()))
                    }
                    other @ (Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) | Value::Tagged(_)) => {
                        bail!("{} cannot be used with {}", self.name, override_type(other))
                    }
                }
            }
            "has" => {
                self.arg_count(args, &[1])?;
                match input {
                    Value::Mapping(map) => {
                        let key = self.string_arg(args, 0)?;
                        Ok(Value::Bool(map.contains_key(key.as_str())))
                    }
                    Value::Sequence(values) => {
                        let (number, integer, ok) = override_number(self.required_arg(args, 0)?);
                        if !ok || !integer {
                            return Ok(Value::Bool(false));
                        }
                        let mut index = override_number_to_i64(number);
                        if index < 0 {
                            index += override_len_i64(values.len());
                        }
                        Ok(Value::Bool(usize::try_from(index).is_ok_and(|index| index < values.len())))
                    }
                    Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) | Value::Tagged(_) => {
                        Ok(Value::Bool(false))
                    }
                }
            }
            "contains" => {
                self.arg_count(args, &[1])?;
                let argument = self.required_arg(args, 0)?;
                match input {
                    Value::String(value) => {
                        let needle = self.string_arg(args, 0)?;
                        Ok(Value::Bool(value.contains(&needle)))
                    }
                    Value::Sequence(value) => {
                        if !matches!(argument, Value::Sequence(_)) {
                            bail!("{} cannot check contained in !!seq", override_type(argument));
                        }
                        Ok(Value::Bool(override_contains(&Value::Sequence(value.clone()), argument)))
                    }
                    Value::Mapping(value) => {
                        if !matches!(argument, Value::Mapping(_)) {
                            bail!("{} cannot check contained in !!map", override_type(argument));
                        }
                        Ok(Value::Bool(override_contains(&Value::Mapping(value.clone()), argument)))
                    }
                    other @ (Value::Null | Value::Bool(_) | Value::Number(_) | Value::Tagged(_)) => {
                        if !is_override_scalar(argument) {
                            bail!("{} cannot check contained in {}", override_type(argument), override_type(other));
                        }
                        if override_type(other) != override_type(argument) {
                            return Ok(Value::Bool(false));
                        }
                        Ok(Value::Bool(override_equal(other, argument)))
                    }
                }
            }
            other => bail!("unsupported function {other:?}"),
        }
    }

    fn eval_array_transform(&self, input: &Value, args: &[Value]) -> Result<Value> {
        match self.name.as_str() {
            "reverse" => {
                self.arg_count(args, &[0])?;
                let Value::Sequence(values) = input else {
                    bail!("reverse only supports arrays, got {}", override_type(input));
                };
                let mut result = values.clone();
                result.reverse();
                Ok(Value::Sequence(result))
            }
            "sort" => {
                self.arg_count(args, &[0])?;
                let Value::Sequence(values) = input else {
                    bail!("sort only supports arrays in override-expr, got {}", override_type(input));
                };
                let mut result = values.clone();
                let mut sort_err = None;
                result.sort_by(|a, b| match compare_override_sort_values(a, b) {
                    Ok(c) => c.cmp(&0),
                    Err(e) => {
                        if sort_err.is_none() {
                            sort_err = Some(e);
                        }
                        std::cmp::Ordering::Equal
                    }
                });
                if let Some(e) = sort_err {
                    return Err(e);
                }
                Ok(Value::Sequence(result))
            }
            "unique" => {
                self.arg_count(args, &[0])?;
                let Value::Sequence(values) = input else {
                    bail!("unique only supports arrays, got {}", override_type(input));
                };
                let mut result = Vec::with_capacity(values.len());
                let mut seen = HashSet::with_capacity(values.len());
                for value in values {
                    let key = override_unique_key(value)?;
                    if seen.insert(key) {
                        result.push(value.clone());
                    }
                }
                Ok(Value::Sequence(result))
            }
            other => bail!("unsupported function {other:?}"),
        }
    }

    fn eval_array_reduce(&self, input: &Value, args: &[Value]) -> Result<Value> {
        match self.name.as_str() {
            "flatten" => {
                self.arg_count(args, &[0, 1])?;
                let Value::Sequence(values) = input else {
                    bail!("flatten only supports arrays, got {}", override_type(input));
                };
                let depth = if args.len() == 1 {
                    let (number, integer, ok) = override_number(self.required_arg(args, 0)?);
                    if !ok || !integer || number < 0.0 {
                        bail!("flatten depth must be a non-negative integer");
                    }
                    override_number_to_i64(number)
                } else {
                    -1i64
                };
                Ok(Value::Sequence(flatten_override_array(values, depth)))
            }
            "any" | "all" => {
                self.arg_count(args, &[0])?;
                let Value::Sequence(values) = input else {
                    bail!("{} only supports arrays, got {}", self.name, override_type(input));
                };
                let result = self.name == "all";
                for value in values {
                    if self.name == "any" && override_truthy(value) {
                        return Ok(Value::Bool(true));
                    }
                    if self.name == "all" && !override_truthy(value) {
                        return Ok(Value::Bool(false));
                    }
                }
                Ok(Value::Bool(result))
            }
            other => bail!("unsupported function {other:?}"),
        }
    }

    fn eval_string_query(&self, input: &Value, args: &[Value]) -> Result<Value> {
        match self.name.as_str() {
            "sub" | "test" => {
                if self.name == "test" {
                    self.arg_count(args, &[1, 2])?;
                    if args.len() == 2 {
                        let options = self.string_arg(args, 1)?;
                        if !options.trim_matches('g').is_empty() {
                            bail!("unsupported test options {options:?}");
                        }
                    }
                } else {
                    self.arg_count(args, &[2])?;
                }
                let Value::String(value) = input else {
                    bail!("{} requires string input", self.name);
                };
                let pattern = self.string_arg(args, 0)?;
                let re = regex::Regex::new(&pattern).map_err(|e| anyhow!("invalid regular expression: {e}"))?;
                if self.name == "test" {
                    return Ok(Value::Bool(re.is_match(value)));
                }
                let replacement = self.string_arg(args, 1)?;
                Ok(Value::String(re.replace_all(value, replacement.as_str()).into_owned()))
            }
            "split" => {
                self.arg_count(args, &[1])?;
                if input.is_null() {
                    return Ok(no_match_value());
                }
                let Value::String(value) = input else {
                    bail!("split requires string input");
                };
                let separator = self.string_arg(args, 0)?;
                Ok(Value::Sequence(value.split(separator.as_str()).map(|s| Value::String(s.to_owned())).collect()))
            }
            "join" => {
                self.arg_count(args, &[1])?;
                let Value::Sequence(values) = input else {
                    bail!("join requires array input");
                };
                let separator = self.string_arg(args, 0)?;
                let parts: Vec<String> = values
                    .iter()
                    .map(|value| match value {
                        Value::Null | Value::Sequence(_) | Value::Mapping(_) => String::new(),
                        Value::String(s) => s.clone(),
                        other @ (Value::Bool(_) | Value::Number(_) | Value::Tagged(_)) => format_scalar(other),
                    })
                    .collect();
                Ok(Value::String(parts.join(&separator)))
            }
            "upcase" | "downcase" | "trim" => {
                self.arg_count(args, &[0])?;
                let Value::String(value) = input else {
                    bail!("{} requires string input", self.name);
                };
                Ok(Value::String(match self.name.as_str() {
                    "upcase" => value.to_uppercase(),
                    "downcase" => value.to_lowercase(),
                    _ => value.trim().to_owned(),
                }))
            }
            other => bail!("unsupported function {other:?}"),
        }
    }

    fn eval_conversion(&self, input: &Value, args: &[Value]) -> Result<Value> {
        match self.name.as_str() {
            "tostring" => {
                self.arg_count(args, &[0])?;
                if let Value::String(value) = input {
                    return Ok(Value::String(value.clone()));
                }
                let encoded = yaml::marshal(&sorted_for_marshal(input))?;
                let encoded = String::from_utf8(encoded)?;
                Ok(Value::String(encoded.trim_end_matches('\n').to_owned()))
            }
            "tonumber" => {
                self.arg_count(args, &[0])?;
                if override_number(input).2 {
                    return Ok(input.clone());
                }
                let Value::String(value) = input else {
                    bail!("tonumber requires string or number input");
                };
                let (base, digits) = if let Some(rest) = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")) {
                    (16, rest)
                } else if let Some(rest) = value.strip_prefix("0o") {
                    (8, rest)
                } else if value.starts_with("0b") || value.starts_with("0B") {
                    bail!("cannot convert {value:?} to number");
                } else {
                    (10, value.as_str())
                };
                if let Ok(integer) = i64::from_str_radix(digits, base) {
                    return Ok(Value::from(integer));
                }
                let number: f64 = value.parse().map_err(|_| anyhow!("cannot convert {value:?} to number"))?;
                Ok(Value::from(number))
            }
            other => bail!("unsupported function {other:?}"),
        }
    }
}

fn evaluate_override_binary(operator: &str, left: &Value, right: &Value) -> Result<Value> {
    match operator {
        "and" => Ok(Value::Bool(override_truthy(left) && override_truthy(right))),
        "or" => Ok(Value::Bool(override_truthy(left) || override_truthy(right))),
        "//" => Ok(if override_truthy(left) { left.clone() } else { right.clone() }),
        "==" => Ok(Value::Bool(override_yq_equal(left, right))),
        "!=" => Ok(Value::Bool(!override_yq_equal(left, right))),
        "<" | "<=" | ">" | ">=" => {
            if !is_override_scalar(left) || !is_override_scalar(right) {
                bail!("cannot compare {} and {}", override_type(left), override_type(right));
            }
            if left.is_null() || right.is_null() {
                let both_null = left.is_null() && right.is_null();
                return Ok(Value::Bool(both_null && (operator == "<=" || operator == ">=")));
            }
            let comparison = compare_override_values(left, right)?;
            Ok(Value::Bool(match operator {
                "<" => comparison < 0,
                "<=" => comparison <= 0,
                ">" => comparison > 0,
                _ => comparison >= 0,
            }))
        }
        "+" => add_override_values(left, right),
        "-" => {
            if left.is_null() {
                return Ok(right.clone());
            }
            if let Value::Sequence(left_array) = left {
                let Value::Sequence(right_array) = right else {
                    bail!("{} cannot be subtracted from !!seq", override_type(right));
                };
                let mut result = Vec::with_capacity(left_array.len());
                for item in left_array {
                    let remove = right_array.iter().any(|candidate| override_equal(item, candidate));
                    if !remove {
                        result.push(item.clone());
                    }
                }
                return Ok(Value::Sequence(result));
            }
            evaluate_override_numbers(operator, left, right)
        }
        "*" => multiply_override_values(left, right),
        "/" => divide_override_values(left, right),
        "%" => evaluate_override_numbers(operator, left, right),
        _ => bail!("unsupported operator {operator:?}"),
    }
}

fn add_override_values(left: &Value, right: &Value) -> Result<Value> {
    if left.is_null() {
        return Ok(right.clone());
    }
    if let Value::String(left_string) = left {
        if right.is_null() {
            return Ok(Value::String(left_string.clone()));
        }
        if !is_override_scalar(right) {
            bail!("cannot add string and {}", override_type(right));
        }
        return Ok(Value::String(format!("{left_string}{}", format_scalar(right))));
    }
    if let Value::Sequence(left_array) = left {
        let mut result = left_array.clone();
        if right.is_null() {
            return Ok(Value::Sequence(result));
        }
        if let Value::Sequence(right_array) = right {
            result.extend(right_array.clone());
        } else {
            result.push(right.clone());
        }
        return Ok(Value::Sequence(result));
    }
    if let Value::Mapping(left_map) = left {
        let Value::Mapping(right_map) = right else {
            bail!("cannot add mapping and {}", override_type(right));
        };
        let mut result = left_map.clone();
        for (key, value) in right_map {
            result.insert(key.clone(), value.clone());
        }
        return Ok(Value::Mapping(result));
    }
    if let Value::String(right_string) = right {
        if is_override_scalar(left) {
            return Ok(Value::String(format!("{}{right_string}", format_scalar(left))));
        }
    }
    evaluate_override_numbers("+", left, right)
}

fn multiply_override_values(left: &Value, right: &Value) -> Result<Value> {
    if right.is_null() {
        return Ok(left.clone());
    }
    if left.is_null() && matches!(right, Value::Sequence(_) | Value::Mapping(_)) {
        return Ok(right.clone());
    }
    if let Value::Mapping(left_map) = left {
        let Value::Mapping(right_map) = right else {
            bail!("cannot multiply mapping and {}", override_type(right));
        };
        return Ok(Value::Mapping(merge_override_maps(left_map, right_map)));
    }
    if matches!(left, Value::Sequence(_)) {
        if let Value::Sequence(right_array) = right {
            return Ok(Value::Sequence(right_array.clone()));
        }
    }
    if let Value::String(value) = left {
        let (count, integer, numeric) = override_number(right);
        if !numeric || !integer || count < 0.0 {
            bail!("string multiplier must be a non-negative integer");
        }
        if count > 10_000_000.0 {
            bail!("string multiplier cannot exceed 10 million");
        }
        return Ok(Value::String(value.repeat(override_number_to_usize(count))));
    }
    if let Value::String(value) = right {
        let (count, integer, numeric) = override_number(left);
        if !numeric || !integer || count < 0.0 {
            bail!("string multiplier must be a non-negative integer");
        }
        if count > 10_000_000.0 {
            bail!("string multiplier cannot exceed 10 million");
        }
        return Ok(Value::String(value.repeat(override_number_to_usize(count))));
    }
    evaluate_override_numbers("*", left, right)
}

fn divide_override_values(left: &Value, right: &Value) -> Result<Value> {
    if let Value::String(left_string) = left {
        let Value::String(right_string) = right else {
            bail!("operator / cannot be used with !!str and {}", override_type(right));
        };
        if left_string.is_empty() {
            return Ok(Value::Sequence(Vec::new()));
        }
        let parts: Vec<Value> = left_string.split(right_string.as_str()).map(|s| Value::String(s.to_owned())).collect();
        return Ok(Value::Sequence(parts));
    }
    evaluate_override_numbers("/", left, right)
}

fn evaluate_override_numbers(operator: &str, left: &Value, right: &Value) -> Result<Value> {
    let (left_number, left_integer, left_ok) = override_number(left);
    let (right_number, right_integer, right_ok) = override_number(right);
    if !left_ok || !right_ok {
        bail!("operator {operator} cannot be used with {} and {}", override_type(left), override_type(right));
    }
    match operator {
        "+" => Ok(if left_integer && right_integer {
            Value::from(override_number_to_i64(left_number) + override_number_to_i64(right_number))
        } else {
            Value::from(left_number + right_number)
        }),
        "-" => Ok(if left_integer && right_integer {
            Value::from(override_number_to_i64(left_number) - override_number_to_i64(right_number))
        } else {
            Value::from(left_number - right_number)
        }),
        "*" => Ok(if left_integer && right_integer {
            Value::from(override_number_to_i64(left_number) * override_number_to_i64(right_number))
        } else {
            Value::from(left_number * right_number)
        }),
        "/" => Ok(Value::from(left_number / right_number)),
        "%" => {
            if left_integer && right_integer {
                if right_number == 0.0 {
                    bail!("cannot modulo by zero");
                }
                Ok(Value::from(override_number_to_i64(left_number) % override_number_to_i64(right_number)))
            } else {
                Ok(Value::from(left_number % right_number))
            }
        }
        _ => bail!("unsupported numeric operator {operator:?}"),
    }
}

fn compare_override_values(left: &Value, right: &Value) -> Result<i32> {
    let (left_number, _, left_ok) = override_number(left);
    if left_ok {
        let (right_number, _, right_ok) = override_number(right);
        if !right_ok {
            bail!("cannot compare number and {}", override_type(right));
        }
        return Ok(if left_number < right_number { -1 } else { i32::from(left_number > right_number) });
    }
    if let (Value::String(left_string), Value::String(right_string)) = (left, right) {
        return Ok(match left_string.cmp(right_string) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        });
    }
    bail!("cannot compare {} and {}", override_type(left), override_type(right));
}

fn compare_override_sort_values(left: &Value, right: &Value) -> Result<i32> {
    fn rank(value: &Value) -> i32 {
        match value {
            Value::Null => 0,
            Value::Bool(_) => 1,
            Value::String(_) => 3,
            Value::Sequence(_) | Value::Mapping(_) => 4,
            Value::Number(_) | Value::Tagged(_) => {
                let (_, _, numeric) = override_number(value);
                if numeric {
                    2
                } else {
                    4
                }
            }
        }
    }
    let left_rank = rank(left);
    let right_rank = rank(right);
    if left_rank != right_rank {
        return Ok(if left_rank < right_rank { -1 } else { 1 });
    }
    match left_rank {
        0 => Ok(0),
        1 => {
            let (Value::Bool(left_bool), Value::Bool(right_bool)) = (left, right) else {
                bail!("sort only supports scalar array values in override-expr");
            };
            Ok(match left_bool.cmp(right_bool) {
                std::cmp::Ordering::Equal => 0,
                std::cmp::Ordering::Less => -1,
                std::cmp::Ordering::Greater => 1,
            })
        }
        2 | 3 => compare_override_values(left, right),
        _ => bail!("sort only supports scalar array values in override-expr"),
    }
}

fn flatten_override_array(values: &[Value], depth: i64) -> Vec<Value> {
    let mut result = Vec::with_capacity(values.len());
    for value in values {
        if let Value::Sequence(children) = value {
            if depth != 0 {
                let next_depth = if depth > 0 { depth - 1 } else { depth };
                result.extend(flatten_override_array(children, next_depth));
                continue;
            }
        }
        result.push(value.clone());
    }
    result
}

fn override_unique_key(value: &Value) -> Result<String> {
    if is_override_scalar(value) {
        if value.is_null() {
            return Ok("null".to_owned());
        }
        return Ok(format_scalar(value));
    }
    let encoded = yaml::marshal(&sorted_for_marshal(value))?;
    Ok(String::from_utf8(encoded)?)
}

#[expect(
    clippy::cast_precision_loss,
    reason = "override arithmetic runs in the float64 domain"
)]
fn override_number(value: &Value) -> (f64, bool, bool) {
    match value {
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                (i as f64, true, true)
            } else if let Some(u) = n.as_u64() {
                (u as f64, true, true)
            } else if let Some(f) = n.as_f64() {
                (f, false, true)
            } else {
                (0.0, false, false)
            }
        }
        Value::Null | Value::Bool(_) | Value::String(_) | Value::Sequence(_) | Value::Mapping(_) | Value::Tagged(_) => {
            (0.0, false, false)
        }
    }
}

/// A float the caller validated as an integral count, as `i64`.
fn override_number_to_i64(number: f64) -> i64 {
    #[expect(clippy::cast_possible_truncation, reason = "callers validate the float as an integral count")]
    let count = number as i64;
    count
}

/// A float the caller validated as a non-negative integral count, as `usize`.
fn override_number_to_usize(number: f64) -> usize {
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "callers validate the float as a non-negative integral count"
    )]
    let count = number as usize;
    count
}

#[expect(clippy::float_cmp, reason = "the compared operands are integral counts")]
fn override_equal(left: &Value, right: &Value) -> bool {
    let (left_number, left_integer, left_ok) = override_number(left);
    if left_ok {
        let (right_number, right_integer, right_ok) = override_number(right);
        return right_ok && left_integer == right_integer && left_number == right_number;
    }
    left == right
}

#[expect(clippy::float_cmp, reason = "the compared operands are integral counts")]
fn override_yq_equal(left: &Value, right: &Value) -> bool {
    if !is_override_scalar(left) || !is_override_scalar(right) {
        return false;
    }
    if left.is_null() || right.is_null() {
        return left.is_null() && right.is_null();
    }
    let (left_number, left_integer, left_numeric) = override_number(left);
    let (right_number, right_integer, right_numeric) = override_number(right);
    if left_numeric && right_numeric {
        return left_integer == right_integer && left_number == right_number;
    }
    format_scalar(left) == format_scalar(right)
}

fn is_override_scalar(value: &Value) -> bool {
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => true,
        Value::Number(_) | Value::Sequence(_) | Value::Mapping(_) | Value::Tagged(_) => override_number(value).2,
    }
}

fn override_contains(container: &Value, needle: &Value) -> bool {
    match container {
        Value::String(container_str) => matches!(needle, Value::String(s) if container_str.contains(s.as_str())),
        Value::Sequence(container_seq) => {
            let values: Vec<Value> = match needle {
                Value::Sequence(v) => v.clone(),
                other @ (Value::Null
                | Value::Bool(_)
                | Value::Number(_)
                | Value::String(_)
                | Value::Mapping(_)
                | Value::Tagged(_)) => vec![other.clone()],
            };
            values.iter().all(|wanted| {
                container_seq
                    .iter()
                    .any(|candidate| override_equal(candidate, wanted) || override_contains(candidate, wanted))
            })
        }
        Value::Mapping(container_map) => {
            let Value::Mapping(values) = needle else {
                return false;
            };
            values.iter().all(|(key, wanted)| match container_map.get(key) {
                Some(candidate) => override_equal(candidate, wanted) || override_contains(candidate, wanted),
                None => false,
            })
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::Tagged(_) => false,
    }
}

fn override_truthy(value: &Value) -> bool {
    if value.is_null() {
        return false;
    }
    match value {
        Value::Bool(b) => *b,
        Value::Null
        | Value::Number(_)
        | Value::String(_)
        | Value::Sequence(_)
        | Value::Mapping(_)
        | Value::Tagged(_) => true,
    }
}

fn override_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "!!null",
        Value::Bool(_) => "!!bool",
        Value::String(_) => "!!str",
        Value::Sequence(_) => "!!seq",
        Value::Mapping(_) => "!!map",
        Value::Number(_) | Value::Tagged(_) => {
            let (_, integer, numeric) = override_number(value);
            if numeric {
                if integer {
                    "!!int"
                } else {
                    "!!float"
                }
            } else {
                "!!unknown"
            }
        }
    }
}

fn merge_override_maps(left: &Mapping, right: &Mapping) -> Mapping {
    let mut result = left.clone();
    for (key, right_value) in right {
        let merged = if let (Some(Value::Mapping(left_map)), Value::Mapping(right_map)) = (result.get(key), right_value)
        {
            Value::Mapping(merge_override_maps(left_map, right_map))
        } else {
            right_value.clone()
        };
        result.insert(key.clone(), merged);
    }
    result
}

/// Formats the scalar kinds this module produces (bool, number, string, and the rarely reached
/// null case) matching the expected textual form.
fn format_scalar(value: &Value) -> String {
    match value {
        Value::Null => "<nil>".to_owned(),
        Value::Bool(b) => b.to_string(),
        Value::String(s) => s.clone(),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i.to_string()
            } else if let Some(u) = n.as_u64() {
                u.to_string()
            } else {
                format_float(n.as_f64().unwrap_or(0.0))
            }
        }
        Value::Sequence(_) | Value::Mapping(_) | Value::Tagged(_) => String::new(),
    }
}

/// Formats a `float64` in the shortest `%g`-style form the output expects.
fn format_float(v: f64) -> String {
    if v.is_nan() {
        return "NaN".to_owned();
    }
    if v.is_infinite() {
        return if v > 0.0 { "+Inf".to_owned() } else { "-Inf".to_owned() };
    }
    if v == 0.0 {
        return if v.is_sign_negative() { "-0".to_owned() } else { "0".to_owned() };
    }
    let negative = v < 0.0;
    let magnitude = v.abs();
    let scientific = format!("{magnitude:e}");
    let (mantissa, exponent_text) = scientific.split_once('e').unwrap_or((scientific.as_str(), "0"));
    let exponent: i32 = exponent_text.parse().unwrap_or(0);
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let digit_count = i32::try_from(digits.len()).unwrap_or(i32::MAX);
    let decimal_point = exponent + 1;
    let use_exponential = decimal_point - 1 < -4 || decimal_point > 21;

    let mut out = String::new();
    if negative {
        out.push('-');
    }
    if use_exponential {
        out.push_str(digits.get(..1).unwrap_or_default());
        if digit_count > 1 {
            out.push('.');
            out.push_str(digits.get(1..).unwrap_or_default());
        }
        out.push('e');
        let e = decimal_point - 1;
        out.push(if e >= 0 { '+' } else { '-' });
        let _ = write!(out, "{:02}", e.abs());
    } else if decimal_point <= 0 {
        out.push_str("0.");
        for _ in 0..(-decimal_point) {
            out.push('0');
        }
        out.push_str(&digits);
    } else if decimal_point >= digit_count {
        out.push_str(&digits);
        for _ in 0..(decimal_point - digit_count) {
            out.push('0');
        }
    } else {
        let point = usize::try_from(decimal_point).unwrap_or_default();
        out.push_str(digits.get(..point).unwrap_or_default());
        out.push('.');
        out.push_str(digits.get(point..).unwrap_or_default());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn must_override_exprs(sources: &[&str]) -> Vec<OverrideExpr> {
        sources.iter().map(|source| OverrideExpr::new(source).expect("parse override-expr")).collect()
    }

    fn apply_all(exprs: &[OverrideExpr], mapping: &mut Mapping) -> Result<()> {
        for expr in exprs {
            expr.apply(mapping)?;
        }
        Ok(())
    }

    fn yaml_mapping(text: &str) -> Mapping {
        serde_yaml::from_str(text).expect("parse test yaml mapping")
    }

    fn get<'a>(mapping: &'a Mapping, key: &str) -> &'a Value {
        mapping.get(key).unwrap_or_else(|| panic!("missing key {key:?}"))
    }

    #[test]
    fn text_round_trip() {
        let source = r#"  .name = "prefix-" + .name  # keep formatting"#;
        let mut expr = OverrideExpr::default();
        expr.unmarshal_text(source.as_bytes()).expect("unmarshal");
        assert_eq!(source.as_bytes(), expr.marshal_text().expect("marshal"));
        assert_eq!(source, expr.to_string());
    }

    #[test]
    fn assignments() {
        let mut mapping = yaml_mapping(
            r#"
name: node
existing: keep
ports: [80, 443]
tags: [base]
weights: {a: 1, b: 2}
"#,
        );
        let exprs = must_override_exprs(&[
            r#".udp = true"#,
            r#".skip-cert-verify = false"#,
            r#".plugin-opts.mode = "tls""#,
            r#".ports[1] = 8443"#,
            r#".slots[2].enabled = true"#,
            r#".weights[] += 1"#,
            r#"."quoted.field" = "quoted""#,
            r#".tags += ["edge"]"#,
            r#".missing = .missing // "fallback""#,
            r#".existing = .existing // "ignored""#,
        ]);

        apply_all(&exprs, &mut mapping).expect("apply");
        assert_eq!(get(&mapping, "udp"), &Value::Bool(true));
        assert_eq!(get(&mapping, "skip-cert-verify"), &Value::Bool(false));
        assert_eq!(get(&mapping, "plugin-opts"), &Value::Mapping(yaml_mapping("mode: tls")));
        assert_eq!(get(&mapping, "ports"), &Value::Sequence(vec![Value::from(80i64), Value::from(8443i64)]));
        assert_eq!(
            get(&mapping, "slots"),
            &Value::Sequence(vec![Value::Null, Value::Null, Value::Mapping(yaml_mapping("enabled: true"))])
        );
        assert_eq!(get(&mapping, "weights"), &Value::Mapping(yaml_mapping("a: 2\nb: 3")));
        assert_eq!(get(&mapping, "quoted.field"), &Value::String("quoted".to_owned()));
        assert_eq!(
            get(&mapping, "tags"),
            &Value::Sequence(vec![Value::String("base".to_owned()), Value::String("edge".to_owned())])
        );
        assert_eq!(get(&mapping, "missing"), &Value::String("fallback".to_owned()));
        assert_eq!(get(&mapping, "existing"), &Value::String("keep".to_owned()));
    }

    #[test]
    fn update_functions_and_conditional_path() {
        let mut mapping = yaml_mapping(
            r#"
name: HK-01
score: 3
labels: [edge, premium]
"#,
        );
        let exprs = must_override_exprs(&[
            r#".name |= sub("^HK-(.*)$"; "Hong Kong $1")"#,
            r#".name = "[Provider] " + .name"#,
            r#".score *= 2"#,
            r#".labels[] |= upcase"#,
            r#".enabled = (.score >= 6 and has("name"))"#,
            r#"(select(.score > 5) | .tier) = "fast" | (select(.score <= 5) | .tier) = "slow""#,
        ]);

        apply_all(&exprs, &mut mapping).expect("apply");
        assert_eq!(get(&mapping, "name"), &Value::String("[Provider] Hong Kong 01".to_owned()));
        assert_eq!(get(&mapping, "score"), &Value::from(6i64));
        assert_eq!(
            get(&mapping, "labels"),
            &Value::Sequence(vec![Value::String("EDGE".to_owned()), Value::String("PREMIUM".to_owned())])
        );
        assert_eq!(get(&mapping, "enabled"), &Value::Bool(true));
        assert_eq!(get(&mapping, "tier"), &Value::String("fast".to_owned()));
    }

    #[test]
    fn collections_and_delete() {
        let mut mapping = yaml_mapping(
            r#"
password: secret
obsolete: true
ports: [80, 443, 8080]
options:
  tls: {sni: example.com}
servers:
  - {host: a, secret: x}
  - {host: b, secret: y}
"#,
        );
        let exprs = must_override_exprs(&[
            r#".options *= {"tls": {"enabled": true}, "retries": 3}"#,
            r#".ports -= [80, 8080]"#,
            r#"del(.password, .obsolete)"#,
            r#"del(.servers[].secret)"#,
        ]);

        apply_all(&exprs, &mut mapping).expect("apply");
        assert!(!mapping.contains_key("password"));
        assert!(!mapping.contains_key("obsolete"));
        assert_eq!(get(&mapping, "ports"), &Value::Sequence(vec![Value::from(443i64)]));
        assert_eq!(
            get(&mapping, "options"),
            &Value::Mapping(yaml_mapping("tls: {sni: example.com, enabled: true}\nretries: 3"))
        );
        assert_eq!(
            get(&mapping, "servers"),
            &Value::Sequence(vec![Value::Mapping(yaml_mapping("host: a")), Value::Mapping(yaml_mapping("host: b"))])
        );
    }

    #[test]
    fn delete_uses_original_array_indexes() {
        let mut mapping = yaml_mapping("values: [0, 1, 2, 3]");
        let exprs = must_override_exprs(&["del(.values[0], .values[2])"]);

        apply_all(&exprs, &mut mapping).expect("apply");
        assert_eq!(get(&mapping, "values"), &Value::Sequence(vec![Value::from(1i64), Value::from(3i64)]));
    }

    #[test]
    fn yq_compatibility() {
        let mut mapping = yaml_mapping(
            r#"
name: edge-01
key.with.dot: quoted
items: [first, last]
csv: "a,b,c"
number: "42"
options: {b: 2, a: 1}
"#,
        );
        let exprs = must_override_exprs(&[
            r#".quoted = .["key.with.dot"]"#,
            r#".quoted-again = ."key.with.dot""#,
            r#".last = .items[-1]"#,
            r#".csv |= split(",") | .csv |= join("-")"#,
            r#".number |= tonumber"#,
            r#".name-length = .name | .name-length |= length"#,
            r#".option-keys = .options | .option-keys |= keys"#,
            r#".fallback = false // "default""#,
            r#".calculated = (5 + 3) * 2"#,
            r#". = . * {"root-merged": true}"#,
        ]);

        apply_all(&exprs, &mut mapping).expect("apply");
        assert_eq!(get(&mapping, "quoted"), &Value::String("quoted".to_owned()));
        assert_eq!(get(&mapping, "quoted-again"), &Value::String("quoted".to_owned()));
        assert_eq!(get(&mapping, "last"), &Value::String("last".to_owned()));
        assert_eq!(get(&mapping, "csv"), &Value::String("a-b-c".to_owned()));
        assert_eq!(get(&mapping, "number"), &Value::from(42i64));
        assert_eq!(get(&mapping, "name-length"), &Value::from(7i64));
        assert_eq!(
            get(&mapping, "option-keys"),
            &Value::Sequence(vec![Value::String("a".to_owned()), Value::String("b".to_owned())])
        );
        assert_eq!(get(&mapping, "fallback"), &Value::String("default".to_owned()));
        assert_eq!(get(&mapping, "calculated"), &Value::from(16i64));
        assert_eq!(get(&mapping, "root-merged"), &Value::Bool(true));
    }

    #[test]
    fn operators_and_functions() {
        struct Case {
            name: &'static str,
            input: &'static str,
            expr: &'static str,
            expected: &'static str,
        }
        let cases = [
            Case { name: "negative literal", input: "4", expr: r#".value = -4"#, expected: "-4" },
            Case { name: "not", input: "true", expr: r#".value |= not"#, expected: "false" },
            Case { name: "numeric subtraction", input: "5", expr: r#".value -= 2"#, expected: "3" },
            Case { name: "division", input: "5", expr: r#".value = .value / 2"#, expected: "2.5" },
            Case { name: "string division", input: r#""a,b""#, expr: r#".value = .value / ",""#, expected: "[a, b]" },
            Case { name: "empty string division", input: r#""""#, expr: r#".value = .value / ",""#, expected: "[]" },
            Case {
                name: "split null can default",
                input: "null",
                expr: r#".value = (.value | split(",")) // "fallback""#,
                expected: r#""fallback""#,
            },
            Case { name: "modulo", input: "5", expr: r#".value = .value % 2"#, expected: "1" },
            Case { name: "float modulo", input: "5.5", expr: r#".value = .value % 2"#, expected: "1.5" },
            Case { name: "repeat", input: r#""ab""#, expr: r#".value *= 2"#, expected: r#""abab""# },
            Case {
                name: "repeat with integer first",
                input: r#""ab""#,
                expr: r#".value = 2 * .value"#,
                expected: r#""abab""#,
            },
            Case { name: "multiply null identity", input: "[1]", expr: r#".value = .value * null"#, expected: "[1]" },
            Case {
                name: "multiply arrays replaces left",
                input: "[1]",
                expr: r#".value = .value * [2]"#,
                expected: "[2]",
            },
            Case {
                name: "sub replaces all",
                input: r#""a-b-c""#,
                expr: r#".value |= sub("-", "_")"#,
                expected: r#""a_b_c""#,
            },
            Case { name: "test", input: r#""edge-01""#, expr: r#".value |= test("^edge-")"#, expected: "true" },
            Case {
                name: "contains string",
                input: r#""edge-01""#,
                expr: r#".value |= contains("ge-")"#,
                expected: "true",
            },
            Case { name: "contains array", input: "[1, 2]", expr: r#".value |= contains([2])"#, expected: "true" },
            Case { name: "contains scalar", input: "2", expr: r#".value |= contains(2)"#, expected: "true" },
            Case {
                name: "string plus number",
                input: r#""port-""#,
                expr: r#".value = .value + 443"#,
                expected: r#""port-443""#,
            },
            Case { name: "array plus scalar", input: "[1]", expr: r#".value = .value + 2"#, expected: "[1, 2]" },
            Case { name: "null subtraction", input: "null", expr: r#".value = .value - 2"#, expected: "2" },
            Case { name: "not equal", input: "2", expr: r#".value = .value != 1"#, expected: "true" },
            Case {
                name: "numeric types are distinct",
                input: "1",
                expr: r#".value = .value == 1.0"#,
                expected: "false",
            },
            Case { name: "scalar equality uses text", input: "1", expr: r#".value = .value == "1""#, expected: "true" },
            Case {
                name: "boolean equality uses text",
                input: "true",
                expr: r#".value = .value == "true""#,
                expected: "true",
            },
            Case { name: "less than", input: "1", expr: r#".value = .value < 2"#, expected: "true" },
            Case { name: "boolean or", input: "false", expr: r#".value = (.value or true)"#, expected: "true" },
            Case {
                name: "trim downcase",
                input: r#""  EDGE  ""#,
                expr: r#".value |= trim | .value |= downcase"#,
                expected: r#""edge""#,
            },
            Case { name: "type", input: "[1]", expr: r#".value |= type"#, expected: r#""!!seq""# },
            Case { name: "map type", input: "{a: 1}", expr: r#".value |= type"#, expected: r#""!!map""# },
            Case { name: "array keys", input: r#"["a", "b"]"#, expr: r#".value |= keys"#, expected: "[0, 1]" },
            Case { name: "has array index", input: r#"["a"]"#, expr: r#".value |= has(0)"#, expected: "true" },
            Case {
                name: "has negative array index",
                input: r#"["a"]"#,
                expr: r#".value |= has(-1)"#,
                expected: "true",
            },
            Case {
                name: "contains keeps scalar tags distinct",
                input: "1",
                expr: r#".value |= contains(1.0)"#,
                expected: "false",
            },
            Case {
                name: "test accepts global option",
                input: r#""edge-edge""#,
                expr: r#".value |= test("edge", "g")"#,
                expected: "true",
            },
            Case {
                name: "null alternative",
                input: "null",
                expr: r#".value = ~ // "fallback""#,
                expected: r#""fallback""#,
            },
        ];

        for case in cases {
            let mut mapping = yaml_mapping(&format!("value: {}", case.input));
            let exprs = must_override_exprs(&[case.expr]);
            apply_all(&exprs, &mut mapping).unwrap_or_else(|e| panic!("{}: {e}", case.name));
            let expected: Value = serde_yaml::from_str(case.expected).expect("parse expected");
            assert_eq!(get(&mapping, "value"), &expected, "case {}", case.name);
        }

        let mut to_string_mapping = yaml_mapping("value: [1, 2]");
        apply_all(&must_override_exprs(&[r#".value |= tostring"#]), &mut to_string_mapping).expect("apply");
        assert_eq!(get(&to_string_mapping, "value"), &Value::String("- 1\n- 2".to_owned()));

        let mut map_to_string_mapping = yaml_mapping("value: {a: 1}");
        apply_all(&must_override_exprs(&[r#".value |= tostring"#]), &mut map_to_string_mapping).expect("apply");
        assert_eq!(get(&map_to_string_mapping, "value"), &Value::String("a: 1".to_owned()));

        let mut comma_mapping = yaml_mapping(r#"value: "a-b""#);
        apply_all(&must_override_exprs(&[r#".value |= sub("-", "_")"#]), &mut comma_mapping).expect("apply");
        assert_eq!(get(&comma_mapping, "value"), &Value::String("a_b".to_owned()));
    }

    #[test]
    fn division_and_modulo_by_zero() {
        let mut mapping = yaml_mapping("one: 1\nzero: 0\nfloat: 1.5");
        let exprs = must_override_exprs(&[
            ".infinite = .one / .zero",
            ".not-a-number = .zero / .zero",
            ".float-modulo = .float % .zero",
        ]);

        apply_all(&exprs, &mut mapping).expect("apply");
        let infinite = get(&mapping, "infinite").as_f64().expect("float");
        let nan = get(&mapping, "not-a-number").as_f64().expect("float");
        let float_modulo = get(&mapping, "float-modulo").as_f64().expect("float");
        assert!(infinite.is_infinite() && infinite > 0.0);
        assert!(nan.is_nan());
        assert!(float_modulo.is_nan());
    }

    #[test]
    fn select_and_pipelines() {
        let mut mapping = yaml_mapping(
            r#"
name: " edge "
score: 8
servers:
  - {name: first, enabled: true}
  - {name: second, enabled: false}
"#,
        );
        let exprs = must_override_exprs(&[
            r#".name = (.name | trim | upcase)"#,
            r#"(select(.score > 5) | .tier) = "fast""#,
            r#"(select(.score < 0) | .ignored) = true"#,
            r#"(.servers[] | select(.enabled) | .name) |= upcase"#,
        ]);

        apply_all(&exprs, &mut mapping).expect("apply");
        assert_eq!(get(&mapping, "name"), &Value::String("EDGE".to_owned()));
        assert_eq!(get(&mapping, "tier"), &Value::String("fast".to_owned()));
        assert!(!mapping.contains_key("ignored"));
        assert_eq!(
            get(&mapping, "servers"),
            &Value::Sequence(vec![
                Value::Mapping(yaml_mapping("name: FIRST\nenabled: true")),
                Value::Mapping(yaml_mapping("name: second\nenabled: false"))
            ])
        );

        let mut low_score = yaml_mapping("score: 3");
        let conditional =
            must_override_exprs(&[r#"(select(.score > 5) | .tier) = "fast" | (select(.score <= 5) | .tier) = "slow""#]);
        apply_all(&conditional, &mut low_score).expect("apply");
        assert_eq!(get(&low_score, "tier"), &Value::String("slow".to_owned()));
    }

    #[test]
    fn yq_behavior_details() {
        struct Case {
            name: &'static str,
            input: &'static str,
            expr: &'static str,
            expected: &'static str,
        }
        let cases = [
            Case {
                name: "scalar path produces null",
                input: r#""text""#,
                expr: r#".result = .value.missing"#,
                expected: "null",
            },
            Case {
                name: "scalar path can default",
                input: r#""text""#,
                expr: r#".result = .value.missing // "fallback""#,
                expected: r#""fallback""#,
            },
            Case {
                name: "recursive contains array",
                input: r#"[{a: 1, b: 2}]"#,
                expr: r#".result = (.value | contains([{"a": 1}]))"#,
                expected: "true",
            },
            Case {
                name: "recursive contains map",
                input: r#"{a: {b: 1, c: 2}}"#,
                expr: r#".result = (.value | contains({"a": {"b": 1}}))"#,
                expected: "true",
            },
            Case { name: "float type", input: "1.0", expr: r#".result = (.value | type)"#, expected: r#""!!float""# },
            Case { name: "number length", input: "1234", expr: r#".result = (.value | length)"#, expected: "4" },
            Case { name: "bool length", input: "false", expr: r#".result = (.value | length)"#, expected: "5" },
            Case { name: "null length", input: "null", expr: r#".result = (.value | length)"#, expected: "0" },
            Case { name: "array length", input: "[1, 2]", expr: r#".result = (.value | length)"#, expected: "2" },
            Case { name: "map length", input: "{a: 1, b: 2}", expr: r#".result = (.value | length)"#, expected: "2" },
            Case {
                name: "unicode byte length",
                input: r#""a界""#,
                expr: r#".result = (.value | length)"#,
                expected: "4",
            },
            Case {
                name: "join skips collections",
                input: r#"["a", null, [1], {a: 1}, 2]"#,
                expr: r#".result = (.value | join("-"))"#,
                expected: r#""a----2""#,
            },
            Case {
                name: "has rejects float index",
                input: r#"["a"]"#,
                expr: r#".result = (.value | has(0.5))"#,
                expected: "false",
            },
            Case {
                name: "decimal leading zero",
                input: r#""010""#,
                expr: r#".result = (.value | tonumber)"#,
                expected: "10",
            },
            Case { name: "octal", input: r#""0o10""#, expr: r#".result = (.value | tonumber)"#, expected: "8" },
            Case { name: "hexadecimal", input: r#""0x10""#, expr: r#".result = (.value | tonumber)"#, expected: "16" },
            Case { name: "float", input: r#""1.5""#, expr: r#".result = (.value | tonumber)"#, expected: "1.5" },
            Case {
                name: "array equality",
                input: "[1, 2]",
                expr: r#".result = (.value == [1, 2])"#,
                expected: "false",
            },
            Case {
                name: "mapping inequality",
                input: "{a: 1}",
                expr: r#".result = (.value != {"a": 1})"#,
                expected: "true",
            },
            Case { name: "null comparison", input: "null", expr: r#".result = (.value < false)"#, expected: "false" },
            Case {
                name: "null equality comparison",
                input: "null",
                expr: r#".result = (.value <= null)"#,
                expected: "true",
            },
        ];

        for case in cases {
            let mut mapping = yaml_mapping(&format!("value: {}", case.input));
            let exprs = must_override_exprs(&[case.expr]);
            apply_all(&exprs, &mut mapping).unwrap_or_else(|e| panic!("{}: {e}", case.name));
            assert!(mapping.contains_key("result"), "case {}", case.name);
            let expected: Value = serde_yaml::from_str(case.expected).expect("parse expected");
            assert_eq!(get(&mapping, "result"), &expected, "case {}", case.name);
        }

        let mut escape_mapping = yaml_mapping("value: null");
        apply_all(&must_override_exprs(&[r#".result = "a\tb\u754c""#]), &mut escape_mapping).expect("apply");
        assert_eq!(get(&escape_mapping, "result"), &Value::String(r"a\tb\u754c".to_owned()));
    }

    #[test]
    fn interpolation_and_collections() {
        let mut mapping = yaml_mapping(
            r#"
name: node
type: ss
port: 443
options: {b: 2, a: 1}
mixed: [3, null, false, 2, true]
duplicates: [1, 1, "1", "1"]
nested: [1, [2, [3]]]
truthy: [null, false, "value"]
all-true: [1, "value", true]
"#,
        );
        let exprs = must_override_exprs(&[
            r#".label = "[\(.type)] \(.name):\(.port)""#,
            r#".fallback-label = "\(.missing // \"default\")-\(.name)""#,
            r#".first-label = "\((.name, .type))""#,
            r#".options-text = "\(.options)""#,
            r#".hex = 0x10"#,
            r#".reversed = (.mixed | reverse)"#,
            r#".sorted = (.mixed | sort)"#,
            r#".deduplicated = (.duplicates | unique)"#,
            r#".flattened = (.nested | flatten)"#,
            r#".flattened-once = (.nested | flatten(1))"#,
            r#".has-truthy = (.truthy | any)"#,
            r#".all-truthy = (.all-true | all)"#,
        ]);

        apply_all(&exprs, &mut mapping).expect("apply");
        assert_eq!(get(&mapping, "label"), &Value::String("[ss] node:443".to_owned()));
        assert_eq!(get(&mapping, "fallback-label"), &Value::String("default-node".to_owned()));
        assert_eq!(get(&mapping, "first-label"), &Value::String("node".to_owned()));
        assert_eq!(get(&mapping, "options-text"), &Value::String("a: 1\nb: 2".to_owned()));
        assert_eq!(get(&mapping, "hex"), &Value::from(16i64));
        assert_eq!(
            get(&mapping, "reversed"),
            &Value::Sequence(vec![
                Value::Bool(true),
                Value::from(2i64),
                Value::Bool(false),
                Value::Null,
                Value::from(3i64)
            ])
        );
        assert_eq!(
            get(&mapping, "sorted"),
            &Value::Sequence(vec![
                Value::Null,
                Value::Bool(false),
                Value::Bool(true),
                Value::from(2i64),
                Value::from(3i64)
            ])
        );
        assert_eq!(get(&mapping, "deduplicated"), &Value::Sequence(vec![Value::from(1i64)]));
        assert_eq!(
            get(&mapping, "flattened"),
            &Value::Sequence(vec![Value::from(1i64), Value::from(2i64), Value::from(3i64)])
        );
        assert_eq!(
            get(&mapping, "flattened-once"),
            &Value::Sequence(vec![Value::from(1i64), Value::from(2i64), Value::Sequence(vec![Value::from(3i64)])])
        );
        assert_eq!(get(&mapping, "has-truthy"), &Value::Bool(true));
        assert_eq!(get(&mapping, "all-truthy"), &Value::Bool(true));
    }

    #[test]
    fn multi_result_pipelines() {
        let mut mapping = yaml_mapping(
            r#"
items:
  - {name: first, port: 80, enabled: true}
  - {name: second, port: 443, enabled: false}
scores: {a: 1, b: 2}
options: {a: 1, b: 2}
"#,
        );
        let exprs = must_override_exprs(&[
            r#".names = [.items[].name]"#,
            r#".enabled-names = [.items[] | select(.enabled) | .name]"#,
            r#".name-ports = [.items[] | (.name, .port)]"#,
            r#".incremented-ports = [.items[].port + 1]"#,
            r#".mapped-names = (.items | map(.name))"#,
            r#".mapped-union = (.items | map(.name, .port))"#,
            r#".filtered = (.items | filter(.enabled))"#,
            r#".mapped-scores = (.scores | map_values(. + 1))"#,
            r#".selected-scores = (.scores | map_values(select(. > 1)))"#,
            r#".entries = (.options | to_entries)"#,
            r#".roundtrip = (.options | to_entries | from_entries)"#,
            r#".upper-options = (.options | with_entries(.key |= upcase))"#,
            r#".has-large-port = ([.items[].port] | any_c(. > 100))"#,
            r#".all-positive = ([.items[].port] | all_c(. > 0))"#,
            r#".no-matches = [.items[] | select(false)]"#,
            r#".defaults = [.items[].missing // "default"]"#,
        ]);

        apply_all(&exprs, &mut mapping).expect("apply");
        assert_eq!(
            get(&mapping, "names"),
            &Value::Sequence(vec![Value::String("first".to_owned()), Value::String("second".to_owned())])
        );
        assert_eq!(get(&mapping, "enabled-names"), &Value::Sequence(vec![Value::String("first".to_owned())]));
        assert_eq!(
            get(&mapping, "name-ports"),
            &Value::Sequence(vec![
                Value::String("first".to_owned()),
                Value::String("second".to_owned()),
                Value::from(80i64),
                Value::from(443i64)
            ])
        );
        assert_eq!(get(&mapping, "incremented-ports"), &Value::Sequence(vec![Value::from(81i64), Value::from(444i64)]));
        assert_eq!(
            get(&mapping, "mapped-names"),
            &Value::Sequence(vec![Value::String("first".to_owned()), Value::String("second".to_owned())])
        );
        assert_eq!(
            get(&mapping, "mapped-union"),
            &Value::Sequence(vec![
                Value::String("first".to_owned()),
                Value::String("second".to_owned()),
                Value::from(80i64),
                Value::from(443i64)
            ])
        );
        assert_eq!(
            get(&mapping, "filtered"),
            &Value::Sequence(vec![Value::Mapping(yaml_mapping("name: first\nport: 80\nenabled: true"))])
        );
        assert_eq!(get(&mapping, "mapped-scores"), &Value::Mapping(yaml_mapping("a: 2\nb: 3")));
        assert_eq!(get(&mapping, "selected-scores"), &Value::Mapping(yaml_mapping("a: 1\nb: 2")));
        assert_eq!(
            get(&mapping, "entries"),
            &Value::Sequence(vec![
                Value::Mapping(yaml_mapping("key: a\nvalue: 1")),
                Value::Mapping(yaml_mapping("key: b\nvalue: 2"))
            ])
        );
        assert_eq!(get(&mapping, "roundtrip"), &Value::Mapping(yaml_mapping("a: 1\nb: 2")));
        assert_eq!(get(&mapping, "upper-options"), &Value::Mapping(yaml_mapping("A: 1\nB: 2")));
        assert_eq!(get(&mapping, "has-large-port"), &Value::Bool(true));
        assert_eq!(get(&mapping, "all-positive"), &Value::Bool(true));
        assert_eq!(get(&mapping, "no-matches"), &Value::Sequence(Vec::new()));
        assert_eq!(
            get(&mapping, "defaults"),
            &Value::Sequence(vec![Value::String("default".to_owned()), Value::String("default".to_owned())])
        );
    }

    #[test]
    fn mapping_values_use_yq_stream_semantics() {
        let mut mapping = yaml_mapping("items: [1, 2]");
        let exprs = must_override_exprs(&[r#".result = {"omitted": select(false), "last": (.items[])}"#]);

        apply_all(&exprs, &mut mapping).expect("apply");
        assert_eq!(get(&mapping, "result"), &Value::Mapping(yaml_mapping("last: 2")));
    }

    #[test]
    fn requires_multi_results_to_be_collected() {
        let mut mapping = yaml_mapping("items: [1, 2]");
        let exprs = must_override_exprs(&[r#".result = (.items[])"#]);

        let err = apply_all(&exprs, &mut mapping).expect_err("multiple results must be rejected");
        let message = err.to_string();
        assert!(message.contains("expression produced 2 results"), "{message}");
        assert!(message.contains("collect them with [...]"), "{message}");
    }

    #[test]
    fn top_level_filter_pipeline() {
        let mut mapping = yaml_mapping("name: node\nudp: false");
        let exprs = must_override_exprs(&[
            r#". | with_entries(.key |= upcase)"#,
            r#"{"name": .NAME, "udp": .UDP, "type": "ss"}"#,
        ]);

        apply_all(&exprs, &mut mapping).expect("apply");
        assert_eq!(mapping, yaml_mapping("name: node\nudp: false\ntype: ss"));
    }

    #[test]
    fn errors_syntax() {
        let err = OverrideExpr::new(".udp =").expect_err("empty right-hand side must fail");
        assert!(err.to_string().contains("expected value"), "{err}");
    }

    #[test]
    fn errors_runtime() {
        let exprs = must_override_exprs(&[r#".port += [1]"#]);
        let mut mapping = yaml_mapping("port: 443");
        let err = apply_all(&exprs, &mut mapping).expect_err("adding an array to a number must fail");
        assert!(err.to_string().contains("operator + cannot be used"), "{err}");
    }

    #[test]
    fn errors_string_repeat_limit() {
        let exprs = must_override_exprs(&[r#".value = "x" * 10000001"#]);
        let mut mapping = yaml_mapping(r#"value: "x""#);
        let err = apply_all(&exprs, &mut mapping).expect_err("string repeat above the limit must fail");
        assert!(err.to_string().contains("cannot exceed 10 million"), "{err}");
    }
}
