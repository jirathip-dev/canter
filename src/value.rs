//! Document value model shared by the #3 schema families.
//!
//! [`Val`] is a closed, lossless model of the JSON/TOML values the contract
//! families use. It can be produced from strict JSON text ([`Val::parse_json`])
//! or from TOML text ([`Val::parse_toml`], which uses the `toml` crate through
//! a custom `serde::Deserialize` implementation so the validator code in
//! [`crate::schema`] sees one uniform shape).
//!
//! Notes:
//! - TOML integers are 64-bit (`i64`); TOML floats become [`Val::Float`].
//! - TOML datetimes decode through serde into the string their RFC3339
//!   representation would carry; no contract family accepts them, which the
//!   closed-surface validators express by requiring explicit string/int/bool
//!   shapes (mirroring the Python fixture probe, which refuses non-string
//!   TOML scalar types).
//! - JSON parsing is deliberately strict: duplicate object keys are refused,
//!   numbers follow the RFC 8259 grammar, and trailing content is an error.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};

/// A document value: null, bool, integer, float, string, array, or object.
///
/// Objects keep keys in a `BTreeMap`, which is what makes deterministic
/// canonical serialization (sorted keys) trivial.
#[derive(Clone, Debug, PartialEq)]
pub enum Val {
    /// JSON `null` / absent TOML value.
    Null,
    /// Boolean.
    Bool(bool),
    /// Signed 64-bit integer (TOML and integral JSON numbers).
    Int(i64),
    /// Floating point (TOML floats and non-integral JSON numbers).
    Float(f64),
    /// String.
    Str(String),
    /// Array.
    Arr(Vec<Val>),
    /// Object with lexicographically ordered keys.
    Obj(BTreeMap<String, Val>),
}

impl Val {
    /// Human-readable type name used in validator messages.
    pub fn type_name(&self) -> &'static str {
        match self {
            Val::Null => "null",
            Val::Bool(_) => "boolean",
            Val::Int(_) => "integer",
            Val::Float(_) => "float",
            Val::Str(_) => "string",
            Val::Arr(_) => "array",
            Val::Obj(_) => "object",
        }
    }

    /// Look up an object key.
    pub fn get(&self, key: &str) -> Option<&Val> {
        match self {
            Val::Obj(map) => map.get(key),
            _ => None,
        }
    }

    /// Whether this value is null (JSON `null` / absent TOML key).
    pub fn is_null(&self) -> bool {
        matches!(self, Val::Null)
    }

    /// Borrow this value as a string, if it is one.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Val::Str(text) => Some(text),
            _ => None,
        }
    }

    /// This value as a bool (only the boolean variant).
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Val::Bool(value) => Some(*value),
            _ => None,
        }
    }

    /// This value as an i64 (only the integer variant).
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Val::Int(value) => Some(*value),
            _ => None,
        }
    }

    /// This value as an array (only the array variant).
    pub fn as_array(&self) -> Option<&Vec<Val>> {
        match self {
            Val::Arr(items) => Some(items),
            _ => None,
        }
    }

    /// Parse strict JSON text (RFC 8259 subset; see module docs).
    pub fn parse_json(text: &str) -> Result<Val, String> {
        let mut parser = Parser {
            bytes: text.as_bytes(),
            pos: 0,
        };
        parser.skip_ws();
        let value = parser.value()?;
        parser.skip_ws();
        if parser.pos != parser.bytes.len() {
            return Err(format!("trailing content at byte {}", parser.pos));
        }
        Ok(value)
    }

    /// Parse TOML text through the `toml` crate into a [`Val`].
    pub fn parse_toml(text: &str) -> Result<Val, String> {
        // `toml` 1.x parses through `Deserializer::parse`, which returns the
        // deserializer as a `Result` (the 0.8 `new` constructor was not
        // fallible); propagate the parse error as this module's `String`.
        let de = toml::de::Deserializer::parse(text).map_err(|err| err.to_string())?;
        Val::deserialize(de).map_err(|err| err.to_string())
    }
}

/// Build an object value from `(key, value)` pairs (keys are sorted on
/// serialization; callers keep insertion order for readability only).
pub fn object(pairs: Vec<(&str, Val)>) -> Val {
    Val::Obj(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

/// Build a string value.
pub fn string(text: &str) -> Val {
    Val::Str(text.to_string())
}

/// Build a boolean value.
pub fn bool_(value: bool) -> Val {
    Val::Bool(value)
}

/// Build an integer value.
pub fn integer(value: i64) -> Val {
    Val::Int(value)
}

/// Build a null value.
pub fn null() -> Val {
    Val::Null
}

/// An empty object value (for ok results that carry no data).
pub fn object_empty() -> Val {
    object(vec![])
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), String> {
        if self.peek() == Some(byte) {
            self.pos += 1;
            Ok(())
        } else {
            Err(format!(
                "expected byte {} at position {}",
                byte as char, self.pos
            ))
        }
    }

    fn literal(&mut self, text: &str) -> Result<(), String> {
        for (i, byte) in text.bytes().enumerate() {
            if self.bytes.get(self.pos + i) != Some(&byte) {
                return Err(format!(
                    "expected literal {text:?} at position {}",
                    self.pos
                ));
            }
        }
        self.pos += text.len();
        Ok(())
    }

    fn value(&mut self) -> Result<Val, String> {
        match self.peek() {
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => Ok(Val::Str(self.string()?)),
            Some(b't') => {
                self.literal("true")?;
                Ok(Val::Bool(true))
            }
            Some(b'f') => {
                self.literal("false")?;
                Ok(Val::Bool(false))
            }
            Some(b'n') => {
                self.literal("null")?;
                Ok(Val::Null)
            }
            Some(c) if c == b'-' || c.is_ascii_digit() => self.number(),
            other => Err(format!(
                "unexpected byte {:?} at position {}",
                other.map(char::from),
                self.pos
            )),
        }
    }

    fn object(&mut self) -> Result<Val, String> {
        self.expect(b'{')?;
        let mut map = BTreeMap::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Val::Obj(map));
        }
        loop {
            self.skip_ws();
            let key = self.string()?;
            self.skip_ws();
            self.expect(b':')?;
            self.skip_ws();
            let value = self.value()?;
            if map.insert(key.clone(), value).is_some() {
                return Err(format!(
                    "duplicate object key {key:?} at position {}",
                    self.pos
                ));
            }
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b'}') => {
                    self.pos += 1;
                    break;
                }
                _ => return Err(format!("expected ',' or '}}' at position {}", self.pos)),
            }
        }
        Ok(Val::Obj(map))
    }

    fn array(&mut self) -> Result<Val, String> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Val::Arr(items));
        }
        loop {
            self.skip_ws();
            items.push(self.value()?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    break;
                }
                _ => return Err(format!("expected ',' or ']' at position {}", self.pos)),
            }
        }
        Ok(Val::Arr(items))
    }

    fn string(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let Some(byte) = self.peek() else {
                return Err(format!("unterminated string at byte {}", self.pos));
            };
            self.pos += 1;
            match byte {
                b'"' => return Ok(out),
                b'\\' => {
                    let Some(esc) = self.peek() else {
                        return Err("unterminated escape".to_string());
                    };
                    self.pos += 1;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{08}'),
                        b'f' => out.push('\u{0c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let code = self.hex4()?;
                            if (0xd800..0xdc00).contains(&code) {
                                // High surrogate: a low surrogate must follow.
                                if self.peek() != Some(b'\\')
                                    || self.bytes.get(self.pos + 1) != Some(&b'u')
                                {
                                    return Err("unpaired high surrogate".to_string());
                                }
                                self.pos += 2;
                                let low = self.hex4()?;
                                if !(0xdc00..0xe000).contains(&low) {
                                    return Err("unpaired high surrogate".to_string());
                                }
                                let combined = 0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00);
                                let Some(c) = char::from_u32(combined) else {
                                    return Err("invalid surrogate pair".to_string());
                                };
                                out.push(c);
                            } else if (0xdc00..0xe000).contains(&code) {
                                return Err("unpaired low surrogate".to_string());
                            } else {
                                let Some(c) = char::from_u32(code) else {
                                    return Err("invalid unicode escape".to_string());
                                };
                                out.push(c);
                            }
                        }
                        other => {
                            return Err(format!("invalid escape \\{}", other as char));
                        }
                    }
                }
                0x00..=0x1f => return Err("unescaped control byte in string".to_string()),
                _ => {
                    // Decode one UTF-8 sequence from the remaining bytes.
                    let start = self.pos - 1;
                    let remaining = &self.bytes[start..];
                    let Ok(text) = std::str::from_utf8(remaining) else {
                        return Err("invalid UTF-8 in string".to_string());
                    };
                    let c = text.chars().next().expect("non-empty remaining");
                    out.push(c);
                    self.pos = start + c.len_utf8();
                }
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let mut code = 0u32;
        for _ in 0..4 {
            let Some(byte) = self.peek() else {
                return Err("truncated unicode escape".to_string());
            };
            let digit = match byte {
                b'0'..=b'9' => (byte - b'0') as u32,
                b'a'..=b'f' => (byte - b'a' + 10) as u32,
                b'A'..=b'F' => (byte - b'A' + 10) as u32,
                _ => return Err("invalid hex digit in unicode escape".to_string()),
            };
            code = code * 16 + digit;
            self.pos += 1;
        }
        Ok(code)
    }

    fn number(&mut self) -> Result<Val, String> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => {
                self.pos += 1;
                if matches!(self.peek(), Some(b'0'..=b'9')) {
                    return Err(format!("leading zeros are not allowed at byte {}", start));
                }
            }
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => return Err(format!("invalid number at byte {}", start)),
        }
        let mut is_float = false;
        if self.peek() == Some(b'.') {
            is_float = true;
            self.pos += 1;
            let digits_start = self.pos;
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
            if self.pos == digits_start {
                return Err(format!("fraction needs digits at byte {}", self.pos));
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            is_float = true;
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            let digits_start = self.pos;
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
            if self.pos == digits_start {
                return Err(format!("exponent needs digits at byte {}", self.pos));
            }
        }
        let text = std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| "number is not valid UTF-8".to_string())?;
        if is_float {
            text.parse::<f64>()
                .map(Val::Float)
                .map_err(|_| format!("invalid float {text:?}"))
        } else {
            match text.parse::<i64>() {
                Ok(int) => Ok(Val::Int(int)),
                Err(_) => text
                    .parse::<f64>()
                    .map(Val::Float)
                    .map_err(|_| format!("invalid number {text:?}")),
            }
        }
    }
}

impl<'de> Deserialize<'de> for Val {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(ValVisitor)
    }
}

struct ValVisitor;

impl<'de> Visitor<'de> for ValVisitor {
    type Value = Val;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON/TOML value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Val, E> {
        Ok(Val::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Val, E> {
        Ok(Val::Int(value))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Val, E>
    where
        E: de::Error,
    {
        i64::try_from(value).map(Val::Int).map_err(|_| {
            de::Error::custom(format!("integer {value} exceeds the supported i64 range"))
        })
    }

    fn visit_f64<E>(self, value: f64) -> Result<Val, E> {
        Ok(Val::Float(value))
    }

    fn visit_str<E>(self, value: &str) -> Result<Val, E> {
        Ok(Val::Str(value.to_string()))
    }

    fn visit_string<E>(self, value: String) -> Result<Val, E> {
        Ok(Val::Str(value))
    }

    fn visit_none<E>(self) -> Result<Val, E> {
        Ok(Val::Null)
    }

    fn visit_unit<E>(self) -> Result<Val, E> {
        Ok(Val::Null)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Val, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element::<Val>()? {
            items.push(item);
        }
        Ok(Val::Arr(items))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Val, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut out = BTreeMap::new();
        while let Some((key, value)) = map.next_entry::<String, Val>()? {
            if out.insert(key.clone(), value).is_some() {
                return Err(de::Error::custom(format!("duplicate key {key:?}")));
            }
        }
        Ok(Val::Obj(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obj(pairs: &[(&str, Val)]) -> Val {
        Val::Obj(
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect(),
        )
    }

    #[test]
    fn parses_nested_document_with_escapes() {
        let text = r#"{"a": [1, -2, 3.5, true, null, "x\n\u0041\u00e9"], "b": {"c": "d"}}"#;
        let parsed = Val::parse_json(text).expect("parse");
        assert_eq!(
            parsed,
            obj(&[
                (
                    "a",
                    Val::Arr(vec![
                        Val::Int(1),
                        Val::Int(-2),
                        Val::Float(3.5),
                        Val::Bool(true),
                        Val::Null,
                        Val::Str("x\nAé".to_string()),
                    ])
                ),
                ("b", obj(&[("c", Val::Str("d".to_string()))])),
            ])
        );
    }

    #[test]
    fn surrogate_pairs_combine() {
        let parsed = Val::parse_json(r#""\ud83d\ude00""#).expect("parse");
        assert_eq!(parsed, Val::Str("😀".to_string()));
    }

    #[test]
    fn strictness_rules_bite() {
        assert!(
            Val::parse_json(r#"{"a":1,"a":2}"#).is_err(),
            "duplicate key"
        );
        assert!(Val::parse_json("01").is_err(), "leading zero");
        assert!(Val::parse_json(r#"{"a": }"#).is_err(), "missing value");
        assert!(
            Val::parse_json(r#""\ud800""#).is_err(),
            "unpaired surrogate"
        );
        assert!(Val::parse_json("true false").is_err(), "trailing content");
        assert!(Val::parse_json(r#"{"a" 1}"#).is_err(), "missing colon");
    }

    #[test]
    fn parses_toml_tables_and_scalars() {
        let text = r#"
schema = "hf-config/v1"
[daemon]
enabled = true
[repository.widgets]
origin = "https://github.com/example-org/widgets"
branch = "staging"
enabled = true
[harness.cli]
kind = "argv"
executable = "hf-cli-example"
env_allow = ["PATH", "HOME"]
"#;
        let parsed = Val::parse_toml(text).expect("toml parse");
        assert_eq!(
            parsed.get("schema").and_then(Val::as_str),
            Some("hf-config/v1")
        );
        let daemon = parsed.get("daemon").expect("daemon table");
        assert_eq!(daemon.get("enabled"), Some(&Val::Bool(true)));
        let repo = parsed
            .get("repository")
            .and_then(|r| r.get("widgets"))
            .expect("repo");
        assert_eq!(repo.get("enabled"), Some(&Val::Bool(true)));
        let allow = parsed
            .get("harness")
            .and_then(|h| h.get("cli"))
            .and_then(|c| c.get("env_allow"));
        assert_eq!(
            allow,
            Some(&Val::Arr(vec![
                Val::Str("PATH".into()),
                Val::Str("HOME".into())
            ]))
        );
    }

    #[test]
    fn toml_float_and_int_shapes_are_distinct() {
        let parsed = Val::parse_toml("a = 1\nb = 1.5\n").expect("parse");
        assert_eq!(parsed.get("a"), Some(&Val::Int(1)));
        assert_eq!(parsed.get("b"), Some(&Val::Float(1.5)));
    }
}
