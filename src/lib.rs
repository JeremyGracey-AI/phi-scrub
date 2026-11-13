#![deny(missing_docs)]
//! phi-scrub: detect and redact Protected Health Information in free text.
//!
//! ```
//! use phi_scrub::Scrubber;
//! let s = Scrubber::new();
//! assert_eq!(s.redact("SSN 123-45-6789"), "SSN [SSN]");
//! ```
//!
//! Reversible redaction returns a token map, so the original values can be
//! put back after a model replies:
//!
//! ```
//! use phi_scrub::{restore, Scrubber};
//! let r = Scrubber::new().redact_reversible("SSN 123-45-6789");
//! assert_eq!(r.text, "SSN [SSN_1]");
//! assert_eq!(restore(&r.text, &r.map), "SSN 123-45-6789");
//! ```

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::LazyLock;

#[cfg(feature = "python")]
mod python;

/// Errors produced by the redaction engine.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Invalid configuration supplied by the caller.
    #[error("invalid configuration: {0}")]
    Config(String),
}

/// Categories of PHI the engine can detect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Category {
    /// Social Security number.
    Ssn,
    /// Phone number.
    Phone,
    /// Email address.
    Email,
}

impl Category {
    /// Placeholder token used when redacting this category.
    pub fn token(self) -> &'static str {
        match self {
            Category::Ssn => "[SSN]",
            Category::Phone => "[PHONE]",
            Category::Email => "[EMAIL]",
        }
    }

    /// Token text without the brackets, e.g. `SSN`.
    fn label(self) -> &'static str {
        self.token().trim_start_matches('[').trim_end_matches(']')
    }
}

/// Numbered tokens mapped to the original values they replaced.
///
/// Serializes as a JSON object, e.g. `{"[SSN_1]": "123-45-6789"}`. The map
/// holds PHI: keep it with the caller and never send it to a model.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TokenMap(BTreeMap<String, String>);

impl TokenMap {
    /// Create an empty map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Original value for `token`, if the map has one.
    pub fn get(&self, token: &str) -> Option<&str> {
        self.0.get(token).map(String::as_str)
    }

    /// Number of tokens in the map.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True when the map holds no tokens.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterate over `(token, value)` pairs, sorted by token.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> + '_ {
        self.0.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }
}

impl FromIterator<(String, String)> for TokenMap {
    fn from_iter<I: IntoIterator<Item = (String, String)>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

/// Result of a reversible redaction: the redacted text and the map that undoes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Redaction {
    /// Text with every finding replaced by a numbered token such as `[SSN_1]`.
    pub text: String,
    /// Tokens issued for this text, mapped to the values they replaced.
    pub map: TokenMap,
}

/// Shape of a numbered token, e.g. `[SSN_1]`.
static TOKEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\[[A-Z]+_[0-9]+\]").expect("valid token regex"));

/// A single detection within the input text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Byte offset where the match starts.
    pub start: usize,
    /// Byte offset where the match ends (exclusive).
    pub end: usize,
    /// Which category matched.
    pub category: Category,
}

static PATTERNS: LazyLock<Vec<(Category, Regex)>> = LazyLock::new(|| {
    vec![
        (
            Category::Ssn,
            Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").expect("valid ssn regex"),
        ),
        (
            Category::Phone,
            Regex::new(r"(?:\(\d{3}\)|\b\d{3})[-.\s]?\d{3}[-.\s]?\d{4}\b")
                .expect("valid phone regex"),
        ),
        (
            Category::Email,
            Regex::new(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b").expect("valid email regex"),
        ),
    ]
});

/// The redaction engine.
#[derive(Debug, Default, Clone)]
pub struct Scrubber;

impl Scrubber {
    /// Create a scrubber with default patterns.
    pub fn new() -> Self {
        Self
    }

    /// Return all findings in `text`, sorted by start offset.
    pub fn detect(&self, text: &str) -> Vec<Finding> {
        let mut out: Vec<Finding> = PATTERNS
            .iter()
            .flat_map(|(cat, re)| {
                re.find_iter(text).map(move |m| Finding {
                    start: m.start(),
                    end: m.end(),
                    category: *cat,
                })
            })
            .collect();
        out.sort_by_key(|f| (f.start, std::cmp::Reverse(f.end)));
        out
    }

    /// Replace every finding with its category token, e.g. `[SSN]`.
    pub fn redact(&self, text: &str) -> String {
        let findings = self.detect(text);
        let mut result = String::with_capacity(text.len());
        let mut cursor = 0;
        for f in findings {
            if f.start < cursor {
                continue; // overlapping match already consumed
            }
            result.push_str(&text[cursor..f.start]);
            result.push_str(f.category.token());
            cursor = f.end;
        }
        result.push_str(&text[cursor..]);
        result
    }

    /// Replace every finding with a numbered token, e.g. `[SSN_1]`, and return
    /// the map that [`restore`] needs to undo it.
    ///
    /// The same value always gets the same token within one call. A token that
    /// already appears in `text` is never issued, so restoring the result
    /// returns `text` byte for byte.
    pub fn redact_reversible(&self, text: &str) -> Redaction {
        let taken: HashSet<&str> = TOKEN.find_iter(text).map(|m| m.as_str()).collect();
        let mut issued: HashMap<(Category, &str), String> = HashMap::new();
        let mut counters: HashMap<Category, usize> = HashMap::new();
        let mut map = BTreeMap::new();
        let mut result = String::with_capacity(text.len());
        let mut cursor = 0;
        for f in self.detect(text) {
            if f.start < cursor {
                continue; // overlapping match already consumed
            }
            let value = &text[f.start..f.end];
            let token = match issued.get(&(f.category, value)) {
                Some(token) => token.clone(),
                None => {
                    let counter = counters.entry(f.category).or_insert(0);
                    let token = loop {
                        *counter += 1;
                        let candidate = format!("[{}_{}]", f.category.label(), counter);
                        if !taken.contains(candidate.as_str()) {
                            break candidate;
                        }
                    };
                    issued.insert((f.category, value), token.clone());
                    map.insert(token.clone(), value.to_owned());
                    token
                }
            };
            result.push_str(&text[cursor..f.start]);
            result.push_str(&token);
            cursor = f.end;
        }
        result.push_str(&text[cursor..]);
        Redaction {
            text: result,
            map: TokenMap(map),
        }
    }
}

/// Put the original values back into `text`, using a map from
/// [`Scrubber::redact_reversible`].
///
/// Makes one left-to-right pass and replaces only numbered tokens that are
/// keys in `map`. Tokens the map does not know, and all other text, are left
/// alone, so a model's reply restores cleanly even if it adds or drops tokens.
pub fn restore(text: &str, map: &TokenMap) -> String {
    let mut result = String::with_capacity(text.len());
    let mut cursor = 0;
    for m in TOKEN.find_iter(text) {
        if let Some(value) = map.get(m.as_str()) {
            result.push_str(&text[cursor..m.start()]);
            result.push_str(value);
            cursor = m.end();
        }
    }
    result.push_str(&text[cursor..]);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_ssn_and_email() {
        let s = Scrubber::new();
        let out = s.redact("SSN 123-45-6789, mail me@example.com");
        assert_eq!(out, "SSN [SSN], mail [EMAIL]");
    }

    #[test]
    fn redacts_phone() {
        let s = Scrubber::new();
        assert_eq!(s.redact("call (808) 555-0100 now"), "call [PHONE] now");
    }

    #[test]
    fn clean_text_untouched() {
        let s = Scrubber::new();
        assert_eq!(s.redact("no phi here"), "no phi here");
    }

    #[test]
    fn findings_are_sorted() {
        let s = Scrubber::new();
        let f = s.detect("a@b.com then 123-45-6789");
        assert_eq!(f[0].category, Category::Email);
        assert_eq!(f[1].category, Category::Ssn);
    }
}
