#![deny(missing_docs)]
//! phi-scrub: detect and redact Protected Health Information in free text.
//!
//! ```
//! use phi_scrub::Scrubber;
//! let s = Scrubber::new();
//! assert_eq!(s.redact("SSN 123-45-6789"), "SSN [SSN]");
//! ```

use regex::Regex;
use serde::{Deserialize, Serialize};
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
}

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
