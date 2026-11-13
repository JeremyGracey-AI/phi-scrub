//! Detector table: one pattern per category, an optional validator, and the
//! capture group that is reported as the finding.
//!
//! Order matters. When two candidates cover the same span, the detector
//! listed first wins.

use crate::Category;
use regex::Regex;
use std::sync::LazyLock;

/// One detection rule.
pub(crate) struct Detector {
    /// Category reported for a match.
    pub category: Category,
    /// Pattern that finds candidates.
    pub regex: Regex,
    /// Capture group reported as the finding; 0 is the whole match.
    pub group: usize,
    /// Extra check on the reported text, such as a check digit.
    pub validate: Option<fn(&str) -> bool>,
}

/// Every detector, in precedence order.
pub(crate) static DETECTORS: LazyLock<Vec<Detector>> = LazyLock::new(|| {
    let re = |pattern: &str| Regex::new(pattern).expect("valid detector regex");
    vec![
        Detector {
            category: Category::Ssn,
            regex: re(r"\b\d{3}-\d{2}-\d{4}\b"),
            group: 0,
            validate: None,
        },
        Detector {
            category: Category::Phone,
            regex: re(r"(?:\(\d{3}\)|\b\d{3})[-.\s]?\d{3}[-.\s]?\d{4}\b"),
            group: 0,
            validate: None,
        },
        Detector {
            category: Category::Email,
            regex: re(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
            group: 0,
            validate: None,
        },
    ]
});
