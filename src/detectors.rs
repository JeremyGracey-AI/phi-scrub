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
            category: Category::Npi,
            regex: re(r"\b[12][0-9]{9}\b"),
            group: 0,
            validate: Some(npi_checksum),
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

/// True when ten NPI digits pass the Luhn check with the `80840` prefix.
pub(crate) fn npi_checksum(digits: &str) -> bool {
    luhn("80840".bytes().chain(digits.bytes()))
}

/// Luhn check over ASCII digits. Any other byte fails.
fn luhn(digits: impl DoubleEndedIterator<Item = u8>) -> bool {
    let mut sum = 0u32;
    for (i, byte) in digits.rev().enumerate() {
        if !byte.is_ascii_digit() {
            return false;
        }
        let digit = u32::from(byte - b'0');
        sum += if i % 2 == 1 {
            let doubled = digit * 2;
            if doubled > 9 {
                doubled - 9
            } else {
                doubled
            }
        } else {
            digit
        };
    }
    sum % 10 == 0
}
