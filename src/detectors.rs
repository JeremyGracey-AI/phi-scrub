//! Detector table: each row is a pattern for one category, an optional
//! validator, and the capture group that is reported as the finding.
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
    // MBI positions are typed: letters exclude S, L, O, I, B, and Z.
    let letter = "[AC-HJKMNP-RT-Y]";
    let either = "[AC-HJKMNP-RT-Y0-9]";
    let mbi = format!(
        r"\b[1-9]{letter}{either}[0-9]-?{letter}{either}[0-9]-?{letter}{letter}[0-9][0-9]\b"
    );
    // "MRN", optionally followed by "number", "num.", or "no.".
    let mrn = r"MRN(?:\s*(?:number|num\.?|no\.?))?";
    // An MRN value after its first character, which each pattern below adds:
    // the whole run of letters, digits, hyphens, and underscores, ending on a
    // letter or digit. No length cap and no trailing `\b`, so a match can
    // never stop partway through an identifier and leave its tail in the clear.
    let mrn_rest = "[A-Z0-9_-]{3,}[A-Z0-9]";
    vec![
        Detector {
            category: Category::Ssn,
            regex: re(r"\b\d{3}-\d{2}-\d{4}\b"),
            group: 0,
            validate: None,
        },
        // "MRN" and a separator, or the spelled-out label, then a value that
        // may start with a letter.
        Detector {
            category: Category::Mrn,
            regex: re(&format!(
                r"(?i)\b(?:{mrn}[\s:#=-]+|medical record\s*(?:number|num\.?|no\.?|#)[\s:#=-]*)([A-Z0-9]{mrn_rest})"
            )),
            group: 1,
            validate: Some(has_digit),
        },
        // A value written straight after "MRN" must start with a digit, so
        // "mRNA-1273" is not read as an MRN.
        Detector {
            category: Category::Mrn,
            regex: re(&format!(r"(?i)\b{mrn}([0-9]{mrn_rest})")),
            group: 1,
            validate: None,
        },
        Detector {
            category: Category::Npi,
            regex: re(r"\b[12][0-9]{9}\b"),
            group: 0,
            validate: Some(npi_checksum),
        },
        Detector {
            category: Category::Dea,
            regex: re(r"\b[A-Za-z][A-Za-z9][0-9]{7}\b"),
            group: 0,
            validate: Some(dea_checksum),
        },
        Detector {
            category: Category::Mbi,
            regex: re(&mbi),
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

/// True when the text holds at least one ASCII digit. Keeps a label followed
/// by a plain word ("MRN pending") from being reported.
fn has_digit(text: &str) -> bool {
    text.bytes().any(|byte| byte.is_ascii_digit())
}

/// True when ten NPI digits pass the Luhn check with the `80840` prefix.
pub(crate) fn npi_checksum(digits: &str) -> bool {
    luhn("80840".bytes().chain(digits.bytes()))
}

/// True when a DEA number's last digit equals its check digit,
/// `(d1 + d3 + d5 + 2 * (d2 + d4 + d6)) % 10`.
pub(crate) fn dea_checksum(candidate: &str) -> bool {
    let digits: Vec<u32> = candidate
        .bytes()
        .skip(2)
        .filter(u8::is_ascii_digit)
        .map(|byte| u32::from(byte - b'0'))
        .collect();
    match digits[..] {
        [d1, d2, d3, d4, d5, d6, check] => (d1 + d3 + d5 + 2 * (d2 + d4 + d6)) % 10 == check,
        _ => false,
    }
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
