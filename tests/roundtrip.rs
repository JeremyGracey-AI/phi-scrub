//! Property test: `restore` inverts `redact_reversible` for any input.

use phi_scrub::{restore, Scrubber};
use proptest::prelude::*;

/// PHI values the engine detects, plus token-shaped literals that must survive untouched.
const SAMPLES: &[&str] = &[
    "123-45-6789",
    "808-555-0100",
    "(808) 555-0100",
    "p@x.org",
    "a@b.com",
    "[SSN_1]",
    "[EMAIL_2]",
    "[PHONE_1]",
    "[SSN_10]",
];

const SEPARATORS: &[&str] = &["", " ", ", ", "\n"];

fn fragment() -> impl Strategy<Value = String> {
    prop_oneof![
        proptest::collection::vec(any::<char>(), 0..=12)
            .prop_map(|chars| chars.into_iter().collect::<String>()),
        proptest::sample::select(SAMPLES).prop_map(str::to_owned),
    ]
}

fn input() -> impl Strategy<Value = String> {
    proptest::collection::vec((fragment(), proptest::sample::select(SEPARATORS)), 0..=12).prop_map(
        |parts| {
            parts
                .into_iter()
                .map(|(fragment, separator)| format!("{fragment}{separator}"))
                .collect()
        },
    )
}

proptest! {
    #[test]
    fn restore_inverts_redact_reversible_for_any_text(input in input()) {
        let r = Scrubber::new().redact_reversible(&input);
        prop_assert_eq!(restore(&r.text, &r.map), input);
    }
}
