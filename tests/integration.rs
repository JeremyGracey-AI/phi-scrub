use phi_scrub::{restore, Category, Scrubber, TokenMap};

const NOTE: &str = "Patient 123-45-6789, reach at 808-555-0100 or p@x.org";

fn token_map(pairs: &[(&str, &str)]) -> TokenMap {
    pairs
        .iter()
        .map(|(token, value)| ((*token).to_owned(), (*value).to_owned()))
        .collect()
}

#[test]
fn public_api_roundtrip() {
    let s = Scrubber::new();
    let text = "Patient 123-45-6789, reach at 808-555-0100 or p@x.org";
    let findings = s.detect(text);
    assert_eq!(findings.len(), 3);
    assert_eq!(findings[0].category, Category::Ssn);
    assert_eq!(findings[1].category, Category::Phone);
    assert_eq!(findings[2].category, Category::Email);
    assert_eq!(s.redact(text), "Patient [SSN], reach at [PHONE] or [EMAIL]");
}

#[test]
fn findings_serialize_to_json() {
    let s = Scrubber::new();
    let json = serde_json::to_string(&s.detect("x 123-45-6789")).unwrap();
    assert!(json.contains("\"Ssn\""));
}

#[test]
fn reversible_redaction_numbers_tokens_per_category() {
    let r = Scrubber::new().redact_reversible(NOTE);
    assert_eq!(r.text, "Patient [SSN_1], reach at [PHONE_1] or [EMAIL_1]");
    assert_eq!(r.map.len(), 3);
    assert_eq!(r.map.get("[SSN_1]"), Some("123-45-6789"));
    assert_eq!(r.map.get("[PHONE_1]"), Some("808-555-0100"));
    assert_eq!(r.map.get("[EMAIL_1]"), Some("p@x.org"));
}

#[test]
fn restore_returns_the_original_text() {
    let r = Scrubber::new().redact_reversible(NOTE);
    assert_eq!(restore(&r.text, &r.map), NOTE);
}

#[test]
fn repeated_value_reuses_its_token() {
    let r = Scrubber::new().redact_reversible("a@b.com then a@b.com and c@d.org");
    assert_eq!(r.text, "[EMAIL_1] then [EMAIL_1] and [EMAIL_2]");
    assert_eq!(r.map.len(), 2);
}

#[test]
fn token_already_in_input_is_never_issued() {
    let input = "Template says [SSN_1]; real SSN 123-45-6789";
    let r = Scrubber::new().redact_reversible(input);
    assert_eq!(r.text, "Template says [SSN_1]; real SSN [SSN_2]");
    assert_eq!(r.map.len(), 1);
    assert_eq!(r.map.get("[SSN_1]"), None);
    assert_eq!(restore(&r.text, &r.map), input);
}

#[test]
fn restore_leaves_unknown_tokens_alone() {
    assert_eq!(restore("[SSN_9] stays", &TokenMap::new()), "[SSN_9] stays");
}

#[test]
fn restore_ignores_keys_that_are_not_tokens() {
    assert_eq!(restore("x marks", &token_map(&[("x", "y")])), "x marks");
}

#[test]
fn restore_is_single_pass() {
    let map = token_map(&[("[SSN_1]", "[SSN_2]"), ("[SSN_2]", "boom")]);
    assert_eq!(restore("[SSN_1]", &map), "[SSN_2]");
}

#[test]
fn round_trip_with_multibyte_text() {
    let input = "Señora García — SSN 123-45-6789 ✓";
    let r = Scrubber::new().redact_reversible(input);
    assert_eq!(r.text, "Señora García — SSN [SSN_1] ✓");
    assert_eq!(restore(&r.text, &r.map), input);
}

#[test]
fn redaction_serializes_map_as_json_object() {
    let r = Scrubber::new().redact_reversible("SSN 123-45-6789");
    let v = serde_json::to_value(&r).unwrap();
    assert_eq!(v["text"], "SSN [SSN_1]");
    assert_eq!(v["map"]["[SSN_1]"], "123-45-6789");
}

#[test]
fn findings_never_overlap() {
    let findings = Scrubber::new().detect("8085550100@x.org and 808-555-0100");
    let found: Vec<Category> = findings.iter().map(|f| f.category).collect();
    assert_eq!(found, vec![Category::Email, Category::Phone]);
    assert!(findings[0].end <= findings[1].start);
}

/// Each finding as (category, matched text).
fn found(text: &str) -> Vec<(Category, &str)> {
    Scrubber::new()
        .detect(text)
        .into_iter()
        .map(|f| (f.category, &text[f.start..f.end]))
        .collect()
}

#[test]
fn npi_passes_luhn_with_80840_prefix() {
    let text = "NPI 1234567893";
    assert_eq!(found(text), vec![(Category::Npi, "1234567893")]);
    assert_eq!(Scrubber::new().redact(text), "NPI [NPI]");
}

#[test]
fn ten_digits_failing_luhn_are_not_npi() {
    assert_eq!(
        found("NPI 1234567890"),
        vec![(Category::Phone, "1234567890")]
    );
}

#[test]
fn valid_npi_outranks_phone_on_same_span() {
    assert_eq!(found("1234567893"), vec![(Category::Npi, "1234567893")]);
}

#[test]
fn phone_shaped_number_stays_phone() {
    assert_eq!(
        found("call 808-555-0100 or 8085550100"),
        vec![
            (Category::Phone, "808-555-0100"),
            (Category::Phone, "8085550100")
        ]
    );
}

#[test]
fn dea_checksum_accepts_valid_number() {
    let text = "DEA AB1234563";
    assert_eq!(found(text), vec![(Category::Dea, "AB1234563")]);
    assert_eq!(Scrubber::new().redact(text), "DEA [DEA]");
}

#[test]
fn dea_checksum_rejects_bad_check_digit() {
    assert_eq!(found("DEA AB1234567"), vec![]);
}
