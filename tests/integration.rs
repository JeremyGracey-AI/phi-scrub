use phi_scrub::{Category, Scrubber};

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
