import phi_scrub


def test_redact_ssn_and_email():
    s = phi_scrub.Scrubber()
    assert s.redact("SSN 123-45-6789, mail me@example.com") == "SSN [SSN], mail [EMAIL]"


def test_detect_returns_findings():
    s = phi_scrub.Scrubber()
    f = s.detect("call (808) 555-0100")
    assert len(f) == 1
    assert f[0].category == "phone"
    assert (f[0].start, f[0].end) == (5, 19)


def test_version_exposed():
    assert phi_scrub.__version__ == "0.1.0"


def test_redact_reversible_round_trip():
    s = phi_scrub.Scrubber()
    original = "SSN 123-45-6789, mail me@example.com"
    text, token_map = s.redact_reversible(original)
    assert text == "SSN [SSN_1], mail [EMAIL_1]"
    assert token_map == {"[SSN_1]": "123-45-6789", "[EMAIL_1]": "me@example.com"}
    assert phi_scrub.restore(text, token_map) == original


def test_restore_ignores_unknown_tokens():
    assert phi_scrub.restore("[SSN_9] stays", {}) == "[SSN_9] stays"


def test_new_categories():
    s = phi_scrub.Scrubber()
    assert s.detect("NPI 1234567893")[0].category == "npi"
    assert s.detect("AB1234563")[0].category == "dea"
    assert s.detect("1EG4TE5MK73")[0].category == "mbi"
    assert s.detect("MRN: 00123456")[0].category == "mrn"
