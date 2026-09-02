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
