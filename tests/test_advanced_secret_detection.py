from mcp_server.advanced_secret_detection import (
    detect_base64_secrets,
    detect_comment_credentials,
    detect_env_variables,
    detect_hardcoded_credentials,
    detect_hex_secrets,
    detect_jwt_tokens,
    detect_multiline_secrets,
    detect_sensitive_config_values,
    detect_split_secrets,
    detect_tokens_in_urls,
    scan_obfuscated_secrets,
)


def test_split_secret_reconstruction() -> None:
    text = 'part1 = "sk_test_123"\npart2 = "456789abcdef"\napi_key = part1 + part2\n'
    findings = detect_split_secrets(text)
    assert "sk_test_123456789abcdef" in findings


def test_multiline_secret_reconstruction() -> None:
    text = 'key = (\n"sk_test_123"\n"456789abcdef"\n)\n'
    findings = detect_multiline_secrets(text)
    assert "sk_test_123456789abcdef" in findings


def test_base64_secret_detection() -> None:
    text = 'encoded = "YXBpX3Rva2VuPWFkbWluMTIzc2VjcmV0"'
    findings = detect_base64_secrets(text)
    assert any("api_token" in item for item in findings)


def test_hex_secret_detection() -> None:
    text = 'value = "6170695f6b65793d736563726574313233"'
    findings = detect_hex_secrets(text)
    assert any("api_key" in item for item in findings)


def test_url_token_detection() -> None:
    text = "https://api.example.com?token=abcdef123456&foo=bar"
    assert "abcdef123456" in detect_tokens_in_urls(text)


def test_comment_credential_detection() -> None:
    text = "# password=admin123\n# normal comment\n"
    assert "admin123" in detect_comment_credentials(text)


def test_env_var_detection() -> None:
    text = 'os.getenv("API_SECRET")\nos.environ["TOKEN"]\nprocess.env.API_KEY\n'
    findings = detect_env_variables(text)
    assert {"API_SECRET", "TOKEN", "API_KEY"}.issubset(set(findings))


def test_hardcoded_credentials_detection() -> None:
    text = 'password = "supersecret123"\n'
    assert "supersecret123" in detect_hardcoded_credentials(text)


def test_sensitive_config_detection() -> None:
    text = 'JWT_SECRET = "my-jwt-secret-value"\n'
    assert "my-jwt-secret-value" in detect_sensitive_config_values(text)


def test_jwt_detection() -> None:
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.signature"
    assert token in detect_jwt_tokens(token)


def test_master_scanner_output_shape() -> None:
    text = 'password = "supersecret123"\nhttps://site.com/login?apikey=xyz123\n'
    results = scan_obfuscated_secrets(text)
    assert results
    first = results[0]
    assert {"secret", "secret_type", "confidence", "reason", "line_number", "context"}.issubset(first.keys())
