"""Tests for the structured ToolErrorEnvelope model."""

import json

import pytest
from pydantic import ValidationError

from mcp_server_ipinfo.models import ToolErrorEnvelope


class TestToolErrorEnvelope:
    """Tests for ToolErrorEnvelope model.

    The envelope is JSON-serialized into a ToolError message string so that
    agents receive both isError: true on the wire AND a parseable structured
    payload describing the failure.
    """

    def test_minimal_envelope(self):
        """An envelope needs code, message, and temporary."""
        env = ToolErrorEnvelope(
            code="invalid_ip_address",
            message="10.0.0.1 is a private IP address.",
            temporary=False,
        )
        assert env.code == "invalid_ip_address"
        assert env.message == "10.0.0.1 is a private IP address."
        assert env.temporary is False
        assert env.field is None
        assert env.repair is None

    def test_full_envelope(self):
        """An envelope can carry field, value, repair, and retry_after_ms."""
        env = ToolErrorEnvelope(
            code="quota_exceeded",
            message="IPInfo API quota exhausted for this token.",
            temporary=True,
            retry_after_ms=60_000,
            field=None,
            repair={"hint": "Upgrade plan or wait for daily reset."},
        )
        assert env.temporary is True
        assert env.retry_after_ms == 60_000
        assert env.repair == {"hint": "Upgrade plan or wait for daily reset."}

    def test_unknown_code_rejected(self):
        """Codes outside the documented set must fail validation."""
        with pytest.raises(ValidationError):
            ToolErrorEnvelope(
                code="oopsie_doopsie",  # type: ignore[arg-type]
                message="x",
                temporary=False,
            )

    @pytest.mark.parametrize(
        "code",
        [
            "invalid_ip_address",
            "special_ip_unsupported",
            "no_valid_ips",
            "too_many_ips",
            "auth_invalid",
            "auth_insufficient_scope",
            "quota_exceeded",
            "timeout",
            "api_error",
            "unknown_error",
        ],
    )
    def test_documented_codes_accepted(self, code):
        """Every documented code is a valid value for the code field."""
        env = ToolErrorEnvelope(code=code, message="ok", temporary=False)
        assert env.code == code

    def test_json_roundtrip(self):
        """An envelope serialized to JSON can be parsed back losslessly.

        This is the wire shape agents will receive (encoded into a ToolError
        message string).
        """
        original = ToolErrorEnvelope(
            code="auth_insufficient_scope",
            message="Token lacks residential-proxy access.",
            temporary=False,
            repair={"hint": "Enable the residential proxy add-on on your plan."},
        )
        wire = original.model_dump_json()
        parsed = json.loads(wire)
        assert parsed["code"] == "auth_insufficient_scope"
        assert parsed["temporary"] is False
        assert parsed["repair"]["hint"].startswith("Enable")
        restored = ToolErrorEnvelope.model_validate_json(wire)
        assert restored == original

    def test_envelope_message_fallback_for_non_json(self):
        """_envelope_message falls back to str() when the message isn't envelope JSON.

        Defensive path: if a non-envelope ToolError ever leaks into
        _filter_valid_ips, the warning string still surfaces something readable.
        """
        from fastmcp.exceptions import ToolError

        from mcp_server_ipinfo.server import _envelope_message

        plain = ToolError("something went wrong")
        assert _envelope_message(plain) == "something went wrong"

        # JSON without a `message` key also falls back.
        no_message = ToolError('{"code": "x"}')
        assert _envelope_message(no_message) == '{"code": "x"}'

    def test_required_fields(self):
        """code, message, and temporary are required."""
        with pytest.raises(ValidationError):
            ToolErrorEnvelope(message="x", temporary=False)  # type: ignore[call-arg]
        with pytest.raises(ValidationError):
            ToolErrorEnvelope(code="api_error", temporary=False)  # type: ignore[call-arg]
        with pytest.raises(ValidationError):
            ToolErrorEnvelope(code="api_error", message="x")  # type: ignore[call-arg]
