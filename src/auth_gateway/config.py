"""Runtime configuration for the edge gateway.

Everything is read from the environment so the same image can run in each tier.
The defaults below are development-only placeholders; production deployments set
real values through the environment.
"""
import os
from functools import lru_cache
from typing import List


def _split_csv(value: str) -> List[str]:
    """Parse a comma-separated environment value into a clean list."""
    return [item.strip() for item in value.split(",") if item.strip()]


class Settings:
    """Gateway settings resolved from environment variables."""

    def __init__(self) -> None:
        # Service identity, surfaced on /health and in introspection responses.
        self.service_name: str = os.environ.get("GATEWAY_SERVICE_NAME", "auth-gateway")
        self.environment: str = os.environ.get("GATEWAY_ENV", "development")

        # HMAC key used to verify the access tokens presented to the gateway.
        # The default is an obvious placeholder; override it everywhere real.
        self.signing_key: str = os.environ.get("GATEWAY_SIGNING_KEY", "dev-only-change-me")

        # Signature algorithms the gateway is willing to accept.
        self.allowed_algorithms: List[str] = _split_csv(
            os.environ.get("GATEWAY_ALLOWED_ALGS", "HS256")
        ) or ["HS256"]

        # Downstream services this gateway fronts, as "name=audience" pairs.
        self.downstreams: dict = self._parse_downstreams(
            os.environ.get("GATEWAY_DOWNSTREAMS", "billing=api.billing,reports=api.reports")
        )

        # Expected token issuer. Empty string disables the issuer check.
        self.expected_issuer: str = os.environ.get("GATEWAY_ISSUER", "")

    @staticmethod
    def _parse_downstreams(value: str) -> dict:
        mapping: dict = {}
        for pair in _split_csv(value):
            name, _, audience = pair.partition("=")
            name = name.strip()
            if name:
                mapping[name] = audience.strip() or name
        return mapping


@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings instance for the process."""
    return Settings()
