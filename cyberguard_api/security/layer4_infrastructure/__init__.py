"""
Layer 4: Infrastructure, Supply Chain, and Continuous Delivery Security
========================================================================
Apollo/Prisma Cloud Paradigm: SBOM, Secret Management, Policy-as-Code.
"""

from cyberguard_api.security.core.interfaces import SecretManager
from cyberguard_api.security.core.exceptions import SecretError
from typing import Optional
import os


class HashiCorpVaultSecretManager(SecretManager):
    """
    HashiCorp Vault secret manager integration.
    """

    def __init__(
        self,
        vault_url: str = None,
        vault_token: str = None,
        mount_point: str = "secret",
    ) -> None:
        self.vault_url = vault_url or os.getenv("VAULT_URL", "http://localhost:8200")
        self.vault_token = vault_token or os.getenv("VAULT_TOKEN")
        self.mount_point = mount_point
        self._client = None

    async def _get_client(self):
        """Get or create Vault client."""
        if self._client is None and self.vault_token:
            import hvac
            self._client = hvac.Client(
                url=self.vault_url,
                token=self.vault_token,
            )
        return self._client

    async def get_secret(self, path: str) -> Optional[str]:
        """Retrieve secret from Vault."""
        client = await self._get_client()
        if not client:
            # Fallback to environment variable
            env_key = path.replace("/", "_").upper()
            return os.getenv(env_key)

        try:
            full_path = f"{self.mount_point}/data/{path}"
            response = client.secrets.kv.v2.read_secret_version(path=path, mount_point=self.mount_point)
            return response["data"]["data"].get("value")
        except Exception as e:
            raise SecretError(f"Failed to retrieve secret {path}: {e}")

    async def rotate_secret(self, path: str) -> str:
        """Rotate secret in Vault."""
        client = await self._get_client()
        if not client:
            raise SecretError("Vault client not configured")

        import secrets
        new_value = secrets.token_urlsafe(32)

        try:
            client.secrets.kv.v2.create_or_update_secret(
                path=path,
                secret={"value": new_value},
                mount_point=self.mount_point,
            )
            return new_value
        except Exception as e:
            raise SecretError(f"Failed to rotate secret {path}: {e}")

    async def audit_secret_access(self, path: str, context) -> None:
        """Audit secret access."""
        # In production, log to audit system
        pass


class EnvironmentSecretManager(SecretManager):
    """
    Environment variable based secret manager (development fallback).
    """

    async def get_secret(self, path: str) -> Optional[str]:
        """Get secret from environment."""
        env_key = path.replace("/", "_").upper()
        return os.getenv(env_key)

    async def rotate_secret(self, path: str) -> str:
        """Rotate secret (not supported for env vars)."""
        raise SecretError("Secret rotation not supported for environment variables")

    async def audit_secret_access(self, path: str, context) -> None:
        """Audit secret access."""
        pass


# Global secret manager (auto-detects Vault or falls back to env)
vault_url = os.getenv("VAULT_URL")
vault_token = os.getenv("VAULT_TOKEN")

if vault_url and vault_token:
    secret_manager = HashiCorpVaultSecretManager(vault_url, vault_token)
else:
    secret_manager = EnvironmentSecretManager()