import asyncio
import logging

from .pki_provider import VaultPKIProvider

logger = logging.getLogger(__name__)


class AuthController:
    def __init__(self, vault_provider: VaultPKIProvider):
        self.vault_provider = vault_provider

    async def login(self):
        raise NotImplementedError

    async def run(self):
        raise NotImplementedError

    @classmethod
    def create_by_auth_data(cls, vault_provider: VaultPKIProvider, auth_data: dict):
        if auth_data["method"] == "token":
            return TokenAuthController(vault_provider, auth_data["token"])
        elif auth_data["method"] == "approle":
            return AppRoleAuthController(
                vault_provider, auth_data["role_id"], auth_data["secret_id"]
            )
        else:
            raise ValueError(f'Unexpected auth method {auth_data["method"]}')


class TokenAuthController(AuthController):
    def __init__(self, vault_provider: VaultPKIProvider, token: str):
        super().__init__(vault_provider)
        self.token = token

    async def login(self):
        self.vault_provider.client.token = self.token

    async def run(self):
        pass


class AppRoleAuthController(AuthController):
    def __init__(self, vault_provider: VaultPKIProvider, role_id: str, secret_id: str):
        super().__init__(vault_provider)
        self.role_id = role_id
        self.secret_id = secret_id
        self.lease_duration = None

    async def login(self) -> int:
        logger.info("Try to authenticate into Vault using AppRole method")
        resp = self.vault_provider.client.auth.approle.login(
            role_id=self.role_id, secret_id=self.secret_id
        )
        self.lease_duration = resp["auth"]["lease_duration"]
        logger.info(
            "Successfully authenticated. "
            f"Renew token after {self.renew_after(self.lease_duration):.2f} sec."
        )

    async def renew(self) -> int:
        resp = self.vault_provider.client.auth.token.renew_self()
        self.lease_duration = resp["auth"]["lease_duration"]

    async def run(self):
        assert self.lease_duration is not None

        while True:
            await asyncio.sleep(self.renew_after(self.lease_duration))
            logger.info("Renew token.")
            await self.renew()
            logger.info(
                "Token successfully renewed. "
                f"Do again after {self.renew_after(self.lease_duration):.2f} sec."
            )

    def renew_after(self, lease_duration: int):
        return lease_duration * 2 / 3
