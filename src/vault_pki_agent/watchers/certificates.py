import asyncio
import logging
import pathlib
import subprocess
import sys
from datetime import datetime
from typing import Optional

from cryptography import x509

from vault_pki_agent.pki_provider import BasePKIProvider

logger = logging.getLogger(__name__)


class CertificatesWatcher:
    def __init__(
        self,
        pki_provider: BasePKIProvider,
        crt_destination: pathlib.Path,
        key_destination: pathlib.Path,
        role: str,
        common_name: str,
        hook: Optional[str] = None,
    ):
        self.pki_provider = pki_provider
        self.crt_destination = crt_destination
        self.key_destination = key_destination
        self.role = role
        self.common_name = common_name
        self.hook = hook

    async def watch(self):
        if not self.crt_destination.exists() or not self.key_destination.exists():
            logger.info(
                f'Key or certificate for common name "{self.common_name}" doesn\'t '
                "exists. Force renew it."
            )
            await self.renew()

        logger.info(f'Start watching for certificate "{self.common_name}"...')
        while True:
            seconds_to_wait = await self.get_wait_period()
            if seconds_to_wait <= 0:
                logger.info(
                    f'Need to force renew certificate "{self.common_name}" because '
                    "it's about to expiration or it's already expired."
                )
            else:
                logger.info(
                    f"Waiting for {seconds_to_wait:.2f} sec before "
                    f'renewal "{self.common_name}" certificate...'
                )
                await asyncio.sleep(seconds_to_wait)
                logger.info(f'It\'s time to renew certificate "{self.common_name}".')
            await self.renew()

    async def renew(self):
        crt, key = self.pki_provider.create_certificate(
            role=self.role,
            common_name=self.common_name,
        )

        with self.crt_destination.open("w") as fh:
            fh.write(crt)
        with self.key_destination.open("w") as fh:
            fh.write(key)

        logger.info(f'Certificate "{self.common_name}" successfully renewed.')

        await self.run_hook()

    async def get_wait_period(self) -> float:
        try:
            with self.crt_destination.open("rb") as fh:
                cert = x509.load_pem_x509_certificate(fh.read())
                duration = cert.not_valid_after - cert.not_valid_before
                renew_after = duration * 2 / 3
                renew_time = cert.not_valid_after + renew_after
                return (renew_time - datetime.utcnow()).total_seconds()
        except FileNotFoundError:
            return 0

    async def run_hook(self):
        if self.hook:
            logger.info(f'Run hook "{self.hook}"')
            return_code = subprocess.call(self.hook, shell=True)
            if return_code != 0:
                logger.critical(
                    "Hook returned non-zero code, immediately exit from the agent."
                )
                sys.exit(1)
