import asyncio
import logging
import pathlib
from datetime import datetime

from cryptography import x509

from vault_pki_agent.pki_provider import BasePKIProvider

logger = logging.getLogger(__name__)


class CRLWatcher:
    def __init__(
        self,
        pki_provider: BasePKIProvider,
        destination: pathlib.Path,
    ):
        self.pki_provider = pki_provider
        self.destination = destination

    async def watch(self):
        if not self.destination.exists():
            logger.info("CRL file doesn't exist for given path. Pull and create it.")
            await self.pull()

        logger.info("Start watching for CRL.")
        while True:
            seconds_to_wait = await self.get_wait_period()
            if seconds_to_wait <= 0:
                logger.info(
                    "Need to force update CRL because it's about to expiration"
                    " or it's already expires."
                )
            else:
                logger.info(f"Waiting for {seconds_to_wait} sec before CRL renewal...")
                await asyncio.sleep(seconds_to_wait)
                logger.info("Renew CRL.")
            await self.update()

    async def pull(self):
        crl = self.pki_provider.get_crl()

        with self.destination.open("w") as fh:
            fh.write(crl)

    async def update(self):
        crl = self.pki_provider.get_crl()
        with self.destination.open("r") as fh:
            old_crl = fh.read()
        with self.destination.open("w") as fh:
            if crl != old_crl:
                logger.info("CRL has been updated, write new one to the destination.")
                fh.write(crl)
            else:
                logger.info(
                    "CRL hasn't been updated, rotate it and "
                    "write new one to the destination."
                )
                self.pki_provider.rotate_crl()
                await self.pull()

    async def get_wait_period(self) -> float:
        try:
            with self.destination.open("rb") as fh:
                crl = x509.load_pem_x509_crl(fh.read())
                duration = crl.next_update - crl.last_update
                renew_after = duration * 2 / 3
                renew_time = crl.last_update + renew_after
                return (renew_time - datetime.utcnow()).total_seconds()
        except FileNotFoundError:
            return 0
