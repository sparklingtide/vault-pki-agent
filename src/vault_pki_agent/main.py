import argparse
import asyncio
import json
import logging
import logging.config
import pathlib

from .auth import AuthController
from .pki_provider import VaultPKIProvider
from .watchers.certificates import CertificatesWatcher
from .watchers.crl import CRLWatcher

logger = logging.getLogger(__name__)


def configure_logging(log_level):
    logging.config.dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": True,
            "formatters": {
                "standard": {"format": "%(asctime)s [%(levelname)s] %(message)s"},
            },
            "handlers": {
                "default": {
                    "level": "DEBUG",
                    "formatter": "standard",
                    "class": "logging.StreamHandler",
                    "stream": "ext://sys.stdout",  # Default is stderr
                },
            },
            "loggers": {
                "vault_pki_agent": {"handlers": ["default"], "level": log_level},
            },
        }
    )


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", dest="config", help="json config to use")
    parser.add_argument(
        "-l",
        "--log-level",
        dest="log_level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        help="logs verbosity",
    )
    args = parser.parse_args()

    configure_logging(args.log_level)

    logger.info(f"Use config {args.config}")
    config = await load_config(args.config)

    pki_provider = VaultPKIProvider(
        url=config["url"], mount_point=config.get("mount_point")
    )
    auth_controller = AuthController.create_by_auth_data(pki_provider, config["auth"])
    await auth_controller.login()

    watchers = []
    for certificate in config["certificates"]:
        watchers.append(
            CertificatesWatcher(
                pki_provider=pki_provider,
                crt_destination=pathlib.Path(certificate["crt_destination"]),
                key_destination=pathlib.Path(certificate["key_destination"]),
                role=certificate["role"],
                common_name=certificate["common_name"],
                hook=certificate.get("hook"),
            )
        )
    watchers.append(
        CRLWatcher(
            pki_provider=pki_provider,
            destination=pathlib.Path(config["crl"]["destination"]),
        )
    )
    await asyncio.gather(
        *[watcher.watch() for watcher in watchers], auth_controller.run()
    )


async def load_config(path) -> dict:
    with open(path, "r") as fh:
        return json.loads(fh.read())


def run():
    asyncio.run(main())
