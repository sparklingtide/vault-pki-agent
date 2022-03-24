from typing import Tuple

import hvac


class BasePKIProvider:
    def get_crl(self) -> str:
        raise NotADirectoryError

    def rotate_crl(self):
        raise NotImplementedError

    def create_certificate(self, role: str, common_name: str) -> Tuple[str, str]:
        raise NotImplementedError


class VaultPKIProvider(BasePKIProvider):
    def __init__(self, url: str, mount_point: str = "pki"):
        self.client = hvac.Client(url=url)
        self.mount_point = mount_point

    def get_crl(self) -> str:
        return self.client.secrets.pki.read_certificate(
            mount_point=self.mount_point, serial="crl"
        )["data"]["certificate"]

    def rotate_crl(self):
        self.client.secrets.pki.rotate_crl(mount_point=self.mount_point)

    def create_certificate(self, role: str, common_name: str) -> Tuple[str, str]:
        generate_resp = self.client.secrets.pki.generate_certificate(
            mount_point=self.mount_point,
            name=role,
            common_name=common_name,
        )
        return (
            generate_resp["data"]["certificate"],
            generate_resp["data"]["private_key"],
        )
