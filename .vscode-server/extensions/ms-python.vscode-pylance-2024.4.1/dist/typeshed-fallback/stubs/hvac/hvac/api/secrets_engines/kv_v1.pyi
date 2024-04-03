from _typeshed import Incomplete

from hvac.api.vault_api_base import VaultApiBase

DEFAULT_MOUNT_POINT: str

class KvV1(VaultApiBase):
    def read_secret(self, path, mount_point="secret"): ...
    def list_secrets(self, path, mount_point="secret"): ...
    def create_or_update_secret(self, path, secret, method: Incomplete | None = None, mount_point="secret"): ...
    def delete_secret(self, path, mount_point="secret"): ...
