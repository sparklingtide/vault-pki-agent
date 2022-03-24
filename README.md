# Vault PKI Agent

[![PyPI version](https://badge.fury.io/py/vault-pki-agent.svg)](https://badge.fury.io/py/vault-pki-agent)

Tool for auto-renewal certificates and CRL from Vault PKI.

## Usage

Basic usage:

```shell
  $ vault_pki_agent -c [CONFIG_PATH] -l [LOG_LEVEL]
```

Log level can be DEBUG (by default), INFO, WARNING, ERROR, CRITICAL

## Configuration

Example:

```json
{
  "url": "http://111.111.111.111:8200",
  "mount_point": "pki",
  "auth": {
    "method": "approle",
    "role_id": "990ff41d-0448-f5d5-e405-22c05a23f976",
    "secret_id": "92871b67-0ad6-a4d5-40cc-0d8fb64e2960"
  },
  "crl": {
    "destination": "/etc/openvpn/keys/ca.crl"
  },
  "certificates": [
    {
      "role": "server",
      "common_name": "server",
      "crt_destination": "/etc/openvpn/keys/server.crt",
      "key_destination": "/etc/openvpn/keys/server.key",
      "hook": "systemctl restart openvpn"
    }
  ]
}
```

### Authentication

Now only two auth methods are implemented:
- *token*: You must define *token* property (it can contain root token)
- *approle*: You must define *role_id* and *secret_id* properties. Also you can use *role_id_file*
  and *secret_id_file* properties if you want to read *role_id* and *secret_id* from files.

## Release

1. Bump version in `pyproject.toml` and `__init__.py` files
2. Commit changes and create git tag with new version:

```shell
  $ git commit -am "Bump version"
  $ git tag v0.2.0
```

3. Build and publish new library version:

```shell
  $ poetry build
  $ poetry publish
```

4. Push:

```shell
  $ git push
  $ git push --tags
```

## License

Vault PKI Agent is released under the MIT License. See the [LICENSE](LICENSE) file for more details.
