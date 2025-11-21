import os
from cerberus import Validator


class CustomValidator(Validator):
    def _check_with_sftp_auth(self, field, value):
        if self.document.get("type") == "sftp":
            if "password" not in value and "private_key" not in value:
                self._error(
                    field,
                    "At least one of 'password' or 'private_key' is required for sftp.",
                )

    def _check_with_safe_path(self, field, value):
        if ".." in value or os.path.isabs(value):
            self._error(field, "Path traversal and absolute paths are not allowed.")


_SCHEMA = {
    "type": {"type": "string", "allowed": ["ftp", "sftp"], "default": "ftp"},
    "ftp": {
        "type": "dict",
        "schema": {
            "host": {"type": "string", "default": "127.0.0.1"},
            "port": {
                "type": "integer",
                "coerce": int,
                "min": 1,
                "max": 65535,
                "default": 21,
            },
            "user": {"type": "string", "default": "anonymous"},
            "password": {"type": "string", "default": ""},
        },
        "default": {},
    },
    "sftp": {
        "type": "dict",
        "check_with": "sftp_auth",
        "schema": {
            "host": {"type": "string", "default": "127.0.0.1"},
            "port": {
                "type": "integer",
                "coerce": int,
                "min": 1,
                "max": 65535,
                "default": 22,
            },
            "user": {"type": "string", "default": "user"},
            "password": {"type": "string", "required": False},
            "private_key": {"type": "string", "required": False},
            "private_key_pass": {
                "type": "string",
                "required": False,
                "dependencies": "private_key",
            },
        },
        "default": {},
    },
    "webdav": {
        "type": "dict",
        "required": True,
        "schema": {
            "host": {"type": "string", "required": True},
            "port": {"type": "integer", "coerce": int, "min": 1, "max": 65535},
            "protocol": {
                "type": "string",
                "allowed": ["http", "https"],
                "default": "https",
            },
            "path": {"type": "string"},
            "verify_ssl": {"type": ["boolean", "string"], "default": True},
            "cert": {"type": "string"},
        },
    },
    "target_dir": {"type": "string", "default": ".", "check_with": "safe_path"},
}


class ConfigurationError(Exception):
    pass


def build_configuration(raw_config):
    v = CustomValidator(allow_unknown=False)
    if not v.validate(raw_config, _SCHEMA):
        raise ConfigurationError(v.errors)
    else:
        return v.normalized(raw_config, _SCHEMA)
