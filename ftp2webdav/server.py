import logging
import os
import socket
import stat as stat_module
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import easywebdav2
import paramiko
from ftprelay import AuthenticationFailedError, Authenticator, FileProcessor, FTPRelay
from paramiko.sftp import (
    SFTP_FAILURE,
    SFTP_NO_SUCH_FILE,
    SFTP_OK,
    SFTP_OP_UNSUPPORTED,
    SFTP_PERMISSION_DENIED,
)

from .config import ConfigurationError

logger = logging.getLogger(__name__)


@dataclass
class WebDAVFileUploader(FileProcessor):
    webdav_client: easywebdav2.Client
    target_dir: Path

    def process_file(self, file: Path) -> None:
        # Create necessary directories
        self.webdav_client.mkdirs(str(self.target_dir))

        # Upload file
        remote_path = str(self.target_dir / file.name)
        self.webdav_client.upload(str(file), remote_path)

        logger.info(f"File '{file.name}' was uploaded successfully to '{remote_path}'.")


@dataclass
class WebDAVAuthenticator(Authenticator):
    webdav_config: dict[str, Any]
    target_dir: Path

    def authenticate(self, username: str, password: str) -> FileProcessor:
        if self.webdav_config.get("protocol") == "http":
            logger.warning("Using insecure WebDAV connection (http)")

        connect_config = self.webdav_config.copy()
        verify_ssl = connect_config.get("verify_ssl", True)
        if not verify_ssl:
            logger.warning("WebDAV SSL verification is disabled")
            # If SSL verification is disabled, the cert is not needed and can cause errors
            connect_config.pop("cert", None)

        try:
            webdav_client = easywebdav2.connect(
                username=username, password=password, **connect_config
            )
            # The exists method uses HEAD, which might not be supported as expected.
            # We can use ls() as a more reliable way to check for existence and auth.
            webdav_client.ls(str(self.target_dir))
            logger.info("WebDAV connection successful.")
        except easywebdav2.OperationFailed as err:
            if err.actual_code == 401:
                logger.warning(f"Authentication failed for user {username}")
            else:
                logger.error(f"WebDAV operation failed: {err}")
            raise AuthenticationFailedError() from err
        except Exception as err:
            logger.error(f"An unexpected error occurred during authentication: {err}")
            raise AuthenticationFailedError() from err

        return WebDAVFileUploader(webdav_client, self.target_dir)


class SftpFileHandle(paramiko.SFTPHandle):
    def __init__(
        self,
        file_processor: FileProcessor,
        local_path: Path,
        server_interface: "SftpServerInterface",
        remote_path: str,
        flags=0,
    ):
        super().__init__(flags)
        self.file_processor = file_processor
        self.local_path = local_path
        self.server_interface = server_interface
        self.remote_path = remote_path
        logger.info(f"[SFTP Handle] Created for remote path: {self.remote_path}")

    def write(self, offset, data):
        logger.info(f"[SFTP Handle] write(offset={offset}, len(data)={len(data)})")
        # The default implementation in paramiko.SFTPHandle writes the data
        # to self.file and returns SFTP_OK. We can just do that.
        try:
            self.file.seek(offset)
            self.file.write(data)
            logger.info("[SFTP Handle] write() returning SFTP_OK")
            return SFTP_OK
        except Exception as e:
            logger.error(f"[SFTP Handle] write() failed: {e}")
            return SFTP_FAILURE

    def stat(self):
        logger.info(f"[SFTP Handle] stat() called for {self.remote_path}")
        try:
            s = os.fstat(self.file.fileno())
            attr = paramiko.SFTPAttributes.from_stat(s)
            logger.info(f"[SFTP Handle] stat() returning attributes: {attr.__dict__}")
            return attr
        except OSError as e:
            logger.error(f"[SFTP Handle] stat() failed: {e}")
            return SFTP_FAILURE

    def close(self):
        logger.info(f"[SFTP Handle] close() called for {self.remote_path}")
        # The file object must be closed to ensure all data is flushed from OS buffers to disk.
        self.file.close()
        super().close()

        # Remove the file from the server's list of open files
        with self.server_interface.open_files_lock:
            if self.remote_path in self.server_interface.open_files:
                del self.server_interface.open_files[self.remote_path]
                logger.info(
                    f"[SFTP Handle] Removed {self.remote_path} from open files list."
                )

        logger.info(
            f"SFTP file transfer finished for {self.local_path.name}. Uploading to WebDAV."
        )
        try:
            # Now that the file is closed, we can safely process it.
            self.file_processor.process_file(self.local_path)
            self.local_path.unlink()  # Clean up the temp file
        except Exception as e:
            logger.error(
                f"Failed to process or cleanup {self.local_path.name} after upload: {e}"
            )
            return SFTP_FAILURE

        # If we get here, the upload and cleanup were successful.
        logger.info(f"[SFTP Handle] close() returning SFTP_OK for {self.remote_path}")
        return SFTP_OK


class SftpServerInterface(paramiko.SFTPServerInterface):
    def __init__(self, server, *args, **kwargs):
        super().__init__(server, *args, **kwargs)
        self.transport = server.transport
        self._temp_dir = tempfile.TemporaryDirectory(prefix="ftp2webdav-sftp-")
        self.temp_dir_path = Path(self._temp_dir.name)
        # Keep track of currently open files to provide proper stat responses
        self.open_files = {}
        self.open_files_lock = threading.Lock()
        logger.info("[SFTP Interface] Initialized.")

    def open(self, path, flags, attr):
        logger.info(f"[SFTP Interface] open(path={path}, flags={flags}, attr={attr})")
        file_processor = getattr(self.transport, "file_processor", None)
        if not file_processor:
            logger.warning("[SFTP Interface] open() returning SFTP_PERMISSION_DENIED")
            return SFTP_PERMISSION_DENIED

        local_path = self.temp_dir_path / Path(path).name

        # Simplified mode handling for write/append
        if flags & (os.O_WRONLY | os.O_RDWR):
            mode = "wb"
            if flags & os.O_APPEND:
                mode = "ab"
        else:
            # The relay does not support reading files from WebDAV
            logger.warning("[SFTP Interface] open() returning SFTP_OP_UNSUPPORTED")
            return SFTP_OP_UNSUPPORTED

        try:
            f = open(local_path, mode)
        except IOError as e:
            logger.error(f"[SFTP Interface] open() failed: {e}")
            return SFTP_FAILURE

        # Track the open file so we can stat it correctly
        with self.open_files_lock:
            self.open_files[path] = local_path
            logger.info(f"[SFTP Interface] Added {path} to open files list.")

        handle = SftpFileHandle(file_processor, local_path, self, path)
        handle.file = f
        logger.info(f"[SFTP Interface] open() returning new handle for {path}")
        return handle

    def listdir(self, path):
        logger.info(f"[SFTP Interface] listdir(path={path}) returning []")
        return []  # Listing files is not supported

    def stat(self, path):
        logger.info(f"[SFTP Interface] stat(path={path})")
        # Check if the client is stat-ing a file that is currently being uploaded.
        with self.open_files_lock:
            local_path = self.open_files.get(path)

        if local_path:
            try:
                # If it's an open file, return its real, current attributes.
                s = os.stat(local_path)
                attr = paramiko.SFTPAttributes.from_stat(s)
                logger.info(
                    f"[SFTP Interface] stat() returning real attributes for open file {path}: {attr.__dict__}"
                )
                return attr
            except OSError:
                # The file might have been closed and removed between our check and now.
                logger.warning(
                    f"[SFTP Interface] stat() could not find open file {path} on disk."
                )
                return SFTP_NO_SUCH_FILE

        # This is a write-only server. The only other path that "exists" is the root directory.
        if path == "/":
            attr = paramiko.SFTPAttributes()
            attr.st_mode = stat_module.S_IFDIR | 0o755
            logger.info(f"[SFTP Interface] stat() returning dummy DIR attributes for /")
            return attr
        else:
            # For any other path, signal that it doesn't exist.
            logger.info(
                f"[SFTP Interface] stat() returning SFTP_NO_SUCH_FILE for {path}"
            )
            return SFTP_NO_SUCH_FILE

    def lstat(self, path):
        logger.info(f"[SFTP Interface] lstat(path={path})")
        # lstat is like stat but for symlinks. We don't support symlinks,
        # so we can just treat it like a regular stat.
        return self.stat(path)

    def fsetstat(self, handle, attr):
        logger.info(f"[SFTP Interface] fsetstat(handle, attr={attr}) returning SFTP_OK")
        # SFTP clients like to set attributes after an upload. We don't need to do
        # anything, but returning SFTP_OK prevents the client from reporting an error.
        return SFTP_OK

    def extended(self, request_name, request_data):
        logger.info(
            f"[SFTP Interface] extended(request_name={request_name}, ...)"
        )
        # Handle the 'fsync@openssh.com' extension used by modern OpenSSH clients.
        # The client sends this to ensure data is written to disk. We don't need
        # to do anything special, but acknowledging it with SFTP_OK is crucial
        # to prevent the client from aborting the upload.
        if request_name == b"fsync@openssh.com":
            logger.info(
                "[SFTP Interface] extended() received fsync, returning SFTP_OK"
            )
            return SFTP_OK
        logger.warning(
            "[SFTP Interface] extended() received unknown request, returning SFTP_OP_UNSUPPORTED"
        )
        return SFTP_OP_UNSUPPORTED


class SftpAuthInterface(paramiko.ServerInterface):
    def __init__(self, authenticator: Authenticator, transport):
        self.authenticator = authenticator
        self.transport = transport
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        try:
            file_processor = self.authenticator.authenticate(username, password)
            self.transport.file_processor = file_processor
            return paramiko.AUTH_SUCCESSFUL
        except AuthenticationFailedError:
            return paramiko.AUTH_FAILED


@dataclass
class SFTPRelay:
    authenticator: Authenticator
    host: str
    port: int
    host_key_file: str

    def __post_init__(self):
        self._sock = None
        self._thread = None
        self._running = False
        try:
            self.host_key = paramiko.RSAKey(filename=self.host_key_file)
        except Exception as e:
            raise ConfigurationError(
                f"Failed to load SFTP host key from {self.host_key_file}: {e}"
            ) from e

    def _run(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(100)
        logger.info(f"SFTP relay listening on {self.host}:{self.port}")

        while self._running:
            try:
                client_sock, addr = self._sock.accept()
                logger.info(f"SFTP connection from {addr}")

                transport = paramiko.Transport(client_sock)
                transport.add_server_key(self.host_key)

                auth_interface = SftpAuthInterface(self.authenticator, transport)
                transport.start_server(server=auth_interface)

                channel = transport.accept(20)
                if channel is not None:
                    transport.set_subsystem_handler(
                        "sftp", paramiko.SFTPServer, SftpServerInterface
                    )
            except Exception as e:
                if self._running:
                    logger.error(f"SFTP relay error: {e}", exc_info=True)

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._sock:
            self._sock.close()
        if self._thread:
            self._thread.join()
        logger.info("SFTP relay stopped.")


@dataclass
class Server:
    config: dict[str, Any]
    relay: Any = field(init=False, default=None)

    def __post_init__(self):
        server_type = self.config.get("type", "ftp")
        target_dir = Path(self.config["target_dir"])
        webdav_config = self.config["webdav"]

        authenticator = WebDAVAuthenticator(webdav_config, target_dir)

        if server_type == "ftp":
            ftp_config = self.config["ftp"]
            self.relay = FTPRelay(
                authenticator=authenticator,
                host=ftp_config["host"],
                port=ftp_config["port"],
            )
            logger.info("FTP relay server selected.")
        elif server_type == "sftp":
            sftp_config = self.config["sftp"]
            host_key_file = sftp_config.get("host_key_file", "host.key")
            if not Path(host_key_file).exists():
                logger.warning(
                    f"SFTP host key '{host_key_file}' not found. Generating a new one."
                )
                key = paramiko.RSAKey.generate(2048)
                key.write_private_key_file(host_key_file)

            self.relay = SFTPRelay(
                authenticator=authenticator,
                host=sftp_config["host"],
                port=sftp_config["port"],
                host_key_file=host_key_file,
            )
            logger.info("SFTP relay server selected.")
        else:
            raise ValueError(f"Unknown server type: {server_type}")

    def start(self):
        self.relay.start()

    def stop(self):
        self.relay.stop()
