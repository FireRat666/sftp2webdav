import logging
import os
import posixpath
import socket
import stat as stat_module
import tempfile
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Tuple
from urllib.parse import unquote, urljoin

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
from paramiko.ssh_exception import SSHException

from .config import ConfigurationError
from .ftp_handler import WebDAVFTPHandler

logger = logging.getLogger(__name__)


@dataclass
class WebDAVFileUploader(FileProcessor):
    webdav_client: easywebdav2.Client
    target_dir: Path

    def process_file(self, file: Path, remote_path: str) -> None:
        logger.debug(f"[[[WebDAVFileUploader]]] process_file called for: {file}, remote_path: {remote_path}")
        # Ensure the parent directories exist on WebDAV
        remote_dir = posixpath.dirname(remote_path)
        if remote_dir and remote_dir != "/": # Don't try to mkdir for root
            self.webdav_client.mkdirs(remote_dir)
        self.webdav_client.upload(str(file), remote_path)
        logger.info(f"File '{file.name}' was uploaded successfully to '{remote_path}'.")


@dataclass
class WebDAVAuthenticator: # Removed inheritance from Authenticator
    webdav_config: dict[str, Any]
    target_dir: Path

    def authenticate(
        self, client_username: str, client_password: str
    ) -> Tuple[FileProcessor, easywebdav2.Client]:
        logger.debug(f"[[[WebDAVAuthenticator]]] Authenticating client user: {client_username}")
        if self.webdav_config.get("protocol") == "http":
            logger.warning("Using insecure WebDAV connection (http)")

        connect_config = self.webdav_config.copy()
        webdav_username = connect_config.pop("user", None)
        webdav_password = connect_config.pop("password", None)

        verify_ssl = connect_config.get("verify_ssl", True)
        if not verify_ssl:
            logger.warning("WebDAV SSL verification is disabled")
            connect_config.pop("cert", None)

        try:
            webdav_client = easywebdav2.connect(
                username=webdav_username, password=webdav_password, **connect_config
            )
            logger.debug(
                f"[[[WebDAVAuthenticator]]] Checking for target directory: {self.target_dir}"
            )
            webdav_client.ls(str(self.target_dir))
            logger.info("WebDAV connection successful.")
        except easywebdav2.OperationFailed as err:
            if err.actual_code == 401:
                logger.warning(f"WebDAV authentication failed for user {webdav_username}")
            else:
                logger.error(f"WebDAV operation failed: {err}")
            raise AuthenticationFailedError() from err
        except Exception as err:
            logger.error(f"An unexpected error occurred during WebDAV authentication: {err}")
            raise AuthenticationFailedError() from err

        logger.debug("[[[WebDAVAuthenticator]]] WebDAV authentication successful.")
        return WebDAVFileUploader(webdav_client, self.target_dir), webdav_client


@dataclass
class FTPClientAuthenticator(Authenticator):
    ftp_config: dict[str, Any]
    webdav_authenticator: WebDAVAuthenticator

    def authenticate(
        self, username: str, password: str
    ) -> Tuple[FileProcessor, easywebdav2.Client]:
        logger.debug(f"[[[FTPClientAuthenticator]]] authenticate(username={username}, password={'*' * len(password) if password else 'None'})")
        configured_user = self.ftp_config.get("user")
        configured_password = self.ftp_config.get("password")

        # FTP Server Authentication (Client -> ftp2webdav)
        if configured_user and configured_password:
            # Authenticate against configured user/password
            if username == configured_user and password == configured_password:
                logger.info(f"FTP client '{username}' authenticated successfully.")
            else:
                logger.warning(f"FTP client authentication failed for user '{username}'.")
                raise AuthenticationFailedError()
        else:
            # Permit anonymous logins if no user/password specified
            logger.info(f"FTP client '{username}' allowed anonymous login.")

        # WebDAV Client Authentication (ftp2webdav -> WebDAV Server)
        # Use the WebDAVAuthenticator to establish the connection to the WebDAV server
        file_processor, webdav_client = self.webdav_authenticator.authenticate(username, password)
        logger.debug(f"[[[FTPClientAuthenticator]]] authenticate returning file_processor: {file_processor}, webdav_client: {webdav_client}")
        return file_processor, webdav_client

    def get_perms(self, username):
        """
        Returns a string representing the permissions for the given username.
        'e': change directory (CWD, CDUP)
        'l': list directory (LIST, NLST)
        'r': retrieve file from server (RETR)
        'a': append data to a file (APPE)
        'd': delete file or directory (DELE, RMD)
        'f': rename file (RNFR, RNTO)
        'w': store file to server (STOR)
        'm': create directory (MKD)
        """
        perms = "elradfmw"
        logger.debug(f"[[[FTPClientAuthenticator]]] get_perms(username={username}) returning: {perms}")
        return perms

    def get_home_dir(self, username):
        """
        Returns the virtual home directory for the FTP user.
        The actual temporary local storage is handled by CustomAuthorizer.
        """
        return "/"


@dataclass
class SFTPClientAuthenticator(Authenticator):
    sftp_config: dict[str, Any]
    webdav_authenticator: WebDAVAuthenticator

    def authenticate(
        self, username: str, password: str = None, private_key: paramiko.PKey = None
    ) -> Tuple[FileProcessor, easywebdav2.Client]:
        configured_user = self.sftp_config.get("user")
        configured_password = self.sftp_config.get("password")
        configured_private_key_path = self.sftp_config.get("private_key")
        configured_private_key_pass = self.sftp_config.get("private_key_pass")

        sftp_auth_successful = False

        if configured_user:
            if username != configured_user:
                logger.warning(f"SFTP client authentication failed: Unknown user '{username}'.")
                raise AuthenticationFailedError()

            if configured_password:
                if password == configured_password:
                    sftp_auth_successful = True
                    logger.info(f"SFTP client '{username}' authenticated successfully with password.")
                else:
                    logger.warning(f"SFTP client authentication failed for user '{username}': Incorrect password.")
                    raise AuthenticationFailedError()
            elif configured_private_key_path:
                try:
                    configured_key = paramiko.RSAKey.from_private_key_file(
                        configured_private_key_path, password=configured_private_key_pass
                    )
                    # In a real scenario, you'd compare the client's provided key with the configured_key
                    # For simplicity, we'll assume if a key is configured, any key-based auth attempt is valid if the username matches.
                    # A more robust implementation would involve comparing fingerprints or actual key objects.
                    if private_key: # This means the client attempted key-based auth
                        sftp_auth_successful = True
                        logger.info(f"SFTP client '{username}' authenticated successfully with private key.")
                    else:
                        logger.warning(f"SFTP client '{username}' expected private key, but password was provided.")
                        raise AuthenticationFailedError()
                except Exception as e:
                    logger.error(f"Error loading configured private key for SFTP: {e}")
                    raise AuthenticationFailedError() from e
            else:
                # No password or private key configured, but a user is. This case shouldn't happen with schema validation.
                logger.warning(f"SFTP configuration for user '{configured_user}' is incomplete (missing password/private_key).")
                raise AuthenticationFailedError()
        else:
            # No user configured in sftp section, allow any SFTP client to connect (anonymous)
            sftp_auth_successful = True
            logger.info(f"SFTP client '{username}' allowed anonymous login (no user configured).")

        if not sftp_auth_successful:
            logger.warning(f"SFTP client authentication failed for user '{username}'.")
            raise AuthenticationFailedError()

        # WebDAV Client Authentication (ftp2webdav -> WebDAV Server)
        return self.webdav_authenticator.authenticate(username, password)

    def get_perms(self, username):
        # SFTP permissions are handled differently, but for consistency with the Authenticator interface
        return "elradfmw"

    def get_home_dir(self, username):
        # SFTP doesn't directly use a "home directory" in the same way FTP does for pyftpdlib's authorizer.
        # This is a placeholder to satisfy the Authenticator interface.
        return "/"


class SftpFileHandle(paramiko.SFTPHandle):
    def __init__(
        self,
        local_path: Path,
        server_interface: "SftpServerInterface",
        remote_path: str,
        flags=0,
    ):
        super().__init__(flags)
        self.local_path = local_path
        self.server_interface = server_interface
        self.remote_path = remote_path
        logger.info(f"[[[SftpFileHandle]]] Created for remote path: {self.remote_path}")

    def write(self, offset, data):
        logger.info(
            f"[[[SftpFileHandle]]] write(offset={offset}, len(data)={len(data)})"
        )
        try:
            self.file.seek(offset)
            self.file.write(data)
            return SFTP_OK
        except Exception as e:
            logger.error(f"[[[SftpFileHandle]]] write() failed: {e}")
            return SFTP_FAILURE

    def stat(self):
        logger.info(f"[[[SftpFileHandle]]] stat() called for {self.remote_path}")
        try:
            s = os.fstat(self.file.fileno())
            logger.debug(f"[[[SftpFileHandle]]] stat() result: {s}")
            return paramiko.SFTPAttributes.from_stat(s)
        except OSError as e:
            logger.error(f"[[[SftpFileHandle]]] stat() failed: {e}")
            return SFTP_FAILURE

    def close(self):
        logger.info(f"[[[SftpFileHandle]]] close() called for {self.remote_path}")
        self.file.close()
        super().close()

        with self.server_interface.open_files_lock:
            if self.remote_path in self.server_interface.open_files:
                del self.server_interface.open_files[self.remote_path]
                logger.debug(
                    f"[[[SftpFileHandle]]] Removed {self.remote_path} from open files list."
                )

        logger.info(
            f"SFTP file transfer finished for {self.local_path.name}. Uploading to WebDAV."
        )
        try:
            webdav_client = self.server_interface.webdav_client
            if not webdav_client:
                logger.error(
                    f"[[[SftpFileHandle]]] WebDAV client not available for upload."
                )
                return SFTP_FAILURE

            remote_dir = posixpath.dirname(self.remote_path)
            webdav_client.mkdirs(remote_dir)
            webdav_client.upload(str(self.local_path), self.remote_path)
            logger.info(
                f"File '{self.local_path.name}' was uploaded successfully to '{self.remote_path}'."
            )

            self.local_path.unlink()
        except Exception as e:
            logger.error(
                f"Failed to process or cleanup {self.local_path.name} after upload: {e}"
            )
            return SFTP_FAILURE
        return SFTP_OK


class SftpServerInterface(paramiko.SFTPServerInterface):
    def __init__(self, server, *args, **kwargs):
        super().__init__(server, *args, **kwargs)
        self.transport = server.transport
        self._temp_dir = tempfile.TemporaryDirectory(prefix="ftp2webdav-sftp-")
        self.temp_dir_path = Path(self._temp_dir.name)
        self.open_files = {}
        self.open_files_lock = threading.Lock()
        self.cwd = "/"
        logger.info(f"[[[SFTP Interface]]] [[[ INITIALIZED ]]] ID: {id(self)}")

    def session_started(self):
        logger.info(f"[[[SFTP Interface]]] [[[ SESSION STARTED ]]] ID: {id(self)}")
        return super().session_started()

    def session_ended(self):
        logger.info(f"[[[SFTP Interface]]] [[[ SESSION ENDED ]]] ID: {id(self)}")
        return super().session_ended()

    @property
    def webdav_client(self) -> easywebdav2.Client | None:
        client = getattr(self.transport, "webdav_client", None)
        logger.debug(
            f"[[[SFTP Interface]]] webdav_client property accessed on {id(self)}: Client is {'present' if client else 'MISSING'}"
        )
        return client

    def _resolve_path(self, path):
        original_path = path
        if not path or path == ".":
            resolved = self.cwd
        elif path.startswith("/"):
            resolved = posixpath.normpath(path)
        else:
            resolved = posixpath.normpath(posixpath.join(self.cwd, path))
        logger.debug(
            f"[[[SFTP Interface]]] _resolve_path: original='{original_path}', cwd='{self.cwd}', resolved='{resolved}'"
        )
        return resolved

    def canonicalize(self, path):
        logger.info(
            f"[[[SFTP Interface]]] [[[ ENTRY canonicalize ]]] path={path} on ID: {id(self)}"
        )
        remote_path = self._resolve_path(path)
        logger.debug(f"[[[SFTP Interface]]] canonicalize resolved path: {remote_path}")

        if not self.webdav_client:
            logger.error(
                "[[[SFTP Interface]]] WebDAV client not available for canonicalize."
            )
            return SFTP_FAILURE

        try:
            # Attempt to list the path. If it's a directory, this will succeed.
            # If it's a file or doesn't exist, it will raise OperationFailed.
            self.webdav_client.ls(remote_path)

            # Success means it's a directory.
            self.cwd = remote_path
            logger.info(f"[[[SFTP Interface]]] CWD updated to {self.cwd}")
            logger.info(
                f"[[[SFTP Interface]]] [[[ EXIT canonicalize ]]] returning path {remote_path}"
            )
            return remote_path

        except easywebdav2.OperationFailed as e:
            if e.actual_code == 404:  # Not Found
                logger.warning(
                    f"[[[SFTP Interface]]] canonicalize path not found: {remote_path}"
                )
            else:
                # Any other failure (e.g., trying to ls a file) is treated as "not a directory".
                logger.warning(
                    f"[[[SFTP Interface]]] canonicalize path is not a directory: {remote_path} (error: {e})"
                )
            return SFTP_NO_SUCH_FILE
        except Exception as e:
            logger.error(
                f"[[[SFTP Interface]]] Unexpected error in canonicalize: {e}",
                exc_info=True,
            )
            return SFTP_FAILURE

    def open(self, path, flags, attr):
        logger.info(
            f"[[[SFTP Interface]]] [[[ ENTRY open ]]] path={path}, flags={flags}, attr={attr} on ID: {id(self)}"
        )
        if not self.webdav_client:
            logger.error("[[[SFTP Interface]]] open() - No WebDAV client. Denying.")
            return SFTP_PERMISSION_DENIED

        remote_path = self._resolve_path(path)
        local_path = self.temp_dir_path / Path(remote_path).name
        logger.debug(f"[[[SFTP Interface]]] open() - Local path: {local_path}")

        if flags & (os.O_WRONLY | os.O_RDWR):
            mode = "wb"
            if flags & os.O_APPEND:
                mode = "ab"
        else:
            logger.warning(
                f"[[[SFTP Interface]]] open() - Unsupported flags {flags}. Denying."
            )
            return SFTP_OP_UNSUPPORTED

        try:
            f = open(local_path, mode)
        except IOError as e:
            logger.error(f"[[[SFTP Interface]]] open() failed to open local file: {e}")
            return SFTP_FAILURE

        with self.open_files_lock:
            self.open_files[remote_path] = local_path
            logger.debug(f"[[[SFTP Interface]]] Added {remote_path} to open files list.")

        handle = SftpFileHandle(local_path, self, remote_path, flags)
        handle.file = f
        logger.info(f"[[[SFTP Interface]]] [[[ EXIT open ]]] on ID: {id(self)}")
        return handle

    def list_folder(self, path):
        logger.info(
            f"[[[SFTP Interface]]] [[[ ENTRY list_folder ]]] path={path} on ID: {id(self)}"
        )
        if not self.webdav_client:
            logger.error(
                "[[[SFTP Interface]]] WebDAV client not available for list_folder."
            )
            return SFTP_FAILURE

        try:
            remote_path = self._resolve_path(path)
            logger.info(f"[[[SFTP Interface]]] Listing WebDAV directory: {remote_path}")

            listing = self.webdav_client.ls(remote_path)
            logger.debug(
                f"[[[SFTP Interface]]] WebDAV listing returned {len(listing)} items."
            )
            sftp_attributes = []
            for item in listing:
                name = item.name.rstrip("/")
                filename = unquote(os.path.basename(name))
                if not filename:
                    continue
                attr = paramiko.SFTPAttributes()
                attr.filename = filename
                attr.st_size = item.size
                if item.mtime:
                    try:
                        if isinstance(item.mtime, str):
                            dt_obj = None
                            try:
                                # Attempt to parse RFC 1123 format, e.g., 'Fri, 21 Nov 2025 08:42:31 GMT'
                                dt_obj = datetime.strptime(
                                    item.mtime, "%a, %d %b %Y %H:%M:%S %Z"
                                )
                                dt_obj = dt_obj.replace(tzinfo=timezone.utc)
                            except ValueError:
                                # Fallback to ISO 8601 format, e.g., '2025-11-21T08:42:31Z'
                                mtime_str = item.mtime.replace("Z", "+00:00")
                                dt_obj = datetime.fromisoformat(mtime_str)
                            attr.st_mtime = int(dt_obj.timestamp())
                        else:
                            attr.st_mtime = int(item.mtime.timestamp())
                    except (ValueError, TypeError, OSError) as e:
                        logger.warning(
                            f"Could not parse mtime '{item.mtime}' for '{filename}': {e}"
                        )
                if item.contenttype == "httpd/unix-directory":
                    attr.st_mode = stat_module.S_IFDIR | 0o755
                else:
                    attr.st_mode = stat_module.S_IFREG | 0o644
                sftp_attributes.append(attr)
                logger.debug(f"[[[SFTP Interface]]] list_folder item: {attr.filename}")
            logger.info(
                f"[[[SFTP Interface]]] [[[ EXIT list_folder ]]] returning {len(sftp_attributes)} items."
            )
            return sftp_attributes
        except Exception as e:
            logger.error(
                f"[[[SFTP Interface]]] Error listing directory: {e}", exc_info=True
            )
            return SFTP_FAILURE

    def mkdir(self, path, attr):
        logger.info(
            f"[[[SFTP Interface]]] [[[ ENTRY mkdir ]]] path={path} on ID: {id(self)}"
        )
        if not self.webdav_client:
            logger.error("[[[SFTP Interface]]] mkdir() - No WebDAV client. Denying.")
            return SFTP_PERMISSION_DENIED

        remote_path = self._resolve_path(path)
        logger.debug(f"[[[SFTP Interface]]] mkdir() - Remote path: {remote_path}")

        try:
            self.webdav_client.mkdir(remote_path)
            logger.info(f"[[[SFTP Interface]]] Directory created: {remote_path}")
            return SFTP_OK
        except easywebdav2.OperationFailed as e:
            logger.error(f"[[[SFTP Interface]]] mkdir() failed: {e}")
            if e.actual_code == 405:  # Method Not Allowed (e.g., directory exists)
                return SFTP_FAILURE # Or a more specific error
            return SFTP_FAILURE
        except Exception as e:
            logger.error(f"[[[SFTP Interface]]] mkdir() unexpected error: {e}", exc_info=True)
            return SFTP_FAILURE

    def rename(self, oldpath, newpath):
        logger.info(
            f"[[[SFTP Interface]]] [[[ ENTRY rename ]]] oldpath={oldpath}, newpath={newpath} on ID: {id(self)}"
        )
        if not self.webdav_client:
            logger.error("[[[SFTP Interface]]] rename() - No WebDAV client. Denying.")
            return SFTP_PERMISSION_DENIED

        remote_oldpath = self._resolve_path(oldpath)
        remote_newpath = self._resolve_path(newpath)
        logger.debug(f"[[[SFTP Interface]]] rename() - From: {remote_oldpath}, To: {remote_newpath}")

        try:
            self.webdav_client.move(remote_oldpath, remote_newpath)
            logger.info(f"[[[SFTP Interface]]] Renamed: {remote_oldpath} to {remote_newpath}")
            return SFTP_OK
        except easywebdav2.OperationFailed as e:
            logger.error(f"[[[SFTP Interface]]] rename() failed: {e}")
            if e.actual_code == 404:
                return SFTP_NO_SUCH_FILE
            return SFTP_FAILURE
        except Exception as e:
            logger.error(f"[[[SFTP Interface]]] rename() unexpected error: {e}", exc_info=True)
            return SFTP_FAILURE

    def remove(self, path):
        logger.info(
            f"[[[SFTP Interface]]] [[[ ENTRY remove ]]] path={path} on ID: {id(self)}"
        )
        if not self.webdav_client:
            logger.error("[[[SFTP Interface]]] remove() - No WebDAV client. Denying.")
            return SFTP_PERMISSION_DENIED

        remote_path = self._resolve_path(path)
        logger.debug(f"[[[SFTP Interface]]] remove() - Remote path: {remote_path}")

        try:
            self.webdav_client.delete(remote_path)
            logger.info(f"[[[SFTP Interface]]] Removed: {remote_path}")
            return SFTP_OK
        except easywebdav2.OperationFailed as e:
            if e.actual_code == 404:
                return SFTP_NO_SUCH_FILE
            return SFTP_FAILURE
        except Exception as e:
            logger.error(f"[[[SFTP Interface]]] remove() unexpected error: {e}", exc_info=True)
            return SFTP_FAILURE

    def rmdir(self, path):
        logger.info(
            f"[[[SFTP Interface]]] [[[ ENTRY rmdir ]]] path={path} on ID: {id(self)}"
        )
        if not self.webdav_client:
            logger.error("[[[SFTP Interface]]] rmdir() - No WebDAV client. Denying.")
            return SFTP_PERMISSION_DENIED

        remote_path = self._resolve_path(path)
        logger.debug(f"[[[SFTP Interface]]] rmdir() - Remote path: {remote_path}")

        try:
            # easywebdav2's delete works for directories too
            self.webdav_client.delete(remote_path)
            logger.info(f"[[[SFTP Interface]]] Removed directory: {remote_path}")
            return SFTP_OK
        except easywebdav2.OperationFailed as e:
            if e.actual_code == 404:
                return SFTP_NO_SUCH_FILE
            # 409 Conflict could mean not empty
            if e.actual_code == 409:
                logger.warning(f"[[[SFTP Interface]]] rmdir() failed, directory likely not empty: {remote_path}")
                return SFTP_FAILURE
            return SFTP_FAILURE
        except Exception as e:
            logger.error(f"[[[SFTP Interface]]] rmdir() unexpected error: {e}", exc_info=True)
            return SFTP_FAILURE

    def stat(self, path):
        logger.info(
            f"[[[SFTP Interface]]] [[[ ENTRY stat ]]] path={path} on ID: {id(self)}"
        )
        with self.open_files_lock:
            local_path = self.open_files.get(path)

        if local_path:
            logger.debug(f"[[[SFTP Interface]]] stat() - Found open file: {local_path}")
            try:
                s = os.stat(local_path)
                logger.info(f"[[[SFTP Interface]]] [[[ EXIT stat ]]] on ID: {id(self)}")
                return paramiko.SFTPAttributes.from_stat(s)
            except OSError:
                logger.warning(
                    f"[[[SFTP Interface]]] stat() - Open file {local_path} not found on disk."
                )
                # Fall through to check WebDAV
                pass

        if not self.webdav_client:
            logger.error("[[[SFTP Interface]]] WebDAV client not available for stat.")
            return SFTP_FAILURE

        remote_path = self._resolve_path(path)
        logger.debug(f"[[[SFTP Interface]]] stat() checking WebDAV path: {remote_path}")

        if remote_path == "/":
            logger.debug(
                "[[[SFTP Interface]]] stat() - Path is root, returning dir attributes."
            )
            attr = paramiko.SFTPAttributes()
            attr.st_mode = stat_module.S_IFDIR | 0o755
            logger.info(f"[[[SFTP Interface]]] [[[ EXIT stat ]]] on ID: {id(self)}")
            return attr

        try:
            parent_dir = posixpath.dirname(remote_path)
            basename = posixpath.basename(remote_path)
            listing = self.webdav_client.ls(parent_dir)

            for item in listing:
                item_name = unquote(posixpath.basename(item.name.rstrip("/")))
                if item_name == basename:
                    logger.debug(f"[[[SFTP Interface]]] stat() found item: {item_name}")
                    attr = paramiko.SFTPAttributes()
                    attr.filename = basename
                    attr.st_size = item.size
                    if item.mtime:
                        try:
                            if isinstance(item.mtime, str):
                                dt_obj = None
                                try:
                                    dt_obj = datetime.strptime(
                                        item.mtime, "%a, %d %b %Y %H:%M:%S %Z"
                                    )
                                    dt_obj = dt_obj.replace(tzinfo=timezone.utc)
                                except ValueError:
                                    mtime_str = item.mtime.replace("Z", "+00:00")
                                    dt_obj = datetime.fromisoformat(mtime_str)
                                attr.st_mtime = int(dt_obj.timestamp())
                            else:
                                attr.st_mtime = int(item.mtime.timestamp())
                        except (ValueError, TypeError, OSError) as e:
                            logger.warning(
                                f"Could not parse mtime '{item.mtime}' for '{filename}': {e}"
                            )
                    if item.contenttype == "httpd/unix-directory":
                        attr.st_mode = stat_module.S_IFDIR | 0o755
                    else:
                        attr.st_mode = stat_module.S_IFREG | 0o644
                    logger.info(
                        f"[[[SFTP Interface]]] [[[ EXIT stat ]]] returning attributes for {path}"
                    )
                    return attr

            logger.warning(f"[[[SFTP Interface]]] stat() - Path {path} not found in parent listing.")
            return SFTP_NO_SUCH_FILE

        except easywebdav2.OperationFailed as e:
            if e.actual_code == 404:
                logger.warning(f"[[[SFTP Interface]]] stat() parent path not found: {parent_dir}")
            else:
                logger.error(f"[[[SFTP Interface]]] stat() WebDAV operation failed: {e}")
            return SFTP_NO_SUCH_FILE
        except Exception as e:
            logger.error(f"[[[SFTP Interface]]] stat() unexpected error: {e}", exc_info=True)
            return SFTP_FAILURE

    def lstat(self, path):
        logger.info(
            f"[[[SFTP Interface]]] [[[ ENTRY lstat ]]] path={path} on ID: {id(self)}"
        )
        result = self.stat(path)
        logger.info(f"[[[SFTP Interface]]] [[[ EXIT lstat ]]] on ID: {id(self)}")
        return result

    def fsetstat(self, handle, attr):
        logger.info(
            f"[[[SFTP Interface]]] [[[ ENTRY fsetstat ]]] handle={handle}, attr={attr} on ID: {id(self)}"
        )
        logger.info(f"[[[SFTP Interface]]] [[[ EXIT fsetstat ]]] on ID: {id(self)}")
        return SFTP_OK

    def extended(self, request_name, request_data):
        logger.info(
            f"[[[SFTP Interface]]] [[[ ENTRY extended ]]] request_name={request_name}, data_len={len(request_data)} on ID: {id(self)}"
        )
        if request_name == b"fsync@openssh.com":
            logger.info(f"[[[SFTP Interface]]] [[[ EXIT extended ]]] on ID: {id(self)}")
            return SFTP_OK
        logger.info(f"[[[SFTP Interface]]] [[[ EXIT extended ]]] on ID: {id(self)}")
        return SFTP_OP_UNSUPPORTED


class SftpAuthInterface(paramiko.ServerInterface):
    def __init__(self, authenticator: Authenticator, transport):
        self.authenticator = authenticator
        self.transport = transport
        logger.debug("[[[SftpAuthInterface]]] Initialized.")

    def check_channel_request(self, kind, chanid):
        logger.debug(
            f"[[[SftpAuthInterface]]] check_channel_request(kind={kind}, chanid={chanid})"
        )
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):
        logger.debug(f"[[[SftpAuthInterface]]] get_allowed_auths(username={username})")
        # Allow both password and publickey if a private key is configured
        if self.authenticator.sftp_config.get("private_key"):
            return "password,publickey"
        return "password"

    def check_auth_password(self, username, password):
        logger.debug(
            f"[[[SftpAuthInterface]]] check_auth_password(username={username})"
        )
        try:
            file_processor, webdav_client = self.authenticator.authenticate(
                username, password=password
            )
            self.transport.file_processor = file_processor
            self.transport.webdav_client = webdav_client
            logger.info(
                f"[[[SftpAuthInterface]]] Client authentication successful for {username}."
            )
            return paramiko.AUTH_SUCCESSFUL
        except AuthenticationFailedError:
            logger.warning(
                f"[[[SftpAuthInterface]]] Client authentication failed for {username}."
            )
            return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        logger.debug(
            f"[[[SftpAuthInterface]]] check_auth_publickey(username={username}, key={key})"
        )
        try:
            file_processor, webdav_client = self.authenticator.authenticate(
                username, private_key=key
            )
            self.transport.file_processor = file_processor
            self.transport.webdav_client = webdav_client
            logger.info(
                f"[[[SftpAuthInterface]]] Client public key authentication successful for {username}."
            )
            return paramiko.AUTH_SUCCESSFUL
        except AuthenticationFailedError:
            logger.warning(
                f"[[[SftpAuthInterface]]] Client public key authentication failed for {username}."
            )
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

    def _handle_connection(self, client_sock):
        peername = client_sock.getpeername()
        logger.info(f"[[[SFTPRelay]]] Handling connection from {peername}")
        transport = None
        try:
            transport = paramiko.Transport(client_sock)
            transport.add_server_key(self.host_key)
            logger.debug(
                f"[[[SFTPRelay]]] [{peername}] Transport created and server key added."
            )

            transport.set_subsystem_handler(
                "sftp", paramiko.SFTPServer, SftpServerInterface
            )
            logger.critical(
                f"[[[SFTPRelay]]] [{peername}] SFTP subsystem handler set to SftpServerInterface."
            )

            auth_interface = SftpAuthInterface(self.authenticator, transport)
            logger.debug(f"[[[SFTPRelay]]] [{peername}] Auth interface created.")

            transport.start_server(server=auth_interface)
            logger.debug(
                f"[[[SFTPRelay]]] [{peername}] transport.start_server() returned."
            )

            chan = transport.accept(20)
            if chan is None:
                logger.error(
                    f"[[[SFTPRelay]]] SFTP channel negotiation timed out for {peername}"
                )
                return
            logger.info(f"[[[SFTPRelay]]] SFTP channel opened for {peername}: {chan}")

            while transport.is_active():
                time.sleep(1)

        except (EOFError, SSHException) as e:
            logger.warning(f"[[[SFTPRelay]]] SFTP session for {peername} ended: {e}")
        except Exception as e:
            logger.error(
                f"[[[SFTPRelay]]] SFTP session error for {peername}: {e}",
                exc_info=True,
            )
        finally:
            logger.info(f"[[[SFTPRelay]]] Closing connection from {peername}")
            if transport and transport.is_active():
                transport.close()
            client_sock.close()

    def _run(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(100)
        logger.info(f"[[[SFTPRelay]]] Listening on {self.host}:{self.port}")

        while self._running:
            try:
                client_sock, addr = self._sock.accept()
                logger.debug(f"[[[SFTPRelay]]] Accepted connection from {addr}")
                threading.Thread(
                    target=self._handle_connection, args=(client_sock,), daemon=True
                ).start()
            except Exception as e:
                if self._running:
                    logger.error(f"[[[SFTPRelay]]] Accept error: {e}", exc_info=True)

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        logger.info("SFTP relay started.")

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

        webdav_authenticator = WebDAVAuthenticator(webdav_config, target_dir)

        if server_type == "ftp":
            ftp_config = self.config["ftp"]
            ftp_client_authenticator = FTPClientAuthenticator(
                ftp_config=ftp_config,
                webdav_authenticator=webdav_authenticator,
            )
            self.relay = FTPRelay(
                authenticator=ftp_client_authenticator,
                host=ftp_config["host"],
                port=ftp_config["port"],
                handler_class=WebDAVFTPHandler,  # Pass WebDAVFTPHandler directly
            )
            logger.info("FTP relay server selected.")
        elif server_type == "sftp":
            sftp_config = self.config["sftp"]
            sftp_client_authenticator = SFTPClientAuthenticator(
                sftp_config=sftp_config,
                webdav_authenticator=webdav_authenticator,
            )
            host_key_file = sftp_config.get("host_key_file", "host.key")
            if not Path(host_key_file).exists():
                logger.warning(
                    f"SFTP host key '{host_key_file}' not found. Generating a new one."
                )
                key = paramiko.RSAKey.generate(2048)
                key.write_private_key_file(host_key_file)

            self.relay = SFTPRelay(
                authenticator=sftp_client_authenticator,
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
