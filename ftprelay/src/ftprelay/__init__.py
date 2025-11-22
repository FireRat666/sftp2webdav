import logging
import tempfile
from abc import ABC, abstractmethod
from pathlib import Path

from pyftpdlib.authorizers import DummyAuthorizer, AuthenticationFailed as FTPAuthenticationFailed
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

logger = logging.getLogger(__name__)

print(f"DEBUG: Loading ftprelay from: {__file__}")


class AuthenticationFailedError(Exception):
    """Custom exception for authentication failures within the Authenticator."""
    pass


class FileProcessor(ABC):
    """Abstract base class for processing a completed file upload."""
    @abstractmethod
    def process_file(self, file: Path, remote_path: str) -> None:
        ...


class Authenticator(ABC):
    """Abstract base class for handling client authentication and permissions."""
    @abstractmethod
    def authenticate(self, username, password) -> tuple[FileProcessor, any]:
        """
        Authenticates a user.
        Returns a tuple of (FileProcessor, webdav_client) on success.
        Raises AuthenticationFailedError on failure.
        """
        ...

    @abstractmethod
    def get_perms(self, username) -> str:
        """Returns the permission string for a user (e.g., 'elradfmw')."""
        ...

    @abstractmethod
    def get_home_dir(self, username) -> str:
        """Returns the home directory for a user."""
        ...


class CustomAuthorizer(DummyAuthorizer):
    """
    A custom authorizer that delegates authentication and permission checks
    to an Authenticator instance.
    """
    def __init__(self, authenticator: Authenticator, temp_dir_path: Path):
        super().__init__()
        self.authenticator = authenticator
        self.temp_dir_path = temp_dir_path
        logger.debug(f"[[[CustomAuthorizer]]] Initialized with authenticator: {authenticator}")

    def validate_authentication(self, username, password, handler):
        logger.debug(f"[[[CustomAuthorizer]]] validate_authentication for user: {username}")
        try:
            file_processor, webdav_client = self.authenticator.authenticate(username, password)
            
            # Add user to the authorizer if not already present
            if not self.has_user(username):
                home_dir = self.get_home_dir(username)
                perms = self.authenticator.get_perms(username)
                self.add_user(username, password, home_dir, perm=perms)

            # Attach the file_processor and webdav_client to the handler instance
            handler.file_processor = file_processor
            handler.webdav_client = webdav_client
            logger.info(f"[[[CustomAuthorizer]]] User '{username}' authenticated successfully.")
        except AuthenticationFailedError as e:
            logger.warning(f"[[[CustomAuthorizer]]] Authentication failed for user '{username}': {e}")
            raise FTPAuthenticationFailed from e
        except Exception as e:
            logger.error(f"[[[CustomAuthorizer]]] Unexpected error during authentication for user '{username}': {e}", exc_info=True)
            raise FTPAuthenticationFailed from e

    def has_user(self, username):
        return username in self.user_table

    def has_perm(self, username, perm, path=None):
        user_perms = self.authenticator.get_perms(username)
        has_permission = perm in user_perms
        logger.debug(f"[[[CustomAuthorizer]]] has_perm(user='{username}', perm='{perm}', path='{path}') -> {has_permission} (user_perms: '{user_perms}')")
        return has_permission

    def get_home_dir(self, username):
        home_dir = str(self.temp_dir_path)
        logger.debug(f"[[[CustomAuthorizer]]] get_home_dir(user='{username}') -> '{home_dir}'")
        return home_dir

    def get_msg_login(self, username):
        return "Hello."

    def get_msg_quit(self, username):
        return "Goodbye."


class FTPRelay:
    def __init__(self, authenticator: Authenticator, host: str, port: int, handler_class: type[FTPHandler], allow_anonymous: bool = False):
        print(f"DEBUG: FTPRelay __init__ called from: {__file__}")
        self._temp_dir = tempfile.TemporaryDirectory(prefix="ftp2webdav-ftp-")
        self.temp_dir_path = Path(self._temp_dir.name)

        authorizer = CustomAuthorizer(authenticator, self.temp_dir_path)

        # Create a new handler class that inherits from the provided one.
        # This avoids modifying the original class and prevents state-sharing issues.
        class _RelayHandler(handler_class):
            pass

        _RelayHandler.authorizer = authorizer
        _RelayHandler.timeout = 1800

        self.server = FTPServer((host, port), _RelayHandler)
        logger.info(f"[[[FTPRelay]]] FTP server initialized on {host}:{port} with handler {handler_class.__name__}")

    def start(self):
        logger.info(
            f"FTP relay started on "
            f"{self.server.address[0]}:{self.server.address[1]}"
        )
        self.server.serve_forever()

    def stop(self):
        self.server.close_all()
        if self._temp_dir:
            self._temp_dir.cleanup()
            logger.debug("[[[FTPRelay]]] Cleaned up temporary directory.")
