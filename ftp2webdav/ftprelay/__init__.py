import logging
import tempfile
from abc import ABC, abstractmethod
from pathlib import Path

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

logger = logging.getLogger(__name__)


class AuthenticationFailedError(Exception):
    pass


class FileProcessor(ABC):
    @abstractmethod
    def process_file(self, file: Path) -> None:
        ...


class Authenticator(ABC):
    @abstractmethod
    def authenticate(self, username, password) -> tuple[FileProcessor, any]:
        ...


class _Authorizer(DummyAuthorizer):
    def __init__(
        self, authenticator: Authenticator, handler: FTPHandler, *args, **kwargs
    ):
        self.authenticator = authenticator
        self.handler = handler
        super().__init__(*args, **kwargs)

    def validate_authentication(
        self, username, password, handler
    ) -> None:
        try:
            file_processor, webdav_client = self.authenticator.authenticate(username, password)
            self.handler.file_processor = file_processor
            self.handler.webdav_client = webdav_client
        except AuthenticationFailedError as e:
            raise AuthenticationFailedError from e
        except Exception as e:
            raise AuthenticationFailedError from e

    def get_user_perms(self, username):
        return "elradfmw"


class FTPRelay:
    def __init__(self, authenticator: Authenticator, host: str, port: int, handler: FTPHandler = FTPHandler):
        self._temp_dir = tempfile.TemporaryDirectory(prefix="ftp2webdav-ftp-")
        authorizer = _Authorizer(authenticator, handler)
        authorizer.add_user(
            "user",
            "password",
            self._temp_dir.name,
        )
        self.handler = handler
        self.handler.authorizer = authorizer
        self.server = FTPServer((host, port), self.handler)

    def start(self):
        logger.info(
            f"FTP relay started on "
            f"{self.server.address[0]}:{self.server.address[1]}"
        )
        self.server.serve_forever()

    def stop(self):
        self.server.close_all()
