import logging
import os
from urllib.parse import urljoin

from pyftpdlib.handlers import FTPHandler

logger = logging.getLogger(__name__)


class WebDAVFTPHandler(FTPHandler):
    def on_list(self, path):
        logger.info(f"LIST request for path: {path}")
        self.respond("150 Here comes the directory listing.")
        try:
            base_path = self.fs.ftp2fs(path)
            # Ensure the base URL has a trailing slash for urljoin to work correctly
            base_url = self.webdav_client.base_url
            if not base_url.endswith("/"):
                base_url += "/"
            remote_path = urljoin(base_url, base_path)
            listing = self.webdav_client.ls(remote_path)
            for item in listing:
                # Format the output to be compatible with the FTP LIST command
                # drwxr-xr-x 1 owner group 0 Jan 01 00:00 directory
                # -rw-r--r-- 1 owner group 1234 Jan 01 00:00 file.txt
                is_dir = item.contenttype == "httpd/unix-directory"
                mode = "drwxr-xr-x" if is_dir else "-rw-r--r--"
                line = f"{mode} 1 owner group {item.size} {item.mtime:%b %d %H:%M} {os.path.basename(item.name)}"
                self.send_line(line)
        except Exception as e:
            logger.error(f"Error listing directory: {e}")
        self.respond("226 Directory send OK.")

    def on_nlst(self, path):
        logger.info(f"NLST request for path: {path}")
        self.respond("150 Here comes the directory listing.")
        try:
            base_path = self.fs.ftp2fs(path)
            # Ensure the base URL has a trailing slash for urljoin to work correctly
            base_url = self.webdav_client.base_url
            if not base_url.endswith("/"):
                base_url += "/"
            remote_path = urljoin(base_url, base_path)
            listing = self.webdav_client.ls(remote_path)
            for item in listing:
                self.send_line(os.path.basename(item.name))
        except Exception as e:
            logger.error(f"Error listing directory: {e}")
        self.respond("226 Directory send OK.")
