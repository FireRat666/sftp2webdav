import logging
import os
import posixpath
import stat as stat_module
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote, urljoin

import easywebdav2
from pyftpdlib.handlers import FTPHandler, DTPHandler
from pyftpdlib.filesystems import AbstractedFS

logger = logging.getLogger(__name__)


class WebDAVFS(AbstractedFS):
    def __init__(self, root, cmd_channel):
        super().__init__(root, cmd_channel)
        self.webdav_client = cmd_channel.webdav_client
        self.target_dir = cmd_channel.file_processor.target_dir
        self.local_temp_root = Path(root)
        logger.debug(f"[[[WebDAVFS]]] Initialized with root: {root}, target_dir: {self.target_dir}, local_temp_root: {self.local_temp_root}")

    def ftp2fs(self, ftp_path):
        """Converts an FTP path to a filesystem path."""
        logger.info(f"[[[WebDAVFS]]] ftp2fs called with ftp_path: '{ftp_path}'")
        fs_path = os.path.join(self.root, ftp_path.lstrip('/\\'))
        logger.info(f"[[[WebDAVFS]]] ftp2fs is returning fs_path: '{fs_path}'")
        return fs_path

    def _webdav_path(self, ftp_path):
        resolved_path = posixpath.join(str(self.target_dir), ftp_path.lstrip('/'))
        logger.debug(f"[[[WebDAVFS]]] _webdav_path: ftp_path='{ftp_path}' -> '{resolved_path}'")
        return resolved_path

    def open(self, filename, mode):
        logger.info(f"[[[WebDAVFS]]] open(filename='{filename}', mode='{mode}')")
        local_temp_file = Path(filename)
        ftp_path = self.fs2ftp(filename)
        # Store the file info on the *command channel* (the main handler)
        # so it can be accessed by the DTP handler later.
        self.cmd_channel.webdav_current_file_info = {
            "local_path": local_temp_file,
            "webdav_path": self._webdav_path(ftp_path),
            "mode": mode,
        }
        logger.debug(f"[[[WebDAVFS]]] Attempting to open local temp file: {local_temp_file} in mode {mode}")
        try:
            f = open(local_temp_file, mode)
            logger.debug(f"[[[WebDAVFS]]] Successfully opened local temp file: {local_temp_file}")
            return f
        except OSError as e:
            logger.error(f"[[[WebDAVFS]]] FAILED to open local temporary file '{local_temp_file}' in mode '{mode}': {e}", exc_info=True)
            raise

    # ... (other WebDAVFS methods remain unchanged)
    def chdir(self, path):
        logger.info(f"[[[WebDAVFS]]] chdir(path='{path}')")
        webdav_path = self._webdav_path(path)
        try:
            item = self.webdav_client.propfind(webdav_path)
            if item.contenttype != "httpd/unix-directory":
                raise OSError(f"Not a directory: {path}")
            self._cwd = path
            logger.debug(f"[[[WebDAVFS]]] Changed CWD to: {self._cwd}")
        except easywebdav2.OperationFailed as e:
            if e.actual_code == 404:
                raise OSError(f"No such directory: {path}") from e
            raise OSError(f"WebDAV error changing directory: {e}") from e

    def listdir(self, path):
        logger.info(f"[[[WebDAVFS]]] listdir(path='{path}')")
        webdav_path = self._webdav_path(path)
        try:
            listing = self.webdav_client.ls(webdav_path)
            names = [unquote(posixpath.basename(item.name.rstrip("/"))) for item in listing if unquote(posixpath.basename(item.name.rstrip("/")))]
            logger.debug(f"[[[WebDAVFS]]] listdir for '{path}' returned {len(names)} items.")
            return names
        except easywebdav2.OperationFailed as e:
            if e.actual_code == 404:
                raise OSError(f"No such directory: {path}") from e
            raise OSError(f"WebDAV error listing directory: {e}") from e

    def stat(self, path):
        logger.info(f"[[[WebDAVFS]]] stat(path='{path}')")
        webdav_path = self._webdav_path(path)
        try:
            item = self.webdav_client.propfind(webdav_path)
            st_mode = stat_module.S_IFDIR | 0o755 if item.contenttype == "httpd/unix-directory" else stat_module.S_IFREG | 0o644
            mtime_timestamp = 0
            if item.mtime:
                try:
                    if isinstance(item.mtime, str):
                        dt_obj = datetime.strptime(item.mtime, "%a, %d %b %Y %H:%M:%S %Z").replace(tzinfo=timezone.utc)
                    else:
                        dt_obj = item.mtime
                    mtime_timestamp = int(dt_obj.timestamp())
                except (ValueError, TypeError, OSError):
                    logger.warning(f"Could not parse mtime '{item.mtime}' for '{path}'")
            st = os.stat_result((st_mode, 0, 0, 0, 0, 0, item.size, mtime_timestamp, mtime_timestamp, mtime_timestamp))
            logger.debug(f"[[[WebDAVFS]]] stat for '{path}' returned: {st}")
            return st
        except easywebdav2.OperationFailed as e:
            if e.actual_code == 404:
                raise FileNotFoundError(f"No such file or directory: {path}") from e
            raise OSError(f"WebDAV error stating path: {e}") from e

    def mkdir(self, path):
        logger.info(f"[[[WebDAVFS]]] mkdir(path='{path}')")
        webdav_path = self._webdav_path(path)
        try:
            self.webdav_client.mkdir(webdav_path)
            logger.info(f"[[[WebDAVFS]]] Directory created: {webdav_path}")
        except easywebdav2.OperationFailed as e:
            if e.actual_code == 405:
                raise FileExistsError(f"Directory already exists or permission denied: {path}") from e
            raise OSError(f"WebDAV error creating directory: {e}") from e

    def rmdir(self, path):
        logger.info(f"[[[WebDAVFS]]] rmdir(path='{path}')")
        webdav_path = self._webdav_path(path)
        try:
            self.webdav_client.delete(webdav_path)
            logger.info(f"[[[WebDAVFS]]] Directory removed: {webdav_path}")
        except easywebdav2.OperationFailed as e:
            if e.actual_code == 404:
                raise FileNotFoundError(f"No such directory: {path}") from e
            if e.actual_code == 409:
                raise OSError(f"Directory not empty or permission denied: {path}") from e
            raise OSError(f"WebDAV error removing directory: {e}") from e

    def remove(self, path):
        logger.info(f"[[[WebDAVFS]]] remove(path='{path}')")
        webdav_path = self._webdav_path(path)
        try:
            self.webdav_client.delete(webdav_path)
            logger.info(f"[[[WebDAVFS]]] File removed: {webdav_path}")
        except easywebdav2.OperationFailed as e:
            if e.actual_code == 404:
                raise FileNotFoundError(f"No such file: {path}") from e
            raise OSError(f"WebDAV error removing file: {e}") from e

    def rename(self, src, dst):
        logger.info(f"[[[WebDAVFS]]] rename(src='{src}', dst='{dst}')")
        webdav_src = self._webdav_path(src)
        webdav_dst = self._webdav_path(dst)
        try:
            self.webdav_client.move(webdav_src, webdav_dst)
            logger.info(f"[[[WebDAVFS]]] Renamed '{webdav_src}' to '{webdav_dst}'")
        except easywebdav2.OperationFailed as e:
            if e.actual_code == 404:
                raise FileNotFoundError(f"Source not found: {src}") from e
            raise OSError(f"WebDAV error renaming: {e}") from e


class WebDAVDTPHandler(DTPHandler):
    """Custom DTP Handler to trigger upload on close."""
    def close(self):
        logger.critical("!!!!!!!!!!!! WebDAVDTPHandler.close() ENTERED !!!!!!!!!!!!")
        # The base DTPHandler.close() sends the "226 Transfer complete." message.
        # We must call it *before* our upload logic to ensure the FTP client
        # doesn't hang waiting for the final response.
        super().close()

        # The command channel (WebDAVFTPHandler) holds the context we need.
        cmd_channel = self.cmd_channel
        file_info = getattr(cmd_channel, 'webdav_current_file_info', None)

        if not file_info:
            logger.debug("[[[WebDAVDTPHandler]]] close() called but no file info found for upload.")
            return

        logger.info(f"[[[WebDAVDTPHandler]]] close(): Triggering WebDAV upload.")
        try:
            if hasattr(cmd_channel, 'file_processor') and cmd_channel.file_processor:
                local_path = file_info.get("local_path")
                webdav_path = file_info.get("webdav_path")

                if local_path and webdav_path:
                    logger.info(f"[[[WebDAVDTPHandler]]] Uploading {local_path} to WebDAV path {webdav_path} via FileProcessor.")
                    cmd_channel.file_processor.process_file(local_path, webdav_path)
                    logger.info(f"[[[WebDAVDTPHandler]]] Successfully uploaded to WebDAV.")
                else:
                    logger.error("[[[WebDAVDTPHandler]]] Mismatched file info for upload.")
            else:
                logger.error("[[[WebDAVDTPHandler]]] File processor not available for WebDAV upload.")
        except Exception as e:
            logger.error(f"[[[WebDAVDTPHandler]]] Error uploading file to WebDAV: {e}", exc_info=True)
        finally:
            # Clean up the temporary file and the stored info
            local_path = file_info.get("local_path")
            if local_path and os.path.exists(local_path):
                os.remove(local_path)
                logger.debug(f"[[[WebDAVDTPHandler]]] Cleaned up temporary file: {local_path}")
            del cmd_channel.webdav_current_file_info


class WebDAVFTPHandler(FTPHandler):
    # Tell the FTP handler to use our custom DTP handler for data transfers.
    dtp_handler = WebDAVDTPHandler

    def on_login(self, username):
        logger.info(f"[[[WebDAVFTPHandler]]] on_login for user '{username}'. Initializing WebDAVFS.")
        root = self.authorizer.get_home_dir(username)
        self.fs = WebDAVFS(root, self)
        super().on_login(username)
