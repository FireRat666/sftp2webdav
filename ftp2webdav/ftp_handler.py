import logging
import os
import posixpath
import stat as stat_module
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote

from easywebdav2 import OperationFailed
from pyftpdlib.filesystems import AbstractedFS
from pyftpdlib.handlers import DTPHandler, FTPHandler

logger = logging.getLogger(__name__)


class WebDAVFS(AbstractedFS):
    def __init__(self, root, cmd_channel):
        super().__init__(root, cmd_channel)
        self.webdav_client = cmd_channel.webdav_client
        self.target_dir = str(cmd_channel.file_processor.target_dir).strip("/")
        self.local_temp_root = Path(root)
        logger.debug(
            f"[[[WebDAVFS]]] Initialized with root: {root}, target_dir: {self.target_dir}, "
            f"local_temp_root: {self.local_temp_root}"
        )

    def getcwd(self):
        """Return the current working directory as a filesystem path."""
        return self._cwd

    def is_subpath(self, path, directory):
        """Check if path is a subpath of directory."""
        try:
            abs_path = os.path.normcase(os.path.abspath(path))
            abs_dir = os.path.normcase(os.path.abspath(directory))
            is_sub = abs_path.startswith(abs_dir)
            logger.debug(
                f"[[[WebDAVFS]]] is_subpath check: path='{path}' ({abs_path}), "
                f"dir='{directory}' ({abs_dir}), is_sub={is_sub}"
            )
            return is_sub
        except (TypeError, ValueError) as e:
            logger.error(f"[[[WebDAVFS]]] is_subpath error: {e}")
            return False

    def ftp2fs(self, ftp_path):
        """Translate ftp path to filesystem path."""
        original_ftp_path = ftp_path

        if isinstance(ftp_path, str) and os.path.isabs(ftp_path):
            normalized_path = os.path.normpath(ftp_path)
            if self.is_subpath(normalized_path, self.root):
                logger.debug(f"[[[WebDAVFS]]] ftp2fs: received a valid filesystem path '{ftp_path}', returning it.")
                return normalized_path

        ftp_path_posix = ftp_path.replace(os.sep, "/")

        if not ftp_path_posix.startswith('/'):
            ftp_path_posix = posixpath.join(self.cmd_channel.cwd, ftp_path_posix)

        if (
            ftp_path_posix.startswith("/")
            and len(ftp_path_posix) > 2
            and ftp_path_posix[1].isalpha()
            and ftp_path_posix[2] == ":"
        ):
            logger.debug(
                f"[[[WebDAVFS]]] ftp2fs: Detected WinSCP-style absolute path: '{ftp_path}'."
            )
            fs_path = ftp_path_posix[1:]
        else:
            fs_path = os.path.join(self.root, ftp_path_posix.lstrip('/\\'))

        normalized_fs_path = os.path.normpath(fs_path)

        if not self.is_subpath(normalized_fs_path, self.root):
            logger.warning(
                f"Path traversal attempt blocked: '{original_ftp_path}' resolved to '{normalized_fs_path}' "
                f"which is outside root '{self.root}'"
            )
            raise OSError(13, "Permission denied.")

        logger.debug(
            f"[[[WebDAVFS]]] ftp2fs: ftp_path='{original_ftp_path}' cwd='{self.cmd_channel.cwd}' -> '{normalized_fs_path}'"
        )
        return normalized_fs_path

    def fs2ftp(self, fs_path):
        """Translate filesystem path to ftp path."""
        fs_path_str = str(fs_path)
        try:
            abs_path = os.path.abspath(fs_path_str)
            abs_root = os.path.abspath(str(self.root))
            # For comparison, use normcase
            if os.path.normcase(abs_path).startswith(os.path.normcase(abs_root)):
                # But for relpath, use the original cased paths to preserve case
                relative_path = os.path.relpath(abs_path, abs_root)
                if relative_path == ".":
                    return "/"
                else:
                    # The ftp path should always use forward slashes.
                    ftp_path = "/" + relative_path.replace(os.sep, "/")
                    logger.debug(f"[[[WebDAVFS]]] fs2ftp: fs_path='{fs_path_str}' -> '{ftp_path}'")
                    return ftp_path
        except (TypeError, ValueError) as e:
            logger.error(f"[[[WebDAVFS]]] fs2ftp error: {e}")
        logger.warning(f"[[[WebDAVFS]]] fs2ftp: fs_path='{fs_path_str}' is outside the root. Returning as is.")
        return "/"

    def _fs2webdav(self, fs_path):
        """Converts a local filesystem path to a WebDAV path."""
        relative_to_root = os.path.relpath(fs_path, self.root)
        webdav_rel_path = "" if relative_to_root == "." else relative_to_root.replace(os.sep, "/")
        full_webdav_path = posixpath.join(self.target_dir, webdav_rel_path)
        logger.debug(f"[[[WebDAVFS]]] _fs2webdav: fs_path='{fs_path}' -> '{full_webdav_path}'")
        return full_webdav_path

    def open(self, filename, mode):
        logger.info(f"[[[WebDAVFS]]] open(filename='{filename}', mode='{mode}')")
        local_temp_file = Path(filename)
        webdav_path = self._fs2webdav(filename)
        self.cmd_channel.webdav_current_file_info = {
            "local_path": local_temp_file,
            "webdav_path": webdav_path,
            "mode": mode,
        }
        logger.debug(f"[[[WebDAVFS]]] Attempting to open local temp file: {local_temp_file} in mode {mode}")
        try:
            local_temp_file.parent.mkdir(parents=True, exist_ok=True)
            if "r" in mode:
                self.webdav_client.download(webdav_path, str(local_temp_file))
            f = open(local_temp_file, mode)
            logger.debug(f"[[[WebDAVFS]]] Successfully opened local temp file: {local_temp_file}")
            return f
        except (OSError, OperationFailed) as e:
            logger.error(f"[[[WebDAVFS]]] FAILED to open/download file '{local_temp_file}' in mode '{mode}': {e}", exc_info=True)
            raise

    def chdir(self, path):
        """Change the current directory. Expects a filesystem path."""
        logger.info(f"[[[WebDAVFS]]] chdir(path='{path}')")
        st = self.stat(path)
        if not stat_module.S_ISDIR(st.st_mode):
            raise OSError(20, f"Not a directory: {path}")
        self._cwd = path
        logger.debug(f"[[[WebDAVFS]]] Changed CWD to: {self._cwd}")

    def isdir(self, path):
        """Return True if path is a directory."""
        logger.info(f"[[[WebDAVFS]]] isdir(path='{path}')")
        try:
            st = self.stat(path)
            is_dir = stat_module.S_ISDIR(st.st_mode)
            logger.info(f"[[[WebDAVFS]]] isdir for path '{path}' is {is_dir}. st_mode={oct(st.st_mode)}")
            return is_dir
        except Exception as e:
            logger.error(f"[[[WebDAVFS]]] isdir for path '{path}' failed: {e}", exc_info=True)
            return False

    def listdir(self, path):
        logger.info(f"[[[WebDAVFS]]] listdir(path='{path}')")
        webdav_path = self._fs2webdav(path)
        try:
            listing = self.webdav_client.ls(webdav_path)
            req_path_norm = posixpath.normpath("/" + webdav_path.strip("/"))
            names = []
            for item in listing:
                item_path_norm = posixpath.normpath(unquote(item.name))
                if item_path_norm == req_path_norm:
                    continue

                # Only include direct children
                if posixpath.dirname(item_path_norm) == req_path_norm:
                    names.append(posixpath.basename(item_path_norm))

            logger.debug(f"[[[WebDAVFS]]] listdir for '{path}' returned {len(names)} items: {names}")
            return names
        except OperationFailed as e:
            if e.actual_code == 404:
                raise OSError(2, f"No such directory: {path}") from e
            raise OSError(1, f"WebDAV error listing directory: {e}") from e

    def exists(self, path):
        """Return True if path exists."""
        logger.info(f"[[[WebDAVFS]]] exists(path='{path}')")
        try:
            self.stat(path)
        except OSError as e:
            if e.errno == 2:  # no such file or directory
                logger.info(f"[[[WebDAVFS]]] exists for path '{path}' is False.")
                return False
            raise
        logger.info(f"[[[WebDAVFS]]] exists for path '{path}' is True.")
        return True

    def stat(self, path):
        logger.info(f"[[[WebDAVFS]]] stat(path='{path}')")
        max_retries = 3
        delay = 0.1
        for attempt in range(max_retries):
            try:
                if os.path.normpath(path) == os.path.normpath(self.root):
                    st_mode = stat_module.S_IFDIR | 0o755
                    now = int(datetime.now(timezone.utc).timestamp())
                    return os.stat_result((st_mode, 0, 0, 0, 0, 0, 0, now, now, now))

                webdav_path = self._fs2webdav(path)
                parent_dir = posixpath.dirname(webdav_path)
                basename = posixpath.basename(webdav_path)
                listing = self.webdav_client.ls(parent_dir)

                item_to_stat = next((item for item in listing if unquote(posixpath.basename(item.name.rstrip('/'))) == basename), None)

                if item_to_stat is None:
                    raise OSError(2, f"No such file or directory: {path}")

                item = item_to_stat
                st_mode = stat_module.S_IFDIR | 0o755 if item.contenttype == "httpd/unix-directory" else stat_module.S_IFREG | 0o644
                mtime_timestamp = 0
                if item.mtime:
                    try:
                        dt_obj = (
                            datetime.strptime(item.mtime, "%a, %d %b %Y %H:%M:%S %Z").replace(tzinfo=timezone.utc)
                            if isinstance(item.mtime, str)
                            else item.mtime
                        )
                        mtime_timestamp = int(dt_obj.timestamp())
                    except (ValueError, TypeError, OSError):
                        logger.warning(f"Could not parse mtime '{item.mtime}' for '{path}'")
                st = os.stat_result((st_mode, 0, 0, 0, 0, 0, item.size, mtime_timestamp, mtime_timestamp, mtime_timestamp))
                logger.debug(f"[[[WebDAVFS]]] stat for '{path}' returned: {st}")
                return st
            except OperationFailed as e:
                if e.actual_code == 404:
                    if attempt < max_retries - 1:
                        time.sleep(delay)
                        continue
                    raise OSError(2, f"No such file or directory: {path}") from e
                raise OSError(1, f"WebDAV error stating path: {e}") from e
            except Exception as e:
                if attempt < max_retries - 1:
                    time.sleep(delay)
                    continue
                raise

    def mkdir(self, path):
        logger.info(f"[[[WebDAVFS]]] mkdir(path='{path}')")
        webdav_path = self._fs2webdav(path)
        try:
            relative_path = webdav_path
            if webdav_path.startswith(self.target_dir + '/'):
                relative_path = webdav_path[len(self.target_dir) + 1:]
            elif webdav_path == self.target_dir:
                return

            parts = relative_path.split('/')
            current_path = self.target_dir
            for part in parts:
                if not part:
                    continue
                current_path = posixpath.join(current_path, part)
                try:
                    self.webdav_client.mkdir(current_path)
                    logger.info(f"[[[WebDAVFS]]] Directory created or exists: {current_path}")
                except OperationFailed as e:
                    if e.actual_code == 405:  # Method Not Allowed (directory exists)
                        pass
                    else:
                        raise
        except OperationFailed as e:
            raise OSError(1, f"WebDAV error creating directory '{webdav_path}': {e}") from e

    def rmdir(self, path):
        logger.info(f"[[[WebDAVFS]]] rmdir(path='{path}')")
        webdav_path = self._fs2webdav(path)
        try:
            self.webdav_client.delete(webdav_path)
            logger.info(f"[[[WebDAVFS]]] Directory removed: {webdav_path}")
        except OperationFailed as e:
            if e.actual_code == 404:
                raise OSError(2, f"No such directory: {path}") from e
            if e.actual_code == 409:
                raise OSError(39, f"Directory not empty: {path}") from e
            raise OSError(1, f"WebDAV error removing directory: {e}") from e

    def remove(self, path):
        logger.info(f"[[[WebDAVFS]]] remove(path='{path}')")
        webdav_path = self._fs2webdav(path)
        try:
            self.webdav_client.delete(webdav_path)
            logger.info(f"[[[WebDAVFS]]] File removed: {webdav_path}")
        except OperationFailed as e:
            if e.actual_code == 404:
                raise OSError(2, f"No such file: {path}") from e
            raise OSError(1, f"WebDAV error removing file: {e}") from e

    def rename(self, src, dst):
        logger.info(f"[[[WebDAVFS]]] rename(src='{src}', dst='{dst}')")
        webdav_src = self._fs2webdav(src)
        webdav_dst = self._fs2webdav(dst)
        try:
            self.webdav_client.move(webdav_src, webdav_dst)
            logger.info(f"[[[WebDAVFS]]] Renamed '{webdav_src}' to '{webdav_dst}'")
        except OperationFailed as e:
            if e.actual_code == 404:
                raise OSError(2, f"Source not found: {src}") from e
            raise OSError(1, f"WebDAV error renaming: {e}") from e


class WebDAVDTPHandler(DTPHandler):
    """Custom DTP Handler to trigger upload on close."""

    def _threaded_upload_and_cleanup(self, file_processor, local_path, webdav_path):
        """Upload the file in a separate thread and then clean up."""
        try:
            logger.info(f"[[[WebDAVDTPHandler]]] Uploading {local_path} to WebDAV path {webdav_path} via FileProcessor.")
            file_processor.process_file(local_path, webdav_path)
            logger.info(f"[[[WebDAVDTPHandler]]] Successfully uploaded to WebDAV.")
        except Exception as e:
            logger.error(f"[[[WebDAVDTPHandler]]] Error uploading file to WebDAV: {e}", exc_info=True)
        finally:
            if local_path and os.path.exists(local_path):
                try:
                    os.remove(local_path)
                    logger.debug(f"[[[WebDAVDTPHandler]]] Cleaned up temporary file: {local_path}")
                except OSError as e:
                    logger.error(f"[[[WebDAVDTPHandler]]] Error cleaning up temporary file {local_path}: {e}", exc_info=True)

    def close(self):
        super().close()
        cmd_channel = self.cmd_channel
        file_info = getattr(cmd_channel, 'webdav_current_file_info', None)
        if not file_info:
            return

        mode = file_info.get("mode", "")
        local_path = file_info.get("local_path")
        webdav_path = file_info.get("webdav_path")

        if 'w' in mode:
            logger.info(f"[[[WebDAVDTPHandler]]] close(): Scheduling WebDAV upload in a background thread.")
            file_processor = getattr(cmd_channel, 'file_processor', None)

            if file_processor and local_path and webdav_path:
                file_processor_copy = file_processor.copy()
                upload_thread = threading.Thread(
                    target=self._threaded_upload_and_cleanup,
                    args=(file_processor_copy, local_path, webdav_path)
                )
                upload_thread.start()
            else:
                logger.error("[[[WebDAVDTPHandler]]] Not scheduling upload. Mismatched file info or file processor not available.")
                if local_path and os.path.exists(local_path):
                    os.remove(local_path)
                    logger.debug(f"[[[WebDAVDTPHandler]]] Cleaned up temporary file: {local_path}")
        else:
            if local_path and os.path.exists(local_path):
                os.remove(local_path)
                logger.debug(f"[[[WebDAVDTPHandler]]] Cleaned up temporary file for read operation: {local_path}")

        if hasattr(cmd_channel, 'webdav_current_file_info'):
            del cmd_channel.webdav_current_file_info


class WebDAVFTPHandler(FTPHandler):
    dtp_handler = WebDAVDTPHandler

    def on_login(self, username):
        logger.info(f"[[[WebDAVFTPHandler]]] on_login for user '{username}'.")
        root = self.authorizer.get_home_dir(username)
        self.fs = WebDAVFS(root, self)
        super().on_login(username)
        self.cwd = "/"

    def ftp_PWD(self, path=None):
        """Return the current working directory."""
        self.respond('257 "%s" is the current directory.' % self.cwd)

    def ftp_CWD(self, path):
        """Change current working directory."""
        try:
            fs_path = self.fs.ftp2fs(path)
            self.run_as_current_user(self.fs.chdir, fs_path)
            self.cwd = self.fs.fs2ftp(self.fs.getcwd())
            self.respond('250 "%s" is the current directory.' % self.cwd)
        except OSError as err:
            logger.warning(f"CWD failed for path '{path}': {err}")
            self.respond(f"550 {err}")

    def ftp_RNFR(self, path):
        """Rename from."""
        # path is already a filesystem path because of pre_process_command
        logger.info(f"[[[WebDAVFTPHandler]]] ftp_RNFR for path '{path}'")
        if not self.fs.exists(path):
            self.respond("550 No such file or directory.")
        else:
            self.rnfr = path
            self.respond("350 Ready for destination name.")

    def ftp_RNTO(self, path):
        """Rename to."""
        logger.info(f"[[[WebDAVFTPHandler]]] ftp_RNTO for path '{path}'")
        if not hasattr(self, 'rnfr'):
            self.respond("503 Bad sequence of commands: use RNFR first.")
            return

        # path is already a filesystem path because of pre_process_command
        dst_path = path
        src_path = self.rnfr

        try:
            self.run_as_current_user(self.fs.rename, src_path, dst_path)
            self.respond("250 Rename successful.")
        except OSError as e:
            self.respond(f"550 Rename failed: {e}")
        finally:
            if hasattr(self, 'rnfr'):
                del self.rnfr
