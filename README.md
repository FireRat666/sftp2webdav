# ftp2webdav

[![PyPI - Version](https://img.shields.io/pypi/v/ftp2webdav)](https://pypi.org/project/ftp2webdav/)


`ftp2webdav` is an FTP server that forwards all uploaded files to a WebDAV server.
It was developed with the specific goal of retrofitting a [Nextcloud](https://nextcloud.com/) interface into older
devices or software that exclusively support FTP upload for file transfer.

**Caution:** `ftp2webdav` has not undergone security testing. Avoid exposing it to untrusted networks or the public
internet without implementing proper security measures.

## Quick Navigation

- [Features](#features)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [License](#license)

## Features

* FTP user authentication seamlessly validates against the WebDAV server
* Lightweight and fast (uses `pyftpdlib` underneath)
* Easy YAML configuration

## Installation

Requires Python version 3.9 or higher and pip.

```bash
pip install ftp2webdav
```

## Configuration

To configure `ftp2webdav`, a configuration file is required. By default, the program looks for it
in `~/.ftp2webdav.conf` or `/etc/ftp2webdav`. Create a sample configuration file with:

```bash
ftp2webdav --create-example-config
```

### Example Configuration File

```yaml
---
ftp:
  host: 127.0.0.1
  port: 21

webdav:
  host: webdav.host
  port: 443
  protocol: https
  path: uri/path/to/webdav/endpoint
  verify_ssl: True
  cert: /path/to/cert

target_dir: path/to/target/dir/
```

- FTP server configuration (`ftp`):
    - `host`: Specifies the FTP server's IP address or hostname.
    - `port`: Specifies the FTP server's port.
- WebDAV Server configuration (`webdav`):
    - `host`: Specifies the hostname or IP address of the WebDAV server.
    - `port`: Specifies the port of the WebDAV server.
    - `protocol`: Specifies the protocol used for WebDAV communication.
    - `path`: Defines the URI path to the WebDAV endpoint.
    - `verify_ssl`: Boolean indicating whether to verify SSL certificates.
    - `cert`: Path to the (local) SSL certificate used for secure communication.
- Target Directory Configuration (`target_dir`):
    - Specifies the path to the target directory on the WebDAV server where uploaded files should be stored.

### Local Testing with a Self-Signed SSL Certificate

When testing locally, you may encounter an SSL error: `[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: IP address mismatch`. This happens because the hostname you are connecting to (e.g., `127.0.0.1`) is not listed in the server's self-signed certificate.

To fix this, you must generate a certificate that includes the correct hostnames in its Subject Alternative Name (SAN) field.

1.  **Generate a new certificate** using the following `openssl` command. This will create a certificate valid for both `localhost` and `127.0.0.1`.

    ```bash
    openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
      -keyout webdav.key -out webdav.crt \
      -subj "/CN=localhost" -addext "subjectAltName = DNS:localhost,IP:127.0.0.1"
    ```

2.  **Configure your WebDAV server** (e.g., SFTPGo) to use the generated `webdav.key` and `webdav.crt` files.

3.  **Update your `ftp2webdav` configuration** to point to the new certificate and use the correct hostname:

    ```yaml
    webdav:
      host: localhost  # Or 127.0.0.1
      port: 10443
      protocol: https
      path: "/"
      # Point verify_ssl to your server's public certificate to trust it.
      verify_ssl: /path/to/your/webdav.crt
    ```

This ensures the hostname in the config matches a name in the certificate, allowing the SSL verification to succeed.

## Usage

Run the server:

```bash
ftp2webdav
```

### Running from a Local Build

If you have cloned the repository and want to run the application from the source code, you can use `poetry`:

```bash
# Install dependencies
poetry install

# Run the application
poetry run ftp2webdav
```

This will use the local source code instead of the version installed from PyPI.

### File Upload

Log into the server using valid user credentials of the WebDAV sever, and then upload a file. The uploaded file will be
automatically stored in the directory specified in the config file.

### Caveats

- There are no subfolders on the FTP server, nor does it allow the creation of any. Thus, all files must be directly
  uploaded to the root directory.
- Using interactive FTP browsers to access the server may result in errors, as they are restricted from reading the
  contents of the root directory.

## License

`ftp2webdav` is distributed under the terms of the MIT License.
