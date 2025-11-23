# sftp2webdav

`sftp2webdav` is a versatile server that accepts file uploads via FTP or SFTP and forwards them to a WebDAV server. It was developed with the specific goal of retrofitting a [Nextcloud](https://nextcloud.com/) interface into older devices or software that exclusively support FTP or SFTP for file transfer.

**Caution:** `sftp2webdav` has not undergone security testing. Avoid exposing it to untrusted networks or the public internet without implementing proper security measures.

## Quick Navigation

- [Features](#features)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [License](#license)

## Features

*   **Dual Protocol Support:** Acts as an FTP or SFTP server.
*   **Seamless Authentication:** FTP/SFTP user authentication seamlessly validates against the WebDAV server.
*   **Lightweight and Fast:** Built on `pyftpdlib` for FTP and `paramiko` for SFTP.
*   **Easy YAML Configuration:** Simple and clear configuration for all server types.
*   **Subdirectory Support:** Create and navigate subdirectories on the remote WebDAV server.

## Installation

Currently, this version of the project must be installed from source.

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/sftp2webdav.git
    cd sftp2webdav
    ```

2.  **Install dependencies using Poetry:**
    ```bash
    poetry install
    ```

## Configuration

To configure `sftp2webdav`, a configuration file is required. By default, the program looks for it in `~/.sftp2webdav.conf` or `/etc/sftp2webdav`. Create a sample configuration file with:

```bash
poetry run sftp2webdav --create-example-config
```

### Example Configuration File

```yaml
---
# Server type: 'ftp' or 'sftp'
type: sftp

ftp:
  host: 127.0.0.1
  port: 21
  # Optional: Define a user and password for the FTP server itself.
  # If not provided, anonymous logins are allowed, but WebDAV credentials are still required.
  # user: "myftpuser"
  # password: "myftppassword"

sftp:
  host: 127.0.0.1
  port: 2023
  host_key_file: "host.key" # Path to the server's private SSH host key.
  # Optional: Define credentials for clients connecting to this SFTP server.
  # If not provided, anonymous logins are allowed, but WebDAV credentials are still required.
  # user: "mysftpuser"
  # password: "mysftppassword"
  # private_key: "/path/to/client_auth.key"
  # private_key_pass: "key-password"

webdav:
  host: webdav.host
  port: 443
  protocol: https
  path: uri/path/to/webdav/endpoint
  # Optional: Credentials for the WebDAV server.
  # user: "mywebdavuser"
  # password: "mywebdavpassword"
  verify_ssl: True
  cert: /path/to/cert

target_dir: path/to/target/dir/
```

-   **Server Type (`type`):** Choose between `ftp` and `sftp`.
-   **FTP/SFTP Configuration (`ftp`/`sftp`):**
    -   `host`: The IP address or hostname for the server to listen on.
    -   `port`: The port for the server to listen on.
    -   `host_key_file`: (**SFTP only**) Path to the server's private SSH key. If the file doesn't exist, a new one will be generated.
    -   `user`/`password`/`private_key`/`private_key_pass`: (**Optional**) Credentials that clients must use to authenticate to this relay server. If not set, anonymous connections are allowed, but clients must still provide valid WebDAV credentials to complete the login.
-   **WebDAV Server Configuration (`webdav`):**
    -   `host`, `port`, `protocol`, `path`: Standard WebDAV connection details.
    -   `user`/`password`: (Optional) Credentials for the WebDAV server.
    -   `verify_ssl`: Can be `True`, `False`, or a path to a CA bundle.
    -   `cert`: Path to a client-side certificate for authentication.
-   **Target Directory (`target_dir`):** The root directory on the WebDAV server where files will be uploaded.

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

3.  **Update your `sftp2webdav` configuration** to point to the new certificate and use the correct hostname:

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

Run the server using Poetry:

```bash
poetry run sftp2webdav
```

### File Upload

Log into the server using valid user credentials, and then upload a file. The uploaded file will be
automatically stored in the directory specified in the config file.

## License

`ftp2webdav` is distributed under the terms of the MIT License.
