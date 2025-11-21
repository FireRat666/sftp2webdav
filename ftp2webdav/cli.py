import importlib.resources
import logging
import time
from pathlib import Path
from typing import Annotated, Optional

import typer
import yaml
from click import ClickException

from ftp2webdav.config import build_configuration
from ftp2webdav.server import Server

app = typer.Typer()

DEFAULT_CONFIG_FILE_PATHS = (
    Path("~/.ftp2webdav.conf").expanduser(),
    Path("/etc/ftp2webdav.conf"),
)


@app.command()
def run(
    *,
    config_file: Annotated[
        Optional[Path],
        typer.Option(
            "--config",
            "-c",
            help="Path to config file.",
        ),
    ] = None,
    create_example_config: Annotated[
        bool,
        typer.Option(
            "--create-example-config",
            help=f"Create an example configuration at {DEFAULT_CONFIG_FILE_PATHS[0]} and exits.",
        ),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-v",
            help="Verbose output (shortcut for --log-level DEBUG).",
        ),
    ] = False,
    log_level: Annotated[
        str,
        typer.Option(
            "--log-level",
            help="Set the log level (DEBUG, INFO, WARNING, ERROR, CRITICAL).",
            case_sensitive=False,
        ),
    ] = "INFO",
):
    if verbose:
        level = logging.DEBUG
    else:
        level = getattr(logging, log_level.upper(), logging.INFO)

    logging.basicConfig(
        level=level, format="%(asctime)-15s %(levelname)-8s %(message)s"
    )

    # The paramiko logger is very verbose at DEBUG level, so we'll set it to INFO
    # unless verbose mode is explicitly enabled.
    if not verbose and level < logging.INFO:
        logging.getLogger("paramiko").setLevel(logging.INFO)

    if create_example_config:
        if DEFAULT_CONFIG_FILE_PATHS[0].exists():
            raise ClickException(
                f"Error: A config file already exists at {DEFAULT_CONFIG_FILE_PATHS[0]}."
            )
        else:
            with DEFAULT_CONFIG_FILE_PATHS[0].open("wb") as fh:
                fh.write(
                    importlib.resources.files("ftp2webdav")
                    .joinpath("resources/example-config.yml")
                    .read_bytes()
                )
            typer.echo(
                f"An example config file has been created at {DEFAULT_CONFIG_FILE_PATHS[0]}."
            )
            raise typer.Exit(0)

    # Find config file
    if config_file is None:
        for file in DEFAULT_CONFIG_FILE_PATHS:
            if file.exists():
                config_file = file
                break

    if config_file is None or not config_file.exists():
        raise ClickException("No configuration file found.")

    try:
        with config_file.open() as fh:
            config = build_configuration(yaml.safe_load(fh))
    except yaml.YAMLError as err:
        raise ClickException(f"Invalid YAML in configuration file: {config}") from err

    server = Server(config=config)
    server.start()
    typer.echo("Server started. Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        typer.echo("Stopping server...")
        server.stop()
        typer.echo("Server stopped.")
