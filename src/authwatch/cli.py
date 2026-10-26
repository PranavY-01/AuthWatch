"""Command-line interface (Typer). Orchestrates the engine; owns all exit-code mapping."""

import sys
from typing import Annotated

import typer

from authwatch import __version__

app = typer.Typer(pretty_exceptions_enable=False, add_completion=False, no_args_is_help=True,
                  help="AuthWatch: authentication-log analyzer with honest coverage reporting.")


def _version_callback(value: bool) -> None:
    if value:
        sys.stdout.write(f"authwatch {__version__}\n")
        raise typer.Exit(0)


@app.callback()
def _root(
    version: Annotated[bool, typer.Option("--version", callback=_version_callback, is_eager=True,
                                          help="Show the version and exit.")] = False,
) -> None:
    """AuthWatch: authentication-log analyzer with honest coverage reporting."""


def main() -> None:
    """Console-script entry point."""
    app(prog_name="authwatch")
