"""Entry point for command line interface."""

import fire  # type: ignore[import-untyped]

from iok_converter.converter import IOKConverter
from iok_converter.installer import AutomationClient


def do_all(token: str, url: str) -> None:
    IOKConverter().convert_directory()
    AutomationClient().upload_automations(
        token=token,
        url=url,
    )

def main() -> None:
    """Main entry point for CLI."""
    fire.Fire({
        "download": IOKConverter().download_iok_rules,
        "convert": IOKConverter().convert_directory,
        "insert": AutomationClient().upload_automations,
        "all": do_all
    })


if __name__ == "__main__":
    main()
