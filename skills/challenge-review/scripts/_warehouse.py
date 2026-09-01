from __future__ import annotations

from pathlib import Path


WAREHOUSE_ENV = "CYBERARENA_CHALLENGE_WAREHOUSE"


def selected_warehouse(configured: Path) -> Path:
    warehouse = configured
    if not warehouse.is_absolute():
        raise ValueError("warehouse must be an absolute path")
    warehouse = warehouse.resolve()
    if not warehouse.is_dir():
        raise ValueError(f"warehouse is not a directory: {warehouse}")
    if (
        not (warehouse / "_registry" / "index.json").is_file()
        or not any(warehouse.glob("*/*/challenge.py"))
    ):
        raise ValueError(f"not a challenge warehouse: {warehouse}")
    return warehouse
