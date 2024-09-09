from __future__ import annotations


from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from trustpoint_devid_module.service_interface import DevIdModule
    from trustpoint_client.api.schema import Inventory
    from pathlib import Path


class TrustpointClientBaseClass:

    devid_module: DevIdModule
    inventory: None | Inventory
    inventory_path: Path
    working_dir: Path