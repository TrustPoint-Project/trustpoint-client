from __future__ import annotations


from typing import TYPE_CHECKING

from trustpoint_client.api import TrustpointConfigModel

if TYPE_CHECKING:
    from trustpoint_devid_module.service_interface import DevIdModule
    from trustpoint_client.api.schema import Inventory
    from pathlib import Path


class TrustpointClientBaseClass:

    devid_module: DevIdModule
    inventory: None | Inventory
    config: None | TrustpointConfigModel
    inventory_path: Path
    config_path: Path
    working_dir: Path
    _store_inventory: callable
    _store_config: callable
