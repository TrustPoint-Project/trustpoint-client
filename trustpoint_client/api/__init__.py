"""The trustpoint_client.api package __init__ module provides context initialization and data handling features."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import TYPE_CHECKING

import pydantic
from platformdirs import PlatformDirs
from prettytable import PrettyTable
from trustpoint_devid_module import exceptions as devid_exceptions  # type: ignore[import-untyped]
from trustpoint_devid_module import (
    purge_working_dir_and_inventory as purge_devid_module,  # type: ignore[import-untyped]
)
from trustpoint_devid_module.cli import DevIdModule  # type: ignore[import-untyped]

if TYPE_CHECKING:
    from typing import Any

from trustpoint_client.api.schema import InventoryModel

dirs = PlatformDirs(appname='trustpoint_client', appauthor='trustpoint')
WORKING_DIR = Path(dirs.user_data_dir)
INVENTORY_FILE_PATH = WORKING_DIR / Path('inventory.json')
CONFIG_FILE_PATH = WORKING_DIR / Path('config.json')


class TrustpointClientError(Exception):
    """Base class for all Trustpoint Client Exceptions."""

    def __init__(self, message: str) -> None:
        """Initializes the TrustpointClientError.

        Args:
            message: The error message.
        """
        super().__init__(message)


def get_table_from_dict(data: dict[str, Any], key_header: str = 'Key', value_header: str = 'Value') -> PrettyTable:
    """Gets a PrettyTable object for printing with reformatted keys for printing.

    Args:
        data: The data to be displayed in the table.
        key_header: The heading for the key column.
        value_header: The heading for the value column

    Returns:
        The created table instance.
    """
    table = PrettyTable([key_header, value_header])
    table.add_rows([[key, value] for key, value in data.items()])
    return table


class TrustpointClientContext:
    """The Trustpoint-Client context object provides access to the inventory data.

    Note:
        This context is not thread-safe. It is expected that only one of these instances exists and is used at the
        same time. It is considered sufficient for this PoC type of client at the moment.
    """

    _inventory_file_path: Path
    _inventory_model: InventoryModel
    _devid_module: DevIdModule

    def __init__(self, inventory_file_path: Path = INVENTORY_FILE_PATH) -> None:
        """Initializes the TrustpointClientContext object.

        Tries to load the inventory model. If the inventory model file does not exist, it initializes a new
        empty inventory model.

        Args:
            inventory_file_path: The path to the inventory model file.

        Raises:
            TrustpointClientError: If the initialization of the inventory model failed.
        """
        self._inventory_file_path = inventory_file_path

        try:
            self._devid_module = DevIdModule()
        except devid_exceptions.DevIdModuleCorruptedError as exception:
            raise TrustpointClientError(str(exception)) from exception

        if not inventory_file_path.exists():
            try:
                Path.mkdir(WORKING_DIR, parents=True, exist_ok=False)
            except FileExistsError as exception:
                raise TrustpointClientError(str(exception)) from exception

            inventory = InventoryModel(default_domain=None, device_serial_number=None, domains={})

            try:
                INVENTORY_FILE_PATH.write_text(inventory.model_dump_json())
            except Exception as exception:
                raise TrustpointClientError(str(exception)) from exception

        try:
            with inventory_file_path.open('r') as f:
                self._inventory_model = InventoryModel.model_validate_json(f.read())
        except pydantic.ValidationError as exception:
            raise TrustpointClientError(str(exception)) from exception

    @classmethod
    def purge_working_dir(cls, working_dir: Path = WORKING_DIR) -> None:
        """Purges both the Trustpoint-Client and DevIdModule working directory.

        Args:
            working_dir: The working directory to purge

        Raises:
            TrustpointClientError: If the purge failed. Either the current or DevIdModule working directory.
        """
        try:
            shutil.rmtree(working_dir, ignore_errors=False)
        except FileNotFoundError:
            pass
        except Exception as exception:
            raise TrustpointClientError(str(exception)) from exception

        try:
            purge_devid_module()
        except Exception as exception:
            raise TrustpointClientError(str(exception)) from exception

    @property
    def inventory_file_path(self) -> Path:
        """Gets the inventory file path.

        Returns:
            The inventory file path.
        """
        return self._inventory_file_path

    @property
    def inventory_model(self) -> InventoryModel:
        """Gets the inventory model.

        Returns:
            The inventory model.
        """
        return self._inventory_model

    @property
    def devid_module(self) -> DevIdModule:
        """Gets the DevIdModule instance.

        Returns:
            The DevIdModule instance.
        """
        return self._devid_module

    def store_inventory(self) -> None:
        """Stores the current state of the inventory.

        Raises:
            TrustpointClientError: If storing the inventory model failed.
        """
        try:
            self.inventory_file_path.write_text(self.inventory_model.model_dump_json())
        except Exception as exception:
            raise TrustpointClientError(str(exception)) from exception
