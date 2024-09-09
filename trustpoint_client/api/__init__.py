from __future__ import annotations

from pathlib import Path
from trustpoint_devid_module.cli import get_devid_module, DevIdModule
from trustpoint_devid_module import exceptions as devid_exceptions

from trustpoint_client.api.exceptions import (
    TrustpointClientCorruptedError,
    NotInitializedError,
    AlreadyInitializedError,
    WorkingDirectoryAlreadyExistsError,
    InventoryDataWriteError,
    PurgeError,
    NothingToPurgeError,
    UnexpectedTrustpointClientError
)

from trustpoint_client.api.decorator import handle_unexpected_errors
from trustpoint_client.api.schema import Inventory
from trustpoint_client.api.init import TrustpointClientInit
from trustpoint_client.api.purge import TrustpointClientPurge

import pydantic


WORKING_DIR = Path().home() / '.local' / 'trustpoint' / 'client'
CONFIG_FILE_PATH = WORKING_DIR / 'config.json'


class TrustpointClient(
        TrustpointClientInit,
        TrustpointClientPurge):
    """The Trustpoint Client class."""
    _working_dir: Path
    _devid_module: DevIdModule

    _inventory_path: Path
    _inventory = None

    def __init__(self, working_dir: Path, purge_init: bool = False) -> None: # noqa: FBT001, FBT002
        """Instantiates a TrustpointClient object with the desired working directory.

        Args:
            working_dir: The desired working directory.
            purge_init:
                If purge is True, the purge method is called without trying to load the inventory first.
                This prevents the TrustpointClientCorruptedError to be raised if the stored data is corrupted.

        Raises:
            TrustpointClientCorruptedError: If the Trustpoint Client failed to load and verify the data from storage.
            TrustpointClientCorruptedError: If the Trustpoint Client failed to load and verify the data from storage.
        """
        self._working_dir: Path = Path(working_dir)
        self._config_file_path: Path = CONFIG_FILE_PATH
        self._inventory_path: Path = self.working_dir / 'inventory.json'

        try:
            self._devid_module = get_devid_module()
        except devid_exceptions.DevIdModuleCorruptedError as exception:
            raise TrustpointClientCorruptedError from exception

        if purge_init:
            self.purge()
            return

        if self.inventory_path.exists() and self.inventory_path.is_file():
            try:
                with self.inventory_path.open('r') as f:
                    self._inventory = Inventory.model_validate_json(f.read())
                self._is_initialized = True
            except pydantic.ValidationError as exception:
                raise TrustpointClientCorruptedError from exception


    # ------------------------------------------ Trustpoint Client Properties ------------------------------------------

    @property
    def devid_module(self) -> DevIdModule:
        return self._devid_module

    @property
    @handle_unexpected_errors(message='Failed to get the working directory.')
    def working_dir(self) -> Path:
        """Returns the Path instance containing the working directory path.

        Returns:
            Path: The Path instance containing the working directory path.
        """
        return self._working_dir

    @property
    @handle_unexpected_errors(message='Failed to get the inventory path.')
    def inventory_path(self) -> Path:
        """Returns the Path instance containing the inventory file path.

        Returns:
            Path: The Path instance containing the inventory file path.
        """
        return self._inventory_path

    @property
    @handle_unexpected_errors(message='Failed to get the inventory as a model copy.')
    def inventory(self) -> Inventory:
        """Returns the current inventory as a model copy.

        Returns:
            Inventory: A model copy of the current inventory.

        Raises:
            NotInitializedError: If the Trustpoint Client is not yet initialized.
        """
        if self._inventory is None:
            raise NotInitializedError
        return self._inventory.model_copy()


    # -------------------------------------- Initialization, Purging and Storing ---------------------------------------


    @handle_unexpected_errors(message='Failed to store the inventory.')
    def _store_inventory(self, inventory: Inventory) -> None:
        try:
            self.inventory_path.write_text(inventory.model_dump_json())
            self._inventory = inventory
        except Exception as exception:
            raise InventoryDataWriteError from exception
