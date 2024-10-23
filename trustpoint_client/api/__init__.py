from __future__ import annotations

from pathlib import Path
from trustpoint_devid_module.cli import DevIdModule
from trustpoint_devid_module import purge_working_dir_and_inventory as purge_devid_module
from trustpoint_devid_module import exceptions as devid_exceptions
import shutil


from platformdirs import PlatformDirs

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
from trustpoint_client.api.schema import Inventory, TrustpointConfigModel
from trustpoint_client.api.provision import TrustpointClientProvision
from trustpoint_client.api.config import TrustpointConfig
from trustpoint_client.api.domain import TrustpointClientDomain

import pydantic

dirs = PlatformDirs(appname='trustpoint_client', appauthor='trustpoint')
WORKING_DIR = Path(dirs.user_data_dir)
INVENTORY_FILE_PATH = WORKING_DIR / Path('inventory.json')
CONFIG_FILE_PATH = WORKING_DIR / Path('config.json')


def initialize_working_dir_inventory_and_config() -> None:

    try:
        Path.mkdir(WORKING_DIR, parents=True, exist_ok=False)
    except FileExistsError as exception:
        raise WorkingDirectoryAlreadyExistsError from exception

    inventory = Inventory(
        domains={}
    )

    try:
        INVENTORY_FILE_PATH.write_text(inventory.model_dump_json())
    except Exception as exception:
        raise InventoryDataWriteError from exception

    config_model = TrustpointConfigModel(
        trustpoint_ipv4=None,
        trustpoint_port=None,
        default_domain=None,
    )

    try:
        CONFIG_FILE_PATH.write_text(config_model.model_dump_json())
    except Exception as exception:
        raise InventoryDataWriteError from exception


def purge_working_dir_inventory_and_config() -> None:
    try:
        shutil.rmtree(WORKING_DIR, ignore_errors=False)
    except FileNotFoundError:
        pass
    except Exception as exception:
        raise PurgeError from exception

    try:
        purge_devid_module()
    except Exception as exception:
        raise PurgeError from exception


class TrustpointClient(
    TrustpointClientProvision,
    TrustpointConfig,
    TrustpointClientDomain):
    """The Trustpoint Client class."""

    _inventory_file_path: Path
    _inventory: None | Inventory = None

    _config_file_path: Path
    _config: None | TrustpointConfigModel = None

    _devid_module: DevIdModule

    def __init__(
            self,
            inventory_file_path: Path = INVENTORY_FILE_PATH,
            config_file_path: Path = CONFIG_FILE_PATH) -> None:
        """Instantiates a TrustpointClient object with the desired working directory.

        Args:
            inventory_file_path: Full file path to the inventory.json file.
            config_file_path: Full file path to the config.json file.

        Raises:
            TrustpointClientCorruptedError: If the Trustpoint Client failed to load and verify the data from storage.
            TrustpointClientCorruptedError: If the Trustpoint Client failed to load and verify the data from storage.
        """
        self._inventory_file_path = inventory_file_path
        self._config_file_path = config_file_path

        try:
            self._devid_module = DevIdModule()
        except devid_exceptions.DevIdModuleCorruptedError as exception:
            raise TrustpointClientCorruptedError from exception

        if not self.inventory_file_path.exists() or not self.config_file_path.exists():
            initialize_working_dir_inventory_and_config()

        try:
            with self.inventory_file_path.open('r') as f:
                self._inventory = Inventory.model_validate_json(f.read())
            with self.config_file_path.open('r') as f:
                self._config = TrustpointConfigModel.model_validate_json(f.read())
        except pydantic.ValidationError as exception:
            raise TrustpointClientCorruptedError from exception


    # ------------------------------------------ Trustpoint Client Properties ------------------------------------------

    @property
    def devid_module(self) -> DevIdModule:
        return self._devid_module

    @property
    @handle_unexpected_errors(message='Failed to get the inventory path.')
    def inventory_file_path(self) -> Path:
        """Returns the Path instance containing the inventory file path.

        Returns:
            Path: The Path instance containing the inventory file path.
        """
        return self._inventory_file_path

    @property
    def inventory(self) -> Inventory:
        """Returns the current inventory as a model copy.

        Returns:
            Inventory: A model copy of the current inventory.

        Raises:
            NotInitializedError: If the Trustpoint Client is not yet initialized.
        """
        return self._inventory.model_copy()


    @property
    def config_file_path(self) -> Path:
        """Returns the Path instance containing the config file path.

        Returns:
            Path: The Path instance containing the config file path.
        """
        return self._config_file_path



    @property
    def config(self) -> TrustpointConfigModel:
        """Returns the current inventory as a model copy.

        Returns:
            Inventory: A model copy of the current inventory.

        Raises:
            NotInitializedError: If the Trustpoint Client is not yet initialized.
        """
        return self._config.model_copy()


    # -------------------------------------- Initialization, Purging and Storing ---------------------------------------

    @handle_unexpected_errors(message='Failed to store the inventory.')
    def _store_inventory(self, inventory: Inventory) -> None:
        try:
            self.inventory_file_path.write_text(inventory.model_dump_json())
            self._inventory = inventory
        except Exception as exception:
            raise InventoryDataWriteError from exception

    @handle_unexpected_errors(message='Failed to store the config.')
    def _store_config(self, config_model: TrustpointConfigModel) -> None:
        try:
            self.config_file_path.write_text(config_model.model_dump_json())
            self._config = config_model
        except Exception as exception:
            raise InventoryDataWriteError from exception
