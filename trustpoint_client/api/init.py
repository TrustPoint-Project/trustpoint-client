from pathlib import Path

from trustpoint_client.api import Inventory, TrustpointConfigModel
from trustpoint_client.api import handle_unexpected_errors
from trustpoint_client.api import (
    AlreadyInitializedError,
    WorkingDirectoryAlreadyExistsError,
    InventoryDataWriteError,
    UnexpectedTrustpointClientError
)
from trustpoint_client.api.base import TrustpointClientBaseClass
from trustpoint_client.api import exceptions as devid_exceptions

class TrustpointClientInit(TrustpointClientBaseClass):

    _inventory: None | Inventory
    _config: None | TrustpointConfigModel

    @handle_unexpected_errors(message='Failed to initialize the Trustpoint Client.')
    def init(self) -> None:
        """Initializes the Trustpoint Client.

        Creates the working directory and the json inventory file.

        Raises:
            AlreadyInitializedError: If the Trustpoint Client is already initialized.
            WorkingDirectoryAlreadyExists: If the working directory already exists.
            InventoryDataWriteError: If the Trustpoint Client failed to write the inventory data to disc.
        """

        if self._inventory is not None:
            raise AlreadyInitializedError

        if self._config is not None:
            raise AlreadyInitializedError

        try:
            self.devid_module.initialize()
        except devid_exceptions.AlreadyInitializedError as exception:
            raise AlreadyInitializedError from exception
        except devid_exceptions.WorkingDirectoryAlreadyExistsError as exception:
            raise WorkingDirectoryAlreadyExistsError from exception
        except devid_exceptions.InventoryDataWriteError as exception:
            raise InventoryDataWriteError from exception
        except Exception as exception:
            raise UnexpectedTrustpointClientError(str(exception)) from exception

        try:
            Path.mkdir(self.working_dir, parents=True, exist_ok=False)
        except FileExistsError as exception:
            raise WorkingDirectoryAlreadyExistsError from exception

        inventory = Inventory(
            domains={}
        )

        try:
            self.inventory_path.write_text(inventory.model_dump_json())
        except Exception as exception:
            raise InventoryDataWriteError from exception
        self._inventory = inventory

        config = TrustpointConfigModel(
            device_id=None,
            trustpoint_ipv4=None,
            trustpoint_port=None,
            default_domain=None,
            pki_protocol=None
        )

        try:
            self.config_path.write_text(config.model_dump_json())
        except Exception as exception:
            raise InventoryDataWriteError from exception
        self._config = config
