import shutil
import click

from trustpoint_client.api import handle_unexpected_errors, Inventory
from trustpoint_client.api import (
    NothingToPurgeError,
    PurgeError
)
from trustpoint_client.api.base import TrustpointClientBaseClass
from trustpoint_devid_module import exceptions as devid_exceptions

class TrustpointClientPurge(TrustpointClientBaseClass):

    _inventory: None | Inventory

    @handle_unexpected_errors(message='Failed to purge the working directory.')
    def purge(self) -> None:
        """Purges (deletes) all stored data corresponding to the Trustpoint Client.

        Raises:
            NothingToPurgeError: If the working directory does not exist and thus there is nothing to purge.
            PurgeError: If the Trustpoint Client failed to purge and delete the working directory.
        """
        try:
            shutil.rmtree(self.working_dir)
            click.echo('Client purged.')
        except Exception as exception:
            raise PurgeError from exception

        if self.devid_module:
            self.devid_module.purge()
            click.echo('DevID module purged')

        self._inventory = None
