"""Module containing all custom exceptions."""

from __future__ import annotations

class TrustpointClientError(Exception):
    """Base class for all Trustpoint Client Exceptions."""
    def __init__(self, message: str) -> None:
        """Initializes the TrustpointClientError."""
        super().__init__(message)


class TrustpointClientCorruptedError(TrustpointClientError):
    """Raised if the Trustpoint Client stored data is corrupted."""
    def __init__(self) -> None:
        """Initializes the TrustpointClientCorruptedError."""
        super().__init__(
            'Critical Failure. Trustpoint Client data is corrupted. '
            'You may need to call purge and thus remove all data.')


class NotInitializedError(TrustpointClientError):
    """Raised if trying to use the Trustpoint Client if it is not initialized."""

    def __init__(self) -> None:
        """Initializes the NotInitializedError."""
        super().__init__('Trustpoint Client is not initialized.')


class AlreadyInitializedError(TrustpointClientError):
    """Raised if trying to initialize the Trustpoint Client when it is already initialized."""

    def __init__(self) -> None:
        """Initializes the AlreadyInitializedError."""
        super().__init__('Already initialized.')


class WorkingDirectoryAlreadyExistsError(TrustpointClientError):
    """Raised if the working directory exists while the operation does expect it to not exist."""

    def __init__(self) -> None:
        """Initializes the WorkingDirectoryAlreadyExistsError."""
        super().__init__('Working directory already exists.')


class InventoryDataWriteError(TrustpointClientError):
    """Raised if writing to the inventory data failed."""

    def __init__(self) -> None:
        """Initializes the InventoryDataWriteError."""
        super().__init__('Writing new data to the inventory failed.')


class ConfigDataWriteError(TrustpointClientError):
    """Raised if writing to the config data failed."""

    def __init__(self) -> None:
        """Initializes the ConfigDataWriteError."""
        super().__init__('Writing new settings to the config file failed.')


class PurgeError(TrustpointClientError):
    """Raised if purging the working directory failed."""

    def __init__(self) -> None:
        """Initializes the PurgeError."""
        super().__init__('Failed to purge the working directory.')


class NothingToPurgeError(TrustpointClientError):
    """Raised if the working directory to purge does not exist."""

    def __init__(self) -> None:
        """Initializes the NothingToPurgeError."""
        super().__init__('The working directory does not exist. Nothing to purge.')


class UnexpectedTrustpointClientError(TrustpointClientError):
    """Raised if an unexpected error occurred, e.g. not supported key type found in the inventory."""

    def __init__(self, message: str, exception: None | Exception = None) -> None:
        """Initializes the UnexpectedTrustpointClientError.

        Args:
            message: Description of the error that occurred.
            exception: The exception that caused this exception.
        """
        if exception is None:
            super().__init__(f'\n\n\tAn unexpected error occurred.\n\t{message}\n')
        else:
            super().__init__(f'\n\n\tAn unexpected error occurred.\n\t{message}\n\tException raised: {exception}\n')


class ProvisioningError(TrustpointClientError):
    """Raised if a generic error occurred during the provisioning process."""

    def __init__(self, message: str) -> None:
        """Initializes the ProvisioningError."""
        super().__init__(message)
