"""Provides methods to read and write global trustpoint-client settings."""

from __future__ import annotations

from trustpoint_client.api import TrustpointClientContext, TrustpointClientError


def get_config() -> dict[str, None | str]:
    """Returns the all global configurations as a dictionary.

    Returns:
        Global configurations.
    """
    context = TrustpointClientContext()
    return {
        'default_domain': context.inventory_model.default_domain,
        'device_serial_number': context.inventory_model.device_serial_number,
    }


def get_default_domain() -> None | str:
    """Gets the default domain.

    Returns:
        The configured default domain.
    """
    context = TrustpointClientContext()
    return context.inventory_model.default_domain


def set_default_domain(default_domain: None | str) -> None:
    """Sets the default domain.

    Args:
        default_domain: The default domain to set.
    """
    context = TrustpointClientContext()
    if default_domain is not None and default_domain not in context.inventory_model.domains:
        err_msg = f'{default_domain} domain does not exist. Cannot set it as default domain.'
        raise TrustpointClientError(err_msg)
    context.inventory_model.default_domain = default_domain
    context.store_inventory()


def clear_default_domain() -> None:
    """Clears the default domain."""
    context = TrustpointClientContext()
    context.inventory_model.default_domain = None
    context.store_inventory()


def get_device_serial_number() -> None | str:
    """Gets the device serial number.

    Returns:
        The configured device serial number.
    """
    context = TrustpointClientContext()
    return context.inventory_model.device_serial_number


def set_device_serial_number(device_serial_number: None | str) -> None:
    """Sets the device serial number.

    Args:
        device_serial_number: The device serial number to set.
    """
    context = TrustpointClientContext()
    context.inventory_model.device_serial_number = device_serial_number
    context.store_inventory()


def clear_device_serial_number() -> None:
    """Clears the device serial number."""
    context = TrustpointClientContext()
    context.inventory_model.device_serial_number = None
    context.store_inventory()
