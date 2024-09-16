"""This module contains decorators."""

from __future__ import annotations

import traceback
from typing import TYPE_CHECKING

import click
from trustpoint_client.api.exceptions import TrustpointClientError

if TYPE_CHECKING:
    from typing import Any

def handle_cli_error(original_function: callable) -> callable:
    """Inner decorator function that takes the decorated function or method.

    Args:
        original_function: The decorated function or method.

    Returns:
        callable: The unexpected error handler function.
    """
    def trustpoint_client_error_handler(*args: Any, **kwargs: Any) -> Any:
        """Handles any unexpected errors and re-raises all other TrustpointClientErrors.

        Args:
            *args: Any positional arguments passed to the original function.
            **kwargs: Any keyword arguments passed to the original function.

        Returns:
            Any: The return value of the original function.
        """
        try:
            result = original_function(*args, **kwargs)
        except Exception as exception:
            click.echo(f'\n\t{exception}\n')
            return None

        return result

    return trustpoint_client_error_handler
