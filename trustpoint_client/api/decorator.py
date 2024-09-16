"""This module contains decorators."""

from __future__ import annotations

from typing import TYPE_CHECKING

from trustpoint_client.api.exceptions import TrustpointClientError, UnexpectedTrustpointClientError

if TYPE_CHECKING:
    from typing import Any


def handle_unexpected_errors(message: str) -> callable:
    """Outer decorator function that requires a message to be included in the UnexpectedTrustpointClientError.

    Args:
        message: The message to be included in the UnexpectedTrustpointClientError.

    Returns:
        callable: The decorator function.
    """
    def handle_unexpected_error_decorator_function(original_function: callable) -> callable:
        """Inner decorator function that takes the decorated function or method.

        Args:
            original_function: The decorated function or method.

        Returns:
            callable: The unexpected error handler function.
        """
        def unexpected_error_handler(*args: Any, **kwargs: Any) -> Any:
            """Handles any unexpected errors and re-raises all other TrustpointClientErrors.

            Args:
                *args: Any positional arguments passed to the original function.
                **kwargs: Any keyword arguments passed to the original function.

            Returns:
                Any: The return value of the original function.
            """
            try:
                result = original_function(*args, **kwargs)
            except TrustpointClientError:
                raise
            except Exception as exception:
                raise UnexpectedTrustpointClientError(message=message, exception=exception) from exception
            return result

        return unexpected_error_handler

    return handle_unexpected_error_decorator_function
