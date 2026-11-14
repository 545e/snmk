"""
SWA AI — Tool Backend Handler Resolver

Resolves the ``backend_handler`` strings declared in ``core/tool_registry.py``
into real, callable Python objects and invokes them with the arguments that
are actually available.

Background
----------
The tool registry declares a ``backend_handler`` for every tool (for example
``core.scanner_integrations:ScannerIntegrations.run_nmap_safe``).  Until now
those strings were never resolved: the REST layer hard-coded an ``if/elif``
chain for the handful of tools it knew about, and every *other* registry tool
fell through to a branch that returned::

    {"status": "OPERATIONAL", "output": "Executed handler <name> ..."}

without executing anything at all.  That reported success for work that never
happened — the single most damaging kind of bug in a security tool, because
the caller cannot tell an empty result from a real one.

This module makes the declaration load-bearing:

* ``resolve_handler`` turns ``module:attr.attr`` into a callable.
* ``invoke_handler`` binds the available request inputs to that callable's
  signature and calls it (awaiting it when it is a coroutine).

When a handler cannot be resolved, or its required arguments cannot be
satisfied from the request, the caller is expected to report
``NOT_IMPLEMENTED`` / ``NOT_EXECUTABLE`` honestly instead of claiming success.
"""

from __future__ import annotations

import asyncio
import importlib
import inspect
from typing import Any, Callable, Dict, List, Optional, Tuple

__all__ = [
    "HandlerNotResolvable",
    "HandlerNotExecutable",
    "resolve_handler",
    "invoke_handler",
    "describe_handler",
]


class HandlerNotResolvable(Exception):
    """Raised when a ``backend_handler`` string does not point at a callable."""


class HandlerNotExecutable(Exception):
    """Raised when a handler resolved but its required arguments are missing."""


# Aliases used to match a handler parameter against the request payload.
# The first match wins, so the order encodes preference.
_PARAM_ALIASES: Dict[str, Tuple[str, ...]] = {
    "target": ("target", "url", "domain", "host", "target_url", "target_host"),
    "target_url": ("target_url", "url", "target"),
    "target_host": ("target_host", "host", "domain", "target"),
    "host": ("host", "target_host", "domain", "target"),
    "domain": ("domain", "target_host", "host", "target"),
    "url": ("url", "target_url", "target"),
    "scan_id": ("scan_id", "scanId"),
    "path": ("path", "target_path", "filename", "file"),
    "target_path": ("target_path", "path", "filename"),
    "filename": ("filename", "path", "target_path"),
    "model_name": ("model_name", "model"),
    "dataset_id": ("dataset_id", "dataset"),
    "param_name": ("param_name", "parameter", "param"),
    "token": ("token", "jwt", "jwt_token"),
    "cookie": ("cookie", "session_cookie"),
    "raw_logs": ("raw_logs", "raw_log", "logs"),
    "log_type": ("log_type", "log"),
    "vector_type": ("vector_type", "attack_type", "rule_type"),
    "rule_type": ("rule_type", "attack_type", "vector_type"),
    "ports": ("ports",),
    "provider": ("provider", "target_provider"),
    "profile": ("profile",),
    "target_provider": ("target_provider", "provider"),
    "tool_id": ("tool_id", "tool"),
    "target_name": ("target_name", "name"),
    "port": ("port",),
    "explicit_authorization": ("explicit_authorization", "authorized", "authorization"),
    "authorized": ("authorized", "explicit_authorization", "authorization"),
}


def _split_handler(handler_str: str) -> Tuple[str, List[str]]:
    """Splits ``"module.path:Attr.method"`` into ``("module.path", [...])``."""
    if not handler_str or ":" not in handler_str:
        raise HandlerNotResolvable(
            f"Handler '{handler_str}' is not in 'module:attribute' form."
        )
    module_path, _, attr_path = handler_str.partition(":")
    module_path = module_path.strip()
    attr_path = attr_path.strip()
    if not module_path or not attr_path:
        raise HandlerNotResolvable(
            f"Handler '{handler_str}' is not in 'module:attribute' form."
        )
    return module_path, [part for part in attr_path.split(".") if part]


def _import_module(module_path: str):
    try:
        return importlib.import_module(module_path)
    except Exception as exc:
        raise HandlerNotResolvable(
            f"Could not import module '{module_path}': {exc}"
        ) from exc


def resolve_handler(handler_str: str) -> Tuple[Callable[..., Any], bool]:
    """
    Resolves a handler string into a callable.

    Returns ``(callable, is_bound_method)``.  ``is_bound_method`` is True when
    the resolved attribute is already bound to an instance (for example
    ``core.rea_engine:rea_engine.analyze``, where ``rea_engine`` is a
    module-level singleton) and False when it is an unbound function that
    lives on a class (for example
    ``reports.generator:ReportGenerator.generate_html``), because a
    class-level handler needs an instance to be useful and the caller must
    decide how to construct it.

    Raises :class:`HandlerNotResolvable` when the target does not exist or is
    not callable.
    """
    module_path, attr_parts = _split_handler(handler_str)
    module = _import_module(module_path)

    current: Any = module
    for part in attr_parts:
        if not hasattr(current, part):
            raise HandlerNotResolvable(
                f"Handler '{handler_str}' could not be resolved: "
                f"'{part}' does not exist on '{getattr(current, '__name__', current)}'."
            )
        current = getattr(current, part)

    if not callable(current):
        raise HandlerNotResolvable(
            f"Handler '{handler_str}' resolved to a non-callable object "
            f"of type '{type(current).__name__}'."
        )

    # A bound method already carries its instance (``__self__``); an unbound
    # function reached through a class does not.
    if getattr(current, "__self__", None) is not None:
        return current, True

    if inspect.isfunction(current):
        owner_is_class = False
        if len(attr_parts) >= 2:
            owner = module
            for part in attr_parts[:-1]:
                owner = getattr(owner, part, None)
            owner_is_class = inspect.isclass(owner)
        return current, not owner_is_class

    # Any other callable (a callable object, a partial, a builtin) is usable
    # as-is.
    return current, True


def _coerce(value: Any, annotation: Any) -> Any:
    """Best-effort coercion of a request value to the annotated type."""
    if annotation is inspect.Parameter.empty or value is None:
        return value
    if not isinstance(annotation, type):
        return value
    if annotation is bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() in ("1", "true", "yes", "on")
        return bool(value)
    if annotation is int and isinstance(value, (str, float, bool)):
        try:
            return int(value)
        except (TypeError, ValueError):
            return value
    if annotation is float and isinstance(value, (str, int, bool)):
        try:
            return float(value)
        except (TypeError, ValueError):
            return value
    if annotation is str and not isinstance(value, str):
        return str(value)
    return value


def _candidates_for(param_name: str) -> Tuple[str, ...]:
    aliases = _PARAM_ALIASES.get(param_name)
    if aliases:
        return aliases
    return (param_name,)


def _build_kwargs(
    func: Callable[..., Any],
    payload: Dict[str, Any]
) -> Tuple[Dict[str, Any], List[str]]:
    """
    Binds request ``payload`` values to ``func``'s parameters.

    Returns ``(kwargs, missing_required)``.  ``missing_required`` lists the
    names of required parameters that could not be satisfied.
    """
    try:
        signature = inspect.signature(func)
    except (TypeError, ValueError):
        return {}, []

    kwargs: Dict[str, Any] = {}
    missing: List[str] = []

    for name, param in signature.parameters.items():
        if param.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD):
            continue
        if name == "self":
            continue

        value = None
        found = False
        for candidate in _candidates_for(name):
            if candidate in payload and payload[candidate] is not None:
                value = payload[candidate]
                found = True
                break

        if not found:
            if param.default is inspect.Parameter.empty:
                missing.append(name)
            continue

        kwargs[name] = _coerce(value, param.annotation)

    return kwargs, missing


async def invoke_handler(
    handler_str: str,
    payload: Optional[Dict[str, Any]] = None,
    instance_factory: Optional[Callable[[Dict[str, Any]], Any]] = None,
) -> Any:
    """
    Resolves and calls a handler with the arguments available in ``payload``.

    ``instance_factory`` is used to construct the receiver for class-level
    handlers (for example ``ReportGenerator``); it receives ``payload`` so it
    can build the instance from the request.  When it is omitted and the
    handler needs an instance, :class:`HandlerNotExecutable` is raised.

    Raises:
        HandlerNotResolvable: the handler string does not point at a callable.
        HandlerNotExecutable: required arguments could not be satisfied.
    """
    payload = dict(payload or {})
    func, is_bound = resolve_handler(handler_str)

    if not is_bound:
        if instance_factory is None:
            raise HandlerNotExecutable(
                f"Handler '{handler_str}' is a class-level function and needs an "
                f"instance to run."
            )
        instance = instance_factory(payload)
        func = getattr(instance, func.__name__)
    kwargs, missing = _build_kwargs(func, payload)
    if missing:
        raise HandlerNotExecutable(
            f"Handler '{handler_str}' requires argument(s) "
            f"{', '.join(missing)} which were not supplied."
        )

    result = func(**kwargs)
    if inspect.isawaitable(result):
        result = await result
    return result


def describe_handler(handler_str: str) -> Dict[str, Any]:
    """
    Returns a structured description of a handler string.

    Never raises: unresolvable handlers are reported with
    ``{"resolved": False, ...}`` so the result can be surfaced to operators
    directly.
    """
    description: Dict[str, Any] = {
        "handler": handler_str,
        "resolved": False,
        "callable": None,
        "is_bound_method": None,
        "error": None,
    }
    try:
        func, is_bound = resolve_handler(handler_str)
    except HandlerNotResolvable as exc:
        description["error"] = str(exc)
        return description

    description["resolved"] = True
    description["callable"] = f"{getattr(func, '__module__', '?')}." \
                              f"{getattr(func, '__qualname__', repr(func))}"
    description["is_bound_method"] = is_bound
    try:
        description["signature"] = str(inspect.signature(func))
    except (TypeError, ValueError):
        description["signature"] = None
    return description
