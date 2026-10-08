from .scope import assert_in_scope, get_scope_info, add_target, remove_target, ScopeError
from .audit import log_action, get_recent_logs

__all__ = [
    "assert_in_scope",
    "get_scope_info",
    "add_target",
    "remove_target",
    "ScopeError",
    "log_action",
    "get_recent_logs",
]
