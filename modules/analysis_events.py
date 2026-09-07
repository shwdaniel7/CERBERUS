from dataclasses import dataclass, field
from time import time
from typing import Any, Callable


@dataclass(frozen=True)
class AnalysisEvent:
    event_type: str
    filepath: str
    engine: str | None = None
    status: str = "info"
    progress: float | None = None
    elapsed_seconds: float | None = None
    message: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time)


EventCallback = Callable[[AnalysisEvent], None]


def emit_event(config, event):
    callback = config.get("event_callback")
    if callback:
        callback(event)
