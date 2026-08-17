from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class NeighborImpact:
    device: str
    security_zone: str | None


@dataclass(frozen=True)
class BoundaryResult:
    source_zone: str
    dest_zone: str
    crosses_boundary: bool


class TopologyStore(Protocol):
    def known_devices(self) -> list[str]: ...

    def path_trace(self, source_device: str, target_device: str) -> list[str] | None: ...

    def blast_radius(self, device_name: str) -> list[NeighborImpact]: ...

    def security_boundary(
        self, source_device: str, target_device: str
    ) -> BoundaryResult | None: ...
