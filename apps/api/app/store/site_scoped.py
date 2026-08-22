"""Per-incident site scoping over a shared topology backend."""

from __future__ import annotations

from app.store import BoundaryResult, NeighborImpact, TopologyStore
from app.store.memory import InMemoryTopology
from app.store.neo4j_store import Neo4jTopology


def scoped_topology(store: TopologyStore, site: str) -> TopologyStore:
    """Return a view limited to ``site`` when set, otherwise the original store."""
    site = (site or "").strip()
    if not site:
        return store
    if isinstance(store, (SiteScopedTopology, _Neo4jSiteView, _MemorySiteView)):
        return store.with_site(site)
    if isinstance(store, Neo4jTopology):
        if store._site == site:
            return store
        return _Neo4jSiteView(store, site)
    if isinstance(store, InMemoryTopology):
        return _MemorySiteView(store, site)
    return SiteScopedTopology(store, site)


class SiteScopedTopology:
    """Generic wrapper when the inner store has no native site support."""

    def __init__(self, inner: TopologyStore, site: str) -> None:
        self._inner = inner
        self._site = (site or "").strip()

    def with_site(self, site: str) -> SiteScopedTopology:
        site = (site or "").strip()
        if site == self._site:
            return self
        return SiteScopedTopology(self._inner, site)

    def known_devices(self) -> list[str]:
        names = self._inner.known_devices()
        if not self._site:
            return names
        filtered: list[str] = []
        for name in names:
            if self.device_ip(name) is not None or name in names:
                filtered.append(name)
        return sorted(filtered)

    def device_ip(self, device_name: str) -> str | None:
        return self._inner.device_ip(device_name)

    def path_trace(self, source_device: str, target_device: str) -> list[str] | None:
        if source_device not in self.known_devices() or target_device not in self.known_devices():
            return None
        return self._inner.path_trace(source_device, target_device)

    def blast_radius(self, device_name: str) -> list[NeighborImpact]:
        if device_name not in self.known_devices():
            return []
        return [
            item
            for item in self._inner.blast_radius(device_name)
            if item.device in self.known_devices()
        ]

    def security_boundary(
        self, source_device: str, target_device: str
    ) -> BoundaryResult | None:
        if source_device not in self.known_devices() or target_device not in self.known_devices():
            return None
        return self._inner.security_boundary(source_device, target_device)


class _Neo4jSiteView:
    def __init__(self, inner: Neo4jTopology, site: str) -> None:
        self._inner = inner
        self._site = (site or "").strip()

    def with_site(self, site: str) -> _Neo4jSiteView:
        site = (site or "").strip()
        if site == self._site:
            return self
        return _Neo4jSiteView(self._inner, site)

    def known_devices(self) -> list[str]:
        return self._inner.known_devices(site=self._site)

    def device_ip(self, device_name: str) -> str | None:
        return self._inner.device_ip(device_name, site=self._site)

    def path_trace(self, source_device: str, target_device: str) -> list[str] | None:
        return self._inner.path_trace(source_device, target_device, site=self._site)

    def blast_radius(self, device_name: str) -> list[NeighborImpact]:
        return self._inner.blast_radius(device_name, site=self._site)

    def security_boundary(
        self, source_device: str, target_device: str
    ) -> BoundaryResult | None:
        return self._inner.security_boundary(source_device, target_device, site=self._site)

    def freshness(self):
        return self._inner.freshness()

    def age_seconds(self):
        return self._inner.age_seconds()

    def close(self) -> None:
        self._inner.close()


class _MemorySiteView:
    def __init__(self, inner: InMemoryTopology, site: str) -> None:
        self._inner = inner
        self._site = (site or "").strip()

    def with_site(self, site: str) -> _MemorySiteView:
        site = (site or "").strip()
        if site == self._site:
            return self
        return _MemorySiteView(self._inner, site)

    def known_devices(self) -> list[str]:
        return self._inner.known_devices(site=self._site)

    def device_ip(self, device_name: str) -> str | None:
        return self._inner.device_ip(device_name, site=self._site)

    def path_trace(self, source_device: str, target_device: str) -> list[str] | None:
        return self._inner.path_trace(source_device, target_device, site=self._site)

    def blast_radius(self, device_name: str) -> list[NeighborImpact]:
        return self._inner.blast_radius(device_name, site=self._site)

    def security_boundary(
        self, source_device: str, target_device: str
    ) -> BoundaryResult | None:
        return self._inner.security_boundary(source_device, target_device, site=self._site)
