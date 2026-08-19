from __future__ import annotations

from collections import deque

from app.store import BoundaryResult, NeighborImpact

LAB_DEVICES: dict[str, dict] = {
    "Web_App": {"zone": "DMZ", "neighbors": ["SW_DMZ"], "ip": "10.10.1.10"},
    "SW_DMZ": {"zone": "DMZ", "neighbors": ["Web_App", "FW_Edge"], "ip": "10.10.0.2"},
    "FW_Edge": {"zone": "DMZ", "neighbors": ["SW_DMZ", "SW_TRUST"], "ip": "10.0.0.1"},
    "SW_TRUST": {"zone": "TRUST", "neighbors": ["FW_Edge", "DB_Primary"], "ip": "10.20.0.2"},
    "DB_Primary": {"zone": "TRUST", "neighbors": ["SW_TRUST"], "ip": "10.20.1.50"},
}


class InMemoryTopology:
    """Deterministic copy of infra/neo4j/seed.cypher for tests and dry runs."""

    def __init__(self, devices: dict[str, dict] | None = None) -> None:
        self.devices = devices or LAB_DEVICES

    def known_devices(self) -> list[str]:
        return sorted(self.devices)

    def device_ip(self, device_name: str) -> str | None:
        node = self.devices.get(device_name)
        return node.get("ip") if node else None

    def path_trace(self, source_device: str, target_device: str) -> list[str] | None:
        if source_device not in self.devices or target_device not in self.devices:
            return None
        queue: deque[tuple[str, list[str]]] = deque([(source_device, [source_device])])
        seen = {source_device}
        while queue:
            node, path = queue.popleft()
            if node == target_device:
                return path
            for neighbor in self.devices[node]["neighbors"]:
                if neighbor not in seen:
                    seen.add(neighbor)
                    queue.append((neighbor, path + [neighbor]))
        return None

    def blast_radius(self, device_name: str) -> list[NeighborImpact]:
        node = self.devices.get(device_name)
        if not node:
            return []
        impacts: list[NeighborImpact] = []
        for neighbor in node["neighbors"]:
            zone = self.devices[neighbor]["zone"]
            impacts.append(NeighborImpact(device=neighbor, security_zone=zone))
        return impacts

    def security_boundary(
        self, source_device: str, target_device: str
    ) -> BoundaryResult | None:
        src = self.devices.get(source_device)
        dst = self.devices.get(target_device)
        if not src or not dst:
            return None
        return BoundaryResult(
            source_zone=src["zone"],
            dest_zone=dst["zone"],
            crosses_boundary=src["zone"] != dst["zone"],
        )
