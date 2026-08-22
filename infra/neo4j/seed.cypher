// Cross-zone lab: Web_App (DMZ) ↔ DB_Primary (TRUST) via FW_Edge
// Each statement re-MERGEs by unique keys. Cypher variables do not persist across ';'.

MERGE (z:SecurityZone {name: 'DMZ'})
SET z.risk_level = 'elevated';

MERGE (z:SecurityZone {name: 'TRUST'})
SET z.risk_level = 'low';

MERGE (z:SecurityZone {name: 'UNTRUST'})
SET z.risk_level = 'high';

MERGE (d:Device {name: 'Web_App'})
SET d.type = 'server', d.vendor = 'generic', d.management_ip = '10.10.1.10', d.os_version = 'linux', d.site = 'lab';

MERGE (d:Device {name: 'SW_DMZ'})
SET d.type = 'switch', d.vendor = 'cisco', d.management_ip = '10.10.0.2', d.os_version = 'ios-xe', d.site = 'lab';

MERGE (d:Device {name: 'FW_Edge'})
SET d.type = 'firewall', d.vendor = 'cisco', d.management_ip = '10.0.0.1', d.os_version = 'asa', d.site = 'lab';

MERGE (d:Device {name: 'SW_TRUST'})
SET d.type = 'switch', d.vendor = 'cisco', d.management_ip = '10.20.0.2', d.os_version = 'ios-xe', d.site = 'lab';

MERGE (d:Device {name: 'DB_Primary'})
SET d.type = 'server', d.vendor = 'generic', d.management_ip = '10.20.1.50', d.os_version = 'linux', d.site = 'lab';

MATCH (d:Device {name: 'Web_App'}), (z:SecurityZone {name: 'DMZ'})
MERGE (d)-[:BELONGS_TO]->(z);

MATCH (d:Device {name: 'SW_DMZ'}), (z:SecurityZone {name: 'DMZ'})
MERGE (d)-[:BELONGS_TO]->(z);

MATCH (d:Device {name: 'FW_Edge'}), (z:SecurityZone {name: 'DMZ'})
MERGE (d)-[:BELONGS_TO]->(z);

MATCH (d:Device {name: 'SW_TRUST'}), (z:SecurityZone {name: 'TRUST'})
MERGE (d)-[:BELONGS_TO]->(z);

MATCH (d:Device {name: 'DB_Primary'}), (z:SecurityZone {name: 'TRUST'})
MERGE (d)-[:BELONGS_TO]->(z);

MERGE (i:Interface {id: 'Web_App:eth0'})
SET i.name = 'eth0', i.status = 'up', i.ip_address = '10.10.1.10', i.mac_address = '02:00:00:0a:01:0a';

MERGE (i:Interface {id: 'SW_DMZ:Gi0/1'})
SET i.name = 'Gi0/1', i.status = 'up', i.mac_address = '02:00:00:0a:00:01';

MERGE (i:Interface {id: 'SW_DMZ:Gi0/2'})
SET i.name = 'Gi0/2', i.status = 'up', i.mac_address = '02:00:00:0a:00:02';

MERGE (i:Interface {id: 'FW_Edge:Gi0/0'})
SET i.name = 'Gi0/0', i.status = 'up', i.ip_address = '10.10.0.1', i.mac_address = '02:00:00:00:00:01';

MERGE (i:Interface {id: 'FW_Edge:Gi0/1'})
SET i.name = 'Gi0/1', i.status = 'up', i.ip_address = '10.20.0.1', i.mac_address = '02:00:00:00:00:02';

MERGE (i:Interface {id: 'SW_TRUST:Gi0/1'})
SET i.name = 'Gi0/1', i.status = 'up', i.mac_address = '02:00:00:14:00:01';

MERGE (i:Interface {id: 'SW_TRUST:Gi0/2'})
SET i.name = 'Gi0/2', i.status = 'up', i.mac_address = '02:00:00:14:00:02';

MERGE (i:Interface {id: 'DB_Primary:eth0'})
SET i.name = 'eth0', i.status = 'up', i.ip_address = '10.20.1.50', i.mac_address = '02:00:00:14:01:32';

MATCH (d:Device {name: 'Web_App'}), (i:Interface {id: 'Web_App:eth0'})
MERGE (d)-[:HAS_INTERFACE]->(i);

MATCH (d:Device {name: 'SW_DMZ'}), (i:Interface {id: 'SW_DMZ:Gi0/1'})
MERGE (d)-[:HAS_INTERFACE]->(i);

MATCH (d:Device {name: 'SW_DMZ'}), (i:Interface {id: 'SW_DMZ:Gi0/2'})
MERGE (d)-[:HAS_INTERFACE]->(i);

MATCH (d:Device {name: 'FW_Edge'}), (i:Interface {id: 'FW_Edge:Gi0/0'})
MERGE (d)-[:HAS_INTERFACE]->(i);

MATCH (d:Device {name: 'FW_Edge'}), (i:Interface {id: 'FW_Edge:Gi0/1'})
MERGE (d)-[:HAS_INTERFACE]->(i);

MATCH (d:Device {name: 'SW_TRUST'}), (i:Interface {id: 'SW_TRUST:Gi0/1'})
MERGE (d)-[:HAS_INTERFACE]->(i);

MATCH (d:Device {name: 'SW_TRUST'}), (i:Interface {id: 'SW_TRUST:Gi0/2'})
MERGE (d)-[:HAS_INTERFACE]->(i);

MATCH (d:Device {name: 'DB_Primary'}), (i:Interface {id: 'DB_Primary:eth0'})
MERGE (d)-[:HAS_INTERFACE]->(i);

MATCH (a:Interface {id: 'Web_App:eth0'}), (b:Interface {id: 'SW_DMZ:Gi0/1'})
MERGE (a)-[:CONNECTS_TO {cable_type: 'patch', speed: '1G'}]->(b)
MERGE (b)-[:CONNECTS_TO {cable_type: 'patch', speed: '1G'}]->(a);

MATCH (a:Interface {id: 'SW_DMZ:Gi0/2'}), (b:Interface {id: 'FW_Edge:Gi0/0'})
MERGE (a)-[:CONNECTS_TO {cable_type: 'patch', speed: '10G'}]->(b)
MERGE (b)-[:CONNECTS_TO {cable_type: 'patch', speed: '10G'}]->(a);

MATCH (a:Interface {id: 'FW_Edge:Gi0/1'}), (b:Interface {id: 'SW_TRUST:Gi0/1'})
MERGE (a)-[:CONNECTS_TO {cable_type: 'patch', speed: '10G'}]->(b)
MERGE (b)-[:CONNECTS_TO {cable_type: 'patch', speed: '10G'}]->(a);

MATCH (a:Interface {id: 'SW_TRUST:Gi0/2'}), (b:Interface {id: 'DB_Primary:eth0'})
MERGE (a)-[:CONNECTS_TO {cable_type: 'patch', speed: '1G'}]->(b)
MERGE (b)-[:CONNECTS_TO {cable_type: 'patch', speed: '1G'}]->(a);
