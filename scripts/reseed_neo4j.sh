#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
docker compose exec -T neo4j cypher-shell -u neo4j -p zeronode "MATCH (n) DETACH DELETE n;"
docker compose exec -T -i neo4j cypher-shell -u neo4j -p zeronode < "$ROOT/infra/neo4j/schema.cypher"
docker compose exec -T -i neo4j cypher-shell -u neo4j -p zeronode < "$ROOT/infra/neo4j/seed.cypher"
docker compose exec -T neo4j cypher-shell -u neo4j -p zeronode \
  "MATCH path = shortestPath((s:Device {name:'Web_App'})-[:HAS_INTERFACE|CONNECTS_TO*1..15]-(d:Device {name:'DB_Primary'})) RETURN [n IN nodes(path) WHERE n:Device | n.name] AS devices;"
