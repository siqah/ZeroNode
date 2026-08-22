"""LangGraph checkpoint persistence against real Postgres."""

from __future__ import annotations

import pytest

from app.execute.dryrun import DryRunExecutor
from app.firewall.mock import MockFirewall
from app.graph.builder import build_graph
from app.graph.scripted import scripted_llm
from app.jobs.runner import thread_config

pytest.importorskip("langgraph.checkpoint.postgres.aio")
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver  # noqa: E402

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_checkpoint_survives_new_graph_instance(postgres_pool, neo4j_topology):
    checkpointer = AsyncPostgresSaver(postgres_pool)
    await checkpointer.setup()
    llm = scripted_llm()
    graph = build_graph(
        llm,
        neo4j_topology,
        checkpointer,
        MockFirewall(),
        DryRunExecutor(),
        metrics=None,
        settings=None,
    )
    thread_id = "INC-CP-1"
    await graph.ainvoke(
        {
            "messages": [("user", "Web_App cannot reach DB_Primary:443")],
            "incident_id": thread_id,
            "active_worker": "supervisor",
        },
        thread_config(thread_id),
    )
    snapshot = await graph.aget_state(thread_config(thread_id))
    assert snapshot.values

    graph2 = build_graph(
        llm,
        neo4j_topology,
        checkpointer,
        MockFirewall(),
        DryRunExecutor(),
        metrics=None,
        settings=None,
    )
    restored = await graph2.aget_state(thread_config(thread_id))
    assert restored.values
