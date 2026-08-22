from langchain_core.language_models.fake_chat_models import FakeListChatModel

from app.eval.corpus import load_incident

GOLDEN_RESPONSES = load_incident("cross_zone_block").scripted_responses


def scripted_llm(extra: list[str] | None = None) -> FakeListChatModel:
    return FakeListChatModel(responses=GOLDEN_RESPONSES + (extra or []))
