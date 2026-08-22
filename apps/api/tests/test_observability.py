from app.execute.base import APPLIED
from app.observability import Metrics


def test_inference_fallback_metric_increments():
    metrics = Metrics(enabled=True)
    metrics.observe_inference_fallback("supervisor", "inferred")
    metrics.observe_inference_fallback("firewall_specialist", "parse_error")

    stats = metrics.inference_stats()
    assert stats["fallback_total"] == 2
    assert stats["parse_error_total"] == 1

    payload, _ = metrics.render()
    text = payload.decode()
    assert "zeronode_inference_fallback_total" in text
    assert 'reason="inferred"' in text
    assert 'reason="parse_error"' in text


def test_observe_model_tracks_calls():
    metrics = Metrics(enabled=True)
    metrics.observe_model("native", 0.5)
    metrics.observe_model("xml", 1.2)

    stats = metrics.inference_stats()
    assert stats["model_calls_total"] == 2

    payload, _ = metrics.render()
    text = payload.decode()
    assert "zeronode_model_calls_total" in text
    assert 'outcome="native"' in text


def test_webhook_job_and_execution_metrics_render():
    metrics = Metrics(enabled=True)
    metrics.observe_webhook("generic", "dispatched")
    metrics.observe_webhook("alertmanager", "ignored")
    metrics.observe_alert_flag("tool-call injection")
    metrics.observe_job("start", "completed", 1.5)
    metrics.observe_execution(APPLIED)
    metrics.observe_approval_latency(12.5)
    metrics.set_queue_depth(3)
    metrics.set_circuit_open(True)

    payload, _ = metrics.render()
    text = payload.decode()
    assert "zeronode_webhook_requests_total" in text
    assert "zeronode_alert_flags_total" in text
    assert "zeronode_jobs_total" in text
    assert "zeronode_execution_total" in text
    assert "zeronode_approval_latency_seconds" in text
    assert "zeronode_queue_depth" in text
    assert "zeronode_inference_circuit_open" in text
