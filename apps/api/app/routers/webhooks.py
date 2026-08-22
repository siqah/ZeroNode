from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Depends, HTTPException, Request

from app.auth.models import Principal
from app.auth.webhook_auth import require_webhook_principal, verify_pagerduty_request
from app.ingress.alertmanager import AlertmanagerWebhookBody, normalize_alertmanager
from app.ingress.generic import GenericWebhookBody, normalize_generic, normalize_generic_payload
from app.ingress.pagerduty import PagerDutyWebhookBody, normalize_pagerduty
from app.ingress.trigger import trigger_incident

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/webhooks", tags=["webhooks"])


def _max_body_bytes(request: Request) -> int:
    settings = getattr(request.app.state, "settings", None)
    return int(getattr(settings, "webhook_max_body_bytes", 262144) or 262144)


async def _read_json(request: Request) -> dict:
    body = getattr(request.state, "raw_body", None)
    if body is None:
        body = await request.body()
    if len(body) > _max_body_bytes(request):
        raise HTTPException(status_code=413, detail="Webhook payload too large")
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=422, detail="Invalid JSON payload") from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=422, detail="Webhook payload must be a JSON object")
    return payload


def _response(result) -> dict:
    return {
        "status": result.status,
        "thread_id": result.thread_id,
        "job_id": result.job_id,
        "deduped": result.deduped,
        "source": result.source,
        "ignore_reason": result.ignore_reason,
    }


@router.post("/generic")
async def generic_webhook(
    request: Request,
    principal: Principal = Depends(require_webhook_principal),
):
    payload = await _read_json(request)
    try:
        if payload.get("event") == "incident.opened" and payload.get("incident"):
            trigger = normalize_generic_payload(payload)
        else:
            trigger = normalize_generic(GenericWebhookBody.model_validate(payload))
    except Exception as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    result = await trigger_incident(request, trigger, principal=principal)
    return _response(result)


@router.post("/alertmanager")
async def alertmanager_webhook(
    request: Request,
    principal: Principal = Depends(require_webhook_principal),
):
    payload = await _read_json(request)
    settings = request.app.state.settings
    try:
        trigger = normalize_alertmanager(
            AlertmanagerWebhookBody.model_validate(payload),
            prefix=settings.alertmanager_thread_prefix,
            default_site=settings.webhook_default_site,
        )
    except Exception as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    result = await trigger_incident(request, trigger, principal=principal)
    return _response(result)


@router.post("/pagerduty")
async def pagerduty_webhook(
    request: Request,
    principal: Principal = Depends(verify_pagerduty_request),
):
    payload = await _read_json(request)
    settings = request.app.state.settings
    try:
        trigger = normalize_pagerduty(
            PagerDutyWebhookBody.model_validate(payload),
            prefix=settings.pagerduty_thread_prefix,
        )
    except Exception as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    result = await trigger_incident(request, trigger, principal=principal)
    return _response(result)
