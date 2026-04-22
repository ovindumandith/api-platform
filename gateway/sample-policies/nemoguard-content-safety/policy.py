# Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
#
# WSO2 LLC. licenses this file to you under the Apache License,
# Version 2.0 (the "License"); you may not use this file except
# in compliance with the License. You may obtain a copy of the
# License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Content safety guardrail using NVIDIA NeMo Guard 8B.

Buffers request and/or response bodies, extracts the relevant text via
configurable JSONPath expressions, and forwards the content to a NeMo Guard
content safety endpoint. Unsafe requests are rejected with a 400; unsafe
responses are replaced with a sanitised error message before delivery to the
client.

NeMo Guard responds with "safe" or "unsafe\\nS<N>" where S<N> is one of:
  S1 Violence, S2 Sexual content, S3 Criminal planning,
  S4 Guns/Weapons, S5 Regulated substances, S6 Suicide/Self-harm,
  S7 Hate/Discriminatory, S8 Terrorism.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import requests as http_client

from wso2_gateway_policy_sdk import (
    BodyProcessingMode,
    ExecutionContext,
    HeaderProcessingMode,
    ImmediateResponse,
    ProcessingMode,
    ResponsePolicy,
    RequestPolicy,
    UpstreamRequestModifications,
    DownstreamResponseModifications,
)
from wso2_gateway_policy_sdk.policy.v1alpha2.types import (
    PolicyMetadata,
    RequestContext,
    ResponseContext,
)

logger = logging.getLogger(__name__)

_PASSTHROUGH_REQUEST: UpstreamRequestModifications | None = None
_PASSTHROUGH_RESPONSE: DownstreamResponseModifications | None = None


def _resolve_jsonpath(data: Any, path: str) -> Any:
    """Resolve a simple dotted JSONPath expression against *data*.

    Handles the patterns used throughout this codebase, e.g.:
      ``$.messages[-1].content``    →  data["messages"][-1]["content"]
      ``$.choices[0].message.content``  →  data["choices"][0]["message"]["content"]
    """
    if not path or path == "$":
        return data

    path = path.lstrip("$").lstrip(".")

    segments: list[str | int] = []
    buf = ""
    i = 0
    while i < len(path):
        ch = path[i]
        if ch == "[":
            if buf:
                segments.append(buf)
                buf = ""
            j = path.index("]", i)
            try:
                segments.append(int(path[i + 1 : j]))
            except ValueError:
                return None
            i = j + 1
            if i < len(path) and path[i] == ".":
                i += 1
        elif ch == ".":
            if buf:
                segments.append(buf)
                buf = ""
            i += 1
        else:
            buf += ch
            i += 1
    if buf:
        segments.append(buf)

    current = data
    for seg in segments:
        if current is None:
            return None
        if isinstance(seg, int):
            if isinstance(current, list) and -len(current) <= seg < len(current):
                current = current[seg]
            else:
                return None
        else:
            current = current.get(seg) if isinstance(current, dict) else None
    return current


def _call_nemoguard(
    endpoint: str,
    api_key: str,
    model: str,
    timeout: int,
    messages: list[dict],
) -> tuple[bool, str | None]:
    """Call the NeMo Guard endpoint and return (unsafe, category)."""
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    payload = {
        "model": model,
        "messages": messages,
        "max_tokens": 50,
        "temperature": 0,
    }

    response = http_client.post(
        f"{endpoint}/v1/chat/completions",
        headers=headers,
        json=payload,
        timeout=timeout,
    )
    response.raise_for_status()
    data = response.json()

    raw_verdict: str = data["choices"][0]["message"]["content"].strip()
    first_line = raw_verdict.splitlines()[0].strip().lower()
    unsafe = not first_line.startswith("safe")

    category: str | None = None
    if unsafe and len(raw_verdict.splitlines()) > 1:
        category = raw_verdict.splitlines()[1].strip()

    return unsafe, category


class _NemoGuardBase:
    """Shared initialisation and helper logic for both policy variants."""

    def __init__(self, metadata: PolicyMetadata, params: dict) -> None:
        self._endpoint: str = params.get("endpoint", "").rstrip("/")
        self._api_key: str = params.get("apiKey", "")
        self._model: str = params.get("model", "meta-llama/Llama-Guard-3-8B")
        self._timeout: int = int(params.get("timeout", 60))

        req_cfg = params.get("request", {}) if isinstance(params.get("request"), dict) else {}
        res_cfg = params.get("response", {}) if isinstance(params.get("response"), dict) else {}
        self._check_request: bool = bool(req_cfg.get("enabled", True))
        self._check_response: bool = bool(res_cfg.get("enabled", False))

    def _handle_request_body(
        self,
        execution_ctx: ExecutionContext,
        ctx: RequestContext,
        params: dict,
    ) -> ImmediateResponse | UpstreamRequestModifications | None:
        req_cfg = params.get("request", {}) if isinstance(params.get("request"), dict) else {}
        if not req_cfg.get("enabled", True):
            return _PASSTHROUGH_REQUEST

        if not (ctx.body and ctx.body.present and ctx.body.content):
            return _PASSTHROUGH_REQUEST

        json_path: str = req_cfg.get("jsonPath", "$.messages[-1].content")
        passthrough_on_error: bool = bool(req_cfg.get("passthroughOnError", False))
        show_assessment: bool = bool(req_cfg.get("showAssessment", False))
        block_status_code: int = int(req_cfg.get("blockStatusCode", 400))

        try:
            body_data = json.loads(ctx.body.content)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return _PASSTHROUGH_REQUEST

        user_text = _resolve_jsonpath(body_data, json_path)
        if not user_text or not isinstance(user_text, str):
            return _PASSTHROUGH_REQUEST

        try:
            unsafe, category = _call_nemoguard(
                self._endpoint, self._api_key, self._model, self._timeout,
                messages=[{"role": "user", "content": user_text}],
            )
        except Exception as exc:
            logger.warning(
                "nemoguard request error (request_id=%s): %s",
                execution_ctx.request_id,
                exc,
            )
            if passthrough_on_error:
                return _PASSTHROUGH_REQUEST
            return ImmediateResponse(
                status_code=503,
                headers={"content-type": "application/json"},
                body=json.dumps({
                    "type": "NEMOGUARD_CONTENT_SAFETY",
                    "message": {"action": "SERVICE_UNAVAILABLE", "actionReason": "Content safety service unavailable."},
                }).encode(),
            )

        if unsafe:
            msg: dict = {
                "action": "GUARDRAIL_INTERVENED",
                "interveningGuardrail": "NeMo Guard Content Safety",
                "actionReason": "Unsafe content detected.",
                "direction": "REQUEST",
            }
            if show_assessment and category:
                msg["assessments"] = {"category": category}
            return ImmediateResponse(
                status_code=block_status_code,
                headers={"content-type": "application/json"},
                body=json.dumps({"type": "NEMOGUARD_CONTENT_SAFETY", "message": msg}).encode(),
            )

        return _PASSTHROUGH_REQUEST

    def _handle_response_body(
        self,
        execution_ctx: ExecutionContext,
        ctx: ResponseContext,
        params: dict,
    ) -> ImmediateResponse | DownstreamResponseModifications | None:
        res_cfg = params.get("response", {}) if isinstance(params.get("response"), dict) else {}
        if not res_cfg.get("enabled", False):
            return _PASSTHROUGH_RESPONSE

        if not (ctx.response_body and ctx.response_body.present and ctx.response_body.content):
            return _PASSTHROUGH_RESPONSE

        json_path: str = res_cfg.get("jsonPath", "$.choices[0].message.content")
        passthrough_on_error: bool = bool(res_cfg.get("passthroughOnError", False))
        show_assessment: bool = bool(res_cfg.get("showAssessment", False))

        messages: list[dict] = []

        if ctx.request_body and ctx.request_body.present and ctx.request_body.content:
            req_json_path: str = (
                params.get("request", {}).get("jsonPath", "$.messages[-1].content")
                if isinstance(params.get("request"), dict)
                else "$.messages[-1].content"
            )
            try:
                req_data = json.loads(ctx.request_body.content)
                user_text = _resolve_jsonpath(req_data, req_json_path)
                if user_text and isinstance(user_text, str):
                    messages.append({"role": "user", "content": user_text})
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

        try:
            res_data = json.loads(ctx.response_body.content)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return _PASSTHROUGH_RESPONSE

        assistant_text = _resolve_jsonpath(res_data, json_path)
        if not assistant_text or not isinstance(assistant_text, str):
            return _PASSTHROUGH_RESPONSE

        messages.append({"role": "assistant", "content": assistant_text})

        try:
            unsafe, category = _call_nemoguard(
                self._endpoint, self._api_key, self._model, self._timeout,
                messages=messages,
            )
        except Exception as exc:
            logger.warning(
                "nemoguard response error (request_id=%s): %s",
                execution_ctx.request_id,
                exc,
            )
            if passthrough_on_error:
                return _PASSTHROUGH_RESPONSE
            return ImmediateResponse(
                status_code=503,
                headers={"content-type": "application/json"},
                body=json.dumps({
                    "type": "NEMOGUARD_CONTENT_SAFETY",
                    "message": {"action": "SERVICE_UNAVAILABLE", "actionReason": "Content safety service unavailable."},
                }).encode(),
            )

        if unsafe:
            msg: dict = {
                "action": "GUARDRAIL_INTERVENED",
                "interveningGuardrail": "NeMo Guard Content Safety",
                "actionReason": "Unsafe content detected.",
                "direction": "RESPONSE",
            }
            if show_assessment and category:
                msg["assessments"] = {"category": category}
            return ImmediateResponse(
                status_code=200,
                headers={"content-type": "application/json"},
                body=json.dumps({"type": "NEMOGUARD_CONTENT_SAFETY", "message": msg}).encode(),
            )

        return _PASSTHROUGH_RESPONSE


class NemoGuardRequestOnlyPolicy(_NemoGuardBase, RequestPolicy):
    """Request-phase only variant — used when response.enabled=false."""

    def mode(self) -> ProcessingMode:
        return ProcessingMode(
            request_header_mode=HeaderProcessingMode.SKIP,
            request_body_mode=(
                BodyProcessingMode.BUFFER if self._check_request else BodyProcessingMode.SKIP
            ),
            response_header_mode=HeaderProcessingMode.SKIP,
            response_body_mode=BodyProcessingMode.SKIP,
        )

    def on_request_body(
        self,
        execution_ctx: ExecutionContext,
        ctx: RequestContext,
        params: dict,
    ) -> ImmediateResponse | UpstreamRequestModifications | None:
        return self._handle_request_body(execution_ctx, ctx, params)


class NemoGuardFullPolicy(_NemoGuardBase, RequestPolicy, ResponsePolicy):
    """Request + response variant — used when response.enabled=true."""

    def mode(self) -> ProcessingMode:
        return ProcessingMode(
            request_header_mode=HeaderProcessingMode.SKIP,
            request_body_mode=(
                BodyProcessingMode.BUFFER if self._check_request else BodyProcessingMode.SKIP
            ),
            response_header_mode=HeaderProcessingMode.SKIP,
            response_body_mode=BodyProcessingMode.BUFFER,
        )

    def on_request_body(
        self,
        execution_ctx: ExecutionContext,
        ctx: RequestContext,
        params: dict,
    ) -> ImmediateResponse | UpstreamRequestModifications | None:
        return self._handle_request_body(execution_ctx, ctx, params)

    def on_response_body(
        self,
        execution_ctx: ExecutionContext,
        ctx: ResponseContext,
        params: dict,
    ) -> ImmediateResponse | DownstreamResponseModifications | None:
        return self._handle_response_body(execution_ctx, ctx, params)


def get_policy(
    metadata: PolicyMetadata, params: dict
) -> NemoGuardRequestOnlyPolicy | NemoGuardFullPolicy:
    res_cfg = params.get("response", {}) if isinstance(params.get("response"), dict) else {}
    if bool(res_cfg.get("enabled", False)):
        return NemoGuardFullPolicy(metadata, params)
    return NemoGuardRequestOnlyPolicy(metadata, params)
