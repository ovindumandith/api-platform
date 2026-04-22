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

"""Prompt injection guardrail using IBM Granite Guardian 3.3 8B.

Buffers the request body, extracts the latest user message via JSONPath,
and forwards it to a Granite Guardian endpoint. Requests that the model
classifies as "Yes" for any configured risk are rejected before they
reach the upstream LLM.
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
    RequestPolicy,
    UpstreamRequestModifications,
)
from wso2_gateway_policy_sdk.policy.v1alpha2.types import PolicyMetadata, RequestContext

logger = logging.getLogger(__name__)

# Risk categories supported by Granite Guardian 3.3.
# Both are enabled by default to cover the widest range of prompt attacks.
_DEFAULT_RISKS: list[str] = ["jailbreak", "prompt_injection"]

_PASSTHROUGH: UpstreamRequestModifications | None = None


def _resolve_jsonpath(data: Any, path: str) -> Any:
    """Resolve a simple dotted JSONPath expression against *data*.

    Handles the patterns used throughout this codebase, e.g.:
      ``$.messages[-1].content``  →  data["messages"][-1]["content"]
      ``$.content``               →  data["content"]
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


class GraniteGuardianPromptInjectionPolicy(RequestPolicy):
    """Detects prompt injection and jailbreak attempts via Granite Guardian."""

    def __init__(self, metadata: PolicyMetadata, params: dict) -> None:
        # System parameters are fixed at policy attachment time.
        self._endpoint: str = params.get("endpoint", "").rstrip("/")
        self._api_key: str = params.get("apiKey", "")
        self._model: str = params.get("model", "ibm-granite/granite-guardian-3.3-8b")
        self._timeout: int = int(params.get("timeout", 10))

    def mode(self) -> ProcessingMode:
        return ProcessingMode(
            request_header_mode=HeaderProcessingMode.SKIP,
            request_body_mode=BodyProcessingMode.BUFFER,
            response_header_mode=HeaderProcessingMode.SKIP,
            response_body_mode=BodyProcessingMode.SKIP,
        )

    def on_request_body(
        self,
        execution_ctx: ExecutionContext,
        ctx: RequestContext,
        params: dict,
    ) -> ImmediateResponse | UpstreamRequestModifications | None:
        if not (ctx.body and ctx.body.present and ctx.body.content):
            return _PASSTHROUGH

        json_path: str = params.get("jsonPath", "$.messages[-1].content")
        passthrough_on_error: bool = bool(params.get("passthroughOnError", False))
        show_assessment: bool = bool(params.get("showAssessment", False))
        block_status_code: int = int(params.get("blockStatusCode", 400))
        risk_names: list[str] = params.get("riskNames", _DEFAULT_RISKS)

        try:
            body_data = json.loads(ctx.body.content)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return _PASSTHROUGH

        text = _resolve_jsonpath(body_data, json_path)
        if not text or not isinstance(text, str):
            return _PASSTHROUGH

        for risk_name in risk_names:
            try:
                blocked, assessment = self._call_guardian(text, risk_name)
            except Exception as exc:
                logger.warning(
                    "granite-guardian error (risk=%s, request_id=%s): %s",
                    risk_name,
                    execution_ctx.request_id,
                    exc,
                )
                if passthrough_on_error:
                    continue
                return ImmediateResponse(
                    status_code=503,
                    headers={"content-type": "application/json"},
                    body=json.dumps({
                        "type": "GRANITE_GUARDIAN_PROMPT_INJECTION",
                        "message": {"action": "SERVICE_UNAVAILABLE", "actionReason": "Guardrail service unavailable."},
                    }).encode(),
                )

            if blocked:
                msg: dict = {
                    "action": "GUARDRAIL_INTERVENED",
                    "interveningGuardrail": "Granite Guardian Prompt Injection",
                    "actionReason": "Prompt injection or jailbreak attempt detected.",
                    "direction": "REQUEST",
                }
                if show_assessment:
                    msg["assessments"] = {"riskName": risk_name, "verdict": assessment.get("verdict", "")}
                return ImmediateResponse(
                    status_code=block_status_code,
                    headers={"content-type": "application/json"},
                    body=json.dumps({"type": "GRANITE_GUARDIAN_PROMPT_INJECTION", "message": msg}).encode(),
                )

        return _PASSTHROUGH

    def _call_guardian(self, text: str, risk_name: str) -> tuple[bool, dict]:
        """Call the Granite Guardian endpoint and return (blocked, assessment)."""
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        # Granite Guardian 3.3 embeds the risk config in a system message.
        # The model replies "Yes" when the risk is detected, "No" when safe.
        payload = {
            "model": self._model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        f'<guardianconfig>{{"risk_name": "{risk_name}"}}'
                        "</guardianconfig>"
                    ),
                },
                {"role": "user", "content": text},
            ],
            "max_tokens": 5,
            "temperature": 0,
        }

        response = http_client.post(
            f"{self._endpoint}/v1/chat/completions",
            headers=headers,
            json=payload,
            timeout=self._timeout,
        )
        response.raise_for_status()
        data = response.json()

        raw_verdict: str = data["choices"][0]["message"]["content"].strip()
        blocked = raw_verdict.lower().startswith("yes")
        assessment = {"risk_name": risk_name, "verdict": raw_verdict}
        return blocked, assessment


def get_policy(metadata: PolicyMetadata, params: dict) -> GraniteGuardianPromptInjectionPolicy:
    return GraniteGuardianPromptInjectionPolicy(metadata, params)
