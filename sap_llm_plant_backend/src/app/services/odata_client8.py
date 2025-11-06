from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

from ..services.odata_loader import ODataSchemaLoader
from ..services.odata_client import SAPClient
from ..core.prompt import build_prompt_llm_parser_chain

AFFIRM = {"yes", "y", "confirm", "ok", "okay", "sure", "please do", "proceed", "go ahead"}
DENY   = {"no", "n", "cancel", "stop", "abort", "nope", "don't", "do not"}


def _append_history(history: List[Dict[str, Any]], role: str, content: str, control: Dict[str, Any] | None = None):
    item = {"role": role, "content": content}
    if control is not None:
        item["control"] = {
            k: control.get(k)
            for k in (
                "action", "service", "entity", "method", "key_field",
                "fields_needed", "fields_collected", "payload", "message", "choices"
            )
            if k in control
        }
    history.append(item)


def _format_history(history: List[Dict[str, Any]]) -> str:
    if not history:
        return "(none)"
    lines: List[str] = []
    for item in history[-20:]:
        role = item.get("role", "assistant")
        content = (item.get("content") or "").strip()
        if role == "user":
            lines.append(f"USER: {content}")
        else:
            lines.append(f"ASSISTANT: {content}")
        ctrl = item.get("control")
        if isinstance(ctrl, dict) and ctrl:
            mini = {
                k: ctrl.get(k)
                for k in ("action","service","entity","method","key_field","fields_needed","fields_collected","payload","message","choices")
                if k in ctrl
            }
            lines.append(f"CONTROL: {mini}")
    return "\n".join(lines)


class LLMOrchestrator:
    """
    Orchestrates SAP address assistant chat flow:
    - Uses PROMPT → LLM → PARSER chain (async).
    - Maintains state['history'] so the model never forgets context.
    - Forces a human confirmation BEFORE calling SAP.
    """

    def __init__(self):
        schema_dir = Path(__file__).resolve().parents[2] / "data" / "odata"
        self.loader = ODataSchemaLoader(schema_dir)        # auto-picks newest file in your loader
        self.odata_json = self.loader.get_schema_json()
        self.chain = build_prompt_llm_parser_chain()

    async def chat(self, user: str, state: Dict[str, Any] | None) -> Tuple[str, Dict[str, Any]]:
        state = state or {}
        history: List[Dict[str, Any]] = state.get("history", [])

        # ---- 0) Confirmation short-circuit ----
        if state.get("action") == "confirm":
            msg = (user or "").strip().lower()

            if msg in AFFIRM:
                svc     = state.get("service")
                ent     = state.get("entity")
                method  = (state.get("method") or "POST").upper()
                key_val = state.get("key_field")
                payload = state.get("payload") or {}
                try:
                    sap_resp = await SAPClient.call(svc, ent, key_val, payload, method)
                    bot_text = "✅ Update completed successfully."
                    control  = {
                        "action": "done",
                        "service": svc,
                        "entity": ent,
                        "method": method,
                        "key_field": key_val,
                        "payload": payload,
                        "sap_response": sap_resp,
                    }
                    _append_history(history, "user", user)
                    _append_history(history, "assistant", bot_text, control)
                    control["history"] = history
                    return bot_text, control
                except Exception as e:
                    bot_text = "❌ SAP call failed. Please review details and try again."
                    control  = {"action": "error", "message": str(e)[:400]}
                    _append_history(history, "user", user)
                    _append_history(history, "assistant", bot_text, control)
                    control["history"] = history
                    return bot_text, control

            if msg in DENY:
                bot_text = "✅ Cancelled. No changes were made."
                control  = {"action": "done", "message": "cancelled"}
                _append_history(history, "user", user)
                _append_history(history, "assistant", bot_text, control)
                control["history"] = history
                return bot_text, control
            # else fallthrough to LLM (user typed something else)

        # ---- 1) PROMPT → LLM → PARSER chain (async) ----
        history_text = _format_history(history)
        result = await self.chain.ainvoke({
            "user_input": user,
            "odata_json": self.odata_json,
            "state_json": state or {},
            "history_text": history_text,
        })

        bot_text = result["bot"]
        control_model = result["control"]
        control = control_model.model_dump() if hasattr(control_model, "model_dump") else dict(control_model)

        # ---- 2) Intercept execute → convert to confirm ----
        if control.get("action") == "execute":
            svc     = control.get("service") or ""
            ent     = control.get("entity") or ""
            method  = (control.get("method") or "POST").upper()
            key_val = control.get("key_field")
            payload = control.get("payload") or {}

            lines = ["Please confirm these details before I proceed:"]
            if key_val:
                lines.append(f"- Key (Plant): {key_val}")
            for k, v in payload.items():
                lines.append(f"- {k}: {v}")

            confirm_control = {
                "action": "confirm",
                "service": svc,
                "entity": ent,
                "method": method,
                "key_field": key_val,
                "payload": payload,
            }

            _append_history(history, "user", user)
            _append_history(history, "assistant", "\n".join(lines), confirm_control)
            confirm_control["history"] = history
            return "\n".join(lines), confirm_control

        # ---- 3) Default: return model output and keep history ----
        _append_history(history, "user", user)
        _append_history(history, "assistant", bot_text, control)
        control["history"] = history
        return bot_text, control
