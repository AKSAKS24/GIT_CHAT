import re, json
from pathlib import Path
from ..core.llm import get_llm
from ..core.prompt import SYSTEM_PROMPT, build_prompt
from .odata_loader import ODataSchemaLoader
from .odata_client import SAPClient

class LLMOrchestrator:
    def __init__(self):
        self.llm = get_llm()
        schema_dir = Path(__file__).resolve().parents[2] / "data" / "odata"
        self.loader = ODataSchemaLoader(schema_dir)
        self.odata_json = self.loader.get_schema_json()

    async def chat(self, user, state):
        # ---------- 0) Confirmation short-circuit ----------
        affirm = {"yes","y","confirm","ok","okay","sure","please do","proceed","go ahead"}
        deny   = {"no","n","cancel","stop","abort","nope","don't","do not"}

        if state and state.get("action") == "confirm":
            msg = (user or "").strip().lower()
            if msg in affirm:
                svc     = state.get("service")
                ent     = state.get("entity")
                method  = (state.get("method") or "POST").upper()  # default POST for updates
                key_val = state.get("key_field")
                payload = state.get("payload") or {}
                try:
                    sap_resp = await SAPClient.call(svc, ent, key_val, payload, method)
                    return "✅ Update completed successfully.", {
                        "action": "done",
                        "service": svc,
                        "entity": ent,
                        "method": method,
                        "key_field": key_val,
                        "payload": payload,
                        "sap_response": sap_resp
                    }
                except Exception as e:
                    return "❌ SAP call failed. Please review details and try again.", {
                        "action": "error",
                        "message": str(e)[:400]
                    }
            if msg in deny:
                return "✅ Cancelled. No changes were made.", {"action":"done","message":"cancelled"}
            # else: fall through to LLM to clarify

        # ---------- 1) Ask LLM ----------
        prompt = build_prompt(user, self.odata_json, json.dumps(state or {}))
        res = await self.llm.ainvoke(
            [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt}
            ]
        )
        text = res.content or ""

        # ---------- 2) SAFE PARSER ----------
        bot_match  = re.search(r"<bot>(.*?)</bot>", text, re.DOTALL | re.IGNORECASE)
        ctrl_match = re.search(r"<control>(.*?)</control>", text, re.DOTALL | re.IGNORECASE)

        bot_text    = bot_match.group(1).strip() if bot_match else "I'm here to help."
        control_raw = ctrl_match.group(1).strip() if ctrl_match else "{}"

        cr = control_raw.strip()
        if cr.startswith("```"):
            cr = cr.strip("`").strip()
            cr = re.sub(r"^json\\s*", "", cr, flags=re.IGNORECASE)
        cr = re.sub(r"\\s+", " ", cr).strip()

        try:
            control = json.loads(cr)
        except json.JSONDecodeError:
            return bot_text, {"action":"error","message":"LLM control JSON failed to parse","raw": control_raw[:400]}

        # ---------- 3) Force confirm before execute ----------
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

            return "\n".join(lines), {
                "action": "confirm",
                "service": svc,
                "entity": ent,
                "method": method,
                "key_field": key_val,
                "payload": payload
            }

        return
