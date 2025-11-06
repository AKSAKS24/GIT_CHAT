from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Literal, Tuple

from pydantic import BaseModel, Field, ValidationError

from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import BaseOutputParser

# Your existing LLM factory
from src.app.core.llm import get_llm


# =========================
# SYSTEM PROMPT
# =========================
SYSTEM_PROMPT = """
You are an SAP business assistant for maintaining plant addresses (Telephone / Postal / Fax) in SAP S/4HANA.

STRICT OUTPUT FORMAT (always):
<bot>
[Natural, friendly business-language reply to the user. No technical field names.]
</bot>
<control>
{
  "action": "ask" | "collect" | "confirm" | "execute" | "done" | "error",
  "service": "<service_name or empty>",
  "entity": "<entity_set or empty>",
  "method": "GET" | "PATCH" | "POST" | "",
  "key_field": "<string key value or empty>",
  "fields_needed": ["..."],
  "fields_collected": { "FieldName": "Value" },
  "payload": { "FieldName": "Value" },
  "message": "<short controller hint for the app>",
  "choices": ["choice 1", "choice 2"]
}
</control>

Rules:
- Speak only in simple business language using field DESCRIPTIONS from the metadata (never show technical names in <bot>).
- Conversation plan:
  1) Offer address types (entity descriptions) as a numbered menu.
  2) Collect REQUIRED key fields first (put missing keys at the start of fields_needed).
  3) Then offer OPTIONAL (non-key) fields as a numbered menu with a “Done” option; loop until user chooses Done.
  4) ALWAYS show a human-readable summary of the action and ALL field values provided by the user, then set action="confirm".
  5) Only after the user confirms, set action="execute" and include: service, entity (EntitySet), method (PATCH for updates unless user asked create/read), key_field, and payload.
- fields_needed MUST list missing required keys first; after keys are collected, include optional fields you plan to ask next.
- payload MUST use technical field names from metadata; but do NOT show them in <bot>.
- If anything is unclear, set action="ask" with a clear question and include choices when helpful.
- If you cannot comply, set action="error" with a concise message.
- Output ONLY the two blocks (<bot> and <control>) and ensure the JSON inside <control> is STRICTLY valid JSON (no trailing commas, no comments).
""".strip()


# =========================
# USER PROMPT
# =========================
USER_PROMPT_TEMPLATE = """
Conversation so far:
{history_text}

User said: "{user_input}"

OData Services JSON:
{odata_json}

Conversation State (raw control from last turn):
{state_json}

Follow rules and generate the next assistant message.
""".strip()


# =========================
# Optional: simple builder
# =========================
def build_prompt(user_input: str, odata_json: Dict[str, Any], state_json: Dict[str, Any], history_text: str) -> str:
    user_block = USER_PROMPT_TEMPLATE.format(
        history_text=history_text,
        user_input=user_input,
        odata_json=json.dumps(odata_json, ensure_ascii=False, indent=2)
        if not isinstance(odata_json, str) else odata_json,
        state_json=json.dumps(state_json, ensure_ascii=False, indent=2)
        if not isinstance(state_json, str) else state_json,
    )
    return (SYSTEM_PROMPT + "\n\n" + user_block).strip()


# =========================
# Control schema & parser
# =========================
Action = Literal["ask", "collect", "confirm", "execute", "done", "error"]
Method = Literal["GET", "PATCH", "POST", ""]

class Control(BaseModel):
    action: Action
    service: str
    entity: str
    method: Method
    key_field: str
    fields_needed: List[str]
    fields_collected: Dict[str, Any]
    payload: Dict[str, Any]
    message: str
    choices: List[str] = Field(default_factory=list)

# Robust regex (non-greedy; tolerates whitespace)
BOT_RE  = re.compile(r"<bot>\s*(.*?)\s*</bot>", re.DOTALL | re.IGNORECASE)
CTRL_RE = re.compile(r"<control>\s*(.*?)\s*</control>", re.DOTALL | re.IGNORECASE)

def _clean_control_json(raw: str) -> str:
    """Strip fences like ```json ... ``` and normalize whitespace."""
    s = raw.strip()
    if s.startswith("```"):
        s = s.strip("`").strip()
        s = re.sub(r"^json\s*", "", s, flags=re.IGNORECASE)
    s = s.replace("\r", "")
    return s.strip()

def parse_llm_output(text: str) -> Tuple[str, Control]:
    """Extracts the two blocks and validates the control JSON."""
    bot_match = BOT_RE.search(text or "")
    ctrl_match = CTRL_RE.search(text or "")
    if not bot_match or not ctrl_match:
        raise ValueError("Missing <bot> or <control> blocks")

    bot_text = bot_match.group(1).strip()
    raw_ctrl = _clean_control_json(ctrl_match.group(1))

    try:
        ctrl_obj = json.loads(raw_ctrl)
        control = Control(**ctrl_obj)
    except (json.JSONDecodeError, ValidationError) as e:
        raise ValueError(f"Invalid control JSON: {e}") from e

    return bot_text, control


# =========================
# LangChain output parser & chain
# =========================
class BotControlParser(BaseOutputParser):
    """LangChain output parser that returns {'bot': str, 'control': Control}."""

    def parse(self, text: str) -> Dict[str, Any]:
        bot, ctrl = parse_llm_output(text)
        return {"bot": bot, "control": ctrl}

def build_prompt_llm_parser_chain():
    """
    Returns an async-capable LangChain runnable: PROMPT | LLM | PARSER.
    Inputs: {user_input, odata_json, state_json, history_text}
    Output: {"bot": str, "control": Control}
    """
    prompt = ChatPromptTemplate.from_messages([
        ("system", SYSTEM_PROMPT),
        ("human", USER_PROMPT_TEMPLATE),
    ])
    llm = get_llm()  # must be a LangChain ChatModel
    parser = BotControlParser()
    return prompt | llm | parser
