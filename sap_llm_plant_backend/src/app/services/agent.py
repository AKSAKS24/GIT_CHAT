import json
from ..core.llm import get_llm
from ..core.prompt import SYSTEM_PROMPT, build_prompt
from .odata_loader import ODataSchemaLoader
from .odata_client import SAPClient

loader = ODataSchemaLoader("src/app/data/odata")

class LLMOrchestrator:
    def __init__(self):
        self.llm = get_llm()
        self.odata_json = loader.get_schema_json()

    async def chat(self, user, state):
        prompt = build_prompt(user, self.odata_json, json.dumps(state))
        res = await self.llm.apredict_messages([
            {"role":"system","content":SYSTEM_PROMPT},
            {"role":"user","content":prompt}
        ])
        text=res.content

        # parse control block
        bot_text, control=json.loads(text.split("<control>")[0].replace("<bot>","").replace("</bot>","").strip()), None
        ctrl_raw=text.split("<control>")[1].split("</control>")[0]
        control=json.loads(ctrl_raw)

        # execute if action is execute
        if control.get("action")=="execute":
            resp = await SAPClient.call(
                control["service"],
                control["entity"],
                control["key_field"],
                control["payload"],
                control["method"]
            )
            control["action"]="done"
            bot_text="✅ Update completed successfully."

        return bot_text, control
