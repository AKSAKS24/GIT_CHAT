async def chat(self, user, state):
    prompt = build_prompt(user, self.odata_json, json.dumps(state))
    
    res = await self.llm.ainvoke(
        [
            {"role":"system","content": SYSTEM_PROMPT},
            {"role":"user","content": prompt}
        ]
    )

    text = res.content or ""

    # --- SAFE PARSER ---
    bot_match = re.search(r"<bot>(.*?)</bot>", text, re.DOTALL | re.IGNORECASE)
    ctrl_match = re.search(r"<control>(.*?)</control>", text, re.DOTALL | re.IGNORECASE)

    bot_text = bot_match.group(1).strip() if bot_match else "I'm here to help."
    control_raw = ctrl_match.group(1).strip() if ctrl_match else "{}"

    cr = control_raw.strip()
    if cr.startswith("```"):
        cr = cr.strip("`").strip()
        cr = re.sub(r"^json\\s*", "", cr, flags=re.IGNORECASE)
    cr = re.sub(r"\\s+", " ", cr).strip()

    try:
        control = json.loads(cr)
    except json.JSONDecodeError:
        control = {"action":"error","message":"LLM control JSON failed","raw":control_raw[:400]}

    # EXECUTION BLOCK
    if control.get("action") == "execute":
        resp = await SAPClient.call(
            control["service"],
            control["entity"],
            control.get("key_field"),
            control.get("payload") or {},
            control.get("method") or "GET"
        )
        control["action"] = "done"
        control["sap_response"] = resp
        bot_text = "✅ Update completed successfully."

    return bot_text, control
