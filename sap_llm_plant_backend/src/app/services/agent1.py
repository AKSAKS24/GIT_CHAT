def _extract_blocks(self, text: str):
    bot_match = re.search(r"<bot>(.*?)</bot>", text, re.DOTALL | re.IGNORECASE)
    ctrl_match = re.search(r"<control>(.*?)</control>", text, re.DOTALL | re.IGNORECASE)

    bot_text = bot_match.group(1).strip() if bot_match else "I'm here to help."
    control_raw = ctrl_match.group(1).strip() if ctrl_match else "{}"

    # ✅ remove accidental code fences ```json
    cr = control_raw.strip()
    if cr.startswith("```"):
        cr = cr.strip("`").strip()
        cr = re.sub(r"^json\\s*", "", cr, flags=re.IGNORECASE)

    # ✅ collapse whitespace
    cr = re.sub(r"\\s+", " ", cr).strip()

    try:
        control = json.loads(cr)
    except json.JSONDecodeError:     # ✅ THIS IS THE FIX
        control = {
            "action": "error",
            "message": "LLM control JSON parse failed",
            "raw": control_raw[:400]   # return original for debug
        }

    return bot_text, control
