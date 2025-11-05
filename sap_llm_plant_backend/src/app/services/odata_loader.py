import json
from pathlib import Path

class ODataSchemaLoader:
    def __init__(self, base):
        self.base = Path(base)
        self.services = self._load()

    def _load(self):
        out=[]
        for f in self.base.glob("*.json"):
            with open(f,"r") as j: out.append(json.load(j))
        return out

    def get_schema_json(self):
        return json.dumps(self.services)
