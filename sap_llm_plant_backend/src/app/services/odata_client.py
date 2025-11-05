import httpx
from ..config import settings

class SAPClient:

    @staticmethod
    async def call(service_name, entity, key, payload, method):
        url=f"{settings.SAP_BASE_URL}/{service_name}/{entity}('{key}')"
        async with httpx.AsyncClient() as client:
            if method.upper()=="PATCH":
                r=await client.patch(url,json=payload,auth=(settings.SAP_USERNAME,settings.SAP_PASSWORD))
            elif method.upper()=="POST":
                r=await client.post(url,json=payload,auth=(settings.SAP_USERNAME,settings.SAP_PASSWORD))
            else:
                r=await client.get(url,auth=(settings.SAP_USERNAME,settings.SAP_PASSWORD))
            r.raise_for_status()
            return r.json()
