from fastapi import APIRouter
from pydantic import BaseModel
from ..services.agent import LLMOrchestrator

router=APIRouter(prefix="/chat",tags=["LLM Chat"])
agent=LLMOrchestrator()

class ChatReq(BaseModel):
    user:str
    state:dict={}

@router.post("/")
async def chat(req:ChatReq):
    reply, control = await agent.chat(req.user, req.state)
    return {"reply":reply,"state":control}
