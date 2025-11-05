from langchain.chat_models import ChatOpenAI
from ..config import settings

def get_llm():
    return ChatOpenAI(
        model=settings.LLM_MODEL,
        api_key=settings.OPENAI_API_KEY,
        temperature=0.2
    )
