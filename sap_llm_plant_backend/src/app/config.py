from pydantic import BaseModel
from dotenv import load_dotenv
import os

load_dotenv()

class Settings(BaseModel):
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY")
    LLM_MODEL: str = os.getenv("LLM_MODEL","gpt-4.1")
    SAP_BASE_URL: str = os.getenv("SAP_BASE_URL")
    SAP_USERNAME: str = os.getenv("SAP_USERNAME")
    SAP_PASSWORD: str = os.getenv("SAP_PASSWORD")

settings = Settings()
