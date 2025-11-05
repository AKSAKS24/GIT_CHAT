from fastapi import FastAPI
from .routers import chat

app=FastAPI(title="SAP AI Address Assistant")
app.include_router(chat.router)
