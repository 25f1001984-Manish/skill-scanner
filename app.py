from fastapi import FastAPI
from pydantic import BaseModel
from scanner import scan_skill

app = FastAPI()

class SkillRequest(BaseModel):
    skill: str

@app.get("/")
def root():
    return {"status": "running"}

@app.post("/scan")
def scan(req: SkillRequest):
    return {"categories": scan_skill(req.skill)}
