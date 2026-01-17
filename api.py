import json
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import requests
import os
from dotenv import load_dotenv

# Load Environment
load_dotenv()
API_KEY = os.getenv("OPENROUTER_API_KEY")

if not API_KEY:
    raise ValueError("OPENROUTER_API_KEY not found in .env file.")

app = FastAPI(title="Cyber Risk AI API")

# Load Vulnerability Data
def load_data():
    try:
        with open("NVD_CVE_2008_3844.json", "r") as f1:
            nvd = json.load(f1)
        with open("Vulners_CVE_2008_3844.json", "r") as f2:
            vulners = json.load(f2)
        return {"vulnerabilities": [nvd, vulners]}
    except FileNotFoundError:
        return {"vulnerabilities": []}

data = load_data()

class SimplifyRequest(BaseModel):
    text: str

class QueryRequest(BaseModel):
    user_input: str

@app.post("/simplify")
def simplify_vulnerability(request: SimplifyRequest):
    prompt = f"""Explain this vulnerability in very simple, non-technical language for business staff or managers.
Use short bullet points only.
Keep total response under 150 words.
Focus on: what the problem is, who is affected, real-world risk, and simple fix.

Vulnerability details:
{request.text}"""

    headers = {"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"}
    payload = {
        "model": "openai/gpt-4o-mini",
        "messages": [
            {"role": "system", "content": "You explain cyber vulnerabilities in short, clear bullet points for non-experts."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.3,
        "max_tokens": 200
    }

    try:
        response = requests.post("https://openrouter.ai/api/v1/chat/completions", headers=headers, json=payload, timeout=30)
        if response.status_code == 200:
            return {"simplified_text": response.json()["choices"][0]["message"]["content"].strip()}
        else:
            raise HTTPException(status_code=response.status_code, detail=response.text)
    except requests.exceptions.RequestException:
        raise HTTPException(status_code=500, detail="Connection issue")

@app.post("/query")
def answer_query(request: QueryRequest):
    context = json.dumps(data, indent=2)
    prompt = f"""
You are a cybersecurity risk analysis assistant.
Use this vulnerability data to answer clearly and in simple terms:

{context}

User question:
{request.user_input}
"""

    headers = {"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"}
    payload = {
        "model": "openai/gpt-4o-mini",
        "messages": [
            {"role": "system", "content": "You are a helpful cybersecurity expert."},
            {"role": "user", "content": prompt}
        ]
    }

    try:
        response = requests.post("https://openrouter.ai/api/v1/chat/completions", headers=headers, json=payload, timeout=30)
        if response.status_code == 200:
            return {"answer": response.json()["choices"][0]["message"]["content"]}
        else:
            raise HTTPException(status_code=response.status_code, detail=response.text)
    except requests.exceptions.RequestException:
        raise HTTPException(status_code=500, detail="Connection issue")