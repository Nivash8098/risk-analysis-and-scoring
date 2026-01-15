import json
import io
import base64
import re
import requests
from typing import Dict, List

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors

from fastapi import FastAPI, Form, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

# ===================== CONFIG =====================

OPENROUTER_API_KEY = "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"
OPENROUTER_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"
AI_MODEL = "openai/gpt-4o-mini"
FIRST_EPSS_ENDPOINT = "https://api.first.org/data/v1/epss"

app = FastAPI(title="CVE Analyzer Pro")

# ===================== MODELS =====================

class CVEInput(BaseModel):
    cve_id: str = Field(..., pattern=r"^CVE-\d{4}-\d{4,10}$")
    cvss_vector: str
    severity: str
    cvss_score: float = Field(..., ge=0, le=10)
    affected_assets: List[str] = []

DATA_STORE: Dict[str, Dict] = {}

# ===================== PREVENT FAVICON 404 =====================

@app.get("/favicon.ico")
async def favicon():
    return ""

# ===================== EPSS =====================

def fetch_epss(cve_id: str) -> float:
    try:
        r = requests.get(FIRST_EPSS_ENDPOINT, params={"cve": cve_id}, timeout=15)
        r.raise_for_status()
        data = r.json()
        if not data.get("data"):
            return 0.0
        return float(data["data"][0]["epss"])
    except Exception:
        return 0.0

def predict_epss_30d(cur: float) -> float:
    """
    Future-based EPSS prediction.
    Always >= current EPSS.
    """
    if cur < 0.01:
        growth = 1.50
    elif cur < 0.05:
        growth = 1.30
    elif cur < 0.20:
        growth = 1.15
    elif cur < 0.50:
        growth = 1.08
    else:
        growth = 1.03  # high EPSS still grows slowly

    return round(min(1.0, cur * growth), 5)

# ===================== AI ANALYSIS =====================

def ai_generate_analysis(cve: CVEInput) -> Dict:
    prompt = (
        "Analyze the CVE below and respond ONLY in valid JSON.\n\n"
        "{"
        "\"simple_summary\":\"...\","
        "\"simple_description\":\"...\","
        "\"affected_products\":[\"...\"],"
        "\"fixes\":[\"...\"]"
        "}\n\n"
        f"{json.dumps(cve.model_dump())}"
    )

    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "http://localhost",
        "X-Title": "CVE Analyzer"
    }

    payload = {
        "model": AI_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.2
    }

    try:
        r = requests.post(OPENROUTER_ENDPOINT, headers=headers, json=payload, timeout=30)
        r.raise_for_status()
        content = r.json()["choices"][0]["message"]["content"]
        match = re.search(r"\{.*\}", content, re.DOTALL)
        return json.loads(match.group()) if match else {}
    except Exception:
        return {
            "simple_summary": "AI analysis unavailable",
            "simple_description": "Failed to generate AI analysis",
            "affected_products": [],
            "fixes": []
        }

# ===================== VISUALS =====================

def get_cvss_heatmap(score: float, cve_id: str) -> str:
    cmap = mcolors.LinearSegmentedColormap.from_list(
        "cvss", ["green", "yellow", "orange", "red"]
    )

    fig, ax = plt.subplots(figsize=(5, 1.3))
    ax.imshow([[score]], cmap=cmap, vmin=0, vmax=10)
    ax.set_title(f"CVSS Score — {cve_id}")
    ax.axis("off")

    buf = io.BytesIO()
    plt.savefig(buf, format="png", bbox_inches="tight")
    plt.close(fig)
    return base64.b64encode(buf.getvalue()).decode()

def get_epss_plot(cur: float, pred: float, cve_id: str) -> str:
    fig, ax = plt.subplots(figsize=(5, 2.5))
    ax.plot([0, 30], [cur, pred], marker="o", linestyle="--")
    ax.set_title(f"EPSS 30-Day Future Trend — {cve_id}")
    ax.set_xlabel("Days")
    ax.set_ylabel("EPSS Probability")
    ax.grid(alpha=0.4)

    buf = io.BytesIO()
    plt.savefig(buf, format="png", bbox_inches="tight")
    plt.close(fig)
    return base64.b64encode(buf.getvalue()).decode()

# ===================== ROUTES =====================

@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <h2 style="text-align:center;">🛡️ CVE Analyzer</h2>
    <div style="text-align:center;">
      <a href="/json">Open Analyzer</a>
    </div>
    """

@app.get("/json", response_class=HTMLResponse)
def json_form():
    example = json.dumps({
        "cve_id": "CVE-2023-4863",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "affected_assets": ["libwebp < 1.3.2"]
    }, indent=2)

    return f"""
    <form method="post">
      <textarea name="json_input" rows="12" style="width:100%;">{example}</textarea>
      <button type="submit">Analyze</button>
    </form>
    """

@app.post("/json", response_class=HTMLResponse)
async def analyze(json_input: str = Form(...)):
    try:
        data = CVEInput(**json.loads(json_input))
    except Exception as e:
        return f"<pre>Invalid JSON: {e}</pre>"

    ai_result = ai_generate_analysis(data)
    epss_now = fetch_epss(data.cve_id)
    epss_30 = predict_epss_30d(epss_now)

    DATA_STORE[data.cve_id] = {
        "cvss_score": data.cvss_score,
        "epss_now": epss_now,
        "epss_30": epss_30
    }

    final = {
        **data.model_dump(),
        **ai_result,
        "epss_score": epss_now,
        "epss_30d_prediction": epss_30
    }

    return f"""
    <pre>{json.dumps(final, indent=2)}</pre>
    <a href="/visuals/{data.cve_id}">View Visuals</a>
    """

@app.get("/visuals/{cve_id}", response_class=HTMLResponse)
def visuals(cve_id: str):
    data = DATA_STORE.get(cve_id)
    if not data:
        raise HTTPException(404, "CVE not found")

    return f"""
    <h3>{cve_id}</h3>
    <img src="data:image/png;base64,{get_cvss_heatmap(data['cvss_score'], cve_id)}"/><br>
    <img src="data:image/png;base64,{get_epss_plot(data['epss_now'], data['epss_30'], cve_id)}"/><br>
    <a href="/json">Back</a>
    """

# ===================== RUN =====================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)