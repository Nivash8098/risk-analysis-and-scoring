import os
import json
import uuid
import socket
import logging
from typing import List, Optional, Dict, Any

import requests
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors

# ===================== LOGGING =====================
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cve-analyzer")

# ===================== PATHS =====================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
IMAGE_DIR = os.path.join(STATIC_DIR, "images")

os.makedirs(IMAGE_DIR, exist_ok=True)

# Create empty favicon if missing (prevents 404 forever)
favicon_path = os.path.join(STATIC_DIR, "favicon.ico")
if not os.path.exists(favicon_path):
    open(favicon_path, "wb").close()

# ===================== CONFIG =====================
OPENROUTER_API_KEY = os.getenv("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", "")
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
MODEL_NAME = "openai/gpt-4o-mini"
EPSS_URL = "https://api.first.org/data/v1/epss"

HOST = "127.0.0.1"
PORT = 8000

# ===================== MODELS =====================
class CVEInput(BaseModel):
    cve_id: str
    cvss_vector: Optional[str] = None
    severity: str
    cvss_score: float = Field(ge=0, le=10)
    summary: str
    description: str

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v):
        v = v.upper()
        if v not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"}:
            raise ValueError("Invalid severity")
        return v


class CVEAnalysisResponse(BaseModel):
    cve_id: str
    cvss_vector: Optional[str]
    severity: str
    cvss_score: float
    simple_summary: str
    simple_description: str
    affected_products: List[str]
    affected_assets: List[str]
    fixes: List[str]
    epss_score: float
    epss_30d_prediction: float
    cvss_heatmap_url: str
    epss_plot_url: str

# ===================== AI ANALYSIS =====================
def ai_analyze(cve: Dict[str, Any]) -> Dict[str, Any]:
    """
    Always returns populated lists.
    Uses AI if key exists, otherwise intelligent fallback.
    """

    # --------- FALLBACK (NO AI KEY) ---------
    fallback_products = []
    if "ssh" in cve["summary"].lower():
        fallback_products.append("OpenSSH")
    if "linux" in cve["description"].lower():
        fallback_products.append("Linux systems")

    if not fallback_products:
        fallback_products.append("Affected software components")

    fallback_assets = [
        "Servers",
        "Production systems",
        "Internet-facing hosts"
    ]

    fallback_fixes = [
        "Apply vendor security patches",
        "Upgrade to the latest stable version",
        "Restrict network access",
        "Monitor logs for exploitation attempts"
    ]

    if not OPENROUTER_API_KEY:
        return {
            "simple_summary": cve["summary"],
            "simple_description": cve["description"],
            "affected_products": fallback_products,
            "affected_assets": fallback_assets,
            "fixes": fallback_fixes
        }

    # --------- AI PROMPT ---------
    prompt = f"""
Analyze this CVE and respond ONLY with valid JSON.

JSON FORMAT:
{{
  "simple_summary": "...",
  "simple_description": "...",
  "affected_products": ["..."],
  "affected_assets": ["..."],
  "fixes": ["..."]
}}

Rules:
- Use simple English
- Never return empty arrays
- Extract products/assets from context
- Fixes must be realistic
- No explanation text

CVE DATA:
{json.dumps(cve)}
"""

    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": MODEL_NAME,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.2
    }

    try:
        r = requests.post(OPENROUTER_URL, headers=headers, json=payload, timeout=30)
        r.raise_for_status()
        content = r.json()["choices"][0]["message"]["content"]
        return json.loads(content)
    except Exception as e:
        logger.warning("AI failed, using fallback: %s", e)
        return {
            "simple_summary": cve["summary"],
            "simple_description": cve["description"],
            "affected_products": fallback_products,
            "affected_assets": fallback_assets,
            "fixes": fallback_fixes
        }

# ===================== EPSS =====================
def epss_live(cve_id: str) -> float:
    try:
        r = requests.get(EPSS_URL, params={"cve": cve_id}, timeout=10)
        r.raise_for_status()
        data = r.json().get("data", [])
        return float(data[0]["epss"]) if data else 0.0
    except Exception:
        return 0.0


def epss_predict(current: float) -> float:
    return round(current * 1.15, 5)

# ===================== VISUALS =====================
def cvss_image(score: float, cve_id: str) -> str:
    name = f"cvss_{uuid.uuid4().hex}.png"
    path = os.path.join(IMAGE_DIR, name)

    cmap = mcolors.LinearSegmentedColormap.from_list(
        "cvss", ["green", "yellow", "orange", "red"]
    )

    fig, ax = plt.subplots(figsize=(5, 1.5))
    ax.imshow([[score]], cmap=cmap, vmin=0, vmax=10)
    ax.set_title(f"CVSS – {cve_id}")
    ax.axis("off")
    ax.text(0, 0, score, ha="center", va="center", fontsize=14, fontweight="bold")

    plt.savefig(path)
    plt.close(fig)

    return f"/static/images/{name}"


def epss_image(current: float, predicted: float, cve_id: str) -> str:
    name = f"epss_{uuid.uuid4().hex}.png"
    path = os.path.join(IMAGE_DIR, name)

    plt.figure(figsize=(5, 3))
    plt.plot([0, 30], [current, predicted], marker="o")
    plt.title(f"EPSS – {cve_id}")
    plt.xlabel("Days")
    plt.ylabel("EPSS")
    plt.grid(True)

    plt.savefig(path)
    plt.close()

    return f"/static/images/{name}"

# ===================== FASTAPI =====================
app = FastAPI(title="CVE Analysis API", version="3.0")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# ---- ROOT (NO 404) ----
@app.get("/")
def home():
    return {
        "status": "running",
        "message": "CVE Analyzer API",
        "endpoint": "POST /analyze"
    }

# ---- FAVICON (NO 404) ----
@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return FileResponse(favicon_path)

# ---- ANALYSIS ----
@app.post("/analyze", response_model=CVEAnalysisResponse)
def analyze(cve: CVEInput):
    ai = ai_analyze(cve.model_dump())

    epss_now = epss_live(cve.cve_id)
    epss_30 = epss_predict(epss_now)

    return CVEAnalysisResponse(
        cve_id=cve.cve_id,
        cvss_vector=cve.cvss_vector,
        severity=cve.severity,
        cvss_score=cve.cvss_score,
        simple_summary=ai["simple_summary"],
        simple_description=ai["simple_description"],
        affected_products=ai["affected_products"],
        affected_assets=ai["affected_assets"],
        fixes=ai["fixes"],
        epss_score=epss_now,
        epss_30d_prediction=epss_30,
        cvss_heatmap_url=cvss_image(cve.cvss_score, cve.cve_id),
        epss_plot_url=epss_image(epss_now, epss_30, cve.cve_id)
    )

# ===================== RUN =====================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=HOST, port=PORT)