import json
import requests
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors
import re
from typing import Dict, Any, List

# ===================== CONFIG =====================
OPENROUTER_API_KEY = "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"
MODEL_NAME = "openai/gpt-4o-mini"

OPENROUTER_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"
FIRST_EPSS_ENDPOINT = "https://api.first.org/data/v1/epss"

# ===================== EPSS PREDICTION =====================
def predict_epss_30d(current: float) -> float:
    if current < 0.005:
        growth = 1.30
    elif current < 0.02:
        growth = 1.15
    elif current < 0.10:
        growth = 1.05
    else:
        growth = 0.97
    return round(min(1.0, current * growth), 5)

# ===================== FIRST.ORG EPSS =====================
def fetch_epss(cve_id: str) -> float:
    response = requests.get(
        FIRST_EPSS_ENDPOINT,
        params={"cve": cve_id},
        timeout=15
    )
    response.raise_for_status()
    data = response.json()

    if not data.get("data"):
        raise RuntimeError("EPSS data not found for this CVE")

    return float(data["data"][0]["epss"])

# ===================== AI CVE SUMMARIZER =====================
class CVESummarizer:
    def __init__(self, api_key: str, model: str):
        self.api_key = api_key
        self.model = model

    def summarize(self, cve: Dict[str, Any]) -> Dict[str, Any]:
        prompt = self._build_prompt(cve)
        response = self._call_api(prompt)
        return self._parse_response(response)

    def _build_prompt(self, cve: Dict[str, Any]) -> str:
        return (
            "Analyze the CVE information below and respond ONLY in valid JSON.\n\n"
            "JSON FORMAT:\n"
            "{"
            "\"simple_summary\":\"...\","
            "\"simple_description\":\"...\","
            "\"affected_products\":[\"product name and version\"],"
            "\"fixes\":[\"...\",\"...\"]"
            "}\n\n"
            "Rules:\n"
            "- Use very simple English\n"
            "- Extract affected PRODUCTS only (not assets)\n"
            "- Include versions if mentioned\n"
            "- Infer best product if unclear\n"
            "- Fixes must be practical actions\n"
            "- No text outside JSON\n\n"
            f"Summary: {cve.get('summary')}\n"
            f"Description: {cve.get('description')}\n"
        )

    def _call_api(self, prompt: str) -> Dict[str, Any]:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "http://localhost",
            "X-Title": "CVE Threat Analyzer"
        }

        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.2
        }

        response = requests.post(
            OPENROUTER_ENDPOINT,
            headers=headers,
            json=payload,
            timeout=30
        )
        response.raise_for_status()
        return response.json()

    def _parse_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        content = response["choices"][0]["message"]["content"]
        match = re.search(r"\{.*\}", content, re.DOTALL)
        if not match:
            raise RuntimeError("AI response is not valid JSON")
        return json.loads(match.group())

# ===================== VISUALIZATION =====================
def show_cvss_heatmap(score: float, cve_id: str):
    cmap = mcolors.LinearSegmentedColormap.from_list(
        "cvss", [(0, "green"), (0.4, "yellow"), (0.7, "orange"), (1, "red")]
    )
    norm = mcolors.Normalize(vmin=0, vmax=10)

    fig, ax = plt.subplots(figsize=(5, 1.5))
    im = ax.imshow([[score]], cmap=cmap, norm=norm, aspect="auto")
    ax.set_title(f"CVSS Heatmap — {cve_id}")
    ax.set_xticks([])
    ax.set_yticks([])
    ax.text(0, 0, str(score), ha="center", va="center",
            fontsize=14, fontweight="bold")

    fig.colorbar(im, ax=ax, orientation="horizontal")
    plt.tight_layout()

def plot_epss(current: float, predicted: float, cve_id: str):
    plt.figure(figsize=(6, 4))
    plt.plot([0, 30], [current, predicted], marker="o", linestyle="--")
    plt.title(f"EPSS Prediction — {cve_id}")
    plt.xlabel("Days")
    plt.ylabel("EPSS Score")
    plt.grid(alpha=0.4)
    plt.tight_layout()

# ===================== MAIN =====================
if __name__ == "__main__":

    # ===== USER INPUT (Assets here) =====
    sample_input = {
        "cve_id": "CVE-2026-21428",
        "cvss_score": 7.7,
        "severity": "HIGH",
        "summary": "Improper header handling allows header injection and SSRF in cpp-httplib.",
        "description": "CRLF characters are not validated correctly in versions prior to 0.30.0.",
        "affected_assets": [
            "web-api-server-01",
            "payment-service-container",
            "internal-gateway"
        ]
    }

    # ===== AI PROCESSING =====
    summarizer = CVESummarizer(OPENROUTER_API_KEY, MODEL_NAME)
    ai_result = summarizer.summarize(sample_input)

    # ===== EPSS INTELLIGENCE =====
    epss_current = fetch_epss(sample_input["cve_id"])
    epss_30d = predict_epss_30d(epss_current)

    # ===== VISUALS =====
    show_cvss_heatmap(sample_input["cvss_score"], sample_input["cve_id"])
    plot_epss(epss_current, epss_30d, sample_input["cve_id"])

    # ===== FINAL OUTPUT =====
    final_output = {
        "cve_id": sample_input["cve_id"],
        "severity": sample_input["severity"],
        "cvss_score": sample_input["cvss_score"],

        "simple_summary": ai_result["simple_summary"],
        "simple_description": ai_result["simple_description"],
        "affected_products": ai_result["affected_products"],
        "fixes": ai_result["fixes"],

        "affected_assets": sample_input["affected_assets"],

        "epss_score": epss_current,
        "epss_30d_prediction": epss_30d
    }

    print(json.dumps(final_output, indent=2))
    plt.show()