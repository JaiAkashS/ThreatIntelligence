# backend/main.py
import uvicorn
from fastapi import FastAPI, Query, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional
import json
import os
from dotenv import load_dotenv

from model import score_cve
from explain import generate_explanation

load_dotenv()  # Load environment variables from .env file

app = FastAPI(
    title="AI Threat Intelligence & CVE Prioritization API",
    description="Analyzes and prioritizes CVEs based on contextual risk scoring",
    version="1.0.0"
)

# ─── CORS (allow frontend to call this API) ──────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # tighten this in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Load CVE dataset once at startup ────────────────────────────────────────
DATA_PATH = os.path.join(os.path.dirname(__file__), "data", "cve_sample.json")

def load_cves() -> list[dict]:
    # Added a try/except block to handle missing file gracefully during dev
    try:
        with open(DATA_PATH, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Warning: Data file not found at {DATA_PATH}. Returning empty list.")
        return []

CVE_DB: list[dict] = load_cves()


# ─── Routes ──────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {"message": "CVE Prioritization API is running ✅"}


@app.get("/cves", summary="Get all CVEs with risk scores")
def get_all_cves(
    min_score: Optional[float] = Query(None, description="Filter by minimum risk score (0–100)"),
    severity: Optional[str]  = Query(None, description="Filter by severity: LOW, MEDIUM, HIGH, CRITICAL"),
    limit: int                = Query(50, ge=1, le=200, description="Max results to return"),
):
    """
    Returns all CVEs enriched with risk scores and priority labels.
    (AI explanation removed for performance; fetch on demand via /api/explain-cve)
    """
    results = []

    for cve in CVE_DB:
        scored = score_cve(cve)                          # attach risk_score + priority
        
        # Optional filters
        if min_score is not None and scored["risk_score"] < min_score:
            continue
        if severity and scored.get("severity", "").upper() != severity.upper():
            continue

        results.append(scored)

    # Sort by risk_score descending (highest priority first)
    results.sort(key=lambda x: x["risk_score"], reverse=True)

    return {
        "total": len(results),
        "cves": results[:limit]
    }


@app.get("/cves/{cve_id}", summary="Get a single CVE by ID")
def get_cve_by_id(cve_id: str):
    """
    Returns detailed risk analysis for a specific CVE ID (e.g. CVE-2024-1234).
    """
    for cve in CVE_DB:
        if cve.get("id", "").upper() == cve_id.upper():
            scored = score_cve(cve)
            return scored

    # FIXED: Use FastAPI's HTTPException instead of returning a tuple
    raise HTTPException(status_code=404, detail=f"CVE '{cve_id}' not found")


@app.get("/summary", summary="Dashboard summary statistics")
def get_summary():
    """
    Returns aggregated stats: total CVEs, breakdown by severity/priority,
    and top 5 critical threats — used to power the dashboard header.
    """
    all_scored = [score_cve(cve) for cve in CVE_DB]

    severity_counts: dict[str, int] = {}
    priority_counts: dict[str, int] = {}

    for cve in all_scored:
        sev = cve.get("severity", "UNKNOWN").upper()
        pri = cve.get("priority", "UNKNOWN").upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        priority_counts[pri] = priority_counts.get(pri, 0) + 1

    top5 = sorted(all_scored, key=lambda x: x["risk_score"], reverse=True)[:5]

    return {
        "total_cves": len(all_scored),
        "severity_breakdown": severity_counts,
        "priority_breakdown": priority_counts,
        "top_critical_threats": top5,
    }


@app.get("/search", summary="Search CVEs by keyword")
def search_cves(q: str = Query(..., description="Keyword to search in CVE description or ID")):
    """
    Full-text search across CVE IDs and descriptions.
    """
    q_lower = q.lower()
    matches = [
        cve for cve in CVE_DB
        if q_lower in cve.get("id", "").lower()
        or q_lower in cve.get("description", "").lower()
    ]

    results = []
    for cve in matches:
        scored = score_cve(cve)
        results.append(scored)

    results.sort(key=lambda x: x["risk_score"], reverse=True)

    return {"total": len(results), "cves": results}


# ─── New On-Demand AI Endpoint ───────────────────────────────────────────────

@app.post("/api/explain-cve", summary="Generate AI explanation on demand")
async def explain_single_cve(request: Request):
    """
    Receives a single CVE object from the frontend and returns the AI explanation.
    This prevents hitting rate limits by only calling Gemini when requested.
    """
    try:
        # 1. Get the single CVE data from the React frontend
        cve_data = await request.json()
        
        # 2. Pass it to your Gemini explainer
        ai_result = generate_explanation(cve_data)
        
        # 3. Return just that one explanation
        return ai_result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
if __name__ == "__main__":
    # Get the port from Render's environment, or default to 8000 for local dev
    port = int(os.environ.get("PORT", 8000))
    
    print(f"Starting server on port {port}...")
    
    # Run the server
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)