# backend/main.py

from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional
import json
import os

from model import score_cve
from explain import generate_explanation

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
    Returns all CVEs enriched with risk scores, priority labels, and explanations.
    Supports optional filtering by severity and minimum risk score.
    """
    results = []

    for cve in CVE_DB:
        scored = score_cve(cve)                          # attach risk_score + priority
        scored["explanation"] = generate_explanation(scored)

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
            scored["explanation"] = generate_explanation(scored)
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
    top5_with_explanation = [
        {**cve, "explanation": generate_explanation(cve)} for cve in top5
    ]

    return {
        "total_cves": len(all_scored),
        "severity_breakdown": severity_counts,
        "priority_breakdown": priority_counts,
        "top_critical_threats": top5_with_explanation,
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
        scored["explanation"] = generate_explanation(scored)
        results.append(scored)

    results.sort(key=lambda x: x["risk_score"], reverse=True)

    return {"total": len(results), "cves": results}