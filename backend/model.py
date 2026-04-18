# backend/model.py

"""
Risk Scoring Engine for CVE Prioritization
==========================================
Scoring is based on a weighted multi-factor model:

  Factor                  Weight
  ─────────────────────────────────
  CVSS Base Score           35%
  Exploit Availability      25%
  Asset Criticality         20%
  Threat Intelligence       10%
  Patch Availability        10%

Final risk_score is normalized to 0–100.
Priority labels: CRITICAL (≥80), HIGH (60–79), MEDIUM (40–59), LOW (<40)
"""

from datetime import datetime, timezone
from typing import Optional

# ─── Constants ────────────────────────────────────────────────────────────────

SEVERITY_CVSS_MAP = {
    "CRITICAL": 9.5,
    "HIGH":     7.5,
    "MEDIUM":   5.0,
    "LOW":      2.5,
    "NONE":     0.0,
}

EXPLOIT_MATURITY_SCORES = {
    "weaponized":   1.0,   # Active exploit in the wild, weaponized kit exists
    "poc":          0.75,  # Public proof-of-concept available
    "theoretical":  0.4,   # Theoretically exploitable, no public PoC
    "unproven":     0.15,  # No known exploit path
    "none":         0.0,   # Confirmed unexploitable
}

ASSET_CRITICALITY_SCORES = {
    "mission_critical": 1.0,   # Production, financial, auth systems
    "high":             0.75,  # Internal services with sensitive data
    "medium":           0.5,   # Dev/staging environments
    "low":              0.25,  # Test/sandbox systems
    "unknown":          0.5,   # Default to medium if not specified
}

THREAT_INTEL_SCORES = {
    "apt_linked":       1.0,   # Linked to Advanced Persistent Threat group
    "ransomware":       0.9,   # Used in ransomware campaigns
    "active_campaign":  0.8,   # Part of an active threat campaign
    "trending":         0.6,   # Trending in threat intelligence feeds
    "mentioned":        0.3,   # Mentioned in threat reports, no active use
    "none":             0.0,   # No threat intelligence signal
}

PATCH_STATUS_SCORES = {
    "no_patch":        1.0,    # No patch available — maximum urgency
    "vendor_advisory": 0.7,    # Vendor aware, workaround only
    "patch_available": 0.3,    # Patch released but may not be deployed
    "patched":         0.0,    # Patch confirmed deployed
}

# Scoring weights (must sum to 1.0)
WEIGHTS = {
    "cvss":             0.35,
    "exploit":          0.25,
    "asset":            0.20,
    "threat_intel":     0.10,
    "patch":            0.10,
}

# Age decay: CVEs older than this many days get a slight score reduction
MAX_AGE_DAYS_FOR_DECAY = 365


# ─── Helper Utilities ─────────────────────────────────────────────────────────

def normalize_cvss(cvss_score: float) -> float:
    """Normalize a CVSS score (0–10) to a 0–1 scale."""
    return max(0.0, min(cvss_score, 10.0)) / 10.0


def calculate_severity_from_cvss(cvss: float) -> str:
    """Derive severity label from a CVSS score."""
    if cvss >= 9.0: return "CRITICAL"
    elif cvss >= 7.0: return "HIGH"
    elif cvss >= 4.0: return "MEDIUM"
    else: return "LOW"


def resolve_cvss(cve: dict) -> float:
    """
    Extract CVSS score from CVE dict.
    Checks for both 'cvss' and 'cvss_score' to support different JSON formats.
    """
    raw = cve.get("cvss") if "cvss" in cve else cve.get("cvss_score")
    if raw is not None:
        try:
            return float(raw)
        except (ValueError, TypeError):
            pass

    # Fallback: derive from severity label
    severity = cve.get("severity", "MEDIUM").upper()
    return SEVERITY_CVSS_MAP.get(severity, 5.0)


def resolve_factor(cve: dict, field: str, score_map: dict, default_key: str) -> float:
    """
    Generic resolver for exploit/asset/threat/patch factors.
    Reads the field from the CVE dict, maps it to a score.
    Falls back to default_key if field is missing or unrecognized.
    """
    raw_value = cve.get(field, default_key).lower().replace(" ", "_")
    return score_map.get(raw_value, score_map.get(default_key, 0.5))


def compute_age_penalty(cve: dict) -> float:
    """
    Returns a small multiplicative penalty (0.85–1.0) for very old CVEs.
    Only applies if published_date or publish_date is available.
    """
    published = cve.get("published_date") or cve.get("publish_date")
    if not published:
        return 1.0  # No penalty if date unknown

    try:
        pub_dt = datetime.fromisoformat(published).replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - pub_dt).days
        if age_days <= 0:
            return 1.0
        # Penalty scales from 1.0 (new) down to 0.85 (very old)
        penalty = max(0.85, 1.0 - (age_days / MAX_AGE_DAYS_FOR_DECAY) * 0.15)
        return penalty
    except (ValueError, TypeError):
        return 1.0


def classify_priority(score: float) -> str:
    """Map a 0–100 risk score to a human-readable priority label."""
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    else:
        return "LOW"


def priority_to_color(priority: str) -> str:
    """Return a hex color for UI badge rendering."""
    return {
        "CRITICAL": "#FF2D55",
        "HIGH":     "#FF9500",
        "MEDIUM":   "#FFCC00",
        "LOW":      "#34C759",
    }.get(priority, "#8E8E93")


def estimate_remediation_urgency(score: float) -> str:
    """Plain-English remediation timeline based on risk score."""
    if score >= 80:
        return "Immediate — patch or mitigate within 24 hours"
    elif score >= 60:
        return "Urgent — address within 7 days"
    elif score >= 40:
        return "Moderate — schedule remediation within 30 days"
    else:
        return "Low — include in next regular patch cycle"


# ─── Core Scoring Function ────────────────────────────────────────────────────

def score_cve(cve: dict) -> dict:
    """
    Main entry point. Accepts a raw CVE dict and returns an enriched copy
    with risk_score (0–100), priority label, factor breakdown, and metadata.
    """
    
    cve_clean = cve.copy()
    
    # Normalize description field
    if "description" not in cve_clean and "desc" in cve_clean:
        cve_clean["description"] = cve_clean["desc"]
        
    # Normalize exploit field (boolean -> string maturity label)
    if "exploit_maturity" not in cve_clean and "exploit" in cve_clean:
        cve_clean["exploit_maturity"] = "poc" if cve_clean["exploit"] else "unproven"

    # Ensure severity exists (Calculated dynamically if UNKNOWN or missing)
    cvss_raw = resolve_cvss(cve_clean)
    if cve_clean.get("severity", "UNKNOWN").upper() == "UNKNOWN":
        cve_clean["severity"] = calculate_severity_from_cvss(cvss_raw)

    # ── Step 1: Resolve raw factor scores (all 0.0–1.0) ──────────────────────
    cvss_norm   = normalize_cvss(cvss_raw)

    exploit_score = resolve_factor(
        cve_clean, "exploit_maturity", EXPLOIT_MATURITY_SCORES, "unproven"
    )
    asset_score = resolve_factor(
        cve_clean, "asset_criticality", ASSET_CRITICALITY_SCORES, "unknown"
    )
    threat_score = resolve_factor(
        cve_clean, "threat_intel", THREAT_INTEL_SCORES, "none"
    )
    patch_score = resolve_factor(
        cve_clean, "patch_status", PATCH_STATUS_SCORES, "patch_available"
    )

    # ── Step 2: Weighted sum ──────────────────────────────────────────────────
    weighted_score = (
        cvss_norm     * WEIGHTS["cvss"]       +
        exploit_score * WEIGHTS["exploit"]    +
        asset_score   * WEIGHTS["asset"]      +
        threat_score  * WEIGHTS["threat_intel"] +
        patch_score   * WEIGHTS["patch"]
    )

    # ── Step 3: Apply age decay ───────────────────────────────────────────────
    age_penalty   = compute_age_penalty(cve_clean)
    adjusted_score = weighted_score * age_penalty

    # ── Step 4: Scale to 0–100 and apply Severity Floors ─────────────────────
    final_score = round(min(adjusted_score * 100, 100.0), 2)

    # UPDATED: SEVERITY FLOORS logic
    if cvss_raw >= 9.0:
        # If it's a 9.0+ AND has an exploit, it must be CRITICAL regardless of missing data
        if exploit_score >= 0.75 and final_score < 85.0:
            final_score = 85.0  
        elif final_score < 75.0:
            final_score = 75.0  # Force CVSS 9.0+ without exploit to stay at least HIGH
    elif cvss_raw >= 7.0 and final_score < 45.0:
        final_score = 45.0  # Force CVSS 7.0+ to stay at least MEDIUM

    # ── Step 5: Derive labels and metadata ───────────────────────────────────
    priority           = classify_priority(final_score)
    color              = priority_to_color(priority)
    remediation_urgency = estimate_remediation_urgency(final_score)

    # ── Step 6: Build factor breakdown for transparency ───────────────────────
    factor_breakdown = {
        "cvss": {
            "raw_value":    cvss_raw,
            "normalized":   round(cvss_norm, 4),
            "weight":       WEIGHTS["cvss"],
            "contribution": round(cvss_norm * WEIGHTS["cvss"] * 100, 2),
        },
        "exploit_maturity": {
            "raw_value":    cve_clean.get("exploit_maturity", "unproven"),
            "normalized":   exploit_score,
            "weight":       WEIGHTS["exploit"],
            "contribution": round(exploit_score * WEIGHTS["exploit"] * 100, 2),
        },
        "asset_criticality": {
            "raw_value":    cve_clean.get("asset_criticality", "unknown"),
            "normalized":   asset_score,
            "weight":       WEIGHTS["asset"],
            "contribution": round(asset_score * WEIGHTS["asset"] * 100, 2),
        },
        "threat_intel": {
            "raw_value":    cve_clean.get("threat_intel", "none"),
            "normalized":   threat_score,
            "weight":       WEIGHTS["threat_intel"],
            "contribution": round(threat_score * WEIGHTS["threat_intel"] * 100, 2),
        },
        "patch_status": {
            "raw_value":    cve_clean.get("patch_status", "patch_available"),
            "normalized":   patch_score,
            "weight":       WEIGHTS["patch"],
            "contribution": round(patch_score * WEIGHTS["patch"] * 100, 2),
        },
    }

    # ── Step 7: Return enriched CVE dict ─────────────────────────────────────
    return {
        **cve_clean,
        "risk_score":           final_score,
        "priority":             priority,
        "priority_color":       color,
        "remediation_urgency":  remediation_urgency,
        "age_penalty_applied":  round(age_penalty, 4),
        "severity":             cve_clean.get("severity", "UNKNOWN").upper(),
        "factor_breakdown":     factor_breakdown,
        "dominant_factor":      max(
            factor_breakdown,
            key=lambda k: factor_breakdown[k]["contribution"]
        ),
    }


# ─── Batch Scoring ────────────────────────────────────────────────────────────

def score_all(cves: list[dict]) -> list[dict]:
    """
    Score a list of CVEs and return them sorted by risk_score descending.
    Useful for bulk operations or precomputing scores at startup.
    """
    scored = [score_cve(cve) for cve in cves]
    return sorted(scored, key=lambda x: x["risk_score"], reverse=True)


def get_statistics(cves: list[dict]) -> dict:
    """
    Compute aggregate statistics across a scored CVE list.
    Returns mean, max, min scores + distribution by priority.
    """
    if not cves:
        return {}

    scores = [c["risk_score"] for c in cves]
    priority_dist: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for c in cves:
        priority_dist[c.get("priority", "LOW")] += 1

    return {
        "count":             len(scores),
        "mean_score":        round(sum(scores) / len(scores), 2),
        "max_score":         max(scores),
        "min_score":         min(scores),
        "priority_distribution": priority_dist,
    }