# backend/explain.py

"""
Explanation Generator for CVE Risk Scores
==========================================
Generates human-readable, analyst-style explanations for why a CVE
received its risk score. Works entirely from the enriched CVE dict
produced by model.py — no external API calls required.

Each explanation has 4 layers:
  1. Executive summary    — one-sentence verdict
  2. Factor analysis      — per-factor plain-English reasoning
  3. Threat context       — what this means in the real world
  4. Recommended action   — concrete next steps for the security team
"""

from typing import Optional


# ─── Phrase Libraries ─────────────────────────────────────────────────────────
# Each factor has tiered phrase banks keyed by normalized score ranges.
# This avoids repetitive templated text and gives analyst-quality variety.

CVSS_PHRASES = {
    "critical": [
        "a near-maximum CVSS score of {score}, placing it among the most severe vulnerabilities catalogued",
        "a critical CVSS score of {score} — this vulnerability represents a significant attack surface",
        "an exceptionally high CVSS base score of {score}, indicative of broad exploitability and impact",
    ],
    "high": [
        "a high CVSS score of {score}, reflecting serious potential for damage if exploited",
        "a CVSS score of {score} in the high range, signalling substantial risk to affected systems",
        "a notable CVSS severity of {score}, well above the threshold for urgent attention",
    ],
    "medium": [
        "a moderate CVSS score of {score}, suggesting meaningful but bounded risk",
        "a mid-range CVSS score of {score} — exploitable under certain conditions",
        "a CVSS score of {score}, which warrants attention but is not immediately catastrophic",
    ],
    "low": [
        "a low CVSS score of {score}, indicating limited direct exploitability",
        "a CVSS base score of {score}, suggesting constrained impact under normal conditions",
        "a minor CVSS score of {score} — typically requiring specific conditions to exploit",
    ],
}

EXPLOIT_PHRASES = {
    "weaponized": (
        "Active weaponized exploits are publicly available for this CVE. "
        "Threat actors can leverage ready-made tools with minimal effort, "
        "dramatically increasing the likelihood of opportunistic attacks."
    ),
    "poc": (
        "A public proof-of-concept (PoC) exploit exists. While not yet weaponized, "
        "skilled attackers can adapt the PoC quickly. The window between PoC release "
        "and active exploitation is historically very short — often under 48 hours."
    ),
    "theoretical": (
        "No public exploit code exists, but the vulnerability is theoretically exploitable "
        "by a determined attacker with sufficient expertise. The absence of a PoC provides "
        "a limited time advantage for remediation."
    ),
    "unproven": (
        "No known exploit path has been demonstrated publicly. Exploitation would require "
        "significant research investment, reducing near-term risk from opportunistic actors."
    ),
    "none": (
        "No viable exploitation path is currently known. This vulnerability may still "
        "warrant monitoring as research into the attack surface evolves."
    ),
}

ASSET_PHRASES = {
    "mission_critical": (
        "The affected system is classified as mission-critical — likely a production "
        "environment, financial system, or authentication service. A successful exploit "
        "here could cause immediate operational disruption or data breach."
    ),
    "high": (
        "The affected asset handles sensitive data or provides important internal services. "
        "Compromise would have significant downstream consequences across the organisation."
    ),
    "medium": (
        "The affected system sits in a development or staging environment. While not "
        "directly customer-facing, lateral movement from here into production is a real risk."
    ),
    "low": (
        "The affected asset is a low-criticality test or sandbox system. Direct business "
        "impact is limited, but good hygiene still recommends remediation."
    ),
    "unknown": (
        "Asset criticality has not been classified. This introduces uncertainty into the "
        "risk assessment — classifying this asset should be a priority action."
    ),
}

THREAT_INTEL_PHRASES = {
    "apt_linked": (
        "Threat intelligence links this CVE to one or more Advanced Persistent Threat (APT) "
        "groups. Nation-state or sophisticated criminal actors are actively incorporating "
        "this vulnerability into their toolchains."
    ),
    "ransomware": (
        "This CVE has been observed in ransomware campaigns. Ransomware operators "
        "specifically target vulnerabilities with fast exploitation paths — "
        "immediate containment is strongly advised."
    ),
    "active_campaign": (
        "Threat intelligence confirms this CVE is being actively exploited in ongoing "
        "campaigns. Real-world victims have been recorded. This moves the risk from "
        "theoretical to imminent."
    ),
    "trending": (
        "This CVE is trending across threat intelligence feeds and security communities. "
        "Increased attention from the research community often precedes a spike in "
        "exploitation attempts."
    ),
    "mentioned": (
        "This CVE has appeared in threat reports but without confirmed active exploitation. "
        "It is on the radar of the security community and should be monitored closely."
    ),
    "none": (
        "No specific threat intelligence signals are associated with this CVE at this time. "
        "This does not eliminate risk — it simply means no active campaigns have been "
        "publicly attributed to it yet."
    ),
}

PATCH_PHRASES = {
    "no_patch": (
        "No patch or official fix is currently available. Organisations must rely on "
        "compensating controls — network segmentation, WAF rules, or disabling the "
        "affected feature — until a vendor fix is released."
    ),
    "vendor_advisory": (
        "The vendor has acknowledged the vulnerability and published an advisory, but "
        "a complete patch is not yet available. Recommended workarounds should be "
        "applied immediately as an interim measure."
    ),
    "patch_available": (
        "A patch has been released by the vendor. The primary risk now lies in delayed "
        "deployment. Every day without patching extends exposure to exploitation."
    ),
    "patched": (
        "A patch has been applied to affected systems. Continued monitoring is advised "
        "to confirm the fix is effective and no residual exposure remains."
    ),
}

REMEDIATION_ACTIONS = {
    "CRITICAL": [
        "Activate your incident response plan immediately.",
        "Isolate or take offline affected mission-critical systems if patching cannot be completed within hours.",
        "Apply the vendor patch or compensating controls within 24 hours.",
        "Conduct threat hunting across your environment for indicators of compromise (IoCs).",
        "Notify stakeholders and escalate to your CISO.",
    ],
    "HIGH": [
        "Schedule emergency patching within the next 7 days.",
        "Apply network-level mitigations (firewall rules, WAF policies) as an interim measure.",
        "Audit access logs on affected systems for suspicious activity.",
        "Verify patch applicability across all affected asset instances.",
        "Track remediation progress with daily status updates.",
    ],
    "MEDIUM": [
        "Include in the next scheduled patch cycle (within 30 days).",
        "Review whether compensating controls already reduce the effective risk.",
        "Assess whether affected assets require reclassification to higher criticality.",
        "Monitor threat intel feeds for any escalation in exploit activity.",
    ],
    "LOW": [
        "Log and track for remediation in the next regular patch window.",
        "Confirm CVSS environmental score adjustments for your specific context.",
        "No immediate action required — maintain standard monitoring.",
    ],
}


# ─── Helper Functions ─────────────────────────────────────────────────────────

def _pick_phrase(phrase_list: list[str], index: int = 0) -> str:
    """Pick a phrase from a list using a stable index (based on CVE hash)."""
    return phrase_list[index % len(phrase_list)]


def _cvss_phrase(cvss_score: float, phrase_index: int = 0) -> str:
    """Select and format the appropriate CVSS phrase tier."""
    if cvss_score >= 9.0:
        tier = "critical"
    elif cvss_score >= 7.0:
        tier = "high"
    elif cvss_score >= 4.0:
        tier = "medium"
    else:
        tier = "low"

    template = _pick_phrase(CVSS_PHRASES[tier], phrase_index)
    return template.format(score=cvss_score)


def _resolve_exploit_key(raw: str) -> str:
    return raw.lower().replace(" ", "_") if raw else "unproven"


def _resolve_asset_key(raw: str) -> str:
    return raw.lower().replace(" ", "_") if raw else "unknown"


def _resolve_threat_key(raw: str) -> str:
    return raw.lower().replace(" ", "_") if raw else "none"


def _resolve_patch_key(raw: str) -> str:
    return raw.lower().replace(" ", "_") if raw else "patch_available"


def _stable_index(cve_id: str) -> int:
    """Derive a stable phrase index from a CVE ID string (for variety)."""
    return sum(ord(c) for c in cve_id) % 3


def _format_score_bar(score: float, width: int = 20) -> str:
    """Generate a simple ASCII progress bar for the risk score."""
    filled = int((score / 100) * width)
    bar = "█" * filled + "░" * (width - filled)
    return f"[{bar}] {score}/100"


def _dominant_factor_sentence(dominant: str, breakdown: dict) -> str:
    """Generate a sentence highlighting which factor drove the score highest."""
    contrib = breakdown.get(dominant, {}).get("contribution", 0)
    factor_labels = {
        "cvss":             "CVSS base severity",
        "exploit_maturity": "exploit availability",
        "asset_criticality":"asset criticality",
        "threat_intel":     "active threat intelligence",
        "patch_status":     "patch unavailability",
    }
    label = factor_labels.get(dominant, dominant.replace("_", " "))
    return (
        f"The dominant driver of this score is **{label}**, "
        f"contributing {contrib:.1f} points out of 100 to the final risk score."
    )


# ─── Main Explanation Generator ───────────────────────────────────────────────

def generate_explanation(scored_cve: dict) -> dict:
    """
    Generate a structured, multi-layer explanation for a scored CVE.

    Input:
        scored_cve — enriched CVE dict from model.score_cve()

    Returns a dict with:
        summary          : str  — one-paragraph executive summary
        factor_analysis  : dict — per-factor plain-English reasoning
        threat_context   : str  — real-world threat narrative
        recommended_actions: list[str] — concrete remediation steps
        score_bar        : str  — ASCII visual of risk score
        dominant_factor_note: str — which factor drove the score
    """

    cve_id      = scored_cve.get("id", "UNKNOWN")
    risk_score  = scored_cve.get("risk_score", 0.0)
    priority    = scored_cve.get("priority", "LOW")
    severity    = scored_cve.get("severity", "UNKNOWN")
    breakdown   = scored_cve.get("factor_breakdown", {})
    dominant    = scored_cve.get("dominant_factor", "cvss")
    description = scored_cve.get("description", "No description provided.")
    affected    = scored_cve.get("affected_systems", [])
    age_penalty = scored_cve.get("age_penalty_applied", 1.0)

    idx = _stable_index(cve_id)

    # Raw factor values
    cvss_raw    = breakdown.get("cvss", {}).get("raw_value", 5.0)
    exploit_raw = breakdown.get("exploit_maturity", {}).get("raw_value", "unproven")
    asset_raw   = breakdown.get("asset_criticality", {}).get("raw_value", "unknown")
    threat_raw  = breakdown.get("threat_intel", {}).get("raw_value", "none")
    patch_raw   = breakdown.get("patch_status", {}).get("raw_value", "patch_available")

    # ── Layer 1: Executive Summary ────────────────────────────────────────────
    affected_str = (
        ", ".join(affected[:3]) + (" and others" if len(affected) > 3 else "")
        if affected else "unspecified systems"
    )

    age_note = (
        f" Note: an age adjustment factor of {age_penalty:.2f} was applied "
        f"as this CVE has been public for some time."
        if age_penalty < 0.99 else ""
    )

    summary = (
        f"{cve_id} has been assigned a **{priority} priority** risk score of "
        f"**{risk_score}/100** based on a multi-factor contextual analysis. "
        f"This vulnerability carries {_cvss_phrase(float(cvss_raw), idx)}, "
        f"affecting {affected_str}. "
        f"Given the current exploit landscape and asset exposure, "
        f"this CVE demands {'immediate attention' if priority in ('CRITICAL', 'HIGH') else 'scheduled remediation'}.{age_note}"
    )

    # ── Layer 2: Per-Factor Analysis ──────────────────────────────────────────
    factor_analysis = {
        "cvss_severity": {
            "label":       "CVSS Base Severity",
            "value":       f"{cvss_raw}/10 ({severity})",
            "weight":      f"{int(WEIGHTS_DISPLAY['cvss'] * 100)}% of total score",
            "contribution": f"{breakdown.get('cvss', {}).get('contribution', 0):.1f} pts",
            "reasoning":   (
                f"The CVSS base score of {cvss_raw} reflects the intrinsic severity of this "
                f"vulnerability in isolation — before environmental or temporal context is applied. "
                f"{'At this level, the vulnerability likely offers full system compromise or data exfiltration potential.' if float(cvss_raw) >= 9.0 else ''}"
                f"{'At this score range, significant privilege escalation or data exposure is probable.' if 7.0 <= float(cvss_raw) < 9.0 else ''}"
                f"{'The vulnerability has exploitable impact but typically requires specific conditions or user interaction.' if 4.0 <= float(cvss_raw) < 7.0 else ''}"
                f"{'Limited exploitability constrains direct impact.' if float(cvss_raw) < 4.0 else ''}"
            ),
        },
        "exploit_maturity": {
            "label":        "Exploit Availability",
            "value":        exploit_raw.replace("_", " ").title(),
            "weight":       f"{int(WEIGHTS_DISPLAY['exploit'] * 100)}% of total score",
            "contribution": f"{breakdown.get('exploit_maturity', {}).get('contribution', 0):.1f} pts",
            "reasoning":    EXPLOIT_PHRASES.get(
                                _resolve_exploit_key(exploit_raw),
                                EXPLOIT_PHRASES["unproven"]
                            ),
        },
        "asset_criticality": {
            "label":        "Asset Criticality",
            "value":        asset_raw.replace("_", " ").title(),
            "weight":       f"{int(WEIGHTS_DISPLAY['asset'] * 100)}% of total score",
            "contribution": f"{breakdown.get('asset_criticality', {}).get('contribution', 0):.1f} pts",
            "reasoning":    ASSET_PHRASES.get(
                                _resolve_asset_key(asset_raw),
                                ASSET_PHRASES["unknown"]
                            ),
        },
        "threat_intelligence": {
            "label":        "Threat Intelligence Signal",
            "value":        threat_raw.replace("_", " ").title(),
            "weight":       f"{int(WEIGHTS_DISPLAY['threat_intel'] * 100)}% of total score",
            "contribution": f"{breakdown.get('threat_intel', {}).get('contribution', 0):.1f} pts",
            "reasoning":    THREAT_INTEL_PHRASES.get(
                                _resolve_threat_key(threat_raw),
                                THREAT_INTEL_PHRASES["none"]
                            ),
        },
        "patch_status": {
            "label":        "Patch Availability",
            "value":        patch_raw.replace("_", " ").title(),
            "weight":       f"{int(WEIGHTS_DISPLAY['patch'] * 100)}% of total score",
            "contribution": f"{breakdown.get('patch_status', {}).get('contribution', 0):.1f} pts",
            "reasoning":    PATCH_PHRASES.get(
                                _resolve_patch_key(patch_raw),
                                PATCH_PHRASES["patch_available"]
                            ),
        },
    }

    # ── Layer 3: Threat Context ───────────────────────────────────────────────
    threat_context = _build_threat_context(
        cve_id, priority, exploit_raw, threat_raw, asset_raw, patch_raw, description
    )

    # ── Layer 4: Recommended Actions ─────────────────────────────────────────
    recommended_actions = REMEDIATION_ACTIONS.get(priority, REMEDIATION_ACTIONS["LOW"])

    # ── Bonus: Dominant factor note ───────────────────────────────────────────
    dominant_note = _dominant_factor_sentence(dominant, breakdown)

    return {
        "summary":              summary,
        "factor_analysis":      factor_analysis,
        "threat_context":       threat_context,
        "recommended_actions":  recommended_actions,
        "score_bar":            _format_score_bar(risk_score),
        "dominant_factor_note": dominant_note,
        "priority":             priority,
        "risk_score":           risk_score,
    }


# ─── Threat Context Builder ───────────────────────────────────────────────────

def _build_threat_context(
    cve_id: str,
    priority: str,
    exploit_raw: str,
    threat_raw: str,
    asset_raw: str,
    patch_raw: str,
    description: str,
) -> str:
    """
    Compose a real-world threat narrative by combining signals
    from multiple factors into a coherent analyst paragraph.
    """

    lines = []

    # Opening: threat intel signal
    threat_key = _resolve_threat_key(threat_raw)
    if threat_key in ("apt_linked", "ransomware", "active_campaign"):
        lines.append(
            f"Intelligence feeds indicate that {cve_id} is not a theoretical risk — "
            f"it is being actively leveraged by threat actors in the wild. "
            f"{'Nation-state affiliations have been noted.' if threat_key == 'apt_linked' else ''}"
            f"{'Ransomware groups have been observed deploying this CVE as an initial access vector.' if threat_key == 'ransomware' else ''}"
            f"{'Active exploitation campaigns have been confirmed.' if threat_key == 'active_campaign' else ''}"
        )
    elif threat_key == "trending":
        lines.append(
            f"{cve_id} is gaining rapid attention across the security research community. "
            f"Trending CVEs historically see a spike in exploitation attempts within days "
            f"of entering the public spotlight."
        )
    else:
        lines.append(
            f"While no active campaigns have been publicly attributed to {cve_id} at this time, "
            f"the absence of threat intelligence is not the same as absence of risk."
        )

    # Middle: exploit + patch interaction
    exploit_key = _resolve_exploit_key(exploit_raw)
    patch_key   = _resolve_patch_key(patch_raw)

    if exploit_key in ("weaponized", "poc") and patch_key == "no_patch":
        lines.append(
            "Critically, exploit code is available and no vendor patch exists. "
            "This combination — known exploit, no fix — represents a worst-case scenario "
            "for defenders and requires immediate compensating controls."
        )
    elif exploit_key in ("weaponized", "poc") and patch_key == "patch_available":
        lines.append(
            "A patch is available but the existence of public exploit code means "
            "the window for safe deployment is narrow. Every unpatched instance "
            "is an active liability."
        )
    elif exploit_key == "theoretical" and patch_key == "no_patch":
        lines.append(
            "No patch is available, though exploitation currently requires advanced skill. "
            "This gap should be closed with network-level compensating controls while "
            "awaiting a vendor fix."
        )
    else:
        lines.append(
            "The current exploit maturity and patch landscape suggest defenders "
            "have a workable remediation window — but this should not invite complacency."
        )

    # Closing: asset criticality consequence
    asset_key = _resolve_asset_key(asset_raw)
    if asset_key == "mission_critical":
        lines.append(
            "Given the mission-critical classification of affected assets, a successful "
            "exploit could trigger service outages, data exfiltration, or regulatory "
            "breach notification obligations."
        )
    elif asset_key == "high":
        lines.append(
            "The high criticality of affected assets means exploitation could enable "
            "lateral movement toward more sensitive systems or cause significant "
            "data exposure."
        )
    elif asset_key in ("medium", "unknown"):
        lines.append(
            "Even if the directly affected asset has moderate criticality, attackers "
            "may use it as a stepping stone for deeper network penetration."
        )

    return " ".join(lines)


# ─── Weight Display Map (mirrors model.py WEIGHTS) ───────────────────────────
# Kept here to avoid circular imports

WEIGHTS_DISPLAY = {
    "cvss":         0.35,
    "exploit":      0.25,
    "asset":        0.20,
    "threat_intel": 0.10,
    "patch":        0.10,
}


# ─── Short Explanation (for cards / list views) ───────────────────────────────

def generate_short_explanation(scored_cve: dict) -> str:
    """
    One-sentence summary suitable for dashboard CVE cards.
    Much lighter than generate_explanation() — no breakdown needed.
    """
    cve_id     = scored_cve.get("id", "Unknown CVE")
    score      = scored_cve.get("risk_score", 0)
    priority   = scored_cve.get("priority", "LOW")
    dominant   = scored_cve.get("dominant_factor", "cvss")
    breakdown  = scored_cve.get("factor_breakdown", {})

    contrib    = breakdown.get(dominant, {}).get("contribution", 0)
    factor_map = {
        "cvss":             "high base severity",
        "exploit_maturity": "available exploit code",
        "asset_criticality":"critical asset exposure",
        "threat_intel":     "active threat intelligence",
        "patch_status":     "absence of a patch",
    }
    reason = factor_map.get(dominant, "multiple risk factors")

    return (
        f"{cve_id} scored {score}/100 ({priority}) — "
        f"primarily driven by {reason} ({contrib:.1f} pts)."
    )