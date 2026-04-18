# backend/explain.py

import random
from typing import Optional

# ─── Phrase Libraries ─────────────────────────────────────────────────────────

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
        "Review ingress/egress logs for the last 48 hours.",
    ],
    "HIGH": [
        "Schedule emergency patching within the next 7 days.",
        "Apply network-level mitigations (firewall rules, WAF policies) as an interim measure.",
        "Audit access logs on affected systems for suspicious activity.",
        "Verify patch applicability across all affected asset instances.",
        "Track remediation progress with daily status updates.",
        "Enforce strict MFA for any service interacting with the affected component.",
    ],
    "MEDIUM": [
        "Include in the next scheduled patch cycle (within 30 days).",
        "Review whether compensating controls already reduce the effective risk.",
        "Assess whether affected assets require reclassification to higher criticality.",
        "Monitor threat intel feeds for any escalation in exploit activity.",
        "Update internal vulnerability scanners to ensure coverage for this signature.",
    ],
    "LOW": [
        "Log and track for remediation in the next regular patch window.",
        "Confirm CVSS environmental score adjustments for your specific context.",
        "No immediate action required — maintain standard monitoring.",
        "Review vendor release notes for secondary security hardening opportunities.",
    ],
}

# ─── Helper Functions ─────────────────────────────────────────────────────────

def _pick_phrase(phrase_list: list[str], index: int = 0) -> str:
    return phrase_list[index % len(phrase_list)]

def _cvss_phrase(cvss_score: float, phrase_index: int = 0) -> str:
    if cvss_score >= 9.0: tier = "critical"
    elif cvss_score >= 7.0: tier = "high"
    elif cvss_score >= 4.0: tier = "medium"
    else: tier = "low"
    template = _pick_phrase(CVSS_PHRASES[tier], phrase_index)
    return template.format(score=cvss_score)

def _resolve_exploit_key(raw: str) -> str: return raw.lower().replace(" ", "_") if raw else "unproven"
def _resolve_asset_key(raw: str) -> str: return raw.lower().replace(" ", "_") if raw else "unknown"
def _resolve_threat_key(raw: str) -> str: return raw.lower().replace(" ", "_") if raw else "none"
def _resolve_patch_key(raw: str) -> str: return raw.lower().replace(" ", "_") if raw else "patch_available"

def _stable_index(cve_id: str) -> int:
    return sum(ord(c) for c in cve_id) % 5

def _format_score_bar(score: float, width: int = 20) -> str:
    filled = int((score / 100) * width)
    return f"[{'█' * filled}{'░' * (width - filled)}] {score}/100"

def _dominant_factor_sentence(dominant: str, breakdown: dict) -> str:
    contrib = breakdown.get(dominant, {}).get("contribution", 0)
    factor_labels = {
        "cvss": "CVSS base severity",
        "exploit_maturity": "exploit availability",
        "asset_criticality":"asset criticality",
        "threat_intel": "active threat intelligence",
        "patch_status": "patch unavailability",
    }
    label = factor_labels.get(dominant, dominant.replace("_", " "))
    return f"The dominant driver of this score is **{label}**, contributing {contrib:.1f} points."

# ─── Main Explanation Generator ───────────────────────────────────────────────

def generate_explanation(scored_cve: dict) -> dict:
    cve_id = scored_cve.get("id", "UNKNOWN")
    risk_score = scored_cve.get("risk_score", 0.0)
    priority = scored_cve.get("priority", "LOW")
    severity = scored_cve.get("severity", "UNKNOWN")
    breakdown = scored_cve.get("factor_breakdown", {})
    dominant = scored_cve.get("dominant_factor", "cvss")
    affected = scored_cve.get("affected_systems", [])
    age_penalty = scored_cve.get("age_penalty_applied", 1.0)

    idx = _stable_index(cve_id)

    # Raw factor values
    cvss_raw = breakdown.get("cvss", {}).get("raw_value", 5.0)
    exploit_raw = breakdown.get("exploit_maturity", {}).get("raw_value", "unproven")
    asset_raw = breakdown.get("asset_criticality", {}).get("raw_value", "unknown")
    threat_raw = breakdown.get("threat_intel", {}).get("raw_value", "none")
    patch_raw = breakdown.get("patch_status", {}).get("raw_value", "patch_available")

    # ── Layer 1: Executive Summary ────────────────────────────────────────────
    affected_str = ", ".join(affected[:3]) + (" and others" if len(affected) > 3 else "") if affected else "unspecified systems"
    
    closing_phrases = [
        f"Immediate mitigation is recommended to reduce the attack surface for {cve_id}.",
        f"Security teams should prioritize the remediation of {cve_id} in the upcoming maintenance window.",
        f"Failure to address {cve_id} could leave {affected_str} vulnerable to lateral movement.",
        f"This CVE represents a significant hurdle for internal security compliance if left unpatched.",
        f"Continuous monitoring of {cve_id} is advised due to the evolving exploit landscape."
    ]
    custom_closing = _pick_phrase(closing_phrases, idx)

    summary = (
        f"{cve_id} has been assigned a **{priority} priority** risk score of **{risk_score}/100**. "
        f"This vulnerability carries {_cvss_phrase(float(cvss_raw), idx)}, affecting {affected_str}. "
        f"{custom_closing}"
    )

    # ── Layer 2: Per-Factor Analysis ──────────────────────────────────────────
    # (Mapping logic using the RESOLVE helpers)
    factor_analysis = {
        "cvss_severity": {
            "label": "CVSS Base Severity",
            "value": f"{cvss_raw}/10 ({severity})",
            "reasoning": f"The CVSS score reflects the intrinsic technical severity of {cve_id}."
        },
        "exploit_maturity": {
            "label": "Exploit Availability",
            "value": exploit_raw.replace("_", " ").title(),
            "reasoning": EXPLOIT_PHRASES.get(_resolve_exploit_key(exploit_raw), EXPLOIT_PHRASES["unproven"])
        },
        "asset_criticality": {
            "label": "Asset Criticality",
            "value": asset_raw.replace("_", " ").title(),
            "reasoning": ASSET_PHRASES.get(_resolve_asset_key(asset_raw), ASSET_PHRASES["unknown"])
        },
        "threat_intelligence": {
            "label": "Threat Intelligence",
            "value": threat_raw.replace("_", " ").title(),
            "reasoning": THREAT_INTEL_PHRASES.get(_resolve_threat_key(threat_raw), THREAT_INTEL_PHRASES["none"])
        },
        "patch_status": {
            "label": "Patch Status",
            "value": patch_raw.replace("_", " ").title(),
            "reasoning": PATCH_PHRASES.get(_resolve_patch_key(patch_raw), PATCH_PHRASES["patch_available"])
        }
    }

    # ── Layer 3: Threat Context ───────────────────────────────────────────────
    threat_context = _build_threat_context(cve_id, priority, exploit_raw, threat_raw, asset_raw, patch_raw)

    # ── Layer 4: Recommended Actions (Deterministic Variety) ──────────────────
    base_actions = REMEDIATION_ACTIONS.get(priority, REMEDIATION_ACTIONS["LOW"])
    
    # Use CVE_ID as seed so different CVEs get different selections
    random_gen = random.Random(cve_id)
    sample_size = random_gen.randint(2, 3)
    dynamic_actions = random_gen.sample(base_actions, min(sample_size, len(base_actions)))
    
    # Add one custom-looking technical bullet
    specific_bullet = f"Verify {cve_id} exploitability against the current production kernel version."
    recommended_actions = [specific_bullet] + dynamic_actions

    return {
        "summary": summary,
        "factor_analysis": factor_analysis,
        "threat_context": threat_context,
        "recommended_actions": recommended_actions,
        "score_bar": _format_score_bar(risk_score),
        "dominant_factor_note": _dominant_factor_sentence(dominant, breakdown),
        "priority": priority,
        "risk_score": risk_score,
    }

# ─── Threat Context Builder ───────────────────────────────────────────────────

def _build_threat_context(cve_id, priority, exploit_raw, threat_raw, asset_raw, patch_raw) -> str:
    lines = []
    threat_key = _resolve_threat_key(threat_raw)
    exploit_key = _resolve_exploit_key(exploit_raw)
    patch_key = _resolve_patch_key(patch_raw)

    if threat_key in ("apt_linked", "ransomware", "active_campaign"):
        lines.append(f"{cve_id} is being actively leveraged by sophisticated threat actors in the wild.")
    else:
        lines.append(f"While no active campaigns have been publicly attributed to {cve_id}, it remains on the radar of global security feeds.")

    if exploit_key in ("weaponized", "poc") and patch_key == "no_patch":
        lines.append("The presence of public exploit code without a vendor patch creates a critical zero-day exposure window.")
    elif exploit_key in ("weaponized", "poc"):
        lines.append("Public exploit code availability narrows the remediation window significantly.")

    return " ".join(lines)

# ─── Short Explanation ───────────────────────────────────────────────────────

def generate_short_explanation(scored_cve: dict) -> str:
    cve_id = scored_cve.get("id", "Unknown CVE")
    score = scored_cve.get("risk_score", 0)
    priority = scored_cve.get("priority", "LOW")
    dominant = scored_cve.get("dominant_factor", "cvss")
    breakdown = scored_cve.get("factor_breakdown", {})
    contrib = breakdown.get(dominant, {}).get("contribution", 0)

    factor_map = {
        "cvss": "high base severity",
        "exploit_maturity": "exploit availability",
        "asset_criticality":"asset exposure",
        "threat_intel": "active intelligence",
        "patch_status": "patch unavailability",
    }
    reason = factor_map.get(dominant, "combined risk factors")

    return f"{cve_id} ({score}/100) — {priority} priority driven by {reason} ({contrib:.1f} pts)."

# Necessary to avoid circular import if needed by model
WEIGHTS_DISPLAY = {"cvss": 0.35, "exploit": 0.25, "asset": 0.20, "threat_intel": 0.10, "patch": 0.10}