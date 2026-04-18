# backend/explain.py
import os
import json
import random
from typing import Optional
from google import genai
from google.genai import types

# ─── Configuration ──────────────────────────────────────────────────────────
API_KEY = os.getenv("API_KEY")

if API_KEY:
    # Initialize the new Client
    client = genai.Client(api_key=API_KEY)
    MODEL_ID = 'gemini-2.5-flash'
else:
    print("⚠️ WARNING: GEMINI_API_KEY not found. Operating in Legacy Template Mode.")
    client = None
    MODEL_ID = None

# ─── Phrase Libraries (The Reliability Fallback) ─────────────────────────────

CVSS_PHRASES = {
    "critical": ["a near-maximum CVSS score of {score}, placing it among the most severe vulnerabilities catalogued", "a critical CVSS score of {score} — this vulnerability represents a significant attack surface"],
    "high": ["a high CVSS score of {score}, reflecting serious potential for damage if exploited", "a CVSS score of {score} in the high range, signalling substantial risk"],
    "medium": ["a moderate CVSS score of {score}, suggesting meaningful but bounded risk", "a mid-range CVSS score of {score} — exploitable under certain conditions"],
    "low": ["a low CVSS score of {score}, indicating limited direct exploitability", "a minor CVSS score of {score} — typically requiring specific conditions"],
}

EXPLOIT_PHRASES = {
    "weaponized": "Active weaponized exploits are publicly available. Threat actors can leverage ready-made tools with minimal effort.",
    "poc": "A public proof-of-concept (PoC) exploit exists. The window between PoC release and active exploitation is historically very short.",
    "theoretical": "No public exploit code exists, but the vulnerability is theoretically exploitable by a determined attacker.",
    "unproven": "No known exploit path has been demonstrated publicly. Exploitation would require significant research investment.",
    "none": "No viable exploitation path is currently known.",
}

ASSET_PHRASES = {
    "mission_critical": "The affected system is classified as mission-critical. A successful exploit could cause immediate operational disruption.",
    "high": "The affected asset handles sensitive data. Compromise would have significant downstream consequences.",
    "medium": "The affected system sits in a development/staging environment. Lateral movement into production is a real risk.",
    "low": "The affected asset is a low-criticality test system. Direct business impact is limited.",
    "unknown": "Asset criticality has not been classified. This introduces uncertainty into the risk assessment.",
}

THREAT_INTEL_PHRASES = {
    "apt_linked": "Threat intelligence links this CVE to Advanced Persistent Threat (APT) groups.",
    "ransomware": "This CVE has been observed in ransomware campaigns. Immediate containment is strongly advised.",
    "active_campaign": "Threat intelligence confirms this CVE is being actively exploited in ongoing campaigns.",
    "trending": "This CVE is trending across threat intelligence feeds. Increased attention often precedes a spike in exploitation.",
    "none": "No specific threat intelligence signals are associated with this CVE at this time.",
}

PATCH_PHRASES = {
    "no_patch": "No patch is currently available. Organizations must rely on compensating controls.",
    "patch_available": "A patch has been released. The primary risk now lies in delayed deployment.",
    "patched": "A patch has been applied. Continued monitoring is advised to confirm effectiveness.",
}

REMEDIATION_ACTIONS = {
    "CRITICAL": ["Activate incident response plan.", "Isolate systems within hours.", "Conduct threat hunting for IoCs."],
    "HIGH": ["Schedule emergency patching within 7 days.", "Apply WAF/Firewall mitigations.", "Audit access logs."],
    "MEDIUM": ["Include in next scheduled patch cycle.", "Monitor threat feeds for escalation."],
    "LOW": ["Log and track for regular maintenance.", "Maintain standard monitoring."],
}

# ─── Internal Helpers ────────────────────────────────────────────────────────

def _pick_phrase(phrase_list: list[str], index: int = 0) -> str:
    return phrase_list[index % len(phrase_list)]

def _cvss_phrase(cvss_score: float, phrase_index: int = 0) -> str:
    tier = "critical" if cvss_score >= 9.0 else "high" if cvss_score >= 7.0 else "medium" if cvss_score >= 4.0 else "low"
    return _pick_phrase(CVSS_PHRASES[tier], phrase_index).format(score=cvss_score)

def _stable_index(cve_id: str) -> int:
    return sum(ord(c) for c in cve_id) % 5

def _resolve_key(raw: str, fallback: str) -> str:
    return raw.lower().replace(" ", "_") if raw else fallback

def _format_score_bar(score: float) -> str:
    filled = int((score / 100) * 20)
    return f"[{'█' * filled}{'░' * (20 - filled)}] {score}/100"

# ─── Gemini API Logic ────────────────────────────────────────────────────────

class GeminiExplainer:
    @staticmethod
    def generate(scored_cve: dict) -> Optional[dict]:
        if not client: return None
        
        prompt = f"""
        Role: Senior Security Analyst
        Analyze this specific CVE and provide unique, highly tailored remediation steps. Do not use generic answers.
        CVE Data: {json.dumps(scored_cve)}
        
        Task: Provide a professional JSON summary.
        Format strictly as raw JSON: 
        {{
            "summary": "2 sentences specific to this exact CVE",
            "threat_context": "Specific attack scenario for this vulnerability",
            "recommended_actions": ["Specific step 1", "Specific step 2", "Specific step 3"]
        }}
        """
        try:
            # Using the new genai syntax
            response = client.models.generate_content(
                model=MODEL_ID,
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=0.2, # Low temperature for more factual, professional tone
                )
            )
            raw_text = response.text
            
            # Clean up markdown formatting if Gemini includes it
            if raw_text.startswith("```json"):
                raw_text = raw_text.replace("```json", "").replace("```", "").strip()
            elif raw_text.startswith("```"):
                raw_text = raw_text.replace("```", "").strip()
                
            return json.loads(raw_text)
            
        except Exception as e:
            print(f"❌ Gemini API Error for {scored_cve.get('id', 'Unknown CVE')}: {str(e)}")
            return None

# ─── Main Logic ──────────────────────────────────────────────────────────────

def generate_explanation(scored_cve: dict) -> dict:
    """The entry point for the frontend. Tries Gemini, falls back to Template."""
    
    # 1. Attempt AI analysis
    ai_data = GeminiExplainer.generate(scored_cve)
    
    # 2. Extract common data
    cve_id = scored_cve.get("id", "UNKNOWN")
    risk_score = scored_cve.get("risk_score", 0.0)
    priority = scored_cve.get("priority", "LOW")
    breakdown = scored_cve.get("factor_breakdown", {})
    
    if ai_data:
        # Build response using AI narrative
        return {
            "summary": ai_data.get("summary", "Summary unavailable."),
            "threat_context": ai_data.get("threat_context", "Context unavailable."),
            "recommended_actions": ai_data.get("recommended_actions", []),
            "score_bar": _format_score_bar(risk_score),
            "priority": priority,
            "risk_score": risk_score,
            "ai_enhanced": True
        }
    
    # 3. Fallback to Legacy Template Engine
    idx = _stable_index(cve_id)
    cvss_raw = breakdown.get("cvss", {}).get("raw_value", 5.0)
    
    return {
        "summary": f"{cve_id} has a {priority} priority (Score: {risk_score}). It carries {_cvss_phrase(float(cvss_raw), idx)}.",
        "threat_context": f"Current status: Exploit is {breakdown.get('exploit_maturity', {}).get('raw_value', 'unknown')}.",
        "recommended_actions": REMEDIATION_ACTIONS.get(priority, REMEDIATION_ACTIONS["LOW"]),
        "score_bar": _format_score_bar(risk_score),
        "priority": priority,
        "risk_score": risk_score,
        "ai_enhanced": False
    }

def generate_short_explanation(scored_cve: dict) -> str:
    return f"{scored_cve.get('id')} ({scored_cve.get('risk_score')}/100) — {scored_cve.get('priority')} priority."