import hashlib
import json
import re
from typing import Any


SEVERITIES = ("low", "medium", "high", "critical")


def _text(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False).lower()


def _score(payload: dict[str, Any]) -> tuple[float, float, float, list[str]]:
    text = _text(payload)
    indicators: list[str] = []
    threat = 0.15
    anomaly = 0.10
    false_positive = 0.10

    rules = [
        (r"\b(ransomware|credential theft|exfiltration|malware)\b", .45, "malware_or_exfiltration"),
        (r"\b(brute.?force|multiple failed|impossible travel)\b", .30, "authentication_anomaly"),
        (r"\b(privilege escalation|root|administrator)\b", .25, "privileged_activity"),
        (r"\b(data export|api abuse|injection|suspicious)\b", .25, "suspicious_application_activity"),
    ]
    for pattern, weight, category in rules:
        if re.search(pattern, text):
            threat = min(1.0, threat + weight)
            anomaly = min(1.0, anomaly + weight * .9)
            indicators.append(category)

    if payload.get("test") is True or "healthcheck" in text or "synthetic" in text:
        false_positive = .75
        threat = max(.05, threat - .25)

    return round(anomaly, 3), round(threat, 3), round(false_positive, 3), indicators


def triage(payload: dict[str, Any], source_severity: str | None = None) -> dict[str, Any]:
    anomaly, threat, false_positive, categories = _score(payload)
    numeric = threat * .65 + anomaly * .35
    if false_positive >= .7:
        severity = "low"
    elif numeric >= .85:
        severity = "critical"
    elif numeric >= .62:
        severity = "high"
    elif numeric >= .35:
        severity = "medium"
    else:
        severity = "low"

    if source_severity in SEVERITIES:
        source_rank = SEVERITIES.index(source_severity)
        severity = max(severity, source_severity, key=lambda x: SEVERITIES.index(x))

    confidence = round(min(0.99, max(.45, .5 + abs(threat - false_positive) * .5)), 3)
    summary = (
        f"Normalized security event assessed as {severity} severity. "
        f"Threat score {threat:.2f}, anomaly score {anomaly:.2f}, "
        f"false-positive score {false_positive:.2f}."
    )
    return {
        "severity": severity,
        "confidence": confidence,
        "anomaly_score": anomaly,
        "threat_score": threat,
        "false_positive_score": false_positive,
        "summary": summary,
        "categories": categories,
        "evidence": [{"type": "deterministic_scoring", "categories": categories}],
        "recommended_actions": ["Review event context", "Correlate related telemetry"],
        "model_metadata": {
            "classifier": "deterministic-baseline",
            "provider": "disabled",
            "model": "rules-v1",
            "prompt_version": "triage-v2",
        },
    }


def fingerprint(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()
