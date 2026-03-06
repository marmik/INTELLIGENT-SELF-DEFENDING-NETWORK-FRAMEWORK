from typing import Optional, Dict
import math

def risk_score(anomaly_score: float, packet_count: int, byte_count: int, persistence: int = 0, metadata: Optional[Dict] = None) -> dict:
    """Compute a multi-dimensional risk assessment based on ISDNF principles.
    Formula: Risk Score = f(Anomaly Score, Traffic Intensity, Persistence, Protocol Behavior)
    """
    # 1. Traffic Intensity (Normalization)
    intensity = min(1.0, (packet_count / 500.0) + (byte_count / 2000000.0))
    # 2. Persistence (Stateful factor)
    p_factor = min(1.0, math.log1p(persistence) / 3.0) 
    # 3. Behavioral and Protocol Context
    m = metadata or {}
    standard_ports = [443, 80, 53, 8080, 8443, 22]
    port_diversity = m.get("unique_ports_count", 1)
    is_trusted_port = any(p in standard_ports for p in m.get("dst_ports", []))
    # ML Classification Signal
    classification = m.get("model_classification", "BENIGN")
    class_multiplier = 1.0
    if classification != "BENIGN":
        class_multiplier = 1.3 
        if classification in ["DDoS", "PortScan"]:
            class_multiplier = 1.5
    # ISDNF Core Formula (Base Score 0-1)
    base_score = (0.4 * anomaly_score) + (0.2 * intensity) + (0.2 * p_factor)

    # --- datacenter/infra de‑escalation -----------------------------------
    # traffic originating from large cloud/providers can show unusual
    # characteristics; by default we soften its score rather than blocking it
    # outright.  This does *not* whitelist the host, it only biases the
    # risk calculation so the downstream action tends to LOG or RATE_LIMIT.
    if m.get("is_datacenter"):
        # reduce risk by half but keep some signal in case of very strong
        # anomalies (e.g. the address is both datacenter *and* port‑scanning).
        base_score *= 0.5

    # Protocol / Context Bias
    if is_trusted_port and port_diversity <= 2 and classification == "BENIGN":
        base_score *= 0.6 # Benign traffic to known services suppressed
    # Apply ML Classification multiplier
    base_score *= class_multiplier
    # --- ENHANCED: Stealthy Scan & Attacker Fingerprint Detection ---
    # these heuristics are strong enough to override the base formula, but
    # we must be careful not to automatically escalate known infrastructure
    # addresses; that would reintroduce the problem we just fixed in the
    # orchestrator logic.
    if not m.get("is_datacenter"):
        # 1. Port scan: lower threshold to 5 unique ports
        if port_diversity > 5:
            base_score = max(base_score, 0.75) # HIGH-risk for port scanning
        # 2. Stealthy scan: incomplete handshakes, low packet count, high port diversity
        if m.get("incomplete_handshakes", 0) > 3 and port_diversity > 2:
            base_score = max(base_score, 0.8)
        # 3. Attacker fingerprint: known attacker MAC, TTL, or OS
        if m.get("src_mac", "").startswith("00:0c:29") or m.get("os_fingerprint", "").lower() == "kali":
            base_score = max(base_score, 0.9)
        # 4. TTL anomaly (Kali default is 64, check for outlier)
        if m.get("ttl_mean", 64) == 64 and not is_trusted_port:
            base_score = max(base_score, 0.8)
    # Keep cloud/datacenter traffic from being mis-labeled as HIGH/CRITICAL
    # unless we also see strong attack indicators.
    classification_upper = str(classification).upper()
    strong_scan_ioc = (
        port_diversity >= 12
        or m.get("incomplete_handshakes", 0) >= 6
        or classification_upper in {"PORTSCAN", "RECON", "RECONNAISSANCE"}
    )
    strong_payload_ioc = (
        m.get("payload_score", 0.0) >= 0.92
        and anomaly_score >= 0.9
    )
    if m.get("is_datacenter") and not (strong_scan_ioc or strong_payload_ioc):
        base_score = min(base_score, 0.39)

    # 5. Local Immunity Rule (always apply, datacenter or not)
    if m.get("is_local_infrastructure"):
        base_score = min(0.25, base_score)
    # Final Scaling
    final_score = max(0.0, min(100.0, base_score * 100.0))
    # round for readability and consistency
    final_score = round(final_score,2)
    # ISDNF Tiered Response Mapping
    action = "LOG"
    if final_score >= 90: 
        action = "CRITICAL_BLOCK"
    elif final_score >= 70: 
        action = "BLOCK"
    elif final_score >= 40: 
        action = "RATE_LIMIT"
    return {
        "score": final_score,
        "action": action,
        "classification": classification,
        "breakdown": {
            "anomaly": float(f"{anomaly_score:.2f}"),
            "intensity": float(f"{intensity:.2f}"),
            "persistence": float(f"{p_factor:.2f}"),
            "class_impact": float(f"{class_multiplier:.2f}")
        }
    }

# TODO: Retrain ML model with real Kali attack flows and update feature engineering to include attacker fingerprints, scan timing, and incomplete handshake detection.
