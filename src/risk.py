def risk_score(anomaly_score: float, packet_count: int, byte_count: int, persistence: int = 0) -> dict:
    """Compute a multi-dimensional risk assessment.
    
    anomaly_score: 0..1 (ML signal)
    persistence: count of previous occurrences
    """
    # 1. Traffic Intensity (Normalization)
    # Calibrated thresholds: 200 packets or 1MB to hit 100% intensity in a 3s window
    intensity = min(1.0, (packet_count / 200.0) + (byte_count / 1000000.0))
    
    # 2. Persistence Factor (Logarithmic boost)
    # 0 hits = 0, 1 hit = 0.3, 5 hits = 0.7, 10+ hits = 1.0
    import math
    p_factor = min(1.0, math.log1p(persistence) / 2.4) 
    
    # 3. Weighted Integration (ISDNF Formula)
    base_score = (0.5 * anomaly_score) + (0.2 * intensity) + (0.3 * p_factor)
    
    # Synergistic Volumetric Boost:
    # If a flow is moderately anomalous (>0.5) AND highly intensive (>0.5), it is an active Scan/Flood.
    # Give it an immediate +40% risk boost so it crosses the 85% block threshold immediately.
    if anomaly_score > 0.5 and intensity > 0.5:
        base_score += 0.40
        
    final_score = max(0.0, min(100.0, base_score * 100.0))
    
    # 4. Recommendation Mapping
    action = "LOG"
    if final_score >= 85: action = "BLOCK"
    elif final_score >= 50: action = "RATE_LIMIT"
    
    return {
        "score": final_score,
        "action": action,
        "breakdown": {
            "anomaly": float(f"{anomaly_score:.2f}"),
            "intensity": float(f"{intensity:.2f}"),
            "persistence": float(f"{p_factor:.2f}")
        }
    }
