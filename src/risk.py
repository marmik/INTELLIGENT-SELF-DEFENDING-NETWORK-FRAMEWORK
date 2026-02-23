from typing import Optional, Dict
import math

def risk_score(anomaly_score: float, packet_count: int, byte_count: int, persistence: int = 0, metadata: Optional[Dict] = None) -> dict:
    """Compute a multi-dimensional risk assessment.
    
    anomaly_score: 0..1 (ML signal)
    persistence: count of previous occurrences
    """
    # 1. Traffic Intensity (Normalization)
    # Calibrated thresholds: 200 packets or 1MB to hit 100% intensity in a 3s window
    intensity = min(1.0, (packet_count / 200.0) + (byte_count / 1000000.0))
    
    p_factor = min(1.0, math.log1p(persistence) / 2.4) 
    
    # 3. Weighted Integration (ISDNF Formula)
    # Datacenter/CDN Awareness: Grant significant bias (lower score) to trusted service ports
    m = metadata or {}
    standard_ports = [443, 80, 53, 8080, 8443, 22]
    port_diversity = m.get("unique_ports_count", 1)
    
    # If it's a scan (high diversity), we do NOT grant the benign proto_bias
    is_trusted_port = any(p in standard_ports for p in m.get("dst_ports", []))
    proto_bias = 0.4 if (is_trusted_port and port_diversity <= 3) else 1.0
    adjusted_anomaly = anomaly_score * proto_bias
    
    base_score = (0.5 * adjusted_anomaly) + (0.2 * intensity) + (0.3 * p_factor)
    
    # SOC V11.0 DETERMINISTIC SCAN SIGNATURE
    # Hallmarks of a scan: High port diversity even at low volume
    port_diversity = m.get("unique_ports_count", 1)
    if port_diversity > 10:
        # If they touch > 10 ports, it's a scan. 
        # Boost by 40% immediately if there's any anomaly at all
        if adjusted_anomaly > 0.3:
            base_score += 0.45
        else:
            base_score += 0.25 # Minor boost even if ML is quiet
            
    # Synergistic Volumetric Boost:
    # Rule: Boost if high anomaly and high intensity 
    if adjusted_anomaly > 0.4 and intensity > 0.4:
        base_score += 0.35
        
    # Local Immunity Rule: Never block local gateway or local machine
    if m.get("is_local_infrastructure"):
        base_score = min(0.40, base_score)

    final_score = max(0.0, min(100.0, base_score * 100.0))
    
    # 4. Recommendation Mapping (V12.0 Layered Defense)
    action = "LOG"
    if final_score >= 80: action = "BLOCK"
    elif final_score >= 45: action = "RATE_LIMIT"
    
    return {
        "score": final_score,
        "action": action,
        "breakdown": {
            "anomaly": float(f"{anomaly_score:.2f}"),
            "intensity": float(f"{intensity:.2f}"),
            "persistence": float(f"{p_factor:.2f}")
        }
    }
