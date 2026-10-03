def record(findings, d):
    key = (d["kind"], d["ip"])

    if key in findings:
        findings[key]["count"] += 1
        findings[key]["last_seen"] = d["ts"]
        findings[key]["evidence"].add(d["evidence"])
        
        return False

    findings[key] = {
        "level": d["level"], "kind": d["kind"], "ip":d["ip"],
        "first_seen": d["ts"], "last_seen": d["ts"], "count": 1,
        "evidence": {d["evidence"]}
    }
    
    return True
