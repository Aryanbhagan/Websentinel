def classify_risk(observations):
    """
    Classify the target based on basic observable security conditions.
    This is only the Phase 1 risk model.
    """

    risk_score = 0

    for observation in observations:
        risk_score += observation["score"]

    if risk_score >= 50:
        risk_level = "HIGH"
    elif risk_score >= 25:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "score": risk_score,
        "level": risk_level
    }