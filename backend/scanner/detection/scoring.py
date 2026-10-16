DEFAULT_DECISION_THRESHOLD = 60.0
MODEL_SCORE_WEIGHT = 0.65
RULE_SCORE_WEIGHT = 0.35


def combine_risk_score(model_probability, rule_score):
    return round(model_probability * 100 * MODEL_SCORE_WEIGHT + rule_score * RULE_SCORE_WEIGHT)


def classify_risk_score(risk_score, threshold=DEFAULT_DECISION_THRESHOLD):
    if risk_score >= threshold:
        return "phishing"
    if risk_score >= 25:
        return "suspicious"
    return "safe"
