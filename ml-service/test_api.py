"""
Test FastAPI endpoints for PhishScope ML Microservice
"""

import json
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def test_endpoints():
    print("=" * 60)
    print("  TESTING FASTAPI MICROSERVICE ENDPOINTS")
    print("=" * 60)

    # 1. Health
    res_health = client.get("/health")
    print(f"\n1. GET /health -> HTTP {res_health.status_code}")
    print(f"   Payload: {json.dumps(res_health.json(), indent=2)}")
    assert res_health.status_code == 200

    # 2. List Models
    res_models = client.get("/models")
    print(f"\n2. GET /models -> HTTP {res_models.status_code}")
    models_list = res_models.json()
    for m in models_list:
        print(f"   - {m['id']}: {m['name']} (v{m['version']})")
    assert res_models.status_code == 200
    assert len(models_list) == 4

    # 3. Predict for all 4 models
    test_cases = [
        {
            "name": "High-Risk Credential Harvesting Phish",
            "features": {
                "extractedAt": "2026-11-13T00:00:00Z",
                "subjectText": "URGENT: Suspended Account Security Alert",
                "bodyCleanText": (
                    "Dear customer, your bank account has been suspended. "
                    "Please verify your password immediately at http://192.168.1.1/login "
                    "or your account will be closed."
                ),
                "totalUrlCount": 1,
                "hasDirectIpUrls": "true",
                "hasAnchorTextDivergence": "true",
                "spfPass": "false",
                "dkimPass": "false",
                "dmarcPass": "false"
            }
        },
        {
            "name": "Legitimate Corporate Meeting Schedule",
            "features": {
                "extractedAt": "2026-11-13T00:00:00Z",
                "subjectText": "Meeting Agenda: Q3 Planning Review",
                "bodyCleanText": (
                    "Hi team, please find attached the discussion notes from yesterday "
                    "morning meeting. Let me know if you have any questions regarding the schedule."
                ),
                "totalUrlCount": 0,
                "hasDirectIpUrls": "false",
                "hasAnchorTextDivergence": "false",
                "spfPass": "true",
                "dkimPass": "true",
                "dmarcPass": "true"
            }
        }
    ]

    for model_info in models_list:
        model_id = model_info["id"]
        print(f"\n3. POST /predict with Model '{model_id}':")

        for tc in test_cases:
            payload = {
                "snapshotId": "test-snap-001",
                "modelId": model_id,
                "features": tc["features"]
            }
            res_pred = client.post("/predict", json=payload)
            assert res_pred.status_code == 200, f"Error: {res_pred.text}"
            data = res_pred.json()

            print(f"   [{tc['name']}]")
            print(f"     -> Predicted Class : {data['predictedClass']}")
            print(f"     -> Probability     : {data['scoreSemantics']['probability']}")
            print(f"     -> Calibrated      : {data['scoreSemantics']['isCalibrated']}")
            print(f"     -> Confidence      : {data['confidenceScore']}")
            print(f"     -> Latency (ms)    : {data['inferenceLatencyMs']}")
            print(f"     -> Contributing    : {len(data['contributingFeatures'])} features")

    print("\n" + "=" * 60)
    print("  ALL API TESTS PASSED SUCCESSFULLY!")
    print("=" * 60)


if __name__ == "__main__":
    test_endpoints()

