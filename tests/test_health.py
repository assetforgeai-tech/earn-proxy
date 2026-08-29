from app import create_app


def test_health_endpoint_reports_service_ready(tmp_path):
    app = create_app(
        {
            "TESTING": True,
            "DATABASE": str(tmp_path / "test.db"),
            "SECRET_KEY": "test-secret",
            "FERNET_KEY": "-WjNr7wJTuNQqnbsZog_WamxH_0FcKscBU8vcR2ThIY=",
        }
    )

    response = app.test_client().get("/healthz")

    assert response.status_code == 200
    assert response.get_json() == {"service": "earn-proxy", "status": "ok"}
