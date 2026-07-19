from datetime import UTC, datetime

from crosspatch.api.app import create_app
from crosspatch.api.dependencies import Principal, Role, StaticTokenAuthenticator


class _UnusedService:
    pass


def test_openapi_exposes_only_authenticated_control_surface() -> None:
    authenticator = StaticTokenAuthenticator(
        {
            "read-token": Principal(
                subject="reader-1",
                role=Role.READ_ONLY,
                incident_ids=frozenset({"inc-a"}),
                expires_at=datetime(2099, 1, 1, tzinfo=UTC),
            )
        }
    )
    app = create_app(
        service=_UnusedService(),
        authenticator=authenticator,
        allowed_origins=("https://crosspatch.test",),
    )

    document = app.openapi()
    paths = document["paths"]
    expected = {
        ("/api/incidents", "post"),
        ("/api/incidents/{incident_id}", "get"),
        ("/api/incidents/{incident_id}/evidence", "get"),
        ("/api/incidents/{incident_id}/events", "get"),
        ("/api/incidents/{incident_id}/events/stream", "get"),
        ("/api/warrants/{warrant_id}", "get"),
        ("/api/warrants/{warrant_id}/approve", "post"),
        ("/api/warrants/{warrant_id}/reject", "post"),
        ("/api/incidents/{incident_id}/export", "get"),
        ("/api/judge-tokens", "get"),
        ("/api/judge-tokens/rotate", "post"),
        ("/api/judge-tokens/{token_id}/revoke", "post"),
    }
    assert expected <= {(path, method) for path, item in paths.items() for method in item}

    security_schemes = document["components"]["securitySchemes"]
    assert security_schemes["BearerAuth"] == {"type": "http", "scheme": "bearer"}
    for path, method in expected:
        assert paths[path][method]["security"] == [{"BearerAuth": []}]

    public = {
        ("/api/public/cases", "get"),
        ("/api/public/cases/{incident_id}", "get"),
    }
    assert public <= {(path, method) for path, item in paths.items() for method in item}
    for path, method in public:
        assert paths[path][method].get("security", []) == []


def test_openapi_public_models_expose_no_raw_or_secret_fields() -> None:
    app = create_app(
        service=_UnusedService(),
        authenticator=StaticTokenAuthenticator({}),
        allowed_origins=("https://crosspatch.test",),
    )
    encoded = str(app.openapi()).lower()

    for forbidden in (
        "raw_sha256",
        "raw_path",
        "raw_bytes",
        "approval_mac",
        "secret_value",
    ):
        assert forbidden not in encoded

    summary_schema = app.openapi()["components"]["schemas"]["PublishedCaseSummaryView"]
    assert {"verdict_path", "recorded_cost_usd", "duration_seconds"} <= set(
        summary_schema["required"]
    )


def test_app_rejects_wildcard_cors_configuration() -> None:
    try:
        create_app(
            service=_UnusedService(),
            authenticator=StaticTokenAuthenticator({}),
            allowed_origins=("*",),
        )
    except ValueError as error:
        assert "wildcard" in str(error).lower()
    else:  # pragma: no cover - assertion produces a clearer contract failure
        raise AssertionError("wildcard CORS must be rejected")
