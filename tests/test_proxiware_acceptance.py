from __future__ import annotations

import json

from scripts.proxiware_preflight import run_preflight


def test_preflight_is_redacted_and_keeps_mutations_disabled(tmp_path):
    report = run_preflight(tmp_path / "preflight.db")

    assert report["ok"] is True
    assert report["checks"]["schema"] is True
    assert report["checks"]["auto_swap_default_off"] is True
    assert report["checks"]["distribution_default_off"] is True
    assert report["checks"]["automation_pause_default_off"] is True
    assert report["checks"]["dry_run_no_mutation"] is True
    assert report["checks"]["admin_route_protected"] is True
    serialized = json.dumps(report, sort_keys=True)
    assert "preflight-secret" not in serialized
    assert "api-key" not in serialized
    assert "captcha-token" not in serialized


def test_preflight_does_not_contact_provider_or_claim_jobs(tmp_path):
    report = run_preflight(tmp_path / "preflight.db")

    assert report["provider_calls"] == 0
    assert report["swap_calls"] == 0
    assert report["checks"]["no_provider_mutation"] is True
    assert report["checks"]["no_active_swap_claim"] is True
