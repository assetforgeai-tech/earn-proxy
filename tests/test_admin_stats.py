import re
from datetime import UTC, datetime, timedelta

from conftest import login_admin

from app.db import get_db
from app.services.checks import operational_stats


def test_admin_dashboard_shows_operational_counts_and_sweep_lag(app, client):
    with app.app_context():
        db = get_db()
        db.execute(
            "INSERT INTO users(email,password_hash,role,status,created_at) VALUES('u@example.com','x','user','active',datetime('now'))"
        )
        user_id = db.execute("SELECT id FROM users WHERE email='u@example.com'").fetchone()["id"]
        db.execute(
            "INSERT INTO proxies(user_id,host,port,username_encrypted,password_encrypted,credential_fingerprint,status,eligibility,next_check_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,datetime('now','-2 hour'),datetime('now'),datetime('now'))",
            (user_id, "a.example", 9000, "x", "y", "f1", "online", "allow"),
        )
        db.execute(
            "INSERT INTO proxies(user_id,host,port,username_encrypted,password_encrypted,credential_fingerprint,status,eligibility,next_check_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,datetime('now','+1 hour'),datetime('now'),datetime('now'))",
            (user_id, "b.example", 9001, "x", "y", "f2", "offline", "risk"),
        )
        db.commit()
    login_admin(client)
    page = client.get("/admin").get_data(as_text=True)
    assert "Online" in page and "Offline" in page
    assert "Allow" in page and "Risk" in page
    assert "Sweep lag" in page
    assert "Healthy" in page and "Suspect" in page and "Stale" in page
    assert "Average latency" in page and "Checks/minute" in page
    assert "Per-host concurrency" in page
    assert len(re.findall(r'class="stats admin-stats', page)) == 1


def test_operational_stats_include_health_pipeline_observability(app):
    now = datetime.now(UTC)
    with app.app_context():
        db = get_db()
        db.execute(
            "INSERT INTO users(email,password_hash,role,status,created_at) VALUES('metrics@example.com','x','user','active',?)",
            (now.isoformat(),),
        )
        user_id = db.execute("SELECT id FROM users WHERE email='metrics@example.com'").fetchone()["id"]
        rows = [
            ("healthy.example", "online", (now - timedelta(minutes=10)).isoformat(), 100),
            ("suspect.example", "suspect", (now - timedelta(minutes=30)).isoformat(), 300),
            ("stale.example", "online", (now - timedelta(minutes=130)).isoformat(), 500),
            ("offline.example", "offline", (now - timedelta(minutes=200)).isoformat(), None),
        ]
        for index, (host, status, success, latency) in enumerate(rows):
            db.execute(
                """
                INSERT INTO proxies(user_id,host,port,username_encrypted,password_encrypted,credential_fingerprint,
                    status,eligibility,last_success_at,last_latency_ms,last_checked_at,next_check_at,created_at,updated_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    user_id,
                    host,
                    9000 + index,
                    "x",
                    "y",
                    f"metrics-{index}",
                    status,
                    "allow",
                    success,
                    latency,
                    (now - timedelta(seconds=30 * index)).isoformat(),
                    (now - timedelta(minutes=index)).isoformat(),
                    now.isoformat(),
                    now.isoformat(),
                ),
            )
        db.commit()
        stats = operational_stats(db, now=now)

    assert stats["healthy"] == 1
    assert stats["suspect"] == 1
    assert stats["offline"] == 1
    assert stats["stale"] == 1
    assert stats["average_latency_ms"] == 300
    assert stats["checks_per_minute"] > 0


def test_operational_stats_treat_online_without_success_as_stale(app):
    now = datetime.now(UTC)
    with app.app_context():
        db = get_db()
        db.execute(
            "INSERT INTO users(email,password_hash,role,status,created_at) VALUES('never-live@example.com','x','user','active',?)",
            (now.isoformat(),),
        )
        user_id = db.execute("SELECT id FROM users WHERE email='never-live@example.com'").fetchone()["id"]
        db.execute(
            """
            INSERT INTO proxies(user_id,host,port,username_encrypted,password_encrypted,credential_fingerprint,
                status,eligibility,last_success_at,last_checked_at,next_check_at,created_at,updated_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                user_id,
                "never-live.example",
                9000,
                "x",
                "y",
                "never-live",
                "online",
                "allow",
                None,
                now.isoformat(),
                now.isoformat(),
                now.isoformat(),
                now.isoformat(),
            ),
        )
        db.commit()

        stats = operational_stats(db, now=now)

    assert stats["healthy"] == 0
    assert stats["stale"] == 1
