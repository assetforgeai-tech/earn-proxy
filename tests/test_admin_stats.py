from conftest import login_admin

from app.db import get_db


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
