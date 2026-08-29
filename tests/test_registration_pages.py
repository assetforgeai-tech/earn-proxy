def test_registration_and_login_pages_render(client):
    assert client.get("/register").status_code == 200
    assert client.get("/login").status_code == 200
