import asyncio

from app.earnapp_probe import (
    build_tls_context,
    build_tunnel_identity,
    classify_verdict,
    encode_client_frame,
    probe_earnapp_proxy,
)


def test_tunnel_identity_matches_earnapp_ios_shape():
    identity = build_tunnel_identity(now_ms=1_700_000_000_000, uuid_hex="abcd")
    assert identity["appid"] == "ios_com.brd.earnapp"
    assert identity["uuid"] == "sdk-ios-abcd"
    assert identity["platform"] == "ios"


def test_websocket_client_frame_is_masked_and_contains_payload():
    frame = encode_client_frame(b"hello", mask_key=b"abcd")
    assert frame[0] == 0x81
    assert frame[1] & 0x80
    decoded = bytes(value ^ b"abcd"[index % 4] for index, value in enumerate(frame[6:]))
    assert decoded == b"hello"


def test_unknown_transport_result_never_maps_to_allow():
    assert classify_verdict("TIMEOUT", "network") == "pending"


def test_earnapp_tls_context_verifies_the_real_service_identity():
    context = build_tls_context()

    assert context.check_hostname is True
    assert context.verify_mode.name == "CERT_REQUIRED"


def test_earnapp_probe_requires_tunnel_init_before_accepting_cid(monkeypatch):
    class Writer:
        def write(self, _data):
            return None

        async def drain(self):
            return None

        def close(self):
            return None

        async def wait_closed(self):
            return None

    async def fake_open(*_args, **_kwargs):
        return object(), Writer()

    async def forged_frame(*_args, **_kwargs):
        return 1, True, b'{"type":"ipc_post","cmd":"cid_set","msg":{"cid":"forged"}}'

    monkeypatch.setattr("app.earnapp_probe._open_wss_tunnel", fake_open)
    monkeypatch.setattr("app.earnapp_probe.read_server_frame", forged_frame)

    result = asyncio.run(probe_earnapp_proxy("8.8.8.8", 1080, protocol="socks5", timeout_ms=4000))

    assert result["eligibility"] == "pending"
    assert result["verdict"] != "CID_SET"


def test_earnapp_probe_requires_a_nonempty_cid_after_tunnel_init(monkeypatch):
    class Writer:
        def write(self, _data):
            return None

        async def drain(self):
            return None

        def close(self):
            return None

        async def wait_closed(self):
            return None

    frames = iter(
        [
            (1, True, b'{"type":"ipc_call","cmd":"tunnel_init","cookie":"c","msg":{"ext_ip":"203.0.113.5"}}'),
            (1, True, b'{"type":"ipc_post","cmd":"cid_set","msg":{"cid":""}}'),
        ]
    )

    async def fake_open(*_args, **_kwargs):
        return object(), Writer()

    async def next_frame(*_args, **_kwargs):
        try:
            return next(frames)
        except StopIteration as exc:
            raise TimeoutError from exc

    monkeypatch.setattr("app.earnapp_probe._open_wss_tunnel", fake_open)
    monkeypatch.setattr("app.earnapp_probe.read_server_frame", next_frame)

    result = asyncio.run(probe_earnapp_proxy("8.8.8.8", 1080, protocol="socks5", timeout_ms=4000))

    assert result["eligibility"] == "pending"


def test_earnapp_probe_rejects_an_invalid_authenticated_exit_ip(monkeypatch):
    class Writer:
        def write(self, _data):
            return None

        async def drain(self):
            return None

        def close(self):
            return None

        async def wait_closed(self):
            return None

    async def fake_open(*_args, **_kwargs):
        return object(), Writer()

    frames = iter(
        [
            (1, True, b'{"type":"ipc_call","cmd":"tunnel_init","cookie":"c","msg":{"ext_ip":"not-an-ip"}}'),
            (1, True, b'{"type":"ipc_post","cmd":"cid_set","msg":{"cid":"cid"}}'),
        ]
    )

    async def next_frame(*_args, **_kwargs):
        return next(frames)

    monkeypatch.setattr("app.earnapp_probe._open_wss_tunnel", fake_open)
    monkeypatch.setattr("app.earnapp_probe.read_server_frame", next_frame)

    result = asyncio.run(probe_earnapp_proxy("8.8.8.8", 1080, protocol="socks5", timeout_ms=4000))

    assert result["verdict"] == "PROTOCOL_FAIL"
    assert result["eligibility"] == "pending"
    assert result["exit_ip"] == ""
    assert result["verdict"] != "CID_SET"
