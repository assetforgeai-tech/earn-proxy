from app.earnapp_probe import (
    build_tunnel_identity,
    classify_verdict,
    encode_client_frame,
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
