"""Voice calls: who is called, who joined, when a call is over."""

import base64
import hashlib
import hmac

from test_api import alice_bob, user  # noqa: F401  (fixture)


def dm(alice):
    return alice.post("/api/chats", json={"type": "dm", "username": "bob"}).json["chat_id"]


def states(call):
    return {p["username"]: p["state"] for p in call["participants"]}


def test_call_answer_and_hang_up(alice_bob):
    alice, bob = alice_bob
    chat_id = dm(alice)
    call = alice.post(f"/api/chats/{chat_id}/call").json["call"]
    assert states(call) == {"alice": "joined", "bob": "ringing"}
    assert call["chat_id"] == chat_id and call["started_by"] == alice.user_id

    ringing = bob.get("/api/calls").json["calls"]
    assert [c["id"] for c in ringing] == [call["id"]] and ringing[0]["chat_name"] == "alice"

    answered = bob.post(f"/api/calls/{call['id']}/answer").json["call"]
    assert states(answered) == {"alice": "joined", "bob": "joined"} and answered["answered_at"]

    # When one of two hangs up, the call is over for both.
    assert bob.post(f"/api/calls/{call['id']}/leave").status_code == 200
    assert alice.get("/api/calls").json["calls"] == []
    assert alice.post(f"/api/calls/{call['id']}/leave").status_code == 404


def test_decline_ends_a_two_person_call(alice_bob):
    alice, bob = alice_bob
    call = alice.post(f"/api/chats/{dm(alice)}/call").json["call"]
    assert bob.post(f"/api/calls/{call['id']}/decline").status_code == 200
    assert alice.get("/api/calls").json["calls"] == []


def test_calling_again_joins_the_running_call(alice_bob):
    alice, bob = alice_bob
    chat_id = dm(alice)
    first = alice.post(f"/api/chats/{chat_id}/call").json["call"]
    second = bob.post(f"/api/chats/{chat_id}/call").json["call"]
    assert second["id"] == first["id"] and states(second)["bob"] == "joined"


def test_outsiders_and_blocked_people_cant_call(alice_bob, make_client):
    alice, bob = alice_bob
    chat_id = dm(alice)
    call = alice.post(f"/api/chats/{chat_id}/call").json["call"]
    eve = user(make_client, "eve")
    assert eve.post(f"/api/chats/{chat_id}/call").status_code == 404
    assert eve.post(f"/api/calls/{call['id']}/answer").status_code == 404
    alice.post(f"/api/calls/{call['id']}/leave")
    bob.post("/api/block", json={"username": "alice"})
    assert alice.post(f"/api/chats/{chat_id}/call").status_code == 403


def test_ringing_stops_and_silent_browsers_leave(alice_bob, app_module, monkeypatch):
    alice, bob = alice_bob
    call = alice.post(f"/api/chats/{dm(alice)}/call").json["call"]
    monkeypatch.setattr(app_module, "CALL_RING_SECONDS", -1)
    assert bob.get("/api/calls").json["calls"] == []
    assert alice.get("/api/calls").json["calls"] == []

    call = alice.post(f"/api/chats/{dm(alice)}/call").json["call"]
    monkeypatch.setattr(app_module, "CALL_RING_SECONDS", 45)
    bob.post(f"/api/calls/{call['id']}/answer")
    # Alice's browser stops asking (tab closed): she counts as gone.
    monkeypatch.setattr(app_module, "CALL_GONE_SECONDS", -1)
    assert bob.get("/api/calls").json["calls"] == []


def test_only_one_call_at_a_time(make_client):
    alice = user(make_client, "alice")
    bob = user(make_client, "bob")
    carol = user(make_client, "carol")
    for other, name in ((bob, "bob"), (carol, "carol")):
        alice.post("/api/friends/request", json={"username": name})
        other.post("/api/friends/accept", json={"username": "alice"})
    with_bob = alice.post("/api/chats", json={"type": "dm", "username": "bob"}).json["chat_id"]
    with_carol = alice.post("/api/chats", json={"type": "dm", "username": "carol"}).json["chat_id"]
    first = alice.post(f"/api/chats/{with_bob}/call").json["call"]
    bob.post(f"/api/calls/{first['id']}/answer")
    alice.post(f"/api/chats/{with_carol}/call")
    # Starting the second call left the first one, which is over now.
    assert bob.get("/api/calls").json["calls"] == []


def signal(client, call_id, to, kind="offer"):
    return client.post(f"/api/calls/{call_id}/signal", json={"to": to, "kind": kind, "data": {"sdp": "v=0", "sig": "c2ln"}})


def test_signals_go_to_the_other_browser(alice_bob, make_client):
    alice, bob = alice_bob
    call = alice.post(f"/api/chats/{dm(alice)}/call").json["call"]
    # Only to people who joined.
    assert signal(alice, call["id"], bob.user_id).status_code == 409
    bob.post(f"/api/calls/{call['id']}/answer")
    assert signal(alice, call["id"], bob.user_id).status_code == 200
    got = bob.get("/api/calls").json["signals"]
    assert [(s["from"], s["kind"], s["data"]["sdp"]) for s in got] == [(alice.user_id, "offer", "v=0")]
    assert bob.get(f"/api/calls?after={got[-1]['id']}").json["signals"] == []
    assert alice.get("/api/calls").json["signals"] == []
    assert signal(bob, call["id"], alice.user_id, "answer").status_code == 200
    assert alice.get("/api/calls").json["signals"][0]["kind"] == "answer"
    # Not to yourself, no other kinds, nothing from outsiders.
    assert signal(alice, call["id"], alice.user_id).status_code == 409
    assert signal(alice, call["id"], bob.user_id, "evil").status_code == 400
    eve = user(make_client, "eve")
    assert signal(eve, call["id"], bob.user_id).status_code == 404
    # Ending the call drops what wasn't picked up.
    signal(alice, call["id"], bob.user_id)
    alice.post(f"/api/calls/{call['id']}/leave")
    assert bob.get("/api/calls").json["signals"] == []


def test_ice_servers(alice_bob, monkeypatch):
    alice, _ = alice_bob
    monkeypatch.delenv("TURN_URLS", raising=False)
    monkeypatch.delenv("STUN_URLS", raising=False)
    assert alice.get("/api/calls/ice").json["ice_servers"] == [{"urls": ["stun:stun.cloudflare.com:3478"]}]
    monkeypatch.setenv("TURN_URLS", "turn:turn.example.com:3478?transport=udp,turn:turn.example.com:3478?transport=tcp")
    monkeypatch.setenv("TURN_SECRET", "s3cret")
    stun, turn = alice.get("/api/calls/ice").json["ice_servers"]
    assert stun == {"urls": ["stun:turn.example.com:3478"]}
    assert len(turn["urls"]) == 2 and turn["username"].endswith(":" + alice.user_id)
    expected = base64.b64encode(hmac.new(b"s3cret", turn["username"].encode(), hashlib.sha1).digest()).decode()
    assert turn["credential"] == expected
