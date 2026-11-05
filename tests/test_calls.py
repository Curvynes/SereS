"""Voice calls: who is called, who joined, when a call is over."""

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
