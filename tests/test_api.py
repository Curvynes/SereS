import base64
import json
import os
import sqlite3
import uuid

import pytest


def b64(n=32):
    return base64.b64encode(os.urandom(n)).decode()


def keys():
    return {"pub_ecdh": b64(65), "pub_sign": b64(65), "enc_private": json.dumps({"iv": b64(12), "ct": b64(200)})}


def register(client, username, password_hash=None):
    password_hash = password_hash or b64()
    res = client.post(
        "/api/register",
        json={
            "username": username,
            "email": f"{username}@example.com",
            "auth_hash": password_hash,
            "kdf_salt": b64(16),
            "kdf_iterations": 600000,
            "keys": keys(),
        },
    )
    assert res.status_code == 200, res.json
    return password_hash


def login(client, username, password_hash):
    return client.post("/api/login", json={"nameomail": username, "auth_hash": password_hash})


def user(make_client, username):
    client = make_client()
    pw = register(client, username)
    res = login(client, username, pw)
    assert res.status_code == 200
    client.user_id = res.json["user"]["id"]
    return client


def befriend(a, b, b_name):
    assert a.post("/api/friends/request", json={"username": b_name}).json["status"] == "pending"


def envelope(member_ids):
    return {
        "v": 1,
        "iv": b64(12),
        "ct": b64(64),
        "sig": b64(64),
        "keys": {uid: {"iv": b64(12), "k": b64(48)} for uid in member_ids},
    }


@pytest.fixture
def alice_bob(make_client):
    alice = user(make_client, "alice")
    bob = user(make_client, "bob")
    befriend(alice, bob, "bob")
    assert bob.post("/api/friends/accept", json={"username": "alice"}).status_code == 200
    return alice, bob


def test_session_cookie_is_httponly_and_strict(make_client):
    client = make_client()
    pw = register(client, "carol")
    res = login(client, "carol", pw)
    cookie = res.headers.get("Set-Cookie")
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie
    assert login(client, "carol", b64()).status_code == 400
    assert client.get("/api/me").json["user"]["username"] == "carol"


def session_set_cookie(res):
    return next(c for c in res.headers.getlist("Set-Cookie") if c.startswith("sessioncookie="))


def test_login_cookie_only_persists_with_consent(make_client):
    client = make_client()
    pw = register(client, "dave")
    assert "Max-Age" not in session_set_cookie(login(client, "dave", pw))

    res = client.post("/api/cookie_consent", json={"accepted": True})
    assert "cookie_consent=accepted" in " ".join(res.headers.getlist("Set-Cookie"))
    assert "Max-Age" in session_set_cookie(res)
    assert "Max-Age" in session_set_cookie(login(client, "dave", pw))

    res = client.post("/api/cookie_consent", json={"accepted": False})
    assert "Max-Age" not in session_set_cookie(res)
    assert client.get("/api/me").json["user"]["username"] == "dave"


def test_invite_link_sends_friend_request(make_client):
    alice = user(make_client, "alice")
    bob = user(make_client, "bob")
    token = alice.get("/api/invite").json["token"]
    assert alice.get("/api/invite").json["token"] == token
    assert alice.get(f"/api/invite/{token}").json["status"] == "self"

    info = bob.get(f"/api/invite/{token}").json
    assert info["user"]["username"] == "alice" and info["status"] == "none"
    assert bob.post(f"/api/invite/{token}/accept").json["status"] == "pending"
    assert [u["username"] for u in alice.get("/api/friends").json["incoming"]] == ["bob"]

    new_token = alice.post("/api/invite/renew").json["token"]
    assert new_token != token
    assert bob.get(f"/api/invite/{token}").status_code == 404
    assert make_client().get(f"/api/invite/{new_token}").status_code == 401


def test_display_name_is_shown_and_not_unique(alice_bob, make_client):
    alice, bob = alice_bob
    assert alice.post("/api/profile/display_name", json={"display_name": "  Ali   Cat "}).json["display_name"] == "Ali Cat"
    assert bob.post("/api/profile/display_name", json={"display_name": "Ali Cat"}).status_code == 200
    assert alice.post("/api/profile/display_name", json={"display_name": "x" * 33}).status_code == 400

    friend = bob.get("/api/friends").json["friends"][0]
    assert friend["username"] == "alice" and friend["display_name"] == "Ali Cat"
    chat_id = bob.post("/api/chats", json={"type": "dm", "username": "alice"}).json["chat_id"]
    assert bob.get(f"/api/chats/{chat_id}").json["chat"]["name"] == "Ali Cat"

    assert alice.post("/api/profile/display_name", json={"display_name": ""}).json["display_name"] == "alice"
    assert alice.get("/api/me").json["user"]["display_name"] == "alice"


def test_unblock_restores_friendship(alice_bob):
    alice, bob = alice_bob
    alice.post("/api/block", json={"username": "bob"})
    assert alice.get("/api/friends").json["friends"] == []
    assert alice.post("/api/unblock", json={"username": "bob"}).json["friends"] is True
    assert [u["username"] for u in alice.get("/api/friends").json["friends"]] == ["bob"]


def test_profile_and_mute(alice_bob):
    alice, bob = alice_bob
    chat_id = alice.post("/api/chats", json={"type": "dm", "username": "bob"}).json["chat_id"]
    profile = alice.get("/api/users/bob/profile").json
    assert profile["friend"] and not profile["muted"] and not profile["blocked"]
    assert profile["user"]["pub_ecdh"]

    assert alice.post("/api/users/mute", json={"username": "bob", "muted": True}).json["muted"] is True
    assert alice.get("/api/users/bob/profile").json["muted"] is True
    assert alice.get(f"/api/chats/{chat_id}").json["chat"]["muted"] is True
    assert bob.get(f"/api/chats/{chat_id}").json["chat"]["muted"] is False
    alice.post("/api/users/mute", json={"username": "bob", "muted": False})
    assert alice.get(f"/api/chats/{chat_id}").json["chat"]["muted"] is False
    assert alice.get("/api/users/nobody/profile").status_code == 404


def test_message_info_shows_delivered_and_read(alice_bob):
    alice, bob = alice_bob
    chat_id = alice.post("/api/chats", json={"type": "dm", "username": "bob"}).json["chat_id"]
    message_id = str(uuid.uuid4())
    alice.post(f"/api/chats/{chat_id}/messages", json={"id": message_id, "payload": envelope([alice.user_id, bob.user_id])})

    info = alice.get(f"/api/chats/{chat_id}/messages/{message_id}/info").json
    assert info["sent_at"] and info["members"][0]["delivered"] is False

    receipts = alice.get(f"/api/chats/{chat_id}/messages").json["receipts"]
    seq = bob.get(f"/api/chats/{chat_id}/messages").json["messages"][-1]["seq"]
    assert receipts["delivered_seq"] < seq
    member = alice.get(f"/api/chats/{chat_id}/messages/{message_id}/info").json["members"][0]
    assert member["delivered"] and member["delivered_at"] and not member["read"]
    receipts = alice.get(f"/api/chats/{chat_id}/messages").json["receipts"]
    assert receipts["delivered_seq"] >= seq and receipts["read_seq"] < seq

    bob.post(f"/api/chats/{chat_id}/read", json={"seq": seq})
    assert alice.get(f"/api/chats/{chat_id}/messages").json["receipts"]["read_seq"] >= seq
    member = alice.get(f"/api/chats/{chat_id}/messages/{message_id}/info").json["members"][0]
    assert member["read"] and member["read_at"] and member["username"] == "bob"


def test_edit_and_delete_message(alice_bob):
    alice, bob = alice_bob
    chat_id = alice.post("/api/chats", json={"type": "dm", "username": "bob"}).json["chat_id"]
    message_id = str(uuid.uuid4())
    members = [alice.user_id, bob.user_id]
    alice.post(f"/api/chats/{chat_id}/messages", json={"id": message_id, "payload": envelope(members)})

    new_payload = envelope(members)
    assert bob.post(f"/api/chats/{chat_id}/messages/{message_id}/edit", json={"payload": new_payload}).status_code == 404
    assert alice.post(f"/api/chats/{chat_id}/messages/{message_id}/edit", json={"payload": new_payload}).status_code == 200
    message = bob.get(f"/api/chats/{chat_id}/messages").json["messages"][-1]
    assert message["payload"] == new_payload and message["edited_at"]

    alice.post(f"/api/chats/{chat_id}/messages/{message_id}/delete")
    assert bob.get(f"/api/chats").json["chats"][0]["last_message"] is None
    assert alice.post(f"/api/chats/{chat_id}/messages/{message_id}/edit", json={"payload": new_payload}).status_code == 404


def test_typing_indicator(alice_bob):
    alice, bob = alice_bob
    chat_id = alice.post("/api/chats", json={"type": "dm", "username": "bob"}).json["chat_id"]
    assert bob.get(f"/api/chats/{chat_id}/messages").json["typing"] == []
    alice.post(f"/api/chats/{chat_id}/typing", json={"typing": True})
    assert [u["username"] for u in bob.get(f"/api/chats/{chat_id}/messages").json["typing"]] == ["alice"]
    assert alice.get(f"/api/chats/{chat_id}/messages").json["typing"] == []
    assert bob.get("/api/chats").json["chats"][0]["typing"][0]["username"] == "alice"
    alice.post(f"/api/chats/{chat_id}/typing", json={"typing": False})
    assert bob.get(f"/api/chats/{chat_id}/messages").json["typing"] == []


def test_security_headers(make_client):
    res = make_client().get("/api/online")
    assert "script-src 'self'" in res.headers["Content-Security-Policy"]
    assert res.headers["X-Content-Type-Options"] == "nosniff"


def test_cross_site_post_rejected(make_client):
    client = make_client()
    res = client.post("/api/logout", headers={"Origin": "https://evil.example"})
    assert res.status_code == 403


def test_prelogin_unknown_user_is_stable(make_client):
    client = make_client()
    a = client.post("/api/prelogin", json={"nameomail": "nobody"}).json
    b = client.post("/api/prelogin", json={"nameomail": "nobody"}).json
    assert a["kdf_salt"] == b["kdf_salt"] and a["legacy"] is False


def test_duplicate_username_case_insensitive(make_client):
    client = make_client()
    register(client, "Dave")
    res = client.post(
        "/api/register",
        json={"username": "dave", "email": "x@y.de", "auth_hash": b64(), "kdf_salt": b64(16), "kdf_iterations": 600000, "keys": keys()},
    )
    assert res.status_code == 400


def test_requires_login(make_client):
    assert make_client().get("/api/chats").status_code == 401


def test_dm_flow_and_ciphertext_only(alice_bob, app_module):
    alice, bob = alice_bob
    chat_id = alice.post("/api/chats", json={"type": "dm", "username": "bob"}).json["chat_id"]
    # Opening the DM again returns the same chat.
    assert bob.post("/api/chats", json={"type": "dm", "username": "alice"}).json["chat_id"] == chat_id

    members = [alice.user_id, bob.user_id]
    msg_id = str(uuid.uuid4())
    res = alice.post(f"/api/chats/{chat_id}/messages", json={"id": msg_id, "payload": envelope(members)})
    assert res.status_code == 200, res.json

    # Missing a member's key is rejected.
    res = alice.post(f"/api/chats/{chat_id}/messages", json={"id": str(uuid.uuid4()), "payload": envelope([alice.user_id])})
    assert res.status_code == 409
    # Plaintext is rejected.
    res = alice.post(f"/api/chats/{chat_id}/messages", json={"id": str(uuid.uuid4()), "payload": {"text": "hi"}})
    assert res.status_code == 400

    chats = bob.get("/api/chats").json["chats"]
    assert chats[0]["unread"] == 1 and chats[0]["other_user"] == "alice"
    msgs = bob.get(f"/api/chats/{chat_id}/messages").json["messages"]
    assert len(msgs) == 1 and msgs[0]["payload"]["v"] == 1

    bob.post(f"/api/chats/{chat_id}/read", json={"seq": msgs[0]["seq"]})
    assert bob.get("/api/chats").json["chats"][0]["unread"] == 0

    # Incremental sync and deletion
    rev = msgs[0]["rev"]
    assert bob.get(f"/api/chats/{chat_id}/messages?since_rev={rev}").json["messages"] == []
    assert bob.post(f"/api/chats/{chat_id}/messages/{msg_id}/delete").status_code == 404
    assert alice.post(f"/api/chats/{chat_id}/messages/{msg_id}/delete").status_code == 200
    changed = bob.get(f"/api/chats/{chat_id}/messages?since_rev={rev}").json["messages"]
    assert changed[0]["deleted"] and changed[0]["payload"] is None


def test_outsider_cannot_read(alice_bob, make_client):
    alice, _ = alice_bob
    chat_id = alice.post("/api/chats", json={"type": "dm", "username": "bob"}).json["chat_id"]
    eve = user(make_client, "eve")
    assert eve.get(f"/api/chats/{chat_id}/messages").status_code == 404
    assert eve.post(f"/api/chats/{chat_id}/messages", json={"id": str(uuid.uuid4()), "payload": envelope([])}).status_code == 404
    assert eve.get("/api/users/alice/avatar").status_code == 404


def test_dm_requires_friendship(make_client):
    alice = user(make_client, "alice")
    user(make_client, "bob")
    assert alice.post("/api/chats", json={"type": "dm", "username": "bob"}).status_code == 400


def test_delete_dm_only_for_me(alice_bob):
    alice, bob = alice_bob
    chat_id = alice.post("/api/chats", json={"type": "dm", "username": "bob"}).json["chat_id"]
    alice.post(f"/api/chats/{chat_id}/messages", json={"id": str(uuid.uuid4()), "payload": envelope([alice.user_id, bob.user_id])})
    alice.post(f"/api/chats/{chat_id}/delete")
    assert alice.get("/api/chats").json["chats"] == []
    assert len(bob.get("/api/chats").json["chats"]) == 1
    # A new message brings it back, but without the cleared history.
    bob.post(f"/api/chats/{chat_id}/messages", json={"id": str(uuid.uuid4()), "payload": envelope([alice.user_id, bob.user_id])})
    assert len(alice.get(f"/api/chats/{chat_id}/messages").json["messages"]) == 1


def test_block_stops_dm(alice_bob):
    alice, bob = alice_bob
    chat_id = alice.post("/api/chats", json={"type": "dm", "username": "bob"}).json["chat_id"]
    bob.post("/api/block", json={"username": "alice"})
    res = alice.post(f"/api/chats/{chat_id}/messages", json={"id": str(uuid.uuid4()), "payload": envelope([alice.user_id, bob.user_id])})
    assert res.status_code == 403
    assert alice.post("/api/friends/request", json={"username": "bob"}).status_code == 400
    assert bob.get("/api/friends").json["blocked"][0]["username"] == "alice"


def test_friend_request_reverse_accepts(make_client):
    alice = user(make_client, "alice")
    bob = user(make_client, "bob")
    alice.post("/api/friends/request", json={"username": "bob"})
    assert bob.get("/api/friends").json["incoming"][0]["username"] == "alice"
    assert bob.post("/api/friends/request", json={"username": "alice"}).json["status"] == "friends"
    assert alice.get("/api/friends").json["friends"][0]["username"] == "bob"
    assert bob.post("/api/friends/decline", json={"username": "alice"}).status_code == 400


def test_group_lifecycle(alice_bob, make_client):
    alice, bob = alice_bob
    carol = user(make_client, "carol")
    alice.post("/api/friends/request", json={"username": "carol"})
    carol.post("/api/friends/accept", json={"username": "alice"})

    res = alice.post("/api/chats", json={"type": "group", "name": "Team", "usernames": ["bob"]})
    chat_id = res.json["chat_id"]
    alice.post(f"/api/chats/{chat_id}/messages", json={"id": str(uuid.uuid4()), "payload": envelope([alice.user_id, bob.user_id])})

    assert bob.post(f"/api/chats/{chat_id}/members", json={"username": "carol"}).status_code == 400  # not bob's friend
    assert alice.post(f"/api/chats/{chat_id}/members", json={"username": "carol"}).status_code == 200
    # Carol only sees what happened after she joined.
    kinds = [m["kind"] for m in carol.get(f"/api/chats/{chat_id}/messages").json["messages"]]
    assert kinds == ["system"]
    details = carol.get(f"/api/chats/{chat_id}").json["chat"]
    assert {m["username"] for m in details["members"]} == {"alice", "bob", "carol"}

    assert bob.post(f"/api/chats/{chat_id}/rename", json={"name": "x"}).status_code == 403
    assert alice.post(f"/api/chats/{chat_id}/members/remove", json={"username": "carol"}).status_code == 200
    assert carol.get(f"/api/chats/{chat_id}").status_code == 404

    alice.post(f"/api/chats/{chat_id}/leave")
    details = bob.get(f"/api/chats/{chat_id}").json["chat"]
    assert details["role"] == "owner"


def test_change_password_invalidates_other_sessions(make_client):
    c1 = make_client()
    pw = register(c1, "frank")
    login(c1, "frank", pw)
    c2 = make_client()
    login(c2, "frank", pw)
    new = b64()
    res = c1.post(
        "/api/change_password",
        json={"old_auth_hash": pw, "auth_hash": new, "kdf_salt": b64(16), "kdf_iterations": 600000, "enc_private": "{}"},
    )
    assert res.status_code == 200
    assert c1.get("/api/me").status_code == 200
    assert c2.get("/api/me").status_code == 401
    assert login(make_client(), "frank", new).status_code == 200


def test_legacy_account_and_chat_migration(tmp_path, monkeypatch):
    """Accounts and chats from the old file based storage keep working."""
    import importlib
    import sys

    from argon2 import PasswordHasher

    data = tmp_path
    ph = PasswordHasher()
    conn = sqlite3.connect(data / "users.db")
    conn.execute("CREATE TABLE users (id VARCHAR(255) PRIMARY KEY, email VARCHAR(255), username VARCHAR(255), passwd TEXT)")
    conn.execute("INSERT INTO users VALUES ('u1', 'a@a.de', 'olda', ?)", (ph.hash("password1"),))
    conn.execute("INSERT INTO users VALUES ('u2', 'b@b.de', 'oldb', ?)", (ph.hash("password2"),))
    conn.commit()
    conn.close()
    (data / "user_data" / "u1").mkdir(parents=True)
    (data / "user_data" / "u1" / "friends.json").write_text(json.dumps({"friends": ["u2"]}))
    chat = data / "chats" / "11111111-1111-1111-1111-111111111111"
    chat.mkdir(parents=True)
    (chat / "users.json").write_text(json.dumps({"users": ["u1", "u2"]}))
    hist = sqlite3.connect(chat / "history.db")
    hist.execute("CREATE TABLE messages (id VARCHAR(255) PRIMARY KEY, sender_id VARCHAR(255), content TEXT, timestamp TIMESTAMP)")
    hist.execute("INSERT INTO messages VALUES ('m1', 'u1', 'hello <b>', '2026-01-01 10:00:00')")
    hist.commit()
    hist.close()

    monkeypatch.setenv("SERES_DATA_DIR", str(data))
    monkeypatch.setenv("URL", "")
    for name in ("app", "db", "legacy_migration"):
        sys.modules.pop(name, None)
    module = importlib.import_module("app")
    client = module.app.test_client()

    pre = client.post("/api/prelogin", json={"nameomail": "olda"}).json
    assert pre["legacy"] is True and pre["kdf_salt"]
    auth = b64()
    # Without the old password the upgrade is refused.
    assert client.post("/api/login", json={"nameomail": "olda", "auth_hash": auth, "keys": keys()}).status_code == 400
    res = client.post("/api/login", json={"nameomail": "olda", "auth_hash": auth, "passwd": "password1", "keys": keys()})
    assert res.status_code == 200
    assert client.post("/api/prelogin", json={"nameomail": "olda"}).json["legacy"] is False

    chats = client.get("/api/chats").json["chats"]
    assert chats[0]["other_user"] == "oldb"
    msgs = client.get(f"/api/chats/{chats[0]['id']}/messages").json["messages"]
    assert msgs[0]["kind"] == "legacy" and msgs[0]["payload"]["text"] == "hello <b>"
    assert client.get("/api/friends").json["friends"][0]["username"] == "oldb"

    # A second login uses the new hash only.
    client2 = module.app.test_client()
    assert client2.post("/api/login", json={"nameomail": "olda", "auth_hash": auth}).status_code == 200


def test_same_origin_post_allowed_behind_proxy(make_client):
    client = make_client()
    res = client.post("/api/logout", headers={"Origin": "https://localhost"})
    assert res.status_code == 200


def test_client_ip_behind_tunnel(app_module):
    def ip(remote, headers=None):
        with app_module.app.test_request_context("/", headers=headers or {}, environ_base={"REMOTE_ADDR": remote}):
            return app_module.client_ip()

    # cloudflared / a reverse proxy on the same server passes on the visitor's IP
    assert ip("127.0.0.1", {"CF-Connecting-IP": "203.0.113.7"}) == "203.0.113.7"
    assert ip("::1", {"X-Forwarded-For": "198.51.100.1, 203.0.113.8"}) == "203.0.113.8"
    assert ip("127.0.0.1") == "127.0.0.1"
    # from the internet the headers are ignored, so nobody picks their own IP
    assert ip("203.0.113.9", {"CF-Connecting-IP": "1.2.3.4", "X-Forwarded-For": "1.2.3.4"}) == "203.0.113.9"


def test_pages_are_checked_again_after_updates(make_client):
    client = make_client()
    assert client.get("/index.js").headers["Cache-Control"] == "no-cache"
    assert client.get("/api/me").headers["Cache-Control"] == "no-store"
