"""Integration checks for group pictures and encrypted scheduled delivery."""

import datetime
import io
import time
import uuid

from PIL import Image

from test_api import alice_bob, envelope, user  # noqa: F401


def picture():
    output = io.BytesIO()
    Image.new("RGB", (2, 2), "red").save(output, "PNG")
    output.seek(0)
    return output


def test_group_picture_upload_and_remove(alice_bob, make_client):
    alice, bob = alice_bob
    eve = user(make_client, "eve")
    chat_id = alice.post("/api/chats", json={"type": "group", "name": "Team", "usernames": ["bob"]}).json["chat_id"]
    url = f"/api/chats/{chat_id}/avatar"
    assert bob.post(url, data={"avatar_img": (picture(), "image.png")}).status_code == 403
    assert alice.post(url, data={"avatar_img": (picture(), "image.png")}).status_code == 200
    assert bob.get(url).status_code == 200
    assert eve.get(url).status_code == 404
    assert bob.get(f"/api/chats/{chat_id}").json["chat"]["avatar_updated_at"]
    assert bob.delete(url).status_code == 403
    assert alice.delete(url).status_code == 200
    assert bob.get(url).status_code == 404
    assert bob.get(f"/api/chats/{chat_id}").json["chat"]["avatar_updated_at"] is None


def test_scheduled_message_delivers_ciphertext(alice_bob, app_module):
    alice, bob = alice_bob
    chat_id = alice.post("/api/chats", json={"type": "dm", "username": "bob"}).json["chat_id"]
    message_id = str(uuid.uuid4())
    payload = envelope([alice.user_id, bob.user_id])
    send_at = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=2)).isoformat()
    url = f"/api/chats/{chat_id}/scheduled"
    assert alice.post(url, json={"id": message_id, "payload": payload, "send_at": send_at}).status_code == 200
    assert bob.get(url).json["messages"] == []
    assert bob.get(f"/api/chats/{chat_id}/messages").json["messages"] == []
    conn = app_module.db.connect(app_module.DB)
    conn.execute("UPDATE scheduled_messages SET send_at = '2000-01-01T00:00:00Z' WHERE id = ?", (message_id,))
    conn.commit()
    conn.close()
    for _ in range(30):
        messages = bob.get(f"/api/chats/{chat_id}/messages").json["messages"]
        if messages:
            break
        time.sleep(0.25)
    assert len(messages) == 1
    assert messages[0]["id"] == message_id and messages[0]["payload"] == payload
    assert alice.get(url).json["messages"] == []
