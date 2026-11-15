const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { resolve } = require('node:path');
const ts = require('typescript');
const { JSDOM } = require('jsdom');
const { EventEmitter } = require('node:events');
const source = readFileSync(resolve(__dirname, '../frontend/matrix.ts'), 'utf8').replace(/^import .*;\r?\n/gm, '');
const compiled = ts.transpileModule(source + `
window.testApi = { renderRoom, renderRoomList, saveSession, savedSession, cryptoStoreName, matrixServerName, showCall, stop, activate, connect, openMatrixRtc, joinRoomPrompt, joinRoomTarget, parseRoomTarget, handleRoomUpdate, createRoom, inviteToRoom, addJitsi,
  setClient(value) { client = value; },
  select(room, thread = '') { selectedRoomId = room; threadRootId = thread; },
  space(id) { selectedSpaceId = id; },
  markThreadRead, setActive(value) { active = value; },
  drafts, mediaNodes,
};`, { compilerOptions: { target: ts.ScriptTarget.ES2020, module: ts.ModuleKind.None } }).outputText;
function environment() {
  const dom = new JSDOM('<div class="sidebar"></div><div id="matrix-list"></div><div id="matrix-app-root"></div>', { url: 'https://seres.example/index.html', runScripts: 'outside-only' });
  const w = dom.window;
  w.prompt = () => { throw new Error('prompt() is not supported.'); };
  w.HTMLDialogElement.prototype.showModal = function () { this.setAttribute('open', ''); };
  w.HTMLDialogElement.prototype.close = function () { this.removeAttribute('open'); };
  w.sdk = { EventType: { RoomMessage: 'm.room.message' }, KnownMembership: { Join: 'join', Invite: 'invite' }, NotificationCountType: { Total: 'total' }, CallEvent: { FeedsChanged: 'feeds', State: 'state', Hangup: 'hangup', Error: 'error' }, MatrixEventEvent: { Decrypted: 'decrypted' }, RoomMemberEvent: { Name: 'memberName' }, UserEvent: { DisplayName: 'displayName' }, RoomEvent: { Timeline: 'timeline', Name: 'name', MyMembership: 'membership' }, ClientEvent: { Sync: 'sync', Room: 'room' }, SyncState: { Prepared: 'prepared' } };
  w.sdk.RoomEvent.LocalEchoUpdated = 'Room.localEchoUpdated';
  w.sdk.RoomEvent.UnreadNotifications = 'Room.UnreadNotifications';
  w.sdk.ThreadEvent = { Update: 'Thread.update', NewReply: 'Thread.newReply' };
  w.URL.revokeObjectURL = () => {};
  w.eval(compiled);
  const api = w.testApi;
  const rooms = new Map();
  const matrix = { getRoom: (id) => rooms.get(id), getRooms: () => [...rooms.values()], getUserId: () => '@me:example.org', stopClient() {}, removeAllListeners() {} };
  for (const id of ['!a:example.org', '!b:example.org']) rooms.set(id, {
    roomId: id, name: id, getJoinedMemberCount: () => 2, hasEncryptionStateEvent: () => true,
    getLiveTimeline: () => ({ getEvents: () => [] }), getThread: () => null, getMyMembership: () => 'join', isSpaceRoom: () => false,
    currentState: { getStateEvents: () => null }, getUnreadNotificationCount: () => 0,
  });
  api.setClient(matrix);
  api.select('!a:example.org');
  return { dom, w, api, matrix, rooms, close: () => dom.window.close() };
}
function type(w, value) {
  const input = w.document.querySelector('.matrix-compose-input');
  input.value = value;
  input.dispatchEvent(new w.Event('input'));
}
function submit(w) { w.document.querySelector('.matrix-compose').dispatchEvent(new w.Event('submit', { cancelable: true })); }
function submitDialog(e, values) {
  const form = e.w.document.querySelector('.matrix-input-form');
  if (values) form.querySelectorAll('input').forEach((input, i) => { input.value = values[i] || ''; });
  form.dispatchEvent(new e.w.Event('submit', { cancelable: true }));
}
const tick = () => new Promise((resolve) => setImmediate(resolve));

test('rooms and Spaces can be created without browser prompts', async () => {
  const e = environment();
  try {
    e.w.sdk.Visibility = { Private: 'private' };
    e.w.sdk.Preset = { PrivateChat: 'private_chat' };
    e.w.sdk.EventType.RoomEncryption = 'm.room.encryption';
    const requests = [];
    e.matrix.createRoom = async (options) => { requests.push(options); return { room_id: '!created:example.org' }; };
    for (const isSpace of [false, true]) {
      const task = e.api.createRoom(isSpace);
      assert.equal(e.w.document.activeElement, e.w.document.querySelector('.matrix-input-dialog input'));
      submitDialog(e, [' New name ', '@alex:matrix.org, @alex:matrix.org']);
      await task;
      assert.equal(e.w.document.querySelector('dialog'), null);
    }
    assert.equal(requests.length, 2);
    assert.equal(requests[0].name, 'New name');
    assert.deepEqual(Array.from(requests[0].invite), ['@alex:matrix.org']);
    assert.equal(requests[0].initial_state[0].type, 'm.room.encryption');
    assert.equal(requests[1].creation_content.type, 'm.space');
    assert.equal(requests[1].initial_state.length, 0);
  } finally { e.close(); }
});

test('cancel, Escape, replacement and logout dismiss input without sending requests', async () => {
  const e = environment();
  try {
    let requests = 0;
    e.matrix.joinRoom = async () => { requests++; };
    let task = e.api.joinRoomPrompt();
    e.w.document.querySelector('.matrix-input-actions button').click();
    await task;
    task = e.api.joinRoomPrompt();
    e.w.document.querySelector('dialog').dispatchEvent(new e.w.Event('cancel', { cancelable: true }));
    await task;
    task = e.api.joinRoomPrompt();
    const replacement = e.api.joinRoomPrompt();
    await task;
    assert.equal(e.w.document.querySelectorAll('dialog').length, 1);
    await e.api.stop();
    await replacement;
    assert.equal(e.w.document.querySelector('dialog'), null);
    assert.equal(requests, 0);
  } finally { e.close(); }
});

test('invites validate IDs and Jitsi input stays bound to the original room', async () => {
  const e = environment();
  try {
    const invites = [];
    e.matrix.invite = async (...args) => { invites.push(args); };
    let task = e.api.inviteToRoom('!a:example.org');
    submitDialog(e, ['invalid']); await task;
    assert.equal(invites.length, 0);
    task = e.api.inviteToRoom('!a:example.org');
    submitDialog(e, ['@alex:matrix.org']); await task;
    assert.deepEqual(invites[0], ['!a:example.org', '@alex:matrix.org']);
    const writes = [];
    e.matrix.sendStateEvent = async (...args) => { writes.push(args); };
    task = e.api.addJitsi();
    assert.match(e.w.document.querySelector('dialog input').value, /^https:\/\/meet.jit.si\//);
    e.api.select('!b:example.org');
    submitDialog(e, ['https://meet.jit.si/seres-test']); await task;
    assert.equal(writes[0][0], '!a:example.org');
    assert.equal(writes[0][2].roomId, '!a:example.org');
  } finally { e.close(); }
});

test('drafts are isolated by room and thread and survive rerenders', () => {
  const e = environment();
  try {
    e.api.renderRoom(); type(e.w, 'room A draft');
    e.api.select('!b:example.org'); e.api.renderRoom();
    assert.equal(e.w.document.querySelector('textarea').value, '');
    type(e.w, 'room B draft'); e.api.select('!a:example.org'); e.api.renderRoom();
    assert.equal(e.w.document.querySelector('textarea').value, 'room A draft');
    e.api.select('!a:example.org', '$thread'); e.api.renderRoom();
    assert.equal(e.w.document.querySelector('textarea').value, '');
  } finally { e.close(); }
});

test('completing a send after switching rooms preserves the other draft and prevents duplicate sends', async () => {
  const e = environment();
  try {
    let finish; let sends = 0;
    e.matrix.sendEvent = () => { sends++; return new Promise((resolve) => { finish = resolve; }); };
    e.api.renderRoom(); type(e.w, 'send from A'); submit(e.w); submit(e.w);
    assert.equal(sends, 1);
    e.api.select('!b:example.org'); e.api.renderRoom(); type(e.w, 'unsent in B');
    finish(); await tick();
    assert.equal(e.w.document.querySelector('textarea').value, 'unsent in B');
    e.api.select('!a:example.org'); e.api.renderRoom();
    assert.equal(e.w.document.querySelector('textarea').value, '');
    assert.equal(e.w.document.querySelector('textarea').disabled, false);
  } finally { e.close(); }
});

test('failed sends retain the draft and reenable the composer', async () => {
  const e = environment();
  try {
    e.matrix.sendEvent = async () => { throw new Error('offline'); };
    e.api.renderRoom(); type(e.w, 'retry this'); submit(e.w); await tick();
    assert.equal(e.w.document.querySelector('textarea').value, 'retry this');
    assert.equal(e.w.document.querySelector('textarea').disabled, false);
  } finally { e.close(); }
});

test('Enter sends room and thread messages while Shift+Enter and IME input keep editing', async () => {
  const e = environment();
  try {
    const sends = [];
    e.matrix.sendEvent = async (...args) => { sends.push(args); };
    for (const thread of ['', '$thread']) {
      e.api.select('!a:example.org', thread);
      e.api.renderRoom(); type(e.w, 'Hello');
      const input = e.w.document.querySelector('.matrix-compose-input');
      for (const options of [{ shiftKey: true }, { isComposing: true }, { keyCode: 229 }]) {
        const key = new e.w.KeyboardEvent('keydown', { key: 'Enter', cancelable: true, ...options });
        input.dispatchEvent(key);
        assert.equal(key.defaultPrevented, false);
      }
      const before = sends.length;
      assert.equal(input.value, 'Hello');
      const enter = new e.w.KeyboardEvent('keydown', { key: 'Enter', cancelable: true });
      input.dispatchEvent(enter);
      assert.equal(enter.defaultPrevented, true);
      assert.equal(sends.length, before + 1);
      assert.equal(sends.at(-1)[2].body, 'Hello');
      assert.equal(sends.at(-1)[2]['m.relates_to']?.event_id, thread || undefined);
      await tick();
    }
    assert.equal(sends.length, 2);
  } finally { e.close(); }
});

test('own thread replies stay visible before sync and appear once after sync', () => {
  const e = environment();
  try {
    const message = (id, body, thread = '') => ({
      getId: () => id, getType: () => 'm.room.message', getSender: () => '@me:example.org', getDate: () => null,
      getContent: () => ({ body, ...(thread ? { 'm.relates_to': { rel_type: 'm.thread', event_id: thread } } : {}) }),
    });
    const root = message('$root', 'My original message');
    const reply = message('~local', 'My own reply', '$root');
    const unrelated = message('$other', 'Another thread', '$different');
    const roomEvents = [root, reply, unrelated];
    const threadEvents = [root];
    const room = e.rooms.get('!a:example.org');
    room.getLiveTimeline = () => ({ getEvents: () => roomEvents });
    room.getThread = () => ({ rootEvent: root, timelineSet: { getLiveTimeline: () => ({ getEvents: () => threadEvents }) } });
    e.api.select(room.roomId, '$root');
    e.api.renderRoom();
    const bodies = () => Array.from(e.w.document.querySelectorAll('.matrix-message-body'), (node) => node.textContent);
    assert.deepEqual(bodies(), ['My original message', 'My own reply']);
    reply.getId = () => '$synced';
    threadEvents.push(message('$synced', 'My own reply', '$root'));
    e.api.renderRoom();
    assert.deepEqual(bodies(), ['My original message', 'My own reply']);
  } finally { e.close(); }
});

test('thread read receipts are scoped, deduplicated and clear only the target thread', async () => {
  const e = environment();
  try {
    const room = e.rooms.get('!a:example.org');
    const reply = (id, thread, status = null) => ({
      getId: () => id, status, getType: () => 'm.room.message', getDate: () => null,
      getContent: () => ({ body: id, 'm.relates_to': { rel_type: 'm.thread', event_id: thread } }),
      getSender: () => '@other:example.org',
    });
    const read = reply('$read', '$root');
    room.getLiveTimeline = () => ({ getEvents: () => [read, reply('~pending', '$root', 'sending'), reply('$other', '$another')] });
    const counts = new Map([['$root', 2], ['$another', 3]]);
    room.setThreadUnreadNotificationCount = (id, _type, count) => counts.set(id, count);
    const receipts = [];
    let finish;
    e.matrix.sendReadReceipt = (...args) => { receipts.push(args); return new Promise((resolve) => { finish = resolve; }); };
    const task = e.api.markThreadRead(room, '$root');
    await e.api.markThreadRead(room, '$root');
    assert.equal(receipts.length, 1);
    assert.equal(receipts[0][0], read);
    assert.equal(receipts[0].length, 1);
    assert.equal(counts.get('$root'), 2);
    finish(); await task;
    assert.equal(counts.get('$root'), 0);
    assert.equal(counts.get('$another'), 3);
    await e.api.markThreadRead(room, '$root');
    assert.equal(receipts.length, 1);
  } finally { e.close(); }
});

test('thread read failures preserve unread counts and can be retried using the button', async () => {
  const e = environment();
  try {
    const room = e.rooms.get('!a:example.org');
    const reply = {
      getId: () => '$reply', getType: () => 'm.room.message', getDate: () => null, getSender: () => '@other:example.org',
      getContent: () => ({ body: 'Unread reply', 'm.relates_to': { rel_type: 'm.thread', event_id: '$root' } }),
    };
    room.getLiveTimeline = () => ({ getEvents: () => [reply] });
    let cleared = 0;
    room.setThreadUnreadNotificationCount = () => { cleared++; };
    e.matrix.sendReadReceipt = async () => { throw new Error('offline'); };
    await e.api.markThreadRead(room, '$root');
    assert.equal(cleared, 0);
    assert.match(e.w.document.querySelector('.matrix-toast').textContent, /offline/);
    e.matrix.sendReadReceipt = async () => {};
    e.api.select(room.roomId, '$root'); e.api.renderRoom();
    Array.from(e.w.document.querySelectorAll('.matrix-header-actions button')).find((button) => button.textContent === 'Mark thread as read').click();
    await tick();
    assert.equal(cleared, 2);
  } finally { e.close(); }
});

test('automatic thread reads wait for a visible active view at the bottom', async () => {
  const e = environment();
  try {
    const room = e.rooms.get('!a:example.org');
    const events = [{
      getId: () => '$reply', getType: () => 'm.room.message', getDate: () => null, getSender: () => '@other:example.org',
      getContent: () => ({ body: 'Reply', 'm.relates_to': { rel_type: 'm.thread', event_id: '$root' } }),
    }];
    room.getLiveTimeline = () => ({ getEvents: () => events });
    room.setThreadUnreadNotificationCount = () => {};
    let sends = 0;
    e.matrix.sendReadReceipt = async () => { sends++; };
    e.api.select(room.roomId, '$root');
    e.api.renderRoom(); assert.equal(sends, 0);
    e.api.setActive(true);
    e.api.renderRoom(); assert.equal(sends, 0);
    Object.defineProperty(e.w.document, 'visibilityState', { value: 'visible', configurable: true });
    e.api.renderRoom(); await tick(); assert.equal(sends, 1);
    events.push({ ...events[0], getId: () => '$new' });
    const timeline = e.w.document.querySelector('.matrix-timeline');
    Object.defineProperty(timeline, 'scrollHeight', { value: 1000, configurable: true });
    Object.defineProperty(timeline, 'clientHeight', { value: 200, configurable: true });
    timeline.scrollTop = 0;
    e.api.renderRoom(); assert.equal(sends, 1);
    timeline.scrollTop = 800;
    timeline.dispatchEvent(new e.w.Event('scroll')); await tick(); assert.equal(sends, 2);
  } finally { e.close(); }
});

test('room messages identify their thread replies and unread counts and open the correct thread', () => {
  const e = environment();
  try {
    const message = (id, body, thread = '') => ({
      getId: () => id, getType: () => 'm.room.message', getSender: () => '@other:example.org', getDate: () => null,
      getContent: () => ({ body, ...(thread ? { 'm.relates_to': { rel_type: 'm.thread', event_id: thread } } : {}) }),
    });
    const root = message('$root', 'Original message');
    const other = message('$other', 'Unrelated message');
    const reply = message('$reply', 'Thread reply', '$root');
    const events = [root, other];
    const room = Object.assign(new EventEmitter(), e.rooms.get('!a:example.org'));
    e.rooms.set(room.roomId, room);
    room.getLiveTimeline = () => ({ getEvents: () => events });
    const thread = { rootEvent: root, length: 2, timelineSet: { getLiveTimeline: () => ({ getEvents: () => [root, reply] }) } };
    room.getThread = (id) => id === '$root' ? thread : null;
    let unread = 1;
    room.getThreadUnreadNotificationCount = (id) => id === '$root' ? unread : 0;
    e.api.renderRoom();
    const button = () => e.w.document.querySelector('[data-event-id="$root"] .matrix-thread-button');
    assert.match(button().textContent, /2 replies in thread/);
    assert.equal(button().querySelector('.matrix-thread-unread-count').textContent, '1 unread');
    assert.equal(e.w.document.querySelector('[data-event-id="$other"] .matrix-thread-button').textContent, 'Reply in thread');
    assert.equal(e.w.document.querySelectorAll('.matrix-message').length, 2);
    thread.length = 3;
    room.emit(e.w.sdk.ThreadEvent.Update, thread);
    assert.match(button().textContent, /3 replies in thread/);
    unread = 0;
    room.emit(e.w.sdk.RoomEvent.UnreadNotifications);
    assert.equal(button().querySelector('.matrix-thread-unread-count'), null);
    button().click();
    assert.equal(e.w.document.querySelector('.matrix-room-heading strong').textContent, 'Thread');
    assert.deepEqual(Array.from(e.w.document.querySelectorAll('.matrix-message-body'), (node) => node.textContent), ['Original message', 'Thread reply']);
  } finally { e.close(); }
});

test('tab credentials stay bound to their original identity when localStorage changes', () => {
  const e = environment();
  try {
    const account = { baseUrl: 'https://hs.example', userId: '@a:example', deviceId: 'A', accessToken: 'token-A' };
    e.api.saveSession(account);
    e.w.localStorage.setItem('seres.matrix.session.v1', JSON.stringify({ ...account, userId: '@b:example', deviceId: 'B' }));
    assert.equal(e.api.savedSession().userId, account.userId);
    assert.equal(e.api.savedSession().accessToken, account.accessToken);
    assert.notEqual(e.api.cryptoStoreName(account), e.api.cryptoStoreName({ ...account, deviceId: 'B' }));
    assert.notEqual(e.api.cryptoStoreName(account), e.api.cryptoStoreName({ ...account, userId: '@b:example' }));
  } finally { e.close(); }
});

test('Matrix server routing preserves ports and IPv6', () => {
  const e = environment();
  try {
    assert.equal(e.api.matrixServerName('!id:hs.example:8448'), 'hs.example:8448');
    assert.equal(e.api.matrixServerName('!id:[2001:db8::1]:8448'), '[2001:db8::1]:8448');
  } finally { e.close(); }
});

test('Space listing uses child state even without a child-side parent event', () => {
  const e = environment();
  try {
    e.rooms.set('!space:example.org', { ...e.rooms.get('!a:example.org'), roomId: '!space:example.org', name: 'Space', isSpaceRoom: () => true,
      currentState: { getStateEvents: (type, key) => key === '!a:example.org' ? { getContent: () => ({ via: ['example.org'] }) } : null } });
    e.api.space('!space:example.org'); e.api.renderRoomList();
    assert.match(e.w.document.querySelector('.matrix-room-name').textContent, /!a:/);
    assert.equal(e.w.document.querySelectorAll('.matrix-room-name').length, 1);
  } finally { e.close(); }
});

test('remote audio is played once, unmutes again, and logout hangs up the call', async () => {
  const e = environment();
  try {
    const call = new EventEmitter(); let muted = true; let hangups = 0;
    call.getRemoteFeeds = () => [{ purpose: 'm.usermedia', stream: {}, isAudioMuted: () => muted }];
    call.getLocalFeeds = () => []; call.hangup = () => { hangups++; call.emit('hangup'); };
    e.api.showCall(call, false);
    const audio = e.w.document.querySelector('audio');
    assert.equal(e.w.document.querySelector('.matrix-call-video').muted, true);
    assert.equal(audio.muted, true);
    muted = false; call.emit('feeds'); assert.equal(audio.muted, false);
    e.api.renderRoom(); assert.equal(e.w.document.querySelector('audio'), audio);
    await e.api.stop(); assert.equal(hangups, 1);
    assert.equal(e.w.document.querySelector('.matrix-call-panel'), null);
  } finally { e.close(); }
});

test('call layout hides empty video, updates its status and shows live video in one stage', async () => {
  const e = environment();
  try {
    const call = new EventEmitter();
    call.roomId = '!a:example.org'; call.state = 'ringing';
    let remoteFeeds = []; let localFeeds = [];
    call.getRemoteFeeds = () => remoteFeeds;
    call.getLocalFeeds = () => localFeeds;
    call.hangup = () => call.emit('hangup');
    e.api.showCall(call, true);
    const panel = e.w.document.querySelector('.matrix-call-panel');
    const remote = panel.querySelector('.matrix-call-video');
    const local = panel.querySelector('.matrix-call-local');
    const placeholder = panel.querySelector('.matrix-call-placeholder');
    assert.equal(remote.hidden, true);
    assert.equal(local.hidden, true);
    assert.equal(placeholder.hidden, false);
    assert.equal(panel.querySelector('.matrix-call-status').textContent, 'Incoming call');
    assert.equal(panel.querySelector('.matrix-call-answer-actions').hidden, false);
    call.state = 'connected'; call.emit('state');
    assert.equal(panel.querySelector('.matrix-call-status').textContent, 'Connected');
    assert.match(panel.querySelector('.matrix-call-hint').textContent, /Audio call/);
    assert.equal(panel.querySelector('.matrix-call-answer-actions').hidden, true);
    const track = { enabled: true, readyState: 'live' };
    const stream = { getVideoTracks: () => [track] };
    remoteFeeds = [{ purpose: 'm.usermedia', stream, isVideoMuted: () => false }];
    localFeeds = remoteFeeds;
    call.emit('feeds');
    assert.equal(remote.hidden, false);
    assert.equal(local.hidden, false);
    assert.equal(placeholder.hidden, true);
    assert.equal(remote.parentElement, local.parentElement);
    assert.equal(remote.srcObject, stream);
    track.readyState = 'ended'; call.emit('feeds');
    assert.equal(remote.hidden, true);
    assert.equal(local.hidden, true);
    assert.equal(placeholder.hidden, false);
    await e.api.stop();
  } finally { e.close(); }
});

test('MatrixRTC opens within the click handler and keeps the room server port', () => {
  const e = environment();
  try {
    let target; e.w.open = (url) => { target = new URL(url); };
    e.api.openMatrixRtc({ roomId: '!room:example.org:8448', name: 'Call' });
    assert.equal(target.pathname, '/room/');
    assert.match(decodeURIComponent(target.hash), /viaServers=example.org:8448/);
  } finally { e.close(); }
});

test('real WASM attachment encryption round trips and rejects modified ciphertext', async () => {
  const { Attachment, EncryptedAttachment } = await import('@matrix-org/matrix-sdk-crypto-wasm');
  const original = new TextEncoder().encode('encrypted attachment regression');
  const encrypted = Attachment.encrypt(original);
  try {
    const metadata = encrypted.mediaEncryptionInfo;
    const data = encrypted.encryptedData;
    const copy = new EncryptedAttachment(data, metadata);
    try { assert.deepEqual(Attachment.decrypt(copy), original); } finally { copy.free(); }
    data[0] ^= 1;
    const corrupted = new EncryptedAttachment(data, metadata);
    try { assert.throws(() => Attachment.decrypt(corrupted)); } finally { corrupted.free(); }
  } finally { encrypted.free(); }
});

test('an unchanged media row remains attached during timeline updates', () => {
  const e = environment();
  try {
    const content = { msgtype: 'm.audio', body: 'audio.ogg', url: 'mxc://example.org/audio' };
    const message = { getId: () => '$audio', getType: () => 'm.room.message', getContent: () => content, getSender: () => '@other:example.org', getDate: () => null };
    e.rooms.get('!a:example.org').getLiveTimeline = () => ({ getEvents: () => [message] });
    e.api.renderRoom();
    const row = e.w.document.querySelector('.matrix-message');
    const timeline = row.parentElement;
    const media = e.w.document.createElement('audio');
    e.api.mediaNodes.set(row.dataset.mediaKey, media);
    row.append(media);
    e.api.renderRoom();
    assert.equal(e.w.document.querySelector('.matrix-message'), row);
    assert.equal(row.parentElement, timeline);
    assert.equal(media.parentElement, row);
  } finally { e.close(); }
});

function connectable(e, init = async () => {}) {
  const matrix = Object.assign(new EventEmitter(), e.matrix);
  matrix.initRustCrypto = init;
  matrix.getUserId = () => '@me:example.org';
  matrix.startClient = async () => { matrix.emit('sync', 'error'); matrix.emit('sync', 'prepared'); };
  e.w.sdk.createClient = () => matrix;
  Object.defineProperty(e.w.navigator, 'locks', { value: { request: async (_name, _opts, callback) => callback({}) }, configurable: true });
  return matrix;
}
const account = { baseUrl: 'https://hs.example', userId: '@me:example.org', deviceId: 'DEVICE', accessToken: 'token' };

test('local echo updates refresh the open thread without another participant replying', async () => {
  const e = environment();
  try {
    const matrix = connectable(e);
    await e.api.connect(account);
    const events = [];
    const room = e.rooms.get('!a:example.org');
    room.getLiveTimeline = () => ({ getEvents: () => events });
    room.getThread = () => ({ timelineSet: { getLiveTimeline: () => ({ getEvents: () => [] }) } });
    e.api.select(room.roomId, '$root');
    e.api.renderRoom();
    const reply = {
      getId: () => '~local', getType: () => 'm.room.message', getSender: () => '@me:example.org', getDate: () => null,
      getContent: () => ({ body: 'Visible immediately', 'm.relates_to': { rel_type: 'm.thread', event_id: '$root' } }),
    };
    events.push(reply);
    matrix.emit(e.w.sdk.RoomEvent.LocalEchoUpdated, reply, room);
    assert.equal(e.w.document.querySelector('.matrix-message-body').textContent, 'Visible immediately');
    await e.api.stop();
  } finally { e.close(); }
});

test('concurrent connection attempts initialize crypto once; logout cancels initialization', async () => {
  const e = environment();
  try {
    let finish; let initializations = 0; let starts = 0;
    const matrix = connectable(e, () => { initializations++; return new Promise((resolve) => { finish = resolve; }); });
    matrix.startClient = async () => { starts++; };
    const first = e.api.connect(account);
    const second = e.api.connect(account);
    assert.equal(first, second);
    await tick(); assert.equal(initializations, 1);
    await e.api.stop(); finish(); await first;
    assert.equal(starts, 0);
  } finally { e.close(); }
});

test('encrypted live messages notify after decryption, even after an initial sync error', async () => {
  const e = environment();
  try {
    const matrix = connectable(e);
    await e.api.connect(account);
    let notification;
    e.w.addEventListener('seres:notification', (event) => { notification = event.detail; });
    const event = new EventEmitter(); let decrypted = false;
    Object.assign(event, { getType: () => decrypted ? 'm.room.message' : 'm.room.encrypted', isEncrypted: () => true,
      getContent: () => decrypted ? { body: 'private message' } : {}, getSender: () => '@other:example.org', getId: () => '$encrypted' });
    matrix.emit('timeline', event, e.rooms.get('!b:example.org'), false);
    assert.equal(notification, undefined);
    decrypted = true; event.emit('decrypted', event);
    assert.equal(notification.body, 'private message');
    await e.api.stop();
  } finally { e.close(); }
});

test('forwarded attachments sharing a media URL keep separate controls', () => {
  const e = environment();
  try {
    const content = { msgtype: 'm.audio', body: 'audio.ogg', url: 'mxc://example.org/shared' };
    const events = ['$first', '$forwarded'].map((id) => ({ getId: () => id, getType: () => 'm.room.message', getContent: () => content, getSender: () => '@other:example.org', getDate: () => null }));
    e.rooms.get('!a:example.org').getLiveTimeline = () => ({ getEvents: () => events });
    e.api.renderRoom();
    assert.equal(e.w.document.querySelectorAll('.matrix-attachment-button').length, 2);
    e.api.renderRoom();
    assert.equal(e.w.document.querySelectorAll('.matrix-attachment-button').length, 2);
  } finally { e.close(); }
});

test('thread notifications identify replies and open their thread', async () => {
  const e = environment();
  try {
    const matrix = connectable(e);
    await e.api.connect(account);
    Object.defineProperty(e.w.document, 'visibilityState', { value: 'visible', configurable: true });
    e.api.saveSession(account);
    e.api.activate();
    e.api.select('!a:example.org');
    let notification;
    e.w.addEventListener('seres:notification', (event) => { notification = event.detail; });
    const event = {
      getType: () => 'm.room.message', isEncrypted: () => false, getDate: () => null,
      getContent: () => ({ body: 'New reply', 'm.relates_to': { rel_type: 'm.thread', event_id: '$root' } }),
      getSender: () => '@other:example.org', getId: () => '$reply',
    };
    const room = e.rooms.get('!a:example.org');
    matrix.emit('timeline', event, room, false);
    assert.match(notification.title, /Thread/);
    notification.onClick();
    e.api.renderRoom();
    assert.equal(e.w.document.querySelector('.matrix-room-heading strong').textContent, 'Thread');
    notification = undefined;
    matrix.emit('timeline', event, room, false);
    assert.equal(notification, undefined);
    await e.api.stop();
  } finally { e.close(); }
});

function redesignedPage() {
  const html = readFileSync(resolve(__dirname, '../public/index.html'), 'utf8');
  const app = readFileSync(resolve(__dirname, '../frontend/index.ts'), 'utf8');
  const start = app.indexOf('  function switchView(view:');
  const end = app.indexOf('  // ------------------------------------------------------------ open chat', start);
  const railBinding = app.split('\n').find((line) => line.includes('.rail-nav[data-rail-view]') && line.includes('addEventListener'));
  const script = `const $ = (id) => document.getElementById(id); ${app.slice(start, end)} ${railBinding}`;
  const dom = new JSDOM(html, { url: 'https://seres.example/index.html', runScripts: 'outside-only' });
  const activations = [];
  dom.window.SeresMatrix = { activate: () => activations.push('activate'), deactivate: () => activations.push('deactivate') };
  dom.window.eval(ts.transpileModule(script, { compilerOptions: { target: ts.ScriptTarget.ES2020 } }).outputText);
  return { dom, w: dom.window, activations };
}

test('Matrix rail navigation preserves the redesigned pane and switches back to each existing view', () => {
  const { dom, w, activations } = redesignedPage();
  try {
    const doc = w.document;
    assert.ok(doc.getElementById('pane-resizer'));
    assert.ok(doc.getElementById('rail-settings'));
    assert.ok(doc.getElementById('settings-modal'));
    const matrix = doc.querySelector('[data-rail-view="matrix"]');
    assert.ok(matrix.querySelector('.material-symbols-rounded'));
    matrix.click();
    assert.equal(activations.at(-1), 'activate');
    assert.equal(matrix.getAttribute('aria-current'), 'page');
    assert.equal(doc.querySelectorAll('.rail-nav.active').length, 1);
    assert.ok(doc.querySelector('.main-chat').classList.contains('matrix-open'));
    assert.ok(!doc.getElementById('matrix-app-root').classList.contains('modal-hidden'));
    for (const id of ['chats-header', 'friends-header', 'requests-header']) assert.equal(doc.getElementById(id).style.display, 'none');
    for (const view of ['friends', 'requests', 'chats']) {
      doc.querySelector(`[data-rail-view="${view}"]`).click();
      assert.equal(activations.at(-1), 'deactivate');
      assert.ok(!doc.querySelector('.main-chat').classList.contains('matrix-open'));
      assert.equal(doc.querySelectorAll('.rail-nav.active').length, 1);
      assert.equal(doc.getElementById(`${view}-header`).style.display, 'flex');
      assert.equal(doc.getElementById('list-search').parentElement.style.display, 'block');
      assert.ok(doc.getElementById('matrix-app-root').classList.contains('modal-hidden'));
    }
  } finally { dom.window.close(); }
});

test('Matrix login panel is hidden after leaving Matrix in both themes', () => {
  const { dom, w } = redesignedPage();
  try {
    const doc = w.document;
    const style = doc.createElement('style');
    style.textContent = readFileSync(resolve(__dirname, '../public/style.css'), 'utf8');
    doc.head.append(style);
    // Load the actual controller so activate() adds the login panel's layout class.
    w.eval(compiled);
    const panel = doc.getElementById('matrix-list');
    for (const light of [false, true]) {
      doc.body.classList.toggle('bright-body', light);
      for (const view of ['chats', 'friends', 'requests']) {
        doc.querySelector('[data-rail-view="matrix"]').click();
        assert.ok(panel.querySelector('.matrix-login-form'));
        assert.equal(w.getComputedStyle(panel).display, 'flex');
        doc.querySelector(`[data-rail-view="${view}"]`).click();
        assert.equal(w.getComputedStyle(panel).display, 'none', `Matrix login must be hidden on ${view} (${light ? 'light' : 'dark'})`);
        assert.equal(w.getComputedStyle(doc.getElementById('matrix-app-root')).display, 'none');
      }
    }
  } finally { dom.window.close(); }
});


test('joining a room before sync shows progress instead of a blank conversation', async () => {
  const e = environment();
  try {
    e.matrix.joinRoom = async () => ({ ...e.rooms.get('!a:example.org'), roomId: '!new:example.org', name: 'New room' });
    e.api.joinRoomPrompt(); submitDialog(e, ['#new:example.org']); await tick();
    assert.match(e.w.document.getElementById('matrix-app-root').textContent, /loading|sync|joining/i);
  } finally { e.close(); }
});

test('Matrix join links preserve room aliases and federation routing hints', () => {
  const e = environment();
  try {
    const target = e.api.parseRoomTarget('https://matrix.to/#/!room%3Aexample.org%3A8448?via=relay.example&via=example.org%3A8448');
    assert.equal(target.id, '!room:example.org:8448');
    assert.deepEqual(Array.from(target.viaServers), ['relay.example', 'example.org:8448']);
    assert.equal(e.api.parseRoomTarget('#space/general:example.org').id, '#space/general:example.org');
    assert.throws(() => e.api.parseRoomTarget('just a room name'));
    assert.throws(() => e.api.parseRoomTarget('https://unrelated.example/#/!id:example.org'));
  } finally { e.close(); }
});

test('newly joined rooms become visible when their membership arrives through sync', async () => {
  const e = environment();
  try {
    const matrix = connectable(e);
    await e.api.connect(account);
    const joined = { ...e.rooms.get('!b:example.org'), roomId: '!new:example.org', name: 'Newly joined room' };
    matrix.joinRoom = async () => joined;
    await e.api.joinRoomTarget('#new:example.org');
    assert.match(e.w.document.getElementById('matrix-app-root').textContent, /loading/i);
    e.rooms.set(joined.roomId, joined);
    matrix.emit('room', joined);
    matrix.emit('membership', joined, 'join', 'invite');
    assert.equal(e.w.document.querySelector('.matrix-room-heading strong').textContent, joined.name);
    assert.equal(e.w.document.querySelector('.matrix-room-button.selected .matrix-room-name').textContent, joined.name);
    await e.api.stop();
  } finally { e.close(); }
});

test('joining clears unrelated search and Space filters without modifying the Space', async () => {
  const e = environment();
  try {
    let spaceWrites = 0;
    e.matrix.sendStateEvent = async () => { spaceWrites++; };
    e.matrix.joinRoom = async () => e.rooms.get('!b:example.org');
    e.api.renderRoomList();
    const search = e.w.document.querySelector('.matrix-search');
    search.value = 'does-not-match'; search.dispatchEvent(new e.w.Event('input'));
    e.api.space('!unrelated:example.org');
    await e.api.joinRoomTarget('!b:example.org');
    assert.equal(e.w.document.querySelector('.matrix-search').value, '');
    assert.ok(e.w.document.querySelector('.matrix-room-button.selected'));
    assert.equal(e.w.document.querySelector('.matrix-room-heading strong').textContent, '!b:example.org');
    assert.equal(spaceWrites, 0);
  } finally { e.close(); }
});

test('joining errors are visible, and the join button can be used again', async () => {
  const e = environment();
  try {
    e.matrix.joinRoom = async () => { throw new Error('This room requires an invitation'); };
    await e.api.joinRoomTarget('#private:example.org');
    assert.match(e.w.document.getElementById('matrix-app-root').textContent, /Could not join room:.*invitation/);
    const join = Array.from(e.w.document.querySelectorAll('#matrix-list button')).find(button => button.textContent === 'Join room');
    assert.equal(join.disabled, false);
  } finally { e.close(); }
});

test('a joined Space is recognized when its state arrives after the join response', async () => {
  const e = environment();
  try {
    const temporary = { ...e.rooms.get('!a:example.org'), roomId: '!newspace:example.org' };
    e.matrix.joinRoom = async () => temporary;
    await e.api.joinRoomTarget(temporary.roomId);
    const space = { ...temporary, name: 'Joined Space', isSpaceRoom: () => true };
    e.rooms.set(space.roomId, space);
    e.api.handleRoomUpdate(space);
    assert.ok(e.w.document.querySelector('.matrix-space-button.selected'));
    assert.equal(e.w.document.querySelector('.matrix-compose'), null);
  } finally { e.close(); }
});

test('Matrix messages prefer room display names and keep the full Matrix ID in the tooltip', () => {
  const e = environment();
  try {
    const room = e.rooms.get('!a:example.org');
    const event = { getId: () => '$named', getType: () => 'm.room.message', getContent: () => ({ body: 'Hello' }), getSender: () => '@alex:example.org', getDate: () => null };
    room.getMember = () => ({ name: 'Alex Johnson' });
    room.getLiveTimeline = () => ({ getEvents: () => [event] });
    e.api.renderRoom();
    const sender = e.w.document.querySelector('.matrix-message-sender');
    assert.equal(sender.textContent, 'Alex Johnson');
    assert.equal(sender.title, '@alex:example.org');
    room.getMember = () => ({ name: 'Alex Updated' });
    e.api.renderRoom();
    assert.equal(e.w.document.querySelector('.matrix-message-sender').textContent, 'Alex Updated');
  } finally { e.close(); }
});

test('English Matrix timestamps distinguish morning, evening, midnight and noon despite a 24-hour browser default', () => {
  const e = environment();
  try {
    e.w.document.documentElement.lang = 'en';
    const nativeFormat = e.w.Date.prototype.toLocaleTimeString;
    e.w.Date.prototype.toLocaleTimeString = function(locales, options) {
      return nativeFormat.call(this, !locales || Array.isArray(locales) && !locales.length ? 'en-GB' : locales, options);
    };
    const hours = [9, 21, 0, 12];
    const events = hours.map((hour) => ({ getId: () => `$time-${hour}`, getType: () => 'm.room.message', getContent: () => ({ body: 'Time check' }), getSender: () => '@alex:example.org', getDate: () => new e.w.Date(2026, 10, 11, hour, 5) }));
    e.rooms.get('!a:example.org').getLiveTimeline = () => ({ getEvents: () => events });
    e.api.renderRoom();
    const times = Array.from(e.w.document.querySelectorAll('time'));
    assert.match(times[0].textContent, /9:05\s*AM/);
    assert.match(times[1].textContent, /9:05\s*PM/);
    assert.match(times[2].textContent, /12:05\s*AM/);
    assert.match(times[3].textContent, /12:05\s*PM/);
    for (const time of times) { assert.ok(time.dateTime); assert.ok(time.title.includes('2026')); }
  } finally { e.close(); }
});

test('display names update when Matrix member profiles arrive after messages', async () => {
  const e = environment();
  try {
    const matrix = connectable(e);
    await e.api.connect(account);
    const room = e.rooms.get('!a:example.org');
    const userId = '@alex:example.org';
    let name = userId;
    room.getMember = () => ({ name });
    room.getLiveTimeline = () => ({ getEvents: () => [{ getId: () => '$late-profile', getType: () => 'm.room.message', getContent: () => ({ body: 'Hello' }), getSender: () => userId, getDate: () => null }] });
    e.api.renderRoom();
    assert.equal(e.w.document.querySelector('.matrix-message-sender').textContent, userId);
    name = 'Alex Profile';
    matrix.emit('memberName', undefined, { roomId: room.roomId });
    assert.equal(e.w.document.querySelector('.matrix-message-sender').textContent, 'Alex Profile');
    await e.api.stop();
  } finally { e.close(); }
});

test('messages fall back to cached profile names and safely display names as plain text', () => {
  const e = environment();
  try {
    const room = e.rooms.get('!a:example.org');
    const id = '@alex:example.org';
    const event = { getId: () => '$fallback-profile', getType: () => 'm.room.message', getContent: () => ({ body: 'Hello' }), getSender: () => id, getDate: () => null };
    room.getMember = () => ({ name: id });
    room.getLiveTimeline = () => ({ getEvents: () => [event] });
    e.matrix.getUser = () => ({ displayName: '<img src=x onerror=alert(1)>' });
    e.api.renderRoom();
    const sender = e.w.document.querySelector('.matrix-message-sender');
    assert.equal(sender.textContent, '<img src=x onerror=alert(1)>');
    assert.equal(sender.querySelector('img'), null);
    e.matrix.getUser = () => null;
    e.api.renderRoom();
    assert.equal(e.w.document.querySelector('.matrix-message-sender').textContent, id);
  } finally { e.close(); }
});
