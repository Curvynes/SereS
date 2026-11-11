import * as sdk from "matrix-js-sdk";
import { Attachment, EncryptedAttachment } from "@matrix-org/matrix-sdk-crypto-wasm";

type MatrixSession = {
  baseUrl: string;
  userId: string;
  deviceId: string;
  accessToken: string;
  refreshToken?: string;
};

declare global {
  interface Window {
    SeresMatrix: { activate(): void; deactivate(): void };
  }
}

const SESSION_KEY = "seres.matrix.session.v1";
const TOKEN_KEY = "seres.matrix.token.v1";
const SSO_STATE_KEY = "seres.matrix.sso.state.v1";
const ROOT_ID = "matrix-app-root";
const LIST_ID = "matrix-list";
const MAX_ATTACHMENT_BYTES = 20 * 1024 * 1024;
const h = <K extends keyof HTMLElementTagNameMap>(tag: K, className = "", text = "") => {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text) element.textContent = text;
  return element;
};

let client: sdk.MatrixClient | null = null;
let active = false;
let connectionTask: Promise<void> | null = null;
let lifecycle = 0;
let activeCall: any = null;
const drafts = new Map<string, string>();
const pendingSends = new Set<string>();
let matrixPrepared = false;
let authenticating = false;
let selectedRoomId = "";
let selectedSpaceId = "";
let threadRootId = "";
let loginFlows: any[] = [];
let loginBaseUrl = "";
let roomFilter = "";
let joiningTarget = "";
let awaitingRoomId = "";
let callPanel: HTMLElement | null = null;
let notification = "";
let notificationTimer = 0;
let cryptoLease: (() => void) | null = null;
const mediaObjectUrls = new Set<string>();
const mediaNodes = new Map<string, HTMLElement>();

function symbol(name: string) {
  const icon = h("span", "material-symbols-rounded matrix-symbol", name);
  icon.setAttribute("aria-hidden", "true");
  return icon;
}

function root() { return document.getElementById(ROOT_ID)!; }
function sidebar() { return document.getElementById(LIST_ID)!; }
function savedSession(): MatrixSession | null {
  try {
    const session = JSON.parse(sessionStorage.getItem(TOKEN_KEY) || "null");
    return session?.baseUrl && session.userId && session.deviceId && session.accessToken
      ? session as MatrixSession : null;
  } catch { return null; }
}
function saveSession(session: MatrixSession) {
  localStorage.setItem(SESSION_KEY, JSON.stringify({ baseUrl: session.baseUrl, userId: session.userId, deviceId: session.deviceId }));
  sessionStorage.setItem(TOKEN_KEY, JSON.stringify(session));
}
function safeError(error: unknown) {
  return error instanceof Error ? error.message : String(error);
}
function notify(message: string) {
  notification = message;
  const status = root().querySelector<HTMLElement>("[data-matrix-status]") || sidebar().querySelector<HTMLElement>("[data-matrix-status]");
  if (status) status.textContent = message;
  else {
    let toast = root().querySelector<HTMLElement>(".matrix-toast");
    if (!toast) {
      toast = h("div", "matrix-toast");
      toast.setAttribute("role", "status");
      root().append(toast);
    }
    toast.textContent = message;
  }
  window.clearTimeout(notificationTimer);
  notificationTimer = window.setTimeout(() => {
    notification = "";
    root().querySelector(".matrix-toast")?.remove();
    const currentStatus = root().querySelector<HTMLElement>("[data-matrix-status]") || sidebar().querySelector<HTMLElement>("[data-matrix-status]");
    if (currentStatus) currentStatus.textContent = "";
  }, 4500);
}
function allowedHomeserver(value: string): string {
  const parsed = new URL(value.trim());
  if (!/^https?:$/.test(parsed.protocol) || parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new Error("Enter a valid Matrix homeserver URL.");
  }
  if (parsed.protocol !== "https:" && !["localhost", "127.0.0.1", "[::1]"].includes(parsed.hostname)) {
    throw new Error("Matrix sign-in requires HTTPS.");
  }
  return `${parsed.origin}${parsed.pathname.replace(/\/+$/, "")}`;
}
async function discoverHomeserver(input: string): Promise<string> {
  const entered = allowedHomeserver(input);
  try {
    const response = await fetch(`${entered}/.well-known/matrix/client`, { headers: { Accept: "application/json" } });
    if (response.ok) {
      const data = await response.json();
      if (typeof data?.["m.homeserver"]?.base_url === "string") return allowedHomeserver(data["m.homeserver"].base_url);
    }
  } catch { /* Use the URL the user entered when discovery is unavailable. */ }
  return entered;
}
function clearCallbackFromAddress() {
  const url = new URL(location.href);
  url.searchParams.delete("loginToken");
  url.searchParams.delete("state");
  url.searchParams.delete("matrix_sso");
  history.replaceState({}, document.title, url.pathname + url.search + url.hash);
}

async function handleSsoCallback(): Promise<boolean> {
  const query = new URLSearchParams(location.search);
  const token = query.get("loginToken");
  if (!token) return false;
  const expected = sessionStorage.getItem(SSO_STATE_KEY);
  const received = query.get("state") || query.get("matrix_sso");
  const baseUrl = sessionStorage.getItem("seres.matrix.sso.server");
  sessionStorage.removeItem(SSO_STATE_KEY);
  sessionStorage.removeItem("seres.matrix.sso.server");
  clearCallbackFromAddress();
  if (!expected || !received || expected !== received || !baseUrl) {
    throw new Error("Matrix SSO callback did not match the sign-in request. Please try again.");
  }
  const authClient = sdk.createClient({ baseUrl });
  const response = await authClient.loginRequest({
    type: "m.login.token", token,
    initial_device_display_name: "SereS web",
  });
  await finishLogin(baseUrl, response);
  return true;
}

function startClient(session: MatrixSession): sdk.MatrixClient {
  const matrix = sdk.createClient({
    baseUrl: session.baseUrl,
    userId: session.userId,
    deviceId: session.deviceId,
    accessToken: session.accessToken,
    refreshToken: session.refreshToken,
    onTokenRefresh: ({ accessToken, refreshToken }) => {
      if (client !== matrix) return;
      const updated = { ...session, accessToken, ...(refreshToken ? { refreshToken } : {}) };
      saveSession(updated);
      session.accessToken = accessToken;
      session.refreshToken = refreshToken || session.refreshToken;
    },
  });
  return matrix;
}

async function finishLogin(baseUrl: string, response: sdk.LoginResponse) {
  const session: MatrixSession = {
    baseUrl,
    userId: response.user_id,
    deviceId: response.device_id,
    accessToken: response.access_token,
    ...(response.refresh_token ? { refreshToken: response.refresh_token } : {}),
  };
  saveSession(session);
  await connect(session);
}

function connect(session: MatrixSession): Promise<void> {
  if (connectionTask) return connectionTask;
  connectionTask = connectSession(session).finally(() => { connectionTask = null; });
  return connectionTask;
}

function cryptoStoreName(session: MatrixSession) {
  return `seres-matrix:${encodeURIComponent(JSON.stringify([session.baseUrl, session.userId, session.deviceId]))}`;
}

async function connectSession(session: MatrixSession) {
  await stop();
  const generation = lifecycle;
  const storeName = cryptoStoreName(session);
  if (!navigator.locks) {
    renderLogin("This browser does not support Web Locks, which SereS uses to keep Matrix encryption data safe across tabs.");
    return;
  }
  {
    const lockName = storeName;
    let announce: ((acquired: boolean) => void) | undefined;
    const acquired = new Promise<boolean>((resolve) => { announce = resolve; });
    let releaseLease: (() => void) | undefined;
    const held = new Promise<void>((resolve) => { releaseLease = resolve; });
    void navigator.locks.request(lockName, { mode: "exclusive", ifAvailable: true }, async (lock) => {
      announce?.(!!lock);
      if (lock) await held;
    }).catch(() => announce?.(false));
    if (!await acquired) {
      renderLogin("This Matrix account is already open in another tab. Close its SereS Matrix tab first to keep the encryption store safe.");
      return;
    }
    if (generation !== lifecycle) { releaseLease?.(); return; }
    cryptoLease = () => releaseLease?.();
  }
  const matrix = startClient(session);
  client = matrix;
  try {
    await matrix.initRustCrypto({ cryptoDatabasePrefix: storeName });
    if (generation !== lifecycle) { matrix.stopClient(); return; }
    client.on(sdk.RoomEvent.Timeline, (event, room, toStartOfTimeline) => {
      renderRoomList();
      if (!toStartOfTimeline && room?.roomId === selectedRoomId) renderRoom();
      if (matrixPrepared && !toStartOfTimeline && room) {
        if (event.isEncrypted() && event.getType() !== sdk.EventType.RoomMessage) {
          event.once(sdk.MatrixEventEvent.Decrypted, () => {
            if (client === matrix) notifyMatrixMessage(event, room);
          });
        } else notifyMatrixMessage(event, room);
      }
    });
    client.on(sdk.RoomEvent.Name, handleRoomUpdate);
    client.on(sdk.ClientEvent.Room, handleRoomUpdate);
    client.on(sdk.RoomEvent.MyMembership, handleRoomUpdate);
    client.on(sdk.RoomMemberEvent.Name, (_event, member) => {
      if (member.roomId === selectedRoomId) renderRoom();
    });
    client.on(sdk.UserEvent.DisplayName, () => {
      if (selectedRoomId) renderRoom();
    });
    client.on("Call.incoming" as any, (call: any) => {
      selectedRoomId = call.roomId;
      selectedSpaceId = "";
      threadRootId = "";
      renderRoomList();
      notify("Incoming Matrix call");
      showCall(call, true);
    });
    client.on(sdk.MatrixEventEvent.Decrypted, (_event) => {
      if (active) renderRoom();
    });
    client.on(sdk.ClientEvent.Sync, (state) => {
      if (state === sdk.SyncState.Prepared) {
        matrixPrepared = true;
        renderRoomList();
        if (active) renderWorkspace();
      }
    });
    await matrix.startClient({ initialSyncLimit: 30, lazyLoadMembers: true, threadSupport: true });
    if (generation === lifecycle) renderWorkspace();
  } catch (error) {
    if (generation !== lifecycle) { matrix.stopClient(); return; }
    await stop();
    renderLogin(safeError(error));
  }
}

function notifyMatrixMessage(event: sdk.MatrixEvent, room: sdk.Room) {
  if (!client || !matrixPrepared || event.getType() !== sdk.EventType.RoomMessage || event.getSender() === client.getUserId()) return;
  if (active && selectedRoomId === room.roomId && document.visibilityState === "visible") return;
  window.dispatchEvent(new CustomEvent("seres:notification", { detail: {
    title: room.name || room.roomId,
    body: event.getContent().body || "New Matrix message",
    tag: `matrix:${event.getId() || `${room.roomId}:${Date.now()}`}`,
    onClick: () => {
      selectedRoomId = room.roomId;
      selectedSpaceId = "";
      threadRootId = "";
      window.dispatchEvent(new Event("seres:open-matrix"));
    },
  } }));
}

async function stop() {
  lifecycle++;
  activeCall?.hangup("user_hangup", false);
  activeCall = null;
  callPanel?.querySelector("iframe")?.setAttribute("src", "about:blank");
  for (const url of mediaObjectUrls) URL.revokeObjectURL(url);
  mediaObjectUrls.clear();
  mediaNodes.clear();
  callPanel?.remove();
  matrixPrepared = false;
  joiningTarget = "";
  awaitingRoomId = "";
  if (client) {
    try { client.stopClient(); } catch { /* ignore */ }
    client.removeAllListeners();
    client = null;
  }
  cryptoLease?.();
  cryptoLease = null;
  callPanel = null;
}

function renderWorkspace() {
  if (!client) return renderLogin();
  renderRoomList();
  renderRoom();
}

function renderRoomList() {
  const matrix = client;
  if (!matrix) return;
  const panel = sidebar();
  panel.classList.add("matrix-list-panel");
  const oldSearch = panel.querySelector<HTMLInputElement>(".matrix-search");
  const restoreSearch = !!oldSearch && document.activeElement === oldSearch;
  const searchSelection = oldSearch?.selectionStart ?? null;
  panel.replaceChildren();

  const head = h("div", "matrix-sidebar-head");
  head.append(h("strong", "", "Matrix"));
  const signout = h("button", "matrix-small-button", "Sign out");
  signout.type = "button";
  signout.onclick = () => { void logout(); };
  head.append(signout);
  panel.append(head);

  const search = h("input", "matrix-search") as HTMLInputElement;
  search.type = "search";
  search.placeholder = "Search rooms";
  search.setAttribute("aria-label", "Search Matrix rooms");
  search.value = roomFilter;
  search.oninput = () => { roomFilter = search.value.toLowerCase(); renderRoomList(); };
  panel.append(search);

  const spaces = matrix.getRooms().filter((room) => room.getMyMembership() === sdk.KnownMembership.Join && room.isSpaceRoom());
  panel.append(h("div", "matrix-list-title", "Spaces"));
  for (const space of spaces) {
    const button = h("button", `matrix-room-button matrix-space-button${selectedSpaceId === space.roomId ? " selected" : ""}`, space.name || space.roomId);
    button.prepend(symbol("workspaces"));
    button.type = "button";
    button.onclick = () => { selectedSpaceId = selectedSpaceId === space.roomId ? "" : space.roomId; renderRoomList(); };
    panel.append(button);
  }
  const addSpace = h("button", "matrix-small-button", "+ Space");
  addSpace.type = "button";
  addSpace.onclick = () => createRoom(true);
  panel.append(addSpace);

  const rooms = matrix.getRooms().filter((room) => {
    if (room.getMyMembership() !== sdk.KnownMembership.Join || room.isSpaceRoom()) return false;
    if (selectedSpaceId) {
      const child = matrix.getRoom(selectedSpaceId)?.currentState.getStateEvents("m.space.child", room.roomId);
      if (!child?.getContent().via?.length) return false;
    }
    return `${room.name} ${room.roomId}`.toLowerCase().includes(roomFilter);
  });
  panel.append(h("div", "matrix-list-title", selectedSpaceId ? "Space rooms" : "Rooms"));
  for (const room of rooms.sort((a, b) => a.name.localeCompare(b.name))) {
    const unread = room.getUnreadNotificationCount(sdk.NotificationCountType.Total);
    const button = h("button", `matrix-room-button${selectedRoomId === room.roomId ? " selected" : ""}`);
    button.type = "button";
    button.append(h("span", "matrix-room-name", room.name || room.roomId));
    if (room.hasEncryptionStateEvent()) {
      button.append(symbol("lock"));
      button.setAttribute("aria-label", `${room.name || room.roomId}, end-to-end encrypted`);
    }
    if (unread) button.append(h("span", "matrix-room-unread", String(unread)));
    button.onclick = () => { selectedRoomId = room.roomId; threadRootId = ""; document.querySelector(".sidebar")?.classList.remove("open"); renderRoomList(); renderRoom(); };
    panel.append(button);
  }

  const actions = h("div", "matrix-list-actions");
  if (selectedSpaceId) actions.append(action("Invite to Space", () => inviteToRoom(selectedSpaceId)));
  const newRoom = h("button", "matrix-small-button", selectedSpaceId ? "+ Encrypted room in Space" : "+ Encrypted room");
  newRoom.type = "button";
  newRoom.onclick = () => createRoom(false);
  const join = h("button", "matrix-small-button", joiningTarget ? "Joining room..." : "Join room");
  join.disabled = !!joiningTarget;
  join.type = "button";
  join.onclick = () => joinRoomPrompt();
  actions.append(newRoom, join);
  panel.append(actions);
  if (awaitingRoomId) panel.append(h("p", "matrix-hint", `Loading joined room: ${awaitingRoomId}`));

  const invites = matrix.getRooms().filter((room) => room.getMyMembership() === sdk.KnownMembership.Invite);
  if (invites.length) {
    panel.append(h("div", "matrix-list-title", "Invites"));
    for (const room of invites) {
      const row = h("div", "matrix-invite-row");
      row.append(h("span", "", room.name || room.roomId));
      const accept = h("button", "matrix-small-button", "Join");
      accept.type = "button";
      accept.disabled = !!joiningTarget;
      accept.onclick = () => { void joinRoomTarget(room.roomId); };
      row.append(accept);
      panel.append(row);
    }
  }

  if (restoreSearch) {
    const restored = panel.querySelector<HTMLInputElement>(".matrix-search");
    restored?.focus();
    if (restored && searchSelection !== null) restored.setSelectionRange(searchSelection, searchSelection);
  }
}

function selectJoinedRoom(room: sdk.Room) {
  threadRootId = "";
  if (room.isSpaceRoom()) {
    selectedSpaceId = room.roomId;
    selectedRoomId = "";
  } else selectedRoomId = room.roomId;
}

function mobileRoomsButton() {
  const button = action("Rooms", () => document.querySelector(".sidebar")?.classList.add("open"));
  button.classList.add("matrix-mobile-rooms");
  return button;
}

function mountRoom(shell: HTMLElement) {
  const previous = root().querySelector(".matrix-room-shell");
  if (previous && previous.querySelector(".matrix-timeline") && shell.querySelector(".matrix-timeline") && (previous as HTMLElement).dataset.context === shell.dataset.context) {
    const oldTimeline = previous.querySelector(".matrix-timeline");
    const newTimeline = shell.querySelector(".matrix-timeline");
    if (oldTimeline && newTimeline) {
      const oldRows = new Map(Array.from(oldTimeline.children).map((row) => [(row as HTMLElement).dataset.eventId, row]));
      const desired = Array.from(newTimeline.children).map((row) => {
        const old = oldRows.get((row as HTMLElement).dataset.eventId);
        return old && (old as HTMLElement).dataset.signature === (row as HTMLElement).dataset.signature ? old : row;
      });
      for (const row of Array.from(oldTimeline.children)) if (!desired.includes(row)) row.remove();
      desired.forEach((row, index) => {
        if (oldTimeline.children[index] !== row) oldTimeline.insertBefore(row, oldTimeline.children[index] || null);
      });
    }
    const oldHeader = previous.querySelector(".matrix-room-header");
    const newHeader = shell.querySelector(".matrix-room-header");
    if (oldHeader && newHeader) oldHeader.replaceWith(newHeader);
    const oldCompose = previous.querySelector(".matrix-compose");
    const newCompose = shell.querySelector(".matrix-compose");
    if (oldCompose && newCompose) oldCompose.replaceWith(newCompose);
    previous.querySelectorAll(".matrix-toast").forEach((toast) => toast.remove());
    const toast = shell.querySelector(".matrix-toast");
    if (toast) previous.append(toast);
  } else if (previous) previous.replaceWith(shell);
  else root().replaceChildren(shell);
  root().querySelectorAll<HTMLElement>("[data-media-key]").forEach((row) => {
    const media = mediaNodes.get(row.dataset.mediaKey!);
    if (media && media.parentElement !== row) row.append(media);
  });
  root().querySelectorAll(".matrix-call-panel").forEach((panel) => {
    if (panel !== callPanel) panel.remove();
  });
  if (callPanel && callPanel.parentElement !== root()) root().append(callPanel);
}

function matrixSenderName(event: sdk.MatrixEvent, room: sdk.Room): string {
  const userId = event.getSender();
  if (!userId) return "Matrix user";
  const names = [room.getMember?.(userId)?.name, event.sender?.name, client?.getUser?.(userId)?.displayName];
  return names.find((name) => typeof name === "string" && name.trim() && name !== userId) || userId;
}

function matrixTimestamp(date: Date | null) {
  if (!date || !Number.isFinite(date.getTime())) return { label: "", title: "", iso: "" };
  const locale = document.documentElement.lang || navigator.language || "en";
  return {
    label: date.toLocaleTimeString(locale, { hour: "numeric", minute: "2-digit", hour12: /^en(?:-|$)/i.test(locale) }),
    title: date.toLocaleString(locale, { dateStyle: "medium", timeStyle: "long" }),
    iso: date.toISOString(),
  };
}

function renderRoom() {
  const matrix = client;
  const oldComposer = root().querySelector<HTMLTextAreaElement>(".matrix-compose-input");
  const restoreComposer = !!oldComposer && document.activeElement === oldComposer;
  const composerSelection = oldComposer?.selectionStart ?? null;
  const composerKey = JSON.stringify([selectedRoomId, threadRootId]);
  const composerValue = drafts.get(composerKey) || "";
  const composerDisabled = pendingSends.has(composerKey);
  const sameContext = root().querySelector<HTMLElement>(".matrix-room-shell")?.dataset.context === composerKey;
  const oldTimeline = sameContext ? root().querySelector<HTMLElement>(".matrix-timeline") : null;
  const previousScrollTop = oldTimeline?.scrollTop || 0;
  const shouldScrollToBottom = !oldTimeline || oldTimeline.scrollHeight - oldTimeline.scrollTop - oldTimeline.clientHeight < 48;
  const shell = h("section", "matrix-room-shell");
  shell.dataset.context = composerKey;
  if (!matrix || !selectedRoomId) {
    const welcome = h("div", "matrix-welcome", "Select a Matrix room or create an encrypted room.");
    welcome.append(mobileRoomsButton());
    shell.append(welcome);
    if (notification) shell.append(h("div", "matrix-toast", notification));
    mountRoom(shell);
    return;
  }
  const room = matrix.getRoom(selectedRoomId);
  if (!room || (selectedRoomId === awaitingRoomId && room.getMyMembership() !== sdk.KnownMembership.Join)) {
    shell.append(h("div", "matrix-welcome", awaitingRoomId === selectedRoomId
      ? "Room joined. Loading its messages from the homeserver..."
      : "Loading this Matrix room..."));
    mountRoom(shell);
    return;
  }

  const header = h("header", "matrix-room-header");
  const title = h("div", "matrix-room-heading");
  title.append(h("strong", "", threadRootId ? "Thread" : room.name || room.roomId));
  title.append(h("span", "matrix-room-subtitle", `${room.getJoinedMemberCount()} members | ${room.hasEncryptionStateEvent() ? "End-to-end encrypted" : "Not encrypted"}`));
  header.append(mobileRoomsButton(), title);
  const actions = h("div", "matrix-header-actions");
  if (threadRootId) {
    const back = h("button", "matrix-small-button", "Back to room");
    back.type = "button";
    back.onclick = () => { threadRootId = ""; renderRoom(); };
    actions.append(back);
  } else {
    actions.append(action("Invite", () => inviteToRoom(room.roomId)), action("1:1 voice", () => placeCall(false)), action("1:1 video", () => placeCall(true)), action("Jitsi", () => addJitsi()), action("MatrixRTC", () => openMatrixRtc(room)));
  }
  header.append(actions);
  shell.append(header);

  const body = h("div", "matrix-timeline");
  const events = room.getLiveTimeline().getEvents();
  const thread = threadRootId ? room.getThread(threadRootId) : null;
  const threadEvents = thread?.timelineSet.getLiveTimeline().getEvents() || events;
  const threadRoot = threadRootId ? thread?.rootEvent || events.find((event) => event.getId() === threadRootId) : undefined;
  const filtered = threadRootId
    ? [threadRoot, ...threadEvents.filter((event) => {
      const relation = event.getContent()?.["m.relates_to"];
      return relation?.rel_type === "m.thread" && relation?.event_id === threadRootId;
    })].filter((event): event is sdk.MatrixEvent => !!event)
    : events.filter((event) => !event.getContent()?.["m.relates_to"]?.rel_type);

  for (const event of filtered.slice(-150)) {
    if (event.getType() !== sdk.EventType.RoomMessage && !event.isEncrypted()) continue;
    const content = event.getContent();
    const row = h("article", `matrix-message${threadRootId && event.getId() === threadRootId ? " matrix-thread-root" : ""}`);
    row.dataset.eventId = event.getId() || "";
    const senderName = matrixSenderName(event, room);
    const time = matrixTimestamp(event.getDate());
    row.dataset.signature = JSON.stringify([event.getType(), content, senderName, time]);
    const sender = h("strong", "matrix-message-sender", senderName);
    sender.title = event.getSender() || "";
    const stamp = h("time", "matrix-message-time", time.label);
    stamp.dateTime = time.iso;
    stamp.title = time.title;
    row.append(sender, stamp);
    row.append(h("div", "matrix-message-body", content.body || (event.isEncrypted() ? "Encrypted message could not be decrypted yet." : "Unsupported message")));
    appendAttachment(row, content, matrix);
    if (!threadRootId && event.getId()) {
      const thread = h("button", "matrix-thread-button", "Reply in thread");
      thread.type = "button";
      thread.onclick = () => { threadRootId = event.getId()!; renderRoom(); };
      row.append(thread);
    }
    body.append(row);
  }
  shell.append(body);

  const compose = h("form", "matrix-compose");
  const text = h("textarea", "matrix-compose-input") as HTMLTextAreaElement;
  text.placeholder = threadRootId ? "Reply in thread" : "Message this Matrix room";
  text.setAttribute("aria-label", text.placeholder);
  text.rows = 1;
  text.value = composerValue;
  text.dataset.composerKey = composerKey;
  text.oninput = () => drafts.set(composerKey, text.value);
  text.disabled = composerDisabled;
  const attachmentButton = h("button", "matrix-small-button", "Attach");
  attachmentButton.type = "button";
  attachmentButton.prepend(symbol("attach_file"));
  const attachmentInput = h("input") as HTMLInputElement;
  attachmentInput.type = "file";
  attachmentInput.multiple = true;
  attachmentInput.hidden = true;
  attachmentInput.setAttribute("aria-label", "Attach Matrix files");
  attachmentButton.onclick = () => attachmentInput.click();
  attachmentInput.onchange = () => {
    const inThreadId = threadRootId;
    const files = Array.from(attachmentInput.files || []);
    attachmentInput.value = "";
    void (async () => {
      for (const file of files) {
        try {
          notify(`Encrypting and uploading ${file.name}`);
          await sendAttachment(matrix, room.roomId, file, inThreadId);
          notify(`Sent ${file.name}`);
        } catch (error) { notify(safeError(error)); break; }
      }
    })();
  };
  const send = h("button", "matrix-send", "Send");
  send.type = "submit";
  send.prepend(symbol("send"));
  send.disabled = composerDisabled;
  compose.append(attachmentButton, attachmentInput, text, send);
  compose.onsubmit = (event) => {
    event.preventDefault();
    const message = text.value.trim();
    if (!message || pendingSends.has(composerKey)) return;
    const sendGeneration = lifecycle;
    pendingSends.add(composerKey);
    text.disabled = true;
    send.disabled = true;
    const content: any = { msgtype: "m.text", body: message };
    if (threadRootId) content["m.relates_to"] = { rel_type: "m.thread", event_id: threadRootId, is_falling_back: true, "m.in_reply_to": { event_id: threadRootId } };
    void matrix.sendEvent(room.roomId, sdk.EventType.RoomMessage, content)
      .then(() => {
        if (sendGeneration === lifecycle) drafts.delete(composerKey);
      })
      .catch((error) => notify(safeError(error)))
      .finally(() => {
        if (sendGeneration !== lifecycle) return;
        pendingSends.delete(composerKey);
        if (matrix === client && JSON.stringify([selectedRoomId, threadRootId]) === composerKey) {
          renderRoom();
        }
      });
  };
  shell.append(compose);
  if (notification) {
    const toast = h("div", "matrix-toast", notification);
    toast.setAttribute("role", "status");
    shell.append(toast);
  }
  mountRoom(shell);
  if (restoreComposer) {
    text.focus();
    if (composerSelection !== null) text.setSelectionRange(composerSelection, composerSelection);
  }
  const mountedTimeline = root().querySelector<HTMLElement>(".matrix-timeline");
  if (mountedTimeline) mountedTimeline.scrollTop = shouldScrollToBottom ? mountedTimeline.scrollHeight : previousScrollTop;
}

function appendAttachment(row: HTMLElement, content: any, matrix: sdk.MatrixClient) {
  if (!["m.image", "m.video", "m.audio", "m.file"].includes(content.msgtype)) return;
  const mediaUrlKey = content.file?.url || content.url;
  if (typeof mediaUrlKey !== "string") return;
  const mediaKey = JSON.stringify([row.dataset.eventId, mediaUrlKey]);
  row.dataset.mediaKey = mediaKey;
  const cached = mediaNodes.get(mediaKey);
  if (cached) { if (!cached.isConnected) row.append(cached); return; }
  const fileName = content.filename || content.body || "Matrix attachment";
  const button = h("button", "matrix-small-button matrix-attachment-button", `Open attachment: ${fileName}`);
  button.type = "button";
  button.onclick = () => { void (async () => {
    button.disabled = true;
    button.textContent = `Loading: ${fileName}`;
    try {
      const mxcUrl = content.file?.url || content.url;
      if (typeof mxcUrl !== "string") throw new Error("This Matrix attachment has no media URL.");
      const mediaUrl = matrix.mxcUrlToHttp(mxcUrl, undefined, undefined, undefined, false, true, true);
      const token = matrix.getAccessToken();
      if (!mediaUrl || !token) throw new Error("This Matrix attachment could not be opened.");
      const response = await fetch(mediaUrl, { headers: { Authorization: `Bearer ${token}` } });
      if (!response.ok) throw new Error(`Media download failed (${response.status}).`);
      const encryptedBytes = new Uint8Array(await response.arrayBuffer());
      let bytes: Uint8Array;
      if (content.file) {
        const { url: _url, ...mediaEncryptionInfo } = content.file;
        const encrypted = new EncryptedAttachment(encryptedBytes, JSON.stringify(mediaEncryptionInfo));
        try { bytes = Attachment.decrypt(encrypted); }
        finally { encrypted.free(); }
      } else bytes = encryptedBytes;
      const mimeType = content.info?.mimetype || "application/octet-stream";
      const buffer = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
      const blobUrl = URL.createObjectURL(new Blob([buffer], { type: mimeType }));
      if (client !== matrix) { URL.revokeObjectURL(blobUrl); return; }
      mediaObjectUrls.add(blobUrl);
      let preview: HTMLElement;
      if (content.msgtype === "m.image") {
        const image = h("img", "matrix-attachment-image") as HTMLImageElement;
        image.src = blobUrl; image.alt = fileName; preview = image;
      } else if (content.msgtype === "m.video") {
        const video = h("video", "matrix-attachment-video") as HTMLVideoElement;
        video.src = blobUrl; video.controls = true; video.playsInline = true; preview = video;
      } else if (content.msgtype === "m.audio") {
        const audio = h("audio", "matrix-attachment-audio") as HTMLAudioElement;
        audio.src = blobUrl; audio.controls = true; preview = audio;
      } else {
        const link = h("a", "matrix-attachment-download", `Download ${fileName}`) as HTMLAnchorElement;
        link.href = blobUrl; link.download = fileName; preview = link;
      }
      mediaNodes.set(mediaKey, preview);
      button.replaceWith(preview);
    } catch (error) {
      button.disabled = false;
      button.textContent = `Retry attachment: ${fileName}`;
      notify(safeError(error));
    }
  })(); };
  mediaNodes.set(mediaKey, button);
  row.append(button);
}

async function sendAttachment(matrix: sdk.MatrixClient, roomId: string, file: File, inThreadId: string) {
  const generation = lifecycle;
  if (client !== matrix) throw new Error("Matrix session has ended.");
  if (file.size > MAX_ATTACHMENT_BYTES) throw new Error("Matrix attachments are limited to 20 MB.");
  const encrypted = Attachment.encrypt(new Uint8Array(await file.arrayBuffer()));
  try {
    const encryptionInfo = encrypted.mediaEncryptionInfo;
    if (!encryptionInfo) throw new Error("The Matrix attachment could not be encrypted.");
    const encryptedBytes = encrypted.encryptedData;
    const buffer = encryptedBytes.buffer.slice(encryptedBytes.byteOffset, encryptedBytes.byteOffset + encryptedBytes.byteLength) as ArrayBuffer;
    const upload = await matrix.uploadContent(new Blob([buffer], { type: "application/octet-stream" }), {
      name: file.name, type: "application/octet-stream", includeFilename: false,
    });
    const msgtype = file.type.startsWith("image/") ? "m.image" : file.type.startsWith("video/") ? "m.video" : file.type.startsWith("audio/") ? "m.audio" : "m.file";
    const content: any = {
      msgtype, body: file.name, filename: file.name,
      file: { ...JSON.parse(encryptionInfo), url: upload.content_uri },
      info: { mimetype: file.type || "application/octet-stream", size: file.size },
    };
    if (inThreadId) content["m.relates_to"] = { rel_type: "m.thread", event_id: inThreadId, is_falling_back: true, "m.in_reply_to": { event_id: inThreadId } };
    if (generation !== lifecycle || client !== matrix) throw new Error("Matrix session ended before the attachment could be sent.");
    await matrix.sendEvent(roomId, sdk.EventType.RoomMessage, content);
  } finally { encrypted.free(); }
}

function action(label: string, onClick: () => void) {
  const button = h("button", "matrix-small-button", label);
  const icons: Record<string, string> = {
    "Invite": "person_add", "Invite to Space": "group_add", "1:1 voice": "call", "1:1 video": "videocam",
    "MatrixRTC": "video_call", "Jitsi": "video_chat", "Close Jitsi": "close", "Rooms": "menu",
    "Answer audio": "call", "Answer video": "videocam", "Hang up": "call_end",
  };
  if (icons[label]) button.prepend(symbol(icons[label]));
  button.type = "button";
  button.onclick = onClick;
  return button;
}

async function createRoom(isSpace: boolean) {
  if (!client) return;
  const name = prompt(isSpace ? "Name this Space" : "Name this encrypted room");
  if (!name?.trim()) return;
  const invitees = (prompt("Invite Matrix user IDs, separated by commas (optional)") || "")
    .split(",").map((userId) => userId.trim()).filter(Boolean);
  if (invitees.some((userId) => !/^@[^:\s]+:.+/.test(userId))) {
    notify("Enter full Matrix IDs such as @alex:matrix.org.");
    return;
  }
  try {
    const initial_state: any[] = [];
    if (!isSpace) initial_state.push({ type: sdk.EventType.RoomEncryption, state_key: "", content: { algorithm: "m.megolm.v1.aes-sha2" } });
    const parentSpaceId = !isSpace ? selectedSpaceId : "";
    const result = await client.createRoom({
      name: name.trim(), visibility: sdk.Visibility.Private, preset: sdk.Preset.PrivateChat, initial_state, invite: [...new Set(invitees)],
      ...(isSpace ? { creation_content: { type: "m.space" } } : {}),
    });
    if (parentSpaceId) {
      try { await linkRoomToSpace(parentSpaceId, result.room_id); }
      catch (error) { notify(`Room created, but could not add it to the Space: ${safeError(error)}`); }
    }
    if (isSpace) {
      selectedSpaceId = result.room_id;
      selectedRoomId = "";
    } else selectedRoomId = result.room_id;
    renderWorkspace();
  } catch (error) { notify(safeError(error)); }
}

function matrixServerName(id: string) {
  return id.slice(id.indexOf(":") + 1);
}

function inviteToRoom(roomId: string) {
  if (!client) return;
  const userId = prompt("Matrix user ID to invite (for example @alex:matrix.org)");
  if (!userId?.trim()) return;
  if (!/^@[^:\s]+:.+/.test(userId.trim())) { notify("Enter a full Matrix ID such as @alex:matrix.org."); return; }
  void client.invite(roomId, userId.trim()).then(() => notify(`Invited ${userId.trim()}`)).catch((error) => notify(safeError(error)));
}

async function linkRoomToSpace(spaceId: string, roomId: string) {
  if (!client) return;
  const parentVia = matrixServerName(spaceId);
  const roomVia = matrixServerName(roomId);
  const sendState = client.sendStateEvent.bind(client) as (id: string, type: string, content: object, stateKey?: string) => Promise<unknown>;
  await sendState(spaceId, "m.space.child", { ...(roomVia ? { via: [roomVia] } : {}), suggested: true }, roomId);
  // Child-side parent state is optional, and often needs moderator permissions.
  try { await sendState(roomId, "m.space.parent", { ...(parentVia ? { via: [parentVia] } : {}), canonical: true }, spaceId); }
  catch { /* The Space's child state remains authoritative. */ }
}

function parseRoomTarget(value: string): { id: string; viaServers: string[] } {
  let id = value.trim();
  let viaServers: string[] = [];
  if (/^https?:\/\//i.test(id)) {
    const link = new URL(id);
    if (link.protocol !== "https:" || link.hostname !== "matrix.to" || link.port || link.username || link.password || !link.hash.startsWith("#/")) {
      throw new Error("Use a Matrix room alias (#room:server), room ID (!id:server), or an https://matrix.to room link.");
    }
    const fragment = link.hash.slice(2);
    const queryIndex = fragment.indexOf("?");
    const target = queryIndex < 0 ? fragment : fragment.slice(0, queryIndex);
    id = decodeURIComponent(target.split("/")[0]);
    viaServers = new URLSearchParams(queryIndex < 0 ? "" : fragment.slice(queryIndex + 1)).getAll("via");
  }
  if (!/^[!#][^:\s]+:[^\s/?#]+$/.test(id)) {
    throw new Error("Enter the full room alias (#room:server) or room ID (!id:server), including its server name.");
  }
  viaServers = [...new Set(viaServers)].filter((server) => {
    try {
      const url = new URL(`https://${server}`);
      return !!url.hostname && !url.username && !url.password && url.pathname === "/" && !url.search && !url.hash;
    } catch { return false; }
  }).slice(0, 3);
  if (!viaServers.length && id.startsWith("!")) viaServers = [matrixServerName(id)];
  return { id, viaServers };
}

function handleRoomUpdate(room: sdk.Room) {
  if (!client) return;
  if (room.roomId === awaitingRoomId && room.getMyMembership() === sdk.KnownMembership.Join) {
    awaitingRoomId = "";
    if (selectedRoomId === room.roomId) {
      selectJoinedRoom(room);
      if (!room.isSpaceRoom()) document.querySelector(".sidebar")?.classList.remove("open");
    }
    notify(`Joined ${room.name || room.roomId}`);
  }
  renderRoomList();
  if (active || selectedRoomId === room.roomId) renderRoom();
}

async function joinRoomTarget(value: string) {
  const matrix = client;
  if (!matrix || joiningTarget) return;
  const generation = lifecycle;
  try {
    const target = parseRoomTarget(value);
    joiningTarget = target.id;
    renderRoomList();
    notify(`Joining ${target.id}...`);
    const joined = await matrix.joinRoom(target.id, target.viaServers.length ? { viaServers: target.viaServers } : {});
    if (client !== matrix || generation !== lifecycle) return;
    roomFilter = "";
    selectedSpaceId = "";
    threadRootId = "";
    selectedRoomId = joined.roomId;
    awaitingRoomId = joined.roomId;
    const syncedRoom = matrix.getRoom(joined.roomId);
    if (syncedRoom?.getMyMembership() === sdk.KnownMembership.Join) handleRoomUpdate(syncedRoom);
    else notify("Room joined. Waiting for the homeserver to load its messages...");
    renderWorkspace();
  } catch (error) {
    if (client === matrix && generation === lifecycle) notify(`Could not join room: ${safeError(error)}`);
  } finally {
    if (client === matrix && generation === lifecycle) {
      joiningTarget = "";
      renderRoomList();
    }
  }
}

function joinRoomPrompt() {
  if (!client || joiningTarget) return;
  const room = prompt("Enter a full Matrix room alias (#room:server), room ID (!id:server), or matrix.to link");
  if (room?.trim()) void joinRoomTarget(room);
}

async function addJitsi() {
  if (!client || !selectedRoomId) return;
  const room = client.getRoom(selectedRoomId);
  const suggested = `https://meet.jit.si/${selectedRoomId.replace(/[^a-zA-Z0-9]/g, "").slice(0, 36)}`;
  const url = prompt("Jitsi meeting URL (Jitsi is a separate service and is not Matrix end-to-end encrypted)", suggested);
  if (!url) return;
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:") throw new Error("Use a secure HTTPS Jitsi URL.");
    const widgetId = `seres-jitsi-${crypto.randomUUID()}`;
    const sendState = client.sendStateEvent.bind(client) as (id: string, type: string, content: object, stateKey?: string) => Promise<unknown>;
    await sendState(selectedRoomId, "im.vector.modular.widgets", {
      creator: client.getUserId(), id: widgetId, name: "Jitsi video call", type: "jitsi", url: parsed.href,
      roomId: selectedRoomId, data: {}, waitForIframeLoad: true,
    }, widgetId);
    showJitsi(parsed.href, room?.name || selectedRoomId);
  } catch (error) { notify(safeError(error)); }
}

function showJitsi(url: string, title: string) {
  activeCall?.hangup("user_hangup", false);
  activeCall = null;
  callPanel?.querySelector("iframe")?.setAttribute("src", "about:blank");
  const frame = h("iframe", "matrix-jitsi") as HTMLIFrameElement;
  frame.title = title; frame.src = url;
  frame.allow = "camera; microphone; display-capture; autoplay; clipboard-write";
  frame.allowFullscreen = true;
  const panel = h("section", "matrix-call-panel");
  const close = action("Close Jitsi", () => { frame.src = "about:blank"; callPanel = null; renderRoom(); });
  panel.append(close, frame); callPanel = panel; renderRoom();
}

function openMatrixRtc(room: sdk.Room) {
  const server = matrixServerName(room.roomId);
  const url = new URL("https://call.element.io/room/");
  const params = new URLSearchParams({ roomId: room.roomId, viaServers: server, intent: "start_call", confineToRoom: "true" });
  url.hash = `/${encodeURIComponent(room.name || "call")}?${params.toString()}`;
  window.open(url.href, "_blank", "noopener,noreferrer");
}

async function placeCall(video: boolean) {
  if (!client || !selectedRoomId) return;
  if (client.getRoom(selectedRoomId)?.getJoinedMemberCount() !== 2) {
    notify("Legacy Matrix calls require a direct room with one other member."); return;
  }
  const call: any = client.createCall(selectedRoomId);
  if (!call) { notify("This browser does not support Matrix calls."); return; }
  showCall(call, false);
  try { if (video) await call.placeVideoCall(); else await call.placeVoiceCall(); }
  catch (error) { notify(safeError(error)); }
}

function showCall(call: any, incoming: boolean) {
  if (activeCall && activeCall !== call) activeCall.hangup("user_hangup", false);
  activeCall = call;
  callPanel?.querySelector("iframe")?.setAttribute("src", "about:blank");
  const panel = h("section", "matrix-call-panel");
  panel.append(h("strong", "", incoming ? "Incoming Matrix call" : "Matrix call"));
  const remote = h("video", "matrix-call-video") as HTMLVideoElement;
  remote.autoplay = true;
  remote.muted = true;
  remote.playsInline = true;
  remote.setAttribute("aria-label", "Remote participant video");
  const local = h("video", "matrix-call-video matrix-call-local") as HTMLVideoElement;
  local.autoplay = true;
  local.muted = true;
  local.playsInline = true;
  local.hidden = true;
  local.setAttribute("aria-label", "Your video preview");
  const audio = h("audio") as HTMLAudioElement;
  audio.autoplay = true;
  panel.append(remote, local, audio);
  const updateFeeds = () => {
    const remoteFeed = (call.getRemoteFeeds?.() || []).find((feed: any) => feed.purpose === "m.usermedia");
    if (remoteFeed?.stream) { remote.srcObject = remoteFeed.stream; audio.srcObject = remoteFeed.stream; }
    audio.muted = !!remoteFeed?.isAudioMuted?.();
    const localFeed = (call.getLocalFeeds?.() || []).find((feed: any) => feed.purpose === "m.usermedia");
    if (localFeed?.stream && localFeed.stream.getVideoTracks().length) {
      local.srcObject = localFeed.stream;
      local.hidden = false;
    }
  };
  call.on(sdk.CallEvent.FeedsChanged, updateFeeds);
  call.on(sdk.CallEvent.State, updateFeeds);
  const closeCall = () => {
    if (activeCall === call) activeCall = null;
    if (callPanel === panel) { callPanel = null; renderRoom(); }
  };
  call.on(sdk.CallEvent.Hangup, closeCall);
  call.on(sdk.CallEvent.Error, (error: unknown) => { notify(safeError(error)); closeCall(); });
  updateFeeds();
  const controls = h("div", "matrix-call-controls");
  if (incoming) {
    controls.append(action("Answer audio", () => void call.answer(true, false).catch((error: unknown) => notify(safeError(error)))));
    controls.append(action("Answer video", () => void call.answer(true, true).catch((error: unknown) => notify(safeError(error)))));
  }
  controls.append(action("Hang up", () => { call.hangup("user_hangup", false); closeCall(); }));
  panel.append(controls);
  callPanel = panel;
  renderRoom();
}

function renderLogin(error = "") {
  const panel = sidebar(); panel.classList.add("matrix-list-panel"); panel.replaceChildren(h("div", "matrix-sidebar-head", "Matrix"), h("p", "matrix-hint", "Connect your Matrix account. Your Matrix account stays separate from SereS."));
  const server = h("input", "matrix-field") as HTMLInputElement;
  server.type = "url"; server.setAttribute("autocomplete", "url"); server.setAttribute("aria-label", "Matrix homeserver URL"); server.placeholder = "https://matrix.example.org"; server.value = localStorage.getItem("seres.matrix.server") || "";
  server.oninput = () => { loginBaseUrl = ""; loginFlows = []; sso.replaceChildren(); };
  const user = h("input", "matrix-field") as HTMLInputElement;
  user.autocomplete = "username"; user.setAttribute("aria-label", "Matrix username"); user.placeholder = "Matrix username";
  const password = h("input", "matrix-field") as HTMLInputElement;
  password.type = "password"; password.autocomplete = "current-password"; password.setAttribute("aria-label", "Matrix password"); password.placeholder = "Password";
  const form = h("form", "matrix-login-form");
  const status = h("p", "matrix-status"); status.dataset.matrixStatus = ""; status.setAttribute("role", "status"); status.setAttribute("aria-live", "polite"); status.textContent = error || notification;
  const discover = h("button", "matrix-small-button", "Check homeserver"); discover.type = "button";
  discover.onclick = () => { void (async () => {
    const requestedServer = server.value;
    discover.disabled = true;
    try {
      const baseUrl = await discoverHomeserver(requestedServer);
      const auth = sdk.createClient({ baseUrl });
      const flows = (await auth.loginFlows()).flows || [];
      if (!server.isConnected || server.value !== requestedServer) return;
      loginBaseUrl = baseUrl;
      loginFlows = flows;
      localStorage.setItem("seres.matrix.server", requestedServer.trim());
      renderLogin();
      notify("Homeserver ready. Password and SSO options are shown when supported.");
    } catch (reason) { if (server.isConnected && server.value === requestedServer) renderLogin(safeError(reason)); }
    finally { discover.disabled = false; }
  })(); };
  const login = h("button", "matrix-send", "Sign in"); login.type = "submit";
  form.onsubmit = (event) => { event.preventDefault(); if (authenticating) return; authenticating = true; login.disabled = true; void (async () => {
    const requestedServer = server.value;
    const username = user.value.trim();
    const enteredPassword = password.value;
    server.disabled = user.disabled = password.disabled = discover.disabled = true;
    try {
      const resolvedBaseUrl = await discoverHomeserver(requestedServer);
      if (loginBaseUrl && loginBaseUrl !== resolvedBaseUrl) loginFlows = [];
      loginBaseUrl = resolvedBaseUrl;
      localStorage.setItem("seres.matrix.server", requestedServer.trim());
      const auth = sdk.createClient({ baseUrl: loginBaseUrl });
      if (!loginFlows.length) loginFlows = (await auth.loginFlows()).flows || [];
      if (!loginFlows.some((flow) => flow.type === "m.login.password")) throw new Error("Password login is not enabled by this homeserver. Try its SSO option.");
      const response = await auth.loginRequest({ type: "m.login.password", identifier: { type: "m.id.user", user: username }, password: enteredPassword, initial_device_display_name: "SereS web" });
      await finishLogin(loginBaseUrl, response);
    } catch (reason) { renderLogin(safeError(reason)); }
    finally { authenticating = false; login.disabled = false; server.disabled = user.disabled = password.disabled = discover.disabled = false; }
  })(); };
  form.append(server, discover, user, password, login, status);
  const sso = h("div", "matrix-login-options");
  for (const flow of loginFlows.filter((item) => item.type === "m.login.sso" || item.type === "m.login.cas")) {
    const providers = flow.identity_providers || [];
    const options = providers.length ? providers : [{ id: "", name: flow.type === "m.login.cas" ? "Legacy CAS" : "Single sign-on" }];
    for (const provider of options) {
      const button = h("button", "matrix-small-button", `Continue with ${provider.name || "SSO"}`); button.type = "button";
      button.onclick = () => {
        try {
          if (!loginBaseUrl) throw new Error("Check the homeserver first.");
          const state = crypto.randomUUID();
          sessionStorage.setItem(SSO_STATE_KEY, state);
          sessionStorage.setItem("seres.matrix.sso.server", loginBaseUrl);
          const redirect = new URL(location.href); redirect.searchParams.set("matrix_sso", state);
          const unauth = sdk.createClient({ baseUrl: loginBaseUrl });
          location.href = unauth.getSsoLoginUrl(redirect.href, flow.type === "m.login.cas" ? "cas" : "sso", provider.id || undefined, sdk.SSOAction.LOGIN);
        } catch (reason) { notify(safeError(reason)); }
      };
      sso.append(button);
    }
  }
  panel.append(form, sso);
  const statusBlock = h("div", "matrix-login-explanation");
  statusBlock.append(h("strong", "", "End-to-end encryption"), h("p", "matrix-hint", "Matrix keys are stored in this browser's local IndexedDB crypto store. SereS does not yet provide key backup or device verification controls; use a trusted Matrix client to set up recovery and verify devices."));
  panel.append(statusBlock);
  root().replaceChildren();
  const intro = h("section", "matrix-login-screen");
  intro.append(h("h2", "", "Matrix"), h("p", "", "Use encrypted Matrix rooms, Spaces and threaded conversations from SereS."));
  if (error || notification) status.textContent = error || notification;
  root().append(intro);
  void handleSsoCallback().then((handled) => { if (handled) renderWorkspace(); }).catch((reason) => renderLogin(safeError(reason)));
}

async function logout() {
  try { await client?.logout(true); } catch { /* The homeserver may already have revoked this session. */ }
  await stop();
  localStorage.removeItem(SESSION_KEY);
  sessionStorage.removeItem(TOKEN_KEY);
  selectedRoomId = ""; selectedSpaceId = ""; threadRootId = "";
  drafts.clear();
  pendingSends.clear();
  renderLogin();
}

function activate() {
  active = true;
  if (new URLSearchParams(location.search).has("loginToken")) { renderLogin(); return; }
  const session = savedSession();
  if (!session) { renderLogin(); return; }
  if (connectionTask) return;
  if (!client) void connect(session);
  else renderWorkspace();
}
function deactivate() { active = false; }

window.SeresMatrix = { activate, deactivate };
if (new URLSearchParams(location.search).has("loginToken")) {
  window.dispatchEvent(new Event("seres:open-matrix"));
}
