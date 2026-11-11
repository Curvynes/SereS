(() => {
  // ------------------------------------------------------------------ types

  interface UserRef {
    id: string;
    username: string;
    display_name?: string | null;
  }

  interface Me extends UserRef {
    email: string;
    show_last_seen?: boolean;
    pub_ecdh: string;
    pub_sign: string;
    enc_private: string;
  }

  interface Member extends UserRef {
    pub_ecdh: string | null;
    pub_sign: string | null;
    role: string;
    // Reset the password by e-mail and can't read these messages until someone shares them.
    history_reset?: { from_seq: number; until_seq: number } | null;
  }

  interface Message {
    seq: number;
    rev: number;
    id: string;
    sender_id: string | null;
    sender: string | null;
    sender_display?: string | null;
    kind: "e2e" | "legacy" | "system";
    payload: any;
    created_at: string;
    edited_at?: string | null;
    deleted: boolean;
    silent?: boolean;
    expires_at?: string | null;
    // After a password reset by e-mail: the message key another member shared.
    share?: SeresSharedKey;
  }

  /** An encrypted attachment; key and iv only exist inside the encrypted message. */
  interface FileRef {
    id: string;
    key: string;
    iv: string;
    name: string;
    mime: string;
    size: number;
    kind: "image" | "video" | "audio" | "voice" | "file";
    duration?: number;
    width?: number;
    height?: number;
  }

  /** What is inside an encrypted message. */
  interface Content {
    text?: string;
    reply?: { id: string; sender_id: string | null; preview: string };
    file?: FileRef;
    forwarded?: boolean;
    // Reactions are silent messages pointing at another message.
    type?: "reaction" | "poll";
    target?: string;
    emoji?: string;
    poll?: { question: string; options: string[] };
  }

  interface Presence {
    online: boolean;
    last_seen: string;
  }

  interface Pin {
    message_id: string;
    seq: number;
    pinned_at: string;
    pinned_by: string | null;
  }

  interface ChatSummary {
    id: string;
    type: "dm" | "group";
    name: string;
    avatar_updated_at?: string | null;
    role: string;
    member_count: number;
    last_message: Message | null;
    unread: number;
    last_activity: string;
    other_user?: string;
    other_user_id?: string;
    blocked?: boolean;
    muted?: boolean;
    typing?: UserRef[];
    members?: Member[];
    owner_id?: string;
    pinned?: boolean;
    archived?: boolean;
    disappear_seconds?: number;
    presence?: Presence | null;
    pins?: Pin[];
  }

  interface Shown {
    type: "text" | "legacy" | "system" | "deleted" | "error";
    text: string;
    content?: Content;
  }

  interface OpenChat {
    id: string;
    details: ChatSummary | null;
    messages: Map<string, Message>;
    maxRev: number;
    oldestSeq: number;
    hasMore: boolean;
    lastReadSent: number;
    changedKeys: Member[];
    missingKeys: Member[];
    subtitle: string;
    typing: UserRef[];
    // Up to which message all other members got / read it (for the ticks).
    receipts: { delivered_seq: number; read_seq: number } | null;
    // Search in the chat: matching message ids and the selected one.
    search: { query: string; hits: string[]; index: number } | null;
  }

  class ApiError extends Error {
    constructor(
      message: string,
      public status: number,
    ) {
      super(message);
    }
  }

  // ------------------------------------------------------------------ state

  let me: Me;
  let identity: SeresIdentity;
  let chats: ChatSummary[] = [];
  let friends = {
    friends: [] as UserRef[],
    incoming: [] as UserRef[],
    outgoing: [] as UserRef[],
    blocked: [] as UserRef[],
  };
  let current: OpenChat | null = null;
  let chatsSignature = "";
  let friendsSignature = "";
  let sending = false;
  // The own message that is being edited in the input field.
  let editing: { chatId: string; message: Message; content: Content } | null = null;
  // Invite token from a link like /?invite=..., kept across the login redirect.
  const pendingInvite = new URLSearchParams(window.location.search).get("invite");
  // Set by the login page after a password reset ("code" or "mail").
  const recoveredBy = new URLSearchParams(window.location.search).get("recovered");
  let inviteToAccept: { token: string; name: string } | null = null;

  // Message that is being answered (shown above the input field).
  let replyTo: { chatId: string; message: Message; preview: string } | null = null;
  // Unsent text per chat. Kept in memory only, so no plaintext is stored on the device.
  const drafts = new Map<string, string>();
  // Attachments picked but not sent yet.
  let pendingFiles: File[] = [];
  let showArchived = false;
  // Unread counts from the last refresh, to notice new messages for notifications.
  let lastUnread: Map<string, number> | null = null;
  // Decrypted attachments as blob: URLs, by file id.
  const fileUrls = new Map<string, Promise<string>>();

  interface KnownKeys {
    id: string;
    username: string;
    pub_ecdh: string | null;
    pub_sign: string | null;
    // Keys replaced by a password reset, oldest first, valid until "until".
    previous_keys?: { pub_ecdh: string; pub_sign: string; until: string }[];
  }
  const userKeys = new Map<string, KnownKeys>();

  /** The sender's keys that were valid when the message was written. */
  function keysAt(user: KnownKeys, createdAt: string) {
    const previous = (user.previous_keys || []).find((old) => createdAt <= old.until);
    return previous || { pub_ecdh: user.pub_ecdh, pub_sign: user.pub_sign };
  }
  const shownCache = new Map<string, Promise<Shown>>();
  const avatarState = new Map<string, "yes" | "no">();

  const MESSAGE_LIMIT = 4000;
  const MAX_FILE_SIZE = 16 * 1024 * 1024;
  const DISAPPEAR_OPTIONS = [0, 3600, 86400, 7 * 86400, 90 * 86400];
  const t = SeresI18n.t;

  // ------------------------------------------------------------- utilities

  function $(id: string): HTMLElement {
    return document.getElementById(id) as HTMLElement;
  }

  function h<K extends keyof HTMLElementTagNameMap>(
    tag: K,
    options: { className?: string; text?: string; title?: string; attrs?: Record<string, string> } = {},
    children: (Node | null | undefined | false)[] = [],
  ): HTMLElementTagNameMap[K] {
    const element = document.createElement(tag);
    if (options.className) element.className = options.className;
    if (options.text !== undefined) element.textContent = options.text;
    if (options.title) element.title = options.title;
    for (const [key, value] of Object.entries(options.attrs || {})) {
      element.setAttribute(key, value);
    }
    for (const child of children) {
      if (child) element.appendChild(child);
    }
    return element;
  }

  function button(text: string, className: string, onClick: (event: MouseEvent) => void, title?: string) {
    const btn = h("button", { className, text, title, attrs: { type: "button" } });
    btn.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
      onClick(event);
    });
    return btn;
  }

  function goToLogin(reason?: string) {
    const params = new URLSearchParams();
    if (reason) params.set("reason", reason);
    if (pendingInvite) params.set("invite", pendingInvite);
    const query = params.toString();
    window.location.href = "login.html" + (query ? "?" + query : "");
  }

  async function api(path: string, options: { method?: string; body?: object } = {}): Promise<any> {
    const response = await fetch(path, {
      method: options.method || (options.body ? "POST" : "GET"),
      headers: options.body ? { "Content-Type": "application/json" } : {},
      credentials: "same-origin",
      body: options.body ? JSON.stringify(options.body) : undefined,
    });
    if (response.status === 401) {
      goToLogin();
      throw new ApiError("Not logged in", 401);
    }
    const data = await response.json().catch(() => ({}));
    if (!response.ok || data.success === false) {
      throw new ApiError(data.message || t("common.requestFailed"), response.status);
    }
    return data;
  }

  function post(path: string, body: object = {}) {
    return api(path, { method: "POST", body });
  }

  let alertTimer: number | null = null;
  function showAlert(message: string) {
    const box = $("alert");
    $("alert-text").textContent = message;
    box.classList.remove("hidden");
    if (alertTimer !== null) clearTimeout(alertTimer);
    alertTimer = window.setTimeout(() => box.classList.add("hidden"), 4000);
  }

  function errorText(error: unknown) {
    if (error instanceof ApiError) return error.message;
    if (error instanceof TypeError) return t("common.unreachable");
    return error instanceof Error ? error.message : String(error);
  }

  function colorFor(name: string) {
    const palette = ["#5865f2", "#00a884", "#eb459e", "#f0b232", "#3ba55d", "#ed4245", "#53bdeb", "#9b59b6"];
    let hash = 0;
    for (let i = 0; i < name.length; i++) hash = (hash * 31 + name.charCodeAt(i)) | 0;
    return palette[Math.abs(hash) % palette.length];
  }

  /** The name shown in the app; the @username only appears in the profile. */
  function nameOf(user: { username: string; display_name?: string | null }) {
    return user.display_name || user.username;
  }

  /** Avatar of a user (picture loaded by username); label is the name the initial is taken from. */
  function avatarEl(name: string, options: { group?: boolean; groupId?: string; avatarUpdatedAt?: string | null; className?: string; label?: string } = {}) {
    const avatar = h("div", { className: options.className || "avatar" });
    avatar.style.backgroundColor = colorFor(name);
    const initial = h("span", { text: options.group ? "#" : (options.label || name).charAt(0).toUpperCase() || "?" });
    avatar.appendChild(initial);
    if (options.group && options.groupId && options.avatarUpdatedAt) {
      const img = h("img", { attrs: { alt: "" } });
      img.style.display = "none";
      img.addEventListener("load", () => { img.style.display = "block"; initial.style.display = "none"; });
      img.addEventListener("error", () => img.remove());
      img.src = `/api/chats/${encodeURIComponent(options.groupId)}/avatar?v=${encodeURIComponent(options.avatarUpdatedAt || "0")}`;
      avatar.appendChild(img);
    } else if (!options.group && avatarState.get(name) !== "no") {
      const img = h("img", { attrs: { alt: "" } });
      img.style.display = "none";
      img.addEventListener("load", () => {
        avatarState.set(name, "yes");
        img.style.display = "block";
        initial.style.display = "none";
      });
      img.addEventListener("error", () => {
        avatarState.set(name, "no");
        img.remove();
      });
      img.src = "/api/users/" + encodeURIComponent(name) + "/avatar";
      avatar.appendChild(img);
    }
    return avatar;
  }

  function parseTime(iso: string) {
    return new Date(iso);
  }

  function formatTime(iso: string) {
    return parseTime(iso).toLocaleTimeString(SeresI18n.getLanguage(), { hour: "2-digit", minute: "2-digit" });
  }

  function formatDay(date: Date) {
    const today = new Date();
    const yesterday = new Date();
    yesterday.setDate(today.getDate() - 1);
    if (date.toDateString() === today.toDateString()) return t("chat.today");
    if (date.toDateString() === yesterday.toDateString()) return t("chat.yesterday");
    return date.toLocaleDateString(SeresI18n.getLanguage(), { day: "2-digit", month: "2-digit", year: "numeric" });
  }

  function formatListTime(iso: string) {
    const date = parseTime(iso);
    return date.toDateString() === new Date().toDateString()
      ? formatTime(iso)
      : date.toLocaleDateString(SeresI18n.getLanguage(), { day: "2-digit", month: "2-digit" });
  }

  // ------------------------------------------------------------------ keys

  function pinStoreKey(kind: string) {
    return "seres-" + kind + ":" + me.id;
  }

  function readStore(kind: string): Record<string, string> {
    try {
      return JSON.parse(localStorage.getItem(pinStoreKey(kind)) || "{}");
    } catch {
      return {};
    }
  }

  function writeStore(kind: string, value: Record<string, string>) {
    try {
      localStorage.setItem(pinStoreKey(kind), JSON.stringify(value));
    } catch {
      /* storage unavailable */
    }
  }

  async function memberFingerprint(member: { pub_ecdh: string | null; pub_sign: string | null }) {
    if (!member.pub_ecdh || !member.pub_sign) return null;
    return SeresCrypto.fingerprint(member.pub_ecdh, member.pub_sign);
  }

  /**
   * Trust on first use: remember every contact's key fingerprint and warn when
   * the server suddenly hands out a different key for the same person.
   */
  async function checkPins(members: Member[]) {
    const pins = readStore("pins");
    const changed: Member[] = [];
    const missing: Member[] = [];
    let dirty = false;
    for (const member of members) {
      if (member.id === me.id) continue;
      const fp = await memberFingerprint(member);
      if (!fp) {
        missing.push(member);
        continue;
      }
      if (!pins[member.id]) {
        pins[member.id] = fp;
        dirty = true;
      } else if (pins[member.id] !== fp) {
        changed.push(member);
      }
    }
    if (dirty) writeStore("pins", pins);
    return { changed, missing };
  }

  async function acceptNewKeys(members: Member[]) {
    const pins = readStore("pins");
    const verified = readStore("verified");
    for (const member of members) {
      const fp = await memberFingerprint(member);
      if (fp) pins[member.id] = fp;
      delete verified[member.id];
    }
    writeStore("pins", pins);
    writeStore("verified", verified);
  }

  async function ensureUserKeys(ids: string[]) {
    const missing = [...new Set(ids)].filter((id) => id && !userKeys.has(id));
    if (!missing.length) return;
    const data = await api("/api/users/keys?ids=" + encodeURIComponent(missing.join(",")));
    for (const user of data.users) userKeys.set(user.id, user);
  }

  function callLength(seconds: number) {
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = String(seconds % 60).padStart(2, "0");
    return h ? `${h}:${String(m).padStart(2, "0")}:${s}` : `${m}:${s}`;
  }

  function systemText(payload: any) {
    if (!payload) return "";
    switch (payload.event) {
      case "created":
      case "added":
      case "removed":
      case "left":
      case "renamed":
      case "pinned":
      case "keys_reset":
      case "history_shared":
        return t("system." + payload.event, {
          actor: payload.actor ?? "",
          target: payload.target ?? "",
          name: payload.name ?? "",
        });
      case "call":
        return typeof payload.seconds === "number"
          ? t("system.call", { actor: payload.actor ?? "", time: callLength(payload.seconds) })
          : t("system.callMissed", { actor: payload.actor ?? "" });
      case "disappearing":
        return payload.seconds
          ? t("system.disappearingOn", { actor: payload.actor ?? "", time: disappearLabel(payload.seconds) })
          : t("system.disappearingOff", { actor: payload.actor ?? "" });
      default:
        return "";
    }
  }

  function showMessage(chatId: string, message: Message): Promise<Shown> {
    const cacheKey = message.id + ":" + message.rev + (message.share ? ":shared" : "");
    let shown = shownCache.get(cacheKey);
    if (!shown) {
      shown = (async (): Promise<Shown> => {
        if (message.deleted) return { type: "deleted", text: t("msg.deleted") };
        if (message.kind === "system") return { type: "system", text: systemText(message.payload) };
        if (message.kind === "legacy") return { type: "legacy", text: String(message.payload?.text ?? "") };
        try {
          await ensureUserKeys([message.sender_id!]);
          const known = userKeys.get(message.sender_id!);
          const sender = known ? { id: known.id, ...keysAt(known, message.created_at) } : null;
          if (!sender || !sender.pub_ecdh || !sender.pub_sign) throw new Error("unknown sender");
          const content = await SeresCrypto.decryptMessage(
            identity,
            chatId,
            message.id,
            { id: sender.id, pub_ecdh: sender.pub_ecdh, pub_sign: sender.pub_sign },
            message.payload,
            message.share,
          );
          const parsed: Content = content && typeof content === "object" ? content : {};
          return { type: "text", text: String(parsed.text ?? ""), content: parsed };
        } catch (error) {
          console.warn("Could not decrypt message", message.id, error);
          // From before my own reset by e-mail and nobody shared it.
          const resets = userKeys.get(me.id)?.previous_keys || [];
          const lastReset = resets.length ? resets[resets.length - 1].until : "";
          if (!message.share && message.created_at <= lastReset) return { type: "error", text: t("history.notShared") };
          return { type: "error", text: t("msg.decryptError") };
        }
      })();
      shownCache.set(cacheKey, shown);
    }
    return shown;
  }

  // ------------------------------------------------------------ chat list

  async function loadChats() {
    const data = await api("/api/chats");
    // Pinned chats first, otherwise by last activity (as sent by the server).
    chats = (data.chats as ChatSummary[])
      .map((chat, index) => ({ chat, index }))
      .sort((a, b) => Number(!!b.chat.pinned) - Number(!!a.chat.pinned) || a.index - b.index)
      .map((entry) => entry.chat);
    const previews = await Promise.all(
      chats.map(async (chat) => (chat.last_message ? showMessage(chat.id, chat.last_message) : null)),
    );
    notifyNewMessages(previews);
    const signature = JSON.stringify([chats, previews.map((p) => p && p.text), [...drafts], showArchived]);
    updateBadges();
    if (signature === chatsSignature) return;
    chatsSignature = signature;
    renderChatList(previews);
    if (current) {
      const summary = chats.find((chat) => chat.id === current!.id);
      if (!summary) {
        closeChat();
      } else if (current.details && summary.member_count !== current.details.member_count) {
        refreshCurrentDetails();
      }
    }
  }

  // ------------------------------------------------------- notifications

  function notificationsEnabled() {
    return (
      "Notification" in window && Notification.permission === "granted" && readStore("settings").notify === "on"
    );
  }

  /** Shows a desktop notification for chats with new unread messages. */
  function notifyNewMessages(previews: (Shown | null)[]) {
    const counts = new Map(chats.map((chat) => [chat.id, chat.unread] as [string, number]));
    const before = lastUnread;
    lastUnread = counts;
    if (!before || !notificationsEnabled()) return;
    chats.forEach((chat, index) => {
      const old = before.get(chat.id) ?? 0;
      if (chat.unread <= old) return;
      if (document.visibilityState === "visible" && current && current.id === chat.id) return;
      const body = readStore("settings").preview === "off" ? t("notify.newMessage") : previewText(chat, previews[index]);
      try {
        const note = new Notification(chat.name, { body, tag: chat.id, icon: "assets/favicon.png" });
        note.onclick = () => {
          window.focus();
          switchView("chats");
          openChat(chat.id);
          note.close();
        };
      } catch {
        /* notifications not supported here (e.g. some mobile browsers) */
      }
    });
  }

  async function toggleNotifications() {
    const settings = readStore("settings");
    if (settings.notify === "on") {
      settings.notify = "off";
    } else {
      if (!("Notification" in window)) {
        showAlert(t("notify.unsupported"));
        return;
      }
      const permission = await Notification.requestPermission();
      if (permission !== "granted") {
        showAlert(t("notify.denied"));
        return;
      }
      settings.notify = "on";
    }
    writeStore("settings", settings);
    renderSettingsToggles();
  }

  function previewText(chat: ChatSummary, shown: Shown | null) {
    if (!chat.last_message || !shown) return chat.type === "group" ? t("list.members", { count: chat.member_count }) : t("list.noMessages");
    const message = chat.last_message;
    if (shown.type === "system") return shown.text;
    const prefix = message.sender_id === me.id ? t("list.you") : chat.type === "group" && message.sender ? (message.sender_display || message.sender) + ": " : "";
    if (shown.type === "deleted") return prefix + t("list.deleted");
    return prefix + contentPreview(shown);
  }

  /** One line describing a message: its text, or what was attached. */
  function contentPreview(shown: Shown) {
    if (shown.content?.type === "poll" && shown.content.poll) return t("poll.preview", { question: shown.content.poll.question });
    const file = shown.content?.file;
    const text = SeresFormat.plain(shown.text);
    if (!file) return text;
    const label =
      file.kind === "image"
        ? t("file.photo")
        : file.kind === "video"
          ? t("file.video")
          : file.kind === "voice"
            ? t("file.voice", { duration: formatDuration(file.duration || 0) })
            : file.kind === "audio"
              ? file.name
              : file.name;
    return text ? label + " · " + text : label;
  }

  function formatDuration(seconds: number) {
    const s = Math.max(0, Math.round(seconds));
    return Math.floor(s / 60) + ":" + String(s % 60).padStart(2, "0");
  }

  function formatSize(bytes: number) {
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(0) + " KB";
    return (bytes / 1024 / 1024).toFixed(1) + " MB";
  }

  function disappearLabel(seconds: number) {
    if (!seconds) return t("disappear.off");
    if (seconds < 86400) return t("disappear.hours", { count: seconds / 3600 });
    return t("disappear.days", { count: seconds / 86400 });
  }

  function renderChatList(previews: (Shown | null)[]) {
    const list = $("dm-list");
    const filter = (($("list-search") as HTMLInputElement).value || "").toLowerCase();
    list.textContent = "";
    const archivedCount = chats.filter((chat) => chat.archived).length;
    if (archivedCount && !filter) {
      const toggle = h("div", { className: "list-item archive-toggle" }, [
        h("div", { className: "avatar archive-icon" }, [h("span", { className: "material-symbols-rounded", text: showArchived ? "arrow_back" : "archive" })]),
        h("div", { className: "item-info" }, [
          h("span", { className: "item-name", text: showArchived ? t("archive.back") : t("archive.title") }),
          h("span", { className: "item-status", text: t("archive.count", { count: archivedCount }) }),
        ]),
      ]);
      toggle.addEventListener("click", () => {
        showArchived = !showArchived;
        chatsSignature = "";
        loadChats().catch(() => {});
      });
      list.appendChild(toggle);
    }
    chats.forEach((chat, index) => {
      if (filter && !chat.name.toLowerCase().includes(filter)) return;
      // The search looks through all chats, otherwise only the current section is shown.
      if (!filter && !!chat.archived !== showArchived) return;
      const item = h("div", {
        className: "list-item chat-list-item" + (current && current.id === chat.id ? " active" : ""),
        attrs: { "data-chatid": chat.id },
      });
      const avatarName = chat.type === "dm" && chat.other_user ? chat.other_user : chat.name;
      item.appendChild(avatarEl(avatarName, { group: chat.type === "group", groupId: chat.type === "group" ? chat.id : undefined, avatarUpdatedAt: chat.avatar_updated_at, label: chat.name }));
      const nameRow = h("div", { className: "item-row" }, [
        h("span", { className: "item-name" }, [
          document.createTextNode(chat.name),
          chat.muted ? h("span", { className: "material-symbols-rounded muted-icon", text: "notifications_off", title: t("chat.muted") }) : null,
          chat.disappear_seconds ? h("span", { className: "material-symbols-rounded muted-icon", text: "timer", title: t("disappear.title") }) : null,
        ]),
        h("span", { className: "item-time" }, [
          chat.pinned ? h("span", { className: "material-symbols-rounded pin-icon", text: "push_pin", title: t("chatMenu.pinned") }) : null,
          document.createTextNode(formatListTime(chat.last_activity)),
        ]),
      ]);
      const draft = current && current.id === chat.id ? "" : drafts.get(chat.id);
      const statusRow = h("div", { className: "item-row" }, [
        chat.typing && chat.typing.length
          ? h("span", { className: "item-status typing", text: t("typing.short") })
          : draft
            ? h("span", { className: "item-status" }, [
                h("span", { className: "draft-label", text: t("list.draft") }),
                document.createTextNode(" " + draft.replace(/\s+/g, " ")),
              ])
            : h("span", { className: "item-status", text: previewText(chat, previews[index]) }),
        chat.unread > 0 ? h("span", { className: "unread-badge" + (chat.muted ? " muted" : ""), text: chat.unread > 99 ? "99+" : String(chat.unread) }) : null,
      ]);
      item.appendChild(h("div", { className: "item-info" }, [nameRow, statusRow]));
      item.addEventListener("click", () => openChat(chat.id));
      item.addEventListener("contextmenu", (event) => {
        event.preventDefault();
        openChatMenu(chat, event.clientX, event.clientY);
      });
      onLongPress(item, (x, y) => openChatMenu(chat, x, y));
      list.appendChild(item);
    });
    if (!list.querySelector(".chat-list-item")) {
      list.appendChild(
        h("div", { className: "list-empty" }, [
          h("p", { text: t(filter ? "list.noChatsFound" : "list.noChats") }),
          !filter && friends.friends.length
            ? button(t("list.startChat"), "pill-btn", () => openNewChatModal())
            : !filter
              ? button(t("list.addFriend"), "pill-btn", () => openModal("add-friend-modal"))
              : null,
        ]),
      );
    }
    applyTheme();
  }

  function updateBadges() {
    // Muted chats keep their own counter but don't count in the totals.
    const unread = chats.reduce((sum, chat) => sum + (chat.muted ? 0 : chat.unread), 0);
    const chatsBadge = $("chats-badge");
    chatsBadge.textContent = unread ? String(unread) : "";
    const requestsBadge = $("requests-badge");
    requestsBadge.textContent = friends.incoming.length ? String(friends.incoming.length) : "";
    document.title = unread ? `(${unread}) SereS` : "SereS";
    updateFavicon(unread);
  }

  let faviconImage: HTMLImageElement | null = null;
  let faviconCount = 0;

  /** Draws a red badge with the number of unread messages onto the tab icon. */
  function updateFavicon(count: number) {
    if (count === faviconCount) return;
    faviconCount = count;
    const link = document.querySelector<HTMLLinkElement>("link[rel~='icon']");
    if (!link) return;
    if (!count) {
      link.href = "assets/favicon.png";
      return;
    }
    const draw = () => {
      const canvas = document.createElement("canvas");
      canvas.width = canvas.height = 64;
      const ctx = canvas.getContext("2d");
      if (!ctx || !faviconImage || !faviconCount) return;
      ctx.drawImage(faviconImage, 0, 0, 64, 64);
      ctx.fillStyle = "#ea0038";
      ctx.beginPath();
      ctx.arc(44, 20, 20, 0, Math.PI * 2);
      ctx.fill();
      ctx.fillStyle = "#ffffff";
      ctx.font = "bold 26px sans-serif";
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      ctx.fillText(faviconCount > 9 ? "9+" : String(faviconCount), 44, 21);
      link.href = canvas.toDataURL("image/png");
    };
    if (faviconImage && faviconImage.complete) return draw();
    faviconImage = new Image();
    faviconImage.onload = draw;
    faviconImage.src = "assets/favicon.png";
  }

  // --------------------------------------------------------- friends view

  async function loadFriends() {
    friends = await api("/api/friends");
    updateBadges();
    const signature = JSON.stringify(friends);
    if (signature === friendsSignature) return;
    friendsSignature = signature;
    renderFriends();
    renderRequests();
  }

  function sectionTitle(text: string) {
    return h("div", { className: "section-title", text });
  }

  function userRow(user: UserRef, status: string, actions: HTMLElement[]) {
    const avatar = avatarEl(user.username, { label: nameOf(user) });
    const info = h("div", { className: "item-info" }, [
      h("span", { className: "item-name", text: nameOf(user) }),
      h("span", { className: "item-status", text: status }),
    ]);
    [avatar, info].forEach((el) => el.addEventListener("click", () => openProfile(user.username)));
    const row = h("div", { className: "list-item request-list-item" }, [avatar, info, h("div", { className: "request-actions" }, actions)]);
    row.addEventListener("contextmenu", (event) => {
      event.preventDefault();
      openUserMenu(user, event);
    });
    onLongPress(row, () => openProfile(user.username));
    return row;
  }

  function action(label: string, fn: () => Promise<unknown>, confirmText?: string) {
    return async () => {
      if (confirmText && !window.confirm(confirmText)) return;
      try {
        await fn();
      } catch (error) {
        showAlert(errorText(error));
      }
      await refreshAll();
    };
  }

  function renderFriends() {
    const list = $("friends-list");
    const filter = (($("list-search") as HTMLInputElement).value || "").toLowerCase();
    const match = (user: UserRef) =>
      !filter || user.username.toLowerCase().includes(filter) || nameOf(user).toLowerCase().includes(filter);
    list.textContent = "";

    list.appendChild(sectionTitle(t("friends.title", { count: friends.friends.length })));
    friends.friends.filter(match).forEach((friend) => {
      list.appendChild(
        userRow(friend, t("friends.status"), [
          button(t("friends.message"), "request-action-btn accept", () => startDm(friend.username)),
          button("⋯", "request-action-btn more", (event) => openUserMenu(friend, event)),
        ]),
      );
    });
    if (!friends.friends.length) {
      list.appendChild(
        h("div", { className: "list-empty" }, [
          h("p", { text: t("friends.none") }),
          button(t("list.addFriend"), "pill-btn", () => openModal("add-friend-modal")),
        ]),
      );
    }

    if (friends.outgoing.length) {
      list.appendChild(sectionTitle(t("friends.sent")));
      friends.outgoing.filter(match).forEach((user) => {
        list.appendChild(
          userRow(user, t("friends.waiting"), [
            button(t("common.cancel"), "request-action-btn discard", action("cancel", () => post("/api/friends/cancel", { username: user.username }))),
          ]),
        );
      });
    }

    if (friends.blocked.length) {
      list.appendChild(sectionTitle(`${t("friends.blocked")} — ${friends.blocked.length}`));
      list.appendChild(h("p", { className: "list-hint", text: t("friends.blockedHint") }));
      friends.blocked.filter(match).forEach((user) => {
        list.appendChild(
          userRow(user, t("profile.blockedStatus"), [
            button(t("friends.unblock"), "request-action-btn accept", () => unblockUser(user)),
          ]),
        );
      });
    }
    applyTheme();
  }

  function openUserMenu(user: UserRef, event: MouseEvent) {
    closeFloatingMenus();
    const isFriend = friends.friends.some((friend) => friend.id === user.id);
    const isBlocked = friends.blocked.some((blocked) => blocked.id === user.id);
    const menu = h("div", { className: "floating-menu" }, [
      h("div", { className: "floating-title", text: nameOf(user) }),
      button(t("profile.view"), "floating-item", () => openProfile(user.username)),
      isBlocked ? button(t("friends.unblock"), "floating-item", () => {
        closeFloatingMenus();
        unblockUser(user);
      }) : null,
      isFriend ? button(t("friends.messageMenu"), "floating-item", () => {
        closeFloatingMenus();
        startDm(user.username);
      }) : null,
      isFriend ? button(
        t("friends.remove"),
        "floating-item",
        action("remove", () => post("/api/friends/remove", { username: user.username }), t("friends.removeConfirm", { name: nameOf(user) })),
      ) : null,
      isBlocked ? null : button(
        t("friends.block"),
        "floating-item danger",
        action(
          "block",
          () => post("/api/block", { username: user.username }),
          t("friends.blockConfirmLong", { name: nameOf(user) }),
        ),
      ),
    ]);
    const rect = (event.currentTarget as HTMLElement).getBoundingClientRect();
    menu.style.top = Math.min(rect.bottom + 4, window.innerHeight - 140) + "px";
    menu.style.left = Math.max(8, rect.right - 180) + "px";
    document.body.appendChild(menu);
  }

  /** Right-click (or long-press) menu of a chat: delete a direct chat or leave a group. */
  function openChatMenu(chat: ChatSummary, x: number, y: number) {
    closeFloatingMenus();
    const isGroup = chat.type === "group";
    const menu = h("div", { className: "floating-menu" }, [
      h("div", { className: "floating-title", text: chat.name }),
      !isGroup && chat.other_user
        ? button(t("profile.view"), "floating-item", () => openProfile(chat.other_user!))
        : null,
      button(
        chat.pinned ? t("chatMenu.unpin") : t("chatMenu.pin"),
        "floating-item",
        action("pin", async () => {
          closeFloatingMenus();
          await post(`/api/chats/${encodeURIComponent(chat.id)}/prefs`, { pinned: !chat.pinned });
          chatsSignature = "";
        }),
      ),
      button(
        chat.archived ? t("chatMenu.unarchive") : t("chatMenu.archive"),
        "floating-item",
        action("archive", async () => {
          closeFloatingMenus();
          await post(`/api/chats/${encodeURIComponent(chat.id)}/prefs`, { archived: !chat.archived });
          chatsSignature = "";
        }),
      ),
      chat.unread
        ? button(t("chatMenu.markRead"), "floating-item", () => {
            closeFloatingMenus();
            const seq = chat.last_message ? chat.last_message.seq : 0;
            // The server caps the position at the newest message.
            post(`/api/chats/${encodeURIComponent(chat.id)}/read`, { seq: Math.max(seq, 2 ** 31 - 1) })
              .then(() => loadChats())
              .catch((error) => showAlert(errorText(error)));
          })
        : null,
      button(
        t(isGroup ? "info.leave" : "info.deleteChat"),
        "floating-item danger",
        action(
          isGroup ? "leave" : "delete",
          async () => {
            closeFloatingMenus();
            await post(`/api/chats/${encodeURIComponent(chat.id)}/${isGroup ? "leave" : "delete"}`);
            if (current && current.id === chat.id) closeChat();
            chatsSignature = "";
          },
          t(isGroup ? "info.leaveConfirm" : "info.deleteChatConfirm"),
        ),
      ),
    ]);
    document.body.appendChild(menu);
    // Keep the menu inside the viewport.
    menu.style.left = Math.max(8, Math.min(x, window.innerWidth - menu.offsetWidth - 8)) + "px";
    menu.style.top = Math.max(8, Math.min(y, window.innerHeight - menu.offsetHeight - 8)) + "px";
  }

  /** Calls handler after a finger rests ~0.5s on the element (iOS has no contextmenu event). */
  function onLongPress(element: HTMLElement, handler: (x: number, y: number) => void) {
    let timer: number | null = null;
    let fired = false;
    const cancel = () => {
      if (timer !== null) clearTimeout(timer);
      timer = null;
    };
    element.addEventListener(
      "touchstart",
      (event) => {
        fired = false;
        const touch = event.touches[0];
        timer = window.setTimeout(() => {
          fired = true;
          if (navigator.vibrate) navigator.vibrate(15);
          handler(touch.clientX, touch.clientY);
        }, 500);
      },
      { passive: true },
    );
    element.addEventListener("touchmove", cancel, { passive: true });
    element.addEventListener("touchend", (event) => {
      cancel();
      // Don't open the chat when the finger is lifted after the menu appeared.
      if (fired) event.preventDefault();
    });
    element.addEventListener("touchcancel", cancel);
  }

  function closeFloatingMenus() {
    document.querySelectorAll(".floating-menu").forEach((menu) => menu.remove());
  }

  function renderRequests() {
    const list = $("requests-list");
    list.textContent = "";
    if (!friends.incoming.length) {
      list.appendChild(
        h("div", { className: "list-item request-list-item" }, [
          h("div", { className: "avatar", text: "!" }),
          h("div", { className: "item-info" }, [
            h("span", { className: "item-name", text: t("requests.none") }),
            h("span", { className: "item-status", text: t("requests.noneHint") }),
          ]),
        ]),
      );
    }
    friends.incoming.forEach((user) => {
      list.appendChild(
        userRow(user, t("requests.wants"), [
          button(t("requests.accept"), "request-action-btn accept", async () => {
            try {
              await post("/api/friends/accept", { username: user.username });
              await startDm(user.username);
            } catch (error) {
              showAlert(errorText(error));
            }
            await refreshAll();
          }),
          button(t("requests.decline"), "request-action-btn discard", action("decline", () => post("/api/friends/decline", { username: user.username }))),
          button(
            t("friends.blockShort"),
            "request-action-btn more",
            action("block", () => post("/api/block", { username: user.username }), t("friends.blockConfirm", { name: nameOf(user) })),
          ),
        ]),
      );
    });
    applyTheme();
  }

  function switchView(view: "chats" | "friends" | "requests") {
    document.querySelectorAll<HTMLElement>(".list-view-toggle").forEach((btn) => {
      btn.classList.toggle("active", btn.dataset.view === view);
    });
    document.querySelectorAll<HTMLElement>(".list-view-panel").forEach((panel) => {
      panel.classList.toggle("active", panel.dataset.panel === view);
    });
    $("chats-header").style.display = view === "chats" ? "flex" : "none";
    $("friends-header").style.display = view === "friends" ? "flex" : "none";
    $("requests-header").style.display = view === "requests" ? "flex" : "none";
    $("list-search").parentElement!.style.display = view === "requests" ? "none" : "block";
    document.querySelectorAll<HTMLElement>(".rail-nav[data-rail-view]").forEach((button) => button.classList.toggle("active", button.dataset.railView === view));
  }

  // ------------------------------------------------------------ open chat

  async function openChat(chatId: string) {
    cancelEdit();
    sendTyping(false);
    saveDraft();
    cancelReply();
    clearPendingFiles();
    closeSearch();
    closeEmojiPicker();
    current = {
      id: chatId,
      details: null,
      messages: new Map(),
      maxRev: 0,
      oldestSeq: Number.MAX_SAFE_INTEGER,
      hasMore: false,
      lastReadSent: 0,
      changedKeys: [],
      missingKeys: [],
      subtitle: "",
      typing: [],
      receipts: null,
      search: null,
    };
    const opened = current;
    $("pinned-bar").classList.add("modal-hidden");
    $("search-btn").classList.remove("modal-hidden");
    $("call-btn")?.classList.remove("modal-hidden");
    document.querySelectorAll(".chat-list-item").forEach((item) => {
      item.classList.toggle("active", (item as HTMLElement).dataset.chatid === chatId);
    });
    const summary = chats.find((chat) => chat.id === chatId);
    $("current-chat-name").textContent = summary ? summary.name : "";
    $("current-chat-sub").textContent = "";
    $("chat-input-area").classList.remove("modal-hidden");
    $("chat-info-btn").classList.remove("modal-hidden");
    $("messages").textContent = "";
    const input = $("message-input-field") as HTMLTextAreaElement;
    input.value = drafts.get(chatId) || "";
    autoGrow(input);
    updateSendButton();

    if (window.innerWidth <= 768) document.querySelector(".sidebar")?.classList.remove("open");

    try {
      await refreshCurrentDetails();
      const data = await api(`/api/chats/${encodeURIComponent(chatId)}/messages?limit=50`);
      if (current !== opened) return;
      opened.receipts = data.receipts || null;
      mergeMessages(data.messages);
      opened.hasMore = data.has_more;
      await renderMessages({ forceBottom: true });
      markRead();
      ($("message-input-field") as HTMLTextAreaElement).focus();
    } catch (error) {
      showAlert(errorText(error));
    }
  }

  /** Remembers what was typed in the open chat (in memory only). */
  function saveDraft() {
    if (!current || editing) return;
    const text = ($("message-input-field") as HTMLTextAreaElement).value;
    if (text.trim()) drafts.set(current.id, text);
    else drafts.delete(current.id);
    chatsSignature = "";
  }

  function closeChat() {
    cancelEdit();
    sendTyping(false);
    saveDraft();
    cancelReply();
    clearPendingFiles();
    closeSearch();
    closeEmojiPicker();
    ($("message-input-field") as HTMLTextAreaElement).value = "";
    $("pinned-bar").classList.add("modal-hidden");
    $("search-btn").classList.add("modal-hidden");
    $("call-btn")?.classList.add("modal-hidden");
    $("jump-bottom").classList.add("modal-hidden");
    $("typing-bubble").classList.add("modal-hidden");
    current = null;
    $("current-chat-name").textContent = t("app.welcomeUser", { name: nameOf(me) });
    $("current-chat-sub").textContent = "";
    $("chat-input-area").classList.add("modal-hidden");
    $("chat-info-btn").classList.add("modal-hidden");
    $("key-warning").classList.add("modal-hidden");
    const container = $("messages");
    container.textContent = "";
    container.appendChild(emptyState());
  }

  function emptyState() {
    return h("div", { className: "empty-state" }, [
      h("div", { className: "empty-state-icon material-symbols-rounded", text: "chat_bubble" }),
      h("h2", { text: "SereS" }),
      h("p", { text: t("app.emptyState") }),
    ]);
  }

  async function refreshCurrentDetails() {
    if (!current) return;
    const opened = current;
    const data = await api(`/api/chats/${encodeURIComponent(opened.id)}`);
    if (current !== opened) return;
    const details: ChatSummary = data.chat;
    opened.details = details;
    for (const member of details.members || []) userKeys.set(member.id, member);
    const { changed, missing } = await checkPins(details.members || []);
    opened.changedKeys = changed;
    opened.missingKeys = missing;
    $("current-chat-name").textContent = details.name;
    $("call-btn")?.classList.toggle("modal-hidden", !!details.blocked);
    opened.subtitle =
      details.type === "group"
        ? t("chat.groupSub", { count: details.member_count })
        : details.blocked
          ? t("chat.blocked")
          : details.presence
            ? presenceText(details.presence)
            : t("chat.dmSub");
    if (details.disappear_seconds) opened.subtitle = disappearLabel(details.disappear_seconds) + " · " + opened.subtitle;
    renderSubtitle();
    renderKeyWarning();
    renderPinnedBar().catch(() => {});
  }

  /** "online" or "last seen today at 12:30". */
  function presenceText(presence: Presence) {
    if (presence.online) return t("presence.online");
    const date = parseTime(presence.last_seen);
    const day = formatDay(date);
    return t("presence.lastSeen", { day: day.toLowerCase(), time: formatTime(presence.last_seen) });
  }

  // ------------------------------------------------------- pinned messages

  /** Loads a message that is not in the loaded window (pinned or quoted). */
  async function fetchMessage(opened: OpenChat, messageId: string): Promise<Message | null> {
    const loaded = opened.messages.get(messageId);
    if (loaded) return loaded;
    try {
      const data = await api(`/api/chats/${encodeURIComponent(opened.id)}/messages/${encodeURIComponent(messageId)}`);
      return data.message;
    } catch {
      return null;
    }
  }

  async function renderPinnedBar() {
    const opened = current;
    const bar = $("pinned-bar");
    const pins = opened && opened.details ? opened.details.pins || [] : [];
    if (!opened || !pins.length) {
      bar.classList.add("modal-hidden");
      return;
    }
    const message = await fetchMessage(opened, pins[0].message_id);
    if (current !== opened) return;
    const shown = message ? await showMessage(opened.id, message) : null;
    bar.textContent = "";
    bar.append(
      h("span", { className: "material-symbols-rounded pinned-icon", text: "push_pin" }),
      h("div", { className: "pinned-text" }, [
        h("strong", { text: pins.length > 1 ? t("pins.count", { count: pins.length }) : t("pins.one") }),
        h("span", { text: shown ? contentPreview(shown) : "…" }),
      ]),
    );
    bar.classList.remove("modal-hidden");
  }

  async function openPinsModal() {
    const opened = current;
    if (!opened || !opened.details) return;
    const pins = opened.details.pins || [];
    const body = $("pins-body");
    body.textContent = "";
    if (!pins.length) body.appendChild(h("p", { className: "list-hint", text: t("pins.none") }));
    for (const pin of pins) {
      const message = await fetchMessage(opened, pin.message_id);
      if (!message) continue;
      const shown = await showMessage(opened.id, message);
      const row = h("div", { className: "pin-row" }, [
        h("div", { className: "pin-meta" }, [
          h("strong", { text: message.sender_id === me.id ? t("msg.you") : message.sender_display || message.sender || "" }),
          h("span", { text: formatDateTime(message.created_at) }),
        ]),
        h("div", { className: "pin-preview", text: contentPreview(shown) }),
        h("div", { className: "pin-actions" }, [
          button(t("pins.jump"), "pill-btn", () => {
            closeAllModals();
            jumpToMessage(pin.message_id);
          }),
          button(t("pins.unpin"), "pill-btn secondary", async () => {
            await togglePin(opened, message, false);
            openPinsModal();
          }),
        ]),
      ]);
      body.appendChild(row);
    }
    openModal("pins-modal");
  }

  async function togglePin(opened: OpenChat, message: Message, pinned: boolean) {
    try {
      const data = await post(`/api/chats/${encodeURIComponent(opened.id)}/pins`, { message_id: message.id, pinned });
      if (opened.details) opened.details.pins = data.pins;
      showAlert(t(pinned ? "pins.pinned" : "pins.unpinned"));
      await renderPinnedBar();
      await syncCurrent();
    } catch (error) {
      showAlert(errorText(error));
    }
  }

  /** Scrolls to a message, loading older pages if needed, and flashes it. */
  async function jumpToMessage(messageId: string) {
    const opened = current;
    if (!opened) return;
    for (let page = 0; page < 20 && !opened.messages.has(messageId) && opened.hasMore; page++) {
      await loadOlder();
      if (current !== opened) return;
    }
    const row = document.querySelector<HTMLElement>(`.message-row[data-id="${CSS.escape(messageId)}"]`);
    if (!row) {
      showAlert(t("msg.notFound"));
      return;
    }
    row.scrollIntoView({ behavior: "smooth", block: "center" });
    row.classList.remove("flash");
    void row.offsetWidth;
    row.classList.add("flash");
  }

  function typingText(users: UserRef[]) {
    if (users.length === 1) return t("typing.one", { name: nameOf(users[0]) });
    if (users.length === 2) return t("typing.two", { first: nameOf(users[0]), second: nameOf(users[1]) });
    return t("typing.many");
  }

  /** The line under the chat name: who is typing, otherwise members / encryption. */
  function renderSubtitle() {
    if (!current) return;
    const sub = $("current-chat-sub");
    sub.textContent = current.typing.length ? typingText(current.typing) : current.subtitle;
    sub.classList.toggle("typing", current.typing.length > 0);
    // Animated bubble above the input field.
    $("typing-bubble-text").textContent = current.typing.length ? typingText(current.typing) : "";
    $("typing-bubble").classList.toggle("modal-hidden", current.typing.length === 0);
  }

  // Tell the others that we are typing (at most every 3 seconds, stops after sending).
  let typingSentAt = 0;
  let typingChat: string | null = null;

  function sendTyping(typing: boolean) {
    if (!current) return;
    const now = Date.now();
    if (typing && typingChat === current.id && now - typingSentAt < 3000) return;
    if (!typing && typingChat === null) return;
    const chatId = typing ? current.id : typingChat!;
    typingSentAt = typing ? now : 0;
    typingChat = typing ? current.id : null;
    post(`/api/chats/${encodeURIComponent(chatId)}/typing`, { typing }).catch(() => {});
  }

  function renderKeyWarning() {
    const box = $("key-warning");
    box.textContent = "";
    if (!current) return;
    if (current.changedKeys.length) {
      const names = current.changedKeys.map(nameOf).join(", ");
      box.appendChild(
        h("span", {
          text: t("chat.keyChanged", { names }),
        }),
      );
      box.appendChild(
        button(t("chat.acceptKey"), "pill-btn", async () => {
          if (!current) return;
          await acceptNewKeys(current.changedKeys);
          await refreshCurrentDetails();
        }),
      );
      box.appendChild(button(t("app.chatInfo"), "pill-btn secondary", () => openChatInfo()));
    } else if (current.missingKeys.length) {
      const names = current.missingKeys.map(nameOf).join(", ");
      box.appendChild(
        h("span", {
          text: t("chat.keyMissing", { names }),
        }),
      );
    } else {
      renderHistoryNotice(box, current);
    }
    box.classList.toggle("modal-hidden", !box.childElementCount);
  }

  /** Someone reset their password by e-mail and can't read the older messages. */
  function renderHistoryNotice(box: HTMLElement, opened: OpenChat) {
    const members = opened.details?.members || [];
    if (members.find((m) => m.id === me.id)?.history_reset) {
      box.appendChild(h("span", { text: t("history.mine") }));
      return;
    }
    const waiting = members.filter((m) => m.id !== me.id && m.history_reset && m.pub_ecdh);
    if (!waiting.length) return;
    box.appendChild(h("span", { text: t("history.others", { names: waiting.map(nameOf).join(", ") }) }));
    for (const member of waiting) {
      const label = waiting.length > 1 ? t("history.shareWith", { name: nameOf(member) }) : t("history.share");
      const shareButton = button(label, "pill-btn", async () => {
        shareButton.disabled = true;
        shareButton.textContent = t("history.sharing");
        try {
          const count = await shareHistory(opened, member);
          showAlert(t("history.shared", { name: nameOf(member), count }));
        } catch (error) {
          showAlert(errorText(error));
        }
        if (current === opened) await refreshCurrentDetails().catch(() => {});
      });
      box.appendChild(shareButton);
    }
  }

  /**
   * Gives a member who reset their password by e-mail the older messages back:
   * every message key this account can read is wrapped again for their new
   * keys. The messages themselves are not sent again and stay end-to-end encrypted.
   */
  async function shareHistory(opened: OpenChat, member: Member): Promise<number> {
    const range = member.history_reset!;
    const recipient = { id: member.id, pub_ecdh: member.pub_ecdh! };
    const url = `/api/chats/${encodeURIComponent(opened.id)}/history/${encodeURIComponent(member.id)}`;
    let keys: Record<string, { iv: string; k: string }> = {};
    let count = 0;
    let before = range.until_seq + 1;
    for (;;) {
      const data = await api(`/api/chats/${encodeURIComponent(opened.id)}/messages?limit=200&before_seq=${before}`);
      const page = data.messages as Message[];
      for (const message of page) {
        if (message.seq <= range.from_seq || message.kind !== "e2e" || message.deleted || !message.payload) continue;
        try {
          await ensureUserKeys([message.sender_id!]);
          const known = userKeys.get(message.sender_id!);
          const sender = known ? { id: known.id, ...keysAt(known, message.created_at) } : null;
          if (!sender || !sender.pub_ecdh || !sender.pub_sign) continue;
          keys[message.id] = await SeresCrypto.shareMessageKey(
            identity,
            opened.id,
            message.id,
            { id: sender.id, pub_ecdh: sender.pub_ecdh, pub_sign: sender.pub_sign },
            message.payload,
            recipient,
            message.share,
          );
          count++;
        } catch (error) {
          // Messages this account can't read itself can't be shared.
          console.warn("Could not share message", message.id, error);
        }
        if (Object.keys(keys).length >= 200) {
          await post(url, { keys });
          keys = {};
        }
      }
      if (!data.has_more || !page.length || page[0].seq <= range.from_seq) break;
      before = page[0].seq;
    }
    await post(url, { keys, done: true });
    return count;
  }

  /** Adds new or changed messages. Unknown messages older than the loaded window are skipped. */
  function mergeMessages(list: Message[], includeOlder = false) {
    if (!current) return false;
    let changed = false;
    for (const message of list) {
      current.maxRev = Math.max(current.maxRev, message.rev);
      const known = current.messages.get(message.id);
      if (!known && !includeOlder && current.messages.size && message.seq < current.oldestSeq) continue;
      if (!known || known.rev !== message.rev) {
        current.messages.set(message.id, message);
        changed = true;
      }
      current.oldestSeq = Math.min(current.oldestSeq, message.seq);
    }
    return changed;
  }

  async function loadOlder() {
    if (!current || !current.hasMore) return;
    const opened = current;
    const data = await api(
      `/api/chats/${encodeURIComponent(opened.id)}/messages?limit=50&before_seq=${opened.oldestSeq}`,
    );
    if (current !== opened) return;
    mergeMessages(data.messages, true);
    opened.hasMore = data.has_more;
    await renderMessages({ keepPosition: true });
  }

  async function syncCurrent() {
    if (!current) return;
    const opened = current;
    const data = await api(
      `/api/chats/${encodeURIComponent(opened.id)}/messages?since_rev=${opened.maxRev}&limit=200`,
    );
    if (current !== opened) return;
    const incoming = (data.messages as Message[]).filter((message) =>
      !opened.messages.has(message.id) && !message.silent && message.kind === "e2e" && message.sender_id !== me.id,
    );
    if (notificationsEnabled() && document.visibilityState === "visible") {
      for (const message of incoming) {
        const shown = await showMessage(opened.id, message);
        if (current !== opened) return;
        const body = readStore("settings").preview === "off" ? t("notify.newMessage") : (message.sender_display || message.sender || "") + ": " + contentPreview(shown);
        try {
          const note = new Notification(opened.details?.name || t("notify.newMessage"), { body, tag: message.id, icon: "assets/favicon.png" });
          note.onclick = () => { window.focus(); note.close(); };
        } catch { /* Browser does not support notifications here. */ }
      }
    }
    opened.typing = data.typing || [];
    renderSubtitle();
    const receiptsChanged = JSON.stringify(data.receipts || null) !== JSON.stringify(opened.receipts);
    opened.receipts = data.receipts || null;
    const events = (data.messages as Message[])
      .filter((message) => message.kind === "system" && !opened.messages.has(message.id))
      .map((message) => message.payload || {});
    if (events.some((event) => event.event === "history_shared" && event.target_id === me.id)) {
      // My old messages are back: load the chat again from the start.
      await openChat(opened.id);
      return;
    }
    if (events.some((event) => event.event === "keys_reset" || event.event === "history_shared")) {
      refreshCurrentDetails().catch(() => {});
    }
    if (mergeMessages(data.messages) || receiptsChanged) {
      await renderMessages({});
      markRead();
    }
  }

  function markRead() {
    if (!current || document.visibilityState !== "visible") return;
    let maxSeq = 0;
    current.messages.forEach((message) => (maxSeq = Math.max(maxSeq, message.seq)));
    if (maxSeq <= current.lastReadSent) return;
    current.lastReadSent = maxSeq;
    const chat = chats.find((c) => c.id === current!.id);
    if (chat && chat.unread) {
      chat.unread = 0;
      updateBadges();
      chatsSignature = "";
    }
    post(`/api/chats/${encodeURIComponent(current.id)}/read`, { seq: maxSeq })
      .then(() => loadChats())
      .catch(() => {});
  }

  // Latest reaction of each member per message: target id -> sender id -> emoji.
  type Reactions = Map<string, Map<string, { emoji: string; seq: number }>>;

  async function renderMessages(options: { forceBottom?: boolean; keepPosition?: boolean }) {
    if (!current) return;
    const opened = current;
    const container = $("messages");
    const all = [...opened.messages.values()].filter((m) => !m.deleted).sort((a, b) => a.seq - b.seq);
    const allShown = await Promise.all(all.map((message) => showMessage(opened.id, message)));
    if (current !== opened) return;

    // Reactions are silent messages; collect them instead of showing them as rows.
    const reactions: Reactions = new Map();
    const ordered: Message[] = [];
    const shown: Shown[] = [];
    all.forEach((message, index) => {
      const view = allShown[index];
      if (message.silent) {
        const content = view.content;
        if (content && content.type === "reaction" && content.target && message.sender_id) {
          const perSender = reactions.get(content.target) || new Map();
          const previous = perSender.get(message.sender_id);
          if (!previous || previous.seq < message.seq) perSender.set(message.sender_id, { emoji: content.emoji || "", seq: message.seq });
          reactions.set(content.target, perSender);
        }
        return;
      }
      ordered.push(message);
      shown.push(view);
    });

    const distanceFromBottom = container.scrollHeight - container.scrollTop - container.clientHeight;
    const nearBottom = distanceFromBottom < 120;

    const fragment = document.createDocumentFragment();
    const banner = h("div", { className: "e2e-banner" }, [
      h("span", { text: t("chat.banner") }),
    ]);
    banner.addEventListener("click", () => openChatInfo());
    fragment.appendChild(banner);

    if (opened.hasMore) {
      fragment.appendChild(
        button(t("chat.loadOlder"), "pill-btn load-older", () => {
          loadOlder().catch((error) => showAlert(errorText(error)));
        }),
      );
    }

    let lastDay = "";
    let previous: Message | null = null;
    ordered.forEach((message, index) => {
      const date = parseTime(message.created_at);
      const day = date.toDateString();
      if (day !== lastDay) {
        fragment.appendChild(h("div", { className: "date-separator" }, [h("span", { text: formatDay(date) })]));
        lastDay = day;
        previous = null;
      }
      const view = shown[index];
      if (view.type === "system") {
        fragment.appendChild(h("div", { className: "system-message" }, [h("span", { text: view.text })]));
        previous = null;
        return;
      }
      const compact =
        previous !== null &&
        previous.sender_id === message.sender_id &&
        date.getTime() - parseTime(previous.created_at).getTime() < 5 * 60 * 1000;
      fragment.appendChild(messageRow(opened, message, view, compact, reactions.get(message.id)));
      previous = message;
    });

    container.textContent = "";
    container.appendChild(fragment);
    applyTheme();
    markSearchHits();

    if (options.keepPosition) {
      container.scrollTop = container.scrollHeight - container.clientHeight - distanceFromBottom;
    } else if (options.forceBottom || nearBottom) {
      container.scrollTop = container.scrollHeight;
    }
    updateJumpButton();
  }

  function messageRow(
    opened: OpenChat,
    message: Message,
    view: Shown,
    compact: boolean,
    reactions?: Map<string, { emoji: string; seq: number }>,
  ) {
    const own = message.sender_id === me.id;
    const sender = message.sender_display || message.sender || t("msg.unknown");
    const content = view.content || {};
    const row = h("div", {
      className: "message-row" + (own ? " message-own" : "") + (compact ? " message-compact" : ""),
      attrs: { "data-id": message.id },
    });
    const avatar = compact ? h("div", { className: "message-avatar spacer" }) : avatarEl(message.sender || sender, { className: "message-avatar", label: sender });
    if (!compact && message.sender) avatar.addEventListener("click", () => openProfile(message.sender!));
    row.appendChild(avatar);

    const wrapper = h("div", { className: "message-content-wrapper" });
    if (!compact) {
      const header = h("div", { className: "message-header" }, [
        h("span", { className: "message-sender clickable", text: own ? t("msg.you") : sender }),
        h("span", { className: "message-timestamp", text: formatTime(message.created_at) }),
      ]);
      if (view.type === "legacy") {
        header.appendChild(
          h("span", {
            className: "message-flag",
            text: t("msg.notEncrypted"),
            title: t("msg.notEncryptedHint"),
          }),
        );
      }
      if (message.sender) header.firstElementChild!.addEventListener("click", () => openProfile(message.sender!));
      wrapper.appendChild(header);
    }

    const bubble = h("div", { className: "message-text" });
    if (content.forwarded) bubble.appendChild(h("div", { className: "message-forwarded", text: t("msg.forwarded") }));
    if (content.reply) bubble.appendChild(replyQuote(opened, content.reply));
    if (content.file) bubble.appendChild(renderFile(opened, content.file));
    if (content.type === "poll" && content.poll && Array.isArray(content.poll.options)) {
      const poll = content.poll;
      const votes = reactions || new Map<string, { emoji: string; seq: number }>();
      const mine = votes.get(me.id)?.emoji;
      const panel = h("div", { className: "poll" }, [h("strong", { text: poll.question })]);
      poll.options.forEach((option, index) => {
        const choice = `poll:${index}`;
        const count = [...votes.values()].filter((vote) => vote.emoji === choice).length;
        panel.appendChild(button(`${option} · ${count}`, "poll-option" + (mine === choice ? " selected" : ""), () => sendReaction(opened, message, mine === choice ? "" : choice)));
      });
      bubble.appendChild(panel);
    }

    if (view.type === "deleted" || view.type === "error") {
      bubble.classList.add("message-muted");
      bubble.appendChild(document.createTextNode(view.text));
    } else if (view.text) {
      const myNames = [me.username.toLowerCase(), nameOf(me).toLowerCase()];
      const formatted = SeresFormat.render(view.text, { myNames, onMention: (name) => openProfile(name) });
      const body = h("div", { className: "message-body" + (formatted.emojiOnly && !content.file ? " emoji-only" : "") });
      body.appendChild(formatted.fragment);
      bubble.appendChild(body);
      if (formatted.mentioned && !own) row.classList.add("mentioned");
    }

    const meta = h("span", { className: "message-meta" });
    if (message.expires_at) meta.appendChild(h("span", { className: "material-symbols-rounded message-expiry", text: "timer", title: t("disappear.expires", { time: formatDateTime(message.expires_at) }) }));
    if (message.edited_at) meta.appendChild(h("span", { className: "message-edited", text: t("msg.edited") }));
    if (compact) meta.appendChild(h("span", { className: "message-time-inline", text: formatTime(message.created_at) }));
    if (own && message.kind === "e2e") meta.appendChild(ticks(opened, message));
    bubble.appendChild(meta);
    bubble.title = parseTime(message.created_at).toLocaleString(SeresI18n.getLanguage());
    wrapper.appendChild(bubble);
    if (reactions && content.type !== "poll") {
      const chips = reactionChips(opened, message, reactions);
      if (chips) wrapper.appendChild(chips);
    }
    row.appendChild(wrapper);

    row.addEventListener("contextmenu", (event) => {
      if ((event.target as Element).closest("a, audio, video")) return;
      event.preventDefault();
      openMessageMenu(opened, message, view, event.clientX, event.clientY);
    });
    row.addEventListener("dblclick", (event) => {
      if ((event.target as Element).closest("a, audio, video, .md-spoiler, img")) return;
      if (view.type === "text" || view.type === "legacy") startReply(opened, message, view);
    });
    onLongPress(row, (x, y) => openMessageMenu(opened, message, view, x, y));
    onSwipe(row, {
      // Swipe right to answer, swipe left (own messages) for the info, like WhatsApp.
      right: view.type === "text" || view.type === "legacy" ? () => startReply(opened, message, view) : undefined,
      left: own && message.kind === "e2e" ? () => openMessageInfo(opened, message, view) : undefined,
    });
    return row;
  }

  function replyQuote(opened: OpenChat, reply: NonNullable<Content["reply"]>) {
    const original = opened.messages.get(reply.id);
    const author =
      reply.sender_id === me.id
        ? t("msg.you")
        : original
          ? original.sender_display || original.sender || ""
          : memberName(opened, reply.sender_id);
    const quote = h("div", { className: "reply-quote" }, [
      h("strong", { text: author }),
      h("span", { text: reply.preview }),
    ]);
    quote.addEventListener("click", (event) => {
      event.stopPropagation();
      jumpToMessage(reply.id);
    });
    return quote;
  }

  function memberName(opened: OpenChat, userId: string | null) {
    const member = opened.details?.members?.find((m) => m.id === userId);
    return member ? nameOf(member) : "";
  }

  function reactionChips(opened: OpenChat, message: Message, perSender: Map<string, { emoji: string; seq: number }>) {
    const groups = new Map<string, string[]>();
    perSender.forEach((value, senderId) => {
      if (!value.emoji) return;
      const names = groups.get(value.emoji) || [];
      names.push(senderId);
      groups.set(value.emoji, names);
    });
    if (!groups.size) return null;
    const box = h("div", { className: "reactions" });
    const mine = perSender.get(me.id)?.emoji || "";
    groups.forEach((senderIds, emoji) => {
      const names = senderIds.map((id) => (id === me.id ? t("msg.you") : memberName(opened, id) || "?")).join(", ");
      const chip = button(
        emoji + (senderIds.length > 1 ? " " + senderIds.length : ""),
        "reaction-chip" + (emoji === mine ? " mine" : ""),
        () => sendReaction(opened, message, emoji === mine ? "" : emoji),
        names,
      );
      box.appendChild(chip);
    });
    return box;
  }

  async function sendReaction(opened: OpenChat, message: Message, emoji: string) {
    if (!opened.details || opened.changedKeys.length || opened.missingKeys.length) {
      showAlert(t(opened.changedKeys.length ? "msg.keyChanged" : "msg.missingKeys"));
      return;
    }
    try {
      const members = (opened.details.members || []).map((m) => ({ id: m.id, pub_ecdh: m.pub_ecdh!, pub_sign: m.pub_sign! }));
      const id = newMessageId();
      const payload = await SeresCrypto.encryptMessage(identity, opened.id, id, { type: "reaction", target: message.id, emoji }, members);
      await post(`/api/chats/${encodeURIComponent(opened.id)}/messages`, { id, payload, silent: true });
      if (emoji && !emoji.startsWith("poll:")) SeresEmoji.remember(emoji);
      await syncCurrent();
    } catch (error) {
      if (error instanceof ApiError && error.status === 409) await refreshCurrentDetails().catch(() => {});
      showAlert(errorText(error));
    }
  }

  // ------------------------------------------------------------ attachments

  const IMAGE_TYPES = ["image/png", "image/jpeg", "image/gif", "image/webp", "image/avif", "image/bmp"];
  const VIDEO_TYPES = ["video/mp4", "video/webm", "video/ogg", "video/quicktime"];

  /** Downloads and decrypts an attachment once; returns a blob: URL. */
  function fileUrl(chatId: string, file: FileRef): Promise<string> {
    let url = fileUrls.get(file.id);
    if (!url) {
      url = (async () => {
        const response = await fetch(`/api/chats/${encodeURIComponent(chatId)}/files/${encodeURIComponent(file.id)}`, {
          credentials: "same-origin",
        });
        if (!response.ok) throw new Error(t("file.missing"));
        const plain = await SeresCrypto.decryptFile(await response.arrayBuffer(), file.key, file.iv);
        // Only media types the page shows itself keep their type; everything else is a plain download.
        const media = IMAGE_TYPES.includes(file.mime) || VIDEO_TYPES.includes(file.mime) || file.mime.startsWith("audio/");
        return URL.createObjectURL(new Blob([plain], { type: media ? file.mime : "application/octet-stream" }));
      })();
      fileUrls.set(file.id, url);
      url.catch(() => fileUrls.delete(file.id));
    }
    return url;
  }

  function renderFile(opened: OpenChat, file: FileRef) {
    const chatId = opened.id;
    if (file.kind === "image" && IMAGE_TYPES.includes(file.mime)) {
      const wrap = h("div", { className: "message-image loading" });
      if (file.width && file.height) wrap.style.aspectRatio = `${file.width} / ${file.height}`;
      const img = h("img", { attrs: { alt: file.name } });
      wrap.appendChild(img);
      fileUrl(chatId, file)
        .then((url) => {
          img.src = url;
          wrap.classList.remove("loading");
        })
        .catch(() => {
          wrap.classList.remove("loading");
          wrap.classList.add("failed");
          wrap.textContent = t("file.missing");
        });
      wrap.addEventListener("click", (event) => {
        event.stopPropagation();
        if (img.src) openLightbox(img.src, file);
      });
      return wrap;
    }
    if ((file.kind === "voice" || file.kind === "audio" || file.kind === "video") && (file.mime.startsWith("audio/") || VIDEO_TYPES.includes(file.mime))) {
      const isVideo = file.kind === "video";
      const media = h(isVideo ? "video" : "audio", { className: isVideo ? "message-video" : "message-audio", attrs: { controls: "", preload: "metadata" } });
      const wrap = h("div", { className: "message-media" + (file.kind === "voice" ? " voice" : "") }, [
        file.kind === "voice" ? h("span", { className: "material-symbols-rounded voice-icon", text: "mic" }) : null,
        media,
      ]);
      fileUrl(chatId, file)
        .then((url) => ((media as HTMLMediaElement).src = url))
        .catch(() => wrap.appendChild(h("span", { className: "list-hint", text: t("file.missing") })));
      return wrap;
    }
    const card = h("div", { className: "file-card" }, [
      h("span", { className: "material-symbols-rounded file-icon", text: "description" }),
      h("div", { className: "file-info" }, [
        h("strong", { text: file.name }),
        h("span", { text: formatSize(file.size) }),
      ]),
      button(t("file.download"), "pill-btn", async () => {
        try {
          downloadUrl(await fileUrl(chatId, file), file.name);
        } catch (error) {
          showAlert(errorText(error));
        }
      }),
    ]);
    return card;
  }

  function downloadUrl(url: string, name: string) {
    const link = h("a", { attrs: { href: url, download: name || "file" } });
    document.body.appendChild(link);
    link.click();
    link.remove();
  }

  function openLightbox(url: string, file: FileRef) {
    const box = $("lightbox");
    ($("lightbox-img") as HTMLImageElement).src = url;
    $("lightbox-name").textContent = file.name;
    $("lightbox-download").onclick = (event) => {
      event.stopPropagation();
      downloadUrl(url, file.name);
    };
    box.classList.remove("modal-hidden");
  }

  /** Phones: swiping a message left or right (like in WhatsApp) calls the handler. */
  function onSwipe(element: HTMLElement, handlers: { left?: () => void; right?: () => void }) {
    if (!handlers.left && !handlers.right) return;
    const MAX = 90;
    const TRIGGER = 60;
    let startX = 0;
    let startY = 0;
    let dx = 0;
    let mode: "idle" | "swipe" | "scroll" = "idle";
    element.addEventListener(
      "touchstart",
      (event) => {
        startX = event.touches[0].clientX;
        startY = event.touches[0].clientY;
        dx = 0;
        mode = "idle";
        element.style.transition = "none";
      },
      { passive: true },
    );
    element.addEventListener(
      "touchmove",
      (event) => {
        const moveX = event.touches[0].clientX - startX;
        const moveY = event.touches[0].clientY - startY;
        if (mode === "idle" && Math.abs(moveX) + Math.abs(moveY) > 8) {
          const horizontal = Math.abs(moveX) > Math.abs(moveY);
          const allowed = moveX < 0 ? !!handlers.left : !!handlers.right;
          mode = horizontal && allowed ? "swipe" : "scroll";
        }
        if (mode !== "swipe") return;
        dx = Math.max(handlers.left ? -MAX : 0, Math.min(handlers.right ? MAX : 0, moveX));
        element.style.transform = `translateX(${dx}px)`;
        element.classList.toggle("swipe-ready", Math.abs(dx) >= TRIGGER);
      },
      { passive: true },
    );
    const end = () => {
      if (mode === "swipe" && dx <= -TRIGGER && handlers.left) handlers.left();
      if (mode === "swipe" && dx >= TRIGGER && handlers.right) handlers.right();
      element.style.transition = "transform 0.2s ease-out";
      element.style.transform = "";
      element.classList.remove("swipe-ready");
      mode = "idle";
    };
    element.addEventListener("touchend", end);
    element.addEventListener("touchcancel", end);
  }

  /** Symbol indicators show sent, delivered, and read status. */
  function ticks(opened: OpenChat, message: Message) {
    const receipts = opened.receipts;
    const read = !!receipts && receipts.read_seq >= message.seq;
    const delivered = read || (!!receipts && receipts.delivered_seq >= message.seq);
    return h("span", {
      className: "message-ticks material-symbols-rounded" + (read ? " read" : delivered ? " delivered" : ""),
      text: delivered ? "done_all" : "check",
      title: t(read ? "msgInfo.read" : delivered ? "msgInfo.delivered" : "msgInfo.sent"),
    });
  }

  /** Right-click / long-press menu of a message: react, reply, copy, forward, pin, edit, info, delete. */
  function openMessageMenu(opened: OpenChat, message: Message, view: Shown, x: number, y: number) {
    closeFloatingMenus();
    if (view.type === "system" || view.type === "deleted") return;
    const own = message.sender_id === me.id && message.kind === "e2e";
    const readable = view.type === "text" || view.type === "legacy";
    const pinned = !!opened.details?.pins?.some((pin) => pin.message_id === message.id);
    const url = `/api/chats/${encodeURIComponent(opened.id)}/messages/${encodeURIComponent(message.id)}`;
    const item = (label: string, fn: () => void, danger = false) =>
      button(label, "floating-item" + (danger ? " danger" : ""), () => {
        closeFloatingMenus();
        fn();
      });

    const quick = h("div", { className: "quick-reactions" });
    if (readable) {
      for (const emoji of SeresEmoji.QUICK) {
        quick.appendChild(button(emoji, "quick-reaction", () => {
          closeFloatingMenus();
          sendReaction(opened, message, emoji);
        }));
      }
      quick.appendChild(
        button("＋", "quick-reaction more", () => {
          const picker = SeresEmoji.picker((emoji) => {
            closeFloatingMenus();
            sendReaction(opened, message, emoji);
          }, t("emoji.recent"));
          menu.textContent = "";
          menu.appendChild(picker);
          placeMenu(menu, x, y);
        }, t("emoji.more")),
      );
    }

    const text = view.text;
    const menu = h("div", { className: "floating-menu message-menu" }, [
      readable ? quick : null,
      readable ? item(t("msg.menuReply"), () => startReply(opened, message, view)) : null,
      readable && text
        ? item(t("msg.menuCopy"), () => {
            navigator.clipboard
              .writeText(text)
              .then(() => showAlert(t("msg.copied")))
              .catch(() => showAlert(t("msg.copyFailed")));
          })
        : null,
      readable && message.kind === "e2e" ? item(t("msg.menuForward"), () => openForwardModal(opened, message, view)) : null,
      readable ? item(pinned ? t("msg.menuUnpin") : t("msg.menuPin"), () => togglePin(opened, message, !pinned)) : null,
      own && view.type === "text" && !view.content?.file?.kind?.startsWith("voice")
        ? item(t("msg.menuEdit"), () => startEdit(opened, message, view))
        : null,
      own ? item(t("msg.menuInfo"), () => openMessageInfo(opened, message, view)) : null,
      own
        ? item(
            t("msg.menuDelete"),
            async () => {
              if (!window.confirm(t("msg.deleteConfirm"))) return;
              try {
                await post(url + "/delete");
                if (editing && editing.message.id === message.id) cancelEdit();
                await syncCurrent();
                chatsSignature = "";
                loadChats().catch(() => {});
              } catch (error) {
                showAlert(errorText(error));
              }
            },
            true,
          )
        : null,
    ]);
    document.body.appendChild(menu);
    placeMenu(menu, x, y);
  }

  /** Keeps a floating menu inside the viewport. */
  function placeMenu(menu: HTMLElement, x: number, y: number) {
    menu.style.left = Math.max(8, Math.min(x, window.innerWidth - menu.offsetWidth - 8)) + "px";
    menu.style.top = Math.max(8, Math.min(y, window.innerHeight - menu.offsetHeight - 8)) + "px";
  }

  function formatDateTime(iso: string) {
    return parseTime(iso).toLocaleString(SeresI18n.getLanguage(), { dateStyle: "short", timeStyle: "short" });
  }

  /** When the message was sent, delivered to and seen by each member. */
  async function openMessageInfo(opened: OpenChat, message: Message, view: Shown) {
    let data: any;
    try {
      data = await api(`/api/chats/${encodeURIComponent(opened.id)}/messages/${encodeURIComponent(message.id)}/info`);
    } catch (error) {
      showAlert(errorText(error));
      return;
    }
    $("message-info-preview").textContent = view.text;
    const body = $("message-info-body");
    body.textContent = "";
    const line = (icon: string, label: string, done: boolean, at: string | null) =>
      h("div", { className: "info-line" + (done ? " done" : "") }, [
        h("span", { className: "info-icon material-symbols-rounded", text: icon }),
        h("span", { className: "info-label", text: label }),
        h("span", { className: "info-time" }, [done ? (at ? document.createTextNode(formatDateTime(at)) : h("span", { className: "material-symbols-rounded", text: "check" })) : document.createTextNode(t("msgInfo.notYet"))]),
      ]);
    body.appendChild(line("schedule", t("msgInfo.sent"), true, data.sent_at));
    if (!data.members.length) body.appendChild(h("p", { className: "list-hint", text: t("msgInfo.noRecipients") }));
    for (const member of data.members) {
      body.appendChild(
        h("div", { className: "info-member" }, [
          h("div", { className: "info-member-head" }, [
            avatarEl(member.username, { label: nameOf(member) }),
            h("strong", { text: nameOf(member) }),
          ]),
          line("check", t("msgInfo.delivered"), member.delivered, member.delivered_at),
          line("done_all", t("msgInfo.read"), member.read, member.read_at),
        ]),
      );
    }
    openModal("message-info-modal");
  }

  function startEdit(opened: OpenChat, message: Message, view: Shown) {
    cancelReply();
    editing = { chatId: opened.id, message, content: view.content || {} };
    const input = $("message-input-field") as HTMLTextAreaElement;
    input.value = view.text;
    autoGrow(input);
    updateSendButton();
    $("edit-bar").classList.remove("modal-hidden");
    input.focus();
  }

  function cancelEdit() {
    if (!editing) return;
    editing = null;
    const input = $("message-input-field") as HTMLTextAreaElement;
    input.value = "";
    autoGrow(input);
    updateSendButton();
    $("edit-bar").classList.add("modal-hidden");
  }

  function startReply(opened: OpenChat, message: Message, view: Shown) {
    cancelEdit();
    const preview = contentPreview(view).slice(0, 120) || "…";
    replyTo = { chatId: opened.id, message, preview };
    const author = message.sender_id === me.id ? t("msg.you") : message.sender_display || message.sender || "";
    $("reply-bar-name").textContent = t("reply.to", { name: author });
    $("reply-bar-text").textContent = preview;
    $("reply-bar").classList.remove("modal-hidden");
    ($("message-input-field") as HTMLTextAreaElement).focus();
  }

  function cancelReply() {
    replyTo = null;
    $("reply-bar").classList.add("modal-hidden");
  }

  // ---------------------------------------------------------------- send

  function newMessageId() {
    if (typeof crypto.randomUUID === "function") return crypto.randomUUID();
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  }

  function encryptionMembers(details: ChatSummary) {
    return (details.members || []).map((m) => ({ id: m.id, pub_ecdh: m.pub_ecdh!, pub_sign: m.pub_sign! }));
  }

  /** Throws when the open chat can't receive encrypted messages right now. */
  async function readyToSend(opened: OpenChat, refresh: boolean) {
    if (!opened.details || refresh) await refreshCurrentDetails();
    if (current !== opened || !opened.details) throw new Error(t("common.requestFailed"));
    if (opened.changedKeys.length) throw new Error(t("msg.keyChanged"));
    if (opened.missingKeys.length) throw new Error(t("msg.missingKeys"));
    return opened.details;
  }

  /**
   * Encrypts content for the members of the open chat and sends it (or replaces
   * an own message). If the member list changed meanwhile (409) it encrypts again.
   */
  async function sendContent(
    opened: OpenChat,
    content: Content,
    extra: { files?: string[]; silent?: boolean; editId?: string } = {},
  ) {
    for (let attempt = 0; ; attempt++) {
      const details = await readyToSend(opened, attempt > 0);
      const messageId = extra.editId || newMessageId();
      const payload = await SeresCrypto.encryptMessage(identity, opened.id, messageId, content, encryptionMembers(details));
      try {
        if (extra.editId) {
          await post(`/api/chats/${encodeURIComponent(opened.id)}/messages/${encodeURIComponent(messageId)}/edit`, { payload });
        } else {
          await post(`/api/chats/${encodeURIComponent(opened.id)}/messages`, {
            id: messageId,
            payload,
            silent: !!extra.silent,
            files: extra.files || [],
          });
        }
        return messageId;
      } catch (error) {
        if (error instanceof ApiError && error.status === 409 && attempt === 0) continue;
        throw error;
      }
    }
  }

  async function sendMessage() {
    const input = $("message-input-field") as HTMLTextAreaElement;
    const text = input.value.trim();
    if (!current || sending) return;
    if (!text && !pendingFiles.length) return;
    if (text.length > MESSAGE_LIMIT) {
      showAlert(t("msg.tooLong", { limit: MESSAGE_LIMIT }));
      return;
    }
    const opened = current;
    sending = true;
    ($("send-btn") as HTMLButtonElement).disabled = true;
    closeEmojiPicker();
    closeMentionList();
    try {
      const edit = editing && editing.chatId === opened.id ? editing : null;
      if (edit) {
        if (!text && !edit.content.file) return;
        await sendContent(opened, { ...edit.content, text }, { editId: edit.message.id });
        cancelEdit();
      } else {
        const reply =
          replyTo && replyTo.chatId === opened.id
            ? { id: replyTo.message.id, sender_id: replyTo.message.sender_id, preview: replyTo.preview }
            : undefined;
        const files = pendingFiles.slice();
        if (files.length) {
          // One message per file; the text goes with the last one.
          for (let i = 0; i < files.length; i++) {
            const ref = await uploadFile(opened.id, files[i], files[i].name);
            const content: Content = { file: ref };
            if (i === 0 && reply) content.reply = reply;
            if (i === files.length - 1 && text) content.text = text;
            await sendContent(opened, content, { files: [ref.id] });
          }
          clearPendingFiles();
        } else {
          await sendContent(opened, reply ? { text, reply } : { text });
        }
        cancelReply();
      }
      input.value = "";
      drafts.delete(opened.id);
      autoGrow(input);
      updateSendButton();
      typingChat = null; // the server forgets it when a message arrives
      await syncCurrent();
      chatsSignature = "";
      loadChats().catch(() => {});
    } catch (error) {
      showAlert(errorText(error));
    } finally {
      sending = false;
      ($("send-btn") as HTMLButtonElement).disabled = false;
    }
  }

  async function createPoll() {
    const opened = current;
    if (!opened || opened.details?.type !== "group") return;
    const question = window.prompt(t("poll.question"))?.trim();
    if (!question) return;
    const answers = window.prompt(t("poll.options"));
    if (answers === null) return;
    const options = answers.split("\n").map((option) => option.trim()).filter(Boolean);
    if (question.length > 200 || options.length < 2 || options.length > 10 || options.some((option) => option.length > 100)) {
      showAlert(t("poll.invalid"));
      return;
    }
    try {
      await sendContent(opened, { type: "poll", poll: { question, options } });
      await syncCurrent();
      chatsSignature = "";
      loadChats().catch(() => {});
    } catch (error) { showAlert(errorText(error)); }
  }

  async function scheduleMessage() {
    const opened = current;
    const input = $("message-input-field") as HTMLTextAreaElement;
    const message = input.value.trim();
    if (!opened || !message || editing || pendingFiles.length) {
      showAlert(t("schedule.textOnly"));
      return;
    }
    const defaultTime = new Date(Date.now() + 3600000);
    const localTime = new Date(defaultTime.getTime() - defaultTime.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
    const when = window.prompt(t("schedule.when"), localTime);
    if (!when) return;
    const date = new Date(when);
    if (!Number.isFinite(date.getTime()) || date.getTime() < Date.now() + 60000) {
      showAlert(t("schedule.invalid"));
      return;
    }
    try {
      const details = await readyToSend(opened, true);
      const id = newMessageId();
      const payload = await SeresCrypto.encryptMessage(identity, opened.id, id, { text: message }, encryptionMembers(details));
      await post(`/api/chats/${encodeURIComponent(opened.id)}/scheduled`, { id, payload, send_at: date.toISOString() });
      input.value = "";
      drafts.delete(opened.id);
      autoGrow(input);
      updateSendButton();
      showAlert(t("schedule.saved"));
    } catch (error) { showAlert(errorText(error)); }
  }

  function fileKind(mime: string): FileRef["kind"] {
    if (IMAGE_TYPES.includes(mime)) return "image";
    if (VIDEO_TYPES.includes(mime)) return "video";
    if (mime.startsWith("audio/")) return "audio";
    return "file";
  }

  /** Encrypts a file in the browser and uploads only the ciphertext. */
  async function uploadFile(chatId: string, blob: Blob, name: string, extra: Partial<FileRef> = {}): Promise<FileRef> {
    if (blob.size > MAX_FILE_SIZE) throw new Error(t("file.tooLarge", { name }));
    const mime = (blob.type || "application/octet-stream").split(";")[0];
    const kind = extra.kind || fileKind(mime);
    let width: number | undefined;
    let height: number | undefined;
    if (kind === "image") {
      try {
        const bitmap = await createImageBitmap(blob);
        width = bitmap.width;
        height = bitmap.height;
        bitmap.close();
      } catch {
        /* size unknown, the image is shown without a placeholder */
      }
    }
    const encrypted = await SeresCrypto.encryptFile(await blob.arrayBuffer());
    const response = await fetch(`/api/chats/${encodeURIComponent(chatId)}/files`, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/octet-stream" },
      body: encrypted.data,
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok || !data.success) throw new ApiError(data.message || t("file.uploadFailed"), response.status);
    const ref: FileRef = {
      id: data.file_id,
      key: encrypted.key,
      iv: encrypted.iv,
      name: name.slice(0, 200) || "file",
      mime,
      size: blob.size,
      kind,
      ...extra,
    };
    if (width && height) {
      ref.width = width;
      ref.height = height;
    }
    // Show own uploads right away without downloading them again.
    const media = kind !== "file";
    fileUrls.set(ref.id, Promise.resolve(URL.createObjectURL(media ? blob : new Blob([blob], { type: "application/octet-stream" }))));
    return ref;
  }

  // ------------------------------------------------- picking attachments

  function addPendingFiles(files: FileList | File[]) {
    if (!current) return;
    for (const file of Array.from(files)) {
      if (file.size > MAX_FILE_SIZE) {
        showAlert(t("file.tooLarge", { name: file.name }));
        continue;
      }
      if (pendingFiles.length >= 10) break;
      pendingFiles.push(file);
    }
    renderPendingFiles();
  }

  function clearPendingFiles() {
    pendingFiles = [];
    renderPendingFiles();
  }

  function renderPendingFiles() {
    const bar = $("attach-bar");
    bar.textContent = "";
    pendingFiles.forEach((file, index) => {
      const chip = h("div", { className: "attach-chip" });
      if (IMAGE_TYPES.includes(file.type)) {
        const img = h("img", { attrs: { alt: "" } });
        img.src = URL.createObjectURL(file);
        img.addEventListener("load", () => URL.revokeObjectURL(img.src), { once: true });
        chip.appendChild(img);
      } else {
        chip.appendChild(h("span", { className: "file-icon", text: "📄" }));
      }
      chip.appendChild(h("span", { className: "attach-name", text: file.name }));
      chip.appendChild(h("span", { className: "attach-size", text: formatSize(file.size) }));
      chip.appendChild(
        button("✕", "attach-remove", () => {
          pendingFiles.splice(index, 1);
          renderPendingFiles();
        }, t("common.cancel")),
      );
      bar.appendChild(chip);
    });
    bar.classList.toggle("modal-hidden", !pendingFiles.length);
    updateSendButton();
  }

  /** Shows the microphone when there is nothing to send (like WhatsApp). */
  function updateSendButton() {
    const empty = !($("message-input-field") as HTMLTextAreaElement).value.trim() && !pendingFiles.length && !editing;
    $("send-btn").classList.toggle("modal-hidden", empty && voiceSupported());
    $("record-btn").classList.toggle("modal-hidden", !(empty && voiceSupported()));
  }

  // ------------------------------------------------------- voice messages

  let recording: {
    recorder: MediaRecorder;
    stream: MediaStream;
    chunks: Blob[];
    started: number;
    timer: number;
    send: boolean;
  } | null = null;
  const MAX_RECORDING_SECONDS = 300;

  function voiceSupported() {
    return typeof MediaRecorder !== "undefined" && !!navigator.mediaDevices?.getUserMedia;
  }

  async function startRecording() {
    if (!current || recording) return;
    const opened = current;
    let stream: MediaStream;
    try {
      stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    } catch {
      showAlert(t("voice.noMicrophone"));
      return;
    }
    const type = ["audio/webm;codecs=opus", "audio/webm", "audio/mp4", "audio/ogg;codecs=opus"].find(
      (candidate) => MediaRecorder.isTypeSupported(candidate),
    );
    const recorder = new MediaRecorder(stream, type ? { mimeType: type } : undefined);
    const state = {
      recorder,
      stream,
      chunks: [] as Blob[],
      started: Date.now(),
      timer: 0,
      send: false,
    };
    recording = state;
    recorder.addEventListener("dataavailable", (event) => {
      if (event.data.size) state.chunks.push(event.data);
    });
    recorder.addEventListener("stop", async () => {
      stream.getTracks().forEach((track) => track.stop());
      clearInterval(state.timer);
      recording = null;
      $("record-bar").classList.add("modal-hidden");
      $("chat-input-area").classList.remove("recording");
      if (!state.send || current !== opened) return;
      const duration = (Date.now() - state.started) / 1000;
      if (duration < 0.7) return;
      const mime = (recorder.mimeType || type || "audio/webm").split(";")[0];
      const blob = new Blob(state.chunks, { type: mime });
      try {
        const ref = await uploadFile(opened.id, blob, t("voice.fileName") + "." + (mime.split("/")[1] || "webm"), {
          kind: "voice",
          duration,
        });
        await sendContent(opened, { file: ref }, { files: [ref.id] });
        await syncCurrent();
        loadChats().catch(() => {});
      } catch (error) {
        showAlert(errorText(error));
      }
    });
    recorder.start(250);
    $("record-time").textContent = "0:00";
    $("record-bar").classList.remove("modal-hidden");
    $("chat-input-area").classList.add("recording");
    state.timer = window.setInterval(() => {
      const seconds = (Date.now() - state.started) / 1000;
      $("record-time").textContent = formatDuration(seconds);
      if (seconds >= MAX_RECORDING_SECONDS) stopRecording(true);
    }, 250);
  }

  function stopRecording(send: boolean) {
    if (!recording) return;
    recording.send = send;
    if (recording.recorder.state !== "inactive") recording.recorder.stop();
  }

  // ------------------------------------------------------------ forwarding

  let forwarding: { from: OpenChat; message: Message; view: Shown } | null = null;

  function openForwardModal(opened: OpenChat, message: Message, view: Shown) {
    forwarding = { from: opened, message, view };
    const list = $("forward-list");
    list.textContent = "";
    $("warning-forward").textContent = "";
    for (const chat of chats) {
      if (chat.blocked) continue;
      const checkbox = h("input", { attrs: { type: "checkbox", value: chat.id } });
      list.appendChild(
        h("label", { className: "picker-item" }, [
          checkbox,
          avatarEl(chat.type === "dm" && chat.other_user ? chat.other_user : chat.name, { group: chat.type === "group", groupId: chat.type === "group" ? chat.id : undefined, avatarUpdatedAt: chat.avatar_updated_at, label: chat.name }),
          h("span", { className: "item-name", text: chat.name }),
        ]),
      );
    }
    $("forward-preview").textContent = contentPreview(view);
    openModal("forward-modal");
  }

  async function confirmForward() {
    if (!forwarding) return;
    const { from, view } = forwarding;
    const targets = [...$("forward-list").querySelectorAll<HTMLInputElement>("input:checked")].map((box) => box.value);
    const warning = $("warning-forward");
    if (!targets.length) {
      warning.textContent = t("forward.pick");
      return;
    }
    warning.textContent = t("forward.sending");
    let sent = 0;
    for (const chatId of targets) {
      try {
        const data = await api(`/api/chats/${encodeURIComponent(chatId)}`);
        const details: ChatSummary = data.chat;
        const { changed, missing } = await checkPins(details.members || []);
        if (changed.length || missing.length) throw new Error(t(changed.length ? "msg.keyChanged" : "msg.missingKeys"));
        const content: Content = { forwarded: true };
        if (view.text) content.text = view.text;
        const files: string[] = [];
        const file = view.content?.file;
        if (file) {
          // Re-upload the same ciphertext into the other chat; key and iv stay the same.
          const response = await fetch(`/api/chats/${encodeURIComponent(from.id)}/files/${encodeURIComponent(file.id)}`, {
            credentials: "same-origin",
          });
          if (!response.ok) throw new Error(t("file.missing"));
          const upload = await fetch(`/api/chats/${encodeURIComponent(chatId)}/files`, {
            method: "POST",
            credentials: "same-origin",
            headers: { "Content-Type": "application/octet-stream" },
            body: await response.arrayBuffer(),
          });
          const uploaded = await upload.json().catch(() => ({}));
          if (!upload.ok || !uploaded.success) throw new Error(uploaded.message || t("file.uploadFailed"));
          content.file = { ...file, id: uploaded.file_id };
          files.push(uploaded.file_id);
        }
        const id = newMessageId();
        const payload = await SeresCrypto.encryptMessage(identity, chatId, id, content, encryptionMembers(details));
        await post(`/api/chats/${encodeURIComponent(chatId)}/messages`, { id, payload, files });
        sent++;
      } catch (error) {
        const chat = chats.find((c) => c.id === chatId);
        showAlert((chat ? chat.name + ": " : "") + errorText(error));
      }
    }
    forwarding = null;
    closeAllModals();
    if (sent) showAlert(t("forward.done", { count: sent }));
    if (current && targets.includes(current.id)) await syncCurrent();
    chatsSignature = "";
    loadChats().catch(() => {});
  }

  // ----------------------------------------------------------- emoji picker

  function toggleEmojiPicker() {
    const slot = $("emoji-slot");
    if (slot.childElementCount) {
      closeEmojiPicker();
      return;
    }
    const input = $("message-input-field") as HTMLTextAreaElement;
    slot.appendChild(
      SeresEmoji.picker((emoji) => {
        const start = input.selectionStart ?? input.value.length;
        const end = input.selectionEnd ?? input.value.length;
        input.value = input.value.slice(0, start) + emoji + input.value.slice(end);
        input.selectionStart = input.selectionEnd = start + emoji.length;
        autoGrow(input);
        updateSendButton();
        input.focus();
      }, t("emoji.recent")),
    );
    slot.classList.remove("modal-hidden");
  }

  function closeEmojiPicker() {
    const slot = $("emoji-slot");
    slot.textContent = "";
    slot.classList.add("modal-hidden");
  }

  // --------------------------------------------------------------- mentions

  /** In groups, typing "@na" suggests members; Tab/Enter or a click inserts the username. */
  function updateMentionList() {
    const input = $("message-input-field") as HTMLTextAreaElement;
    const list = $("mention-list");
    const details = current?.details;
    const before = input.value.slice(0, input.selectionStart ?? input.value.length);
    const match = /(?:^|\s)@([A-Za-z0-9_-]{0,32})$/.exec(before);
    if (!details || details.type !== "group" || !match) {
      closeMentionList();
      return;
    }
    const query = match[1].toLowerCase();
    const members = (details.members || []).filter(
      (m) => m.id !== me.id && (m.username.toLowerCase().startsWith(query) || nameOf(m).toLowerCase().startsWith(query)),
    );
    list.textContent = "";
    if (!members.length) {
      closeMentionList();
      return;
    }
    members.slice(0, 6).forEach((member, index) => {
      const item = h("div", { className: "mention-item" + (index === 0 ? " active" : ""), attrs: { "data-username": member.username } }, [
        avatarEl(member.username, { label: nameOf(member) }),
        h("strong", { text: nameOf(member) }),
        h("span", { text: "@" + member.username }),
      ]);
      item.addEventListener("mousedown", (event) => {
        event.preventDefault();
        insertMention(member.username);
      });
      list.appendChild(item);
    });
    list.classList.remove("modal-hidden");
  }

  function insertMention(username: string) {
    const input = $("message-input-field") as HTMLTextAreaElement;
    const caret = input.selectionStart ?? input.value.length;
    const before = input.value.slice(0, caret).replace(/@([A-Za-z0-9_-]{0,32})$/, "@" + username + " ");
    input.value = before + input.value.slice(caret);
    input.selectionStart = input.selectionEnd = before.length;
    closeMentionList();
    input.focus();
  }

  function closeMentionList() {
    $("mention-list").classList.add("modal-hidden");
    $("mention-list").textContent = "";
  }

  // ---------------------------------------------------------------- search

  function openSearch() {
    if (!current) return;
    $("search-bar").classList.remove("modal-hidden");
    const input = $("search-input") as HTMLInputElement;
    input.value = "";
    $("search-count").textContent = "";
    input.focus();
  }

  function closeSearch() {
    $("search-bar").classList.add("modal-hidden");
    if (current) current.search = null;
    markSearchHits();
  }

  let searchTimer: number | null = null;

  function onSearchInput() {
    if (searchTimer !== null) clearTimeout(searchTimer);
    searchTimer = window.setTimeout(() => runSearch().catch((error) => showAlert(errorText(error))), 250);
  }

  /** Searches the decrypted messages on this device; older history is loaded for it (up to ~1000 messages). */
  async function runSearch() {
    const opened = current;
    if (!opened) return;
    const query = ($("search-input") as HTMLInputElement).value.trim().toLowerCase();
    if (!query) {
      opened.search = null;
      $("search-count").textContent = "";
      markSearchHits();
      return;
    }
    $("search-count").textContent = t("search.searching");
    for (let page = 0; page < 20 && opened.hasMore; page++) {
      await loadOlder();
      if (current !== opened) return;
    }
    const ordered = [...opened.messages.values()].filter((m) => !m.deleted && !m.silent && m.kind !== "system").sort((a, b) => a.seq - b.seq);
    const hits: string[] = [];
    for (const message of ordered) {
      const view = await showMessage(opened.id, message);
      const haystack = (view.text + " " + (view.content?.file?.name || "")).toLowerCase();
      if (haystack.includes(query)) hits.push(message.id);
    }
    if (current !== opened) return;
    opened.search = { query, hits, index: hits.length - 1 };
    showSearchHit();
  }

  function moveSearch(step: number) {
    const search = current?.search;
    if (!search || !search.hits.length) return;
    search.index = (search.index + step + search.hits.length) % search.hits.length;
    showSearchHit();
  }

  function showSearchHit() {
    const search = current?.search;
    if (!search) return;
    $("search-count").textContent = search.hits.length
      ? t("search.count", { index: search.index + 1, total: search.hits.length })
      : t("search.none");
    markSearchHits();
    const id = search.hits[search.index];
    if (id) {
      document.querySelector(`.message-row[data-id="${CSS.escape(id)}"]`)?.scrollIntoView({ behavior: "smooth", block: "center" });
    }
  }

  function markSearchHits() {
    const search = current?.search;
    const hits = new Set(search ? search.hits : []);
    const selected = search ? search.hits[search.index] : null;
    document.querySelectorAll<HTMLElement>(".message-row").forEach((row) => {
      row.classList.toggle("search-hit", hits.has(row.dataset.id!));
      row.classList.toggle("search-current", row.dataset.id === selected);
    });
  }

  // ---------------------------------------------------------- jump button

  function updateJumpButton() {
    const container = $("messages");
    const away = container.scrollHeight - container.scrollTop - container.clientHeight > 300;
    $("jump-bottom").classList.toggle("modal-hidden", !current || !away);
  }

  function autoGrow(textarea: HTMLTextAreaElement) {
    textarea.style.height = "auto";
    // While the input area is hidden there is nothing to measure.
    if (!textarea.scrollHeight) return;
    textarea.style.height = Math.min(textarea.scrollHeight, 160) + "px";
  }

  // --------------------------------------------------------- new chats

  async function startDm(username: string) {
    try {
      const data = await post("/api/chats", { type: "dm", username });
      closeAllModals();
      switchView("chats");
      chatsSignature = "";
      await loadChats();
      await openChat(data.chat_id);
    } catch (error) {
      showAlert(errorText(error));
    }
  }

  function friendCheckboxes(container: HTMLElement, exclude: Set<string>) {
    container.textContent = "";
    const available = friends.friends.filter((friend) => !exclude.has(friend.id));
    if (!available.length) {
      container.appendChild(h("p", { text: t("chat.noFriendsToAdd") }));
    }
    available.forEach((friend) => {
      const checkbox = h("input", { attrs: { type: "checkbox", value: friend.username } });
      container.appendChild(
        h("label", { className: "picker-item" }, [
          checkbox,
          avatarEl(friend.username, { label: nameOf(friend) }),
          h("span", { className: "item-name", text: nameOf(friend) }),
        ]),
      );
    });
  }

  function checkedUsernames(container: HTMLElement) {
    return [...container.querySelectorAll<HTMLInputElement>("input[type=checkbox]:checked")].map((box) => box.value);
  }

  // Closes an earlier pick that was dismissed without a button (e.g. Escape).
  let endCallPick: (() => void) | null = null;

  /** Friends to add to a call (picked in a dialog), or null when cancelled. */
  function pickCallPeople(excludeIds: string[]): Promise<string[] | null> {
    endCallPick?.();
    const list = $("call-add-list");
    $("warning-call-add").textContent = "";
    friendCheckboxes(list, new Set(excludeIds));
    openModal("call-add-modal");
    return new Promise((resolve) => {
      const finish = (result: string[] | null) => {
        endCallPick = null;
        $("call-add-modal").classList.add("modal-hidden");
        confirm.removeEventListener("click", onConfirm);
        cancel.removeEventListener("click", onCancel);
        resolve(result);
      };
      const onConfirm = () => {
        const usernames = checkedUsernames(list);
        if (!usernames.length) {
          $("warning-call-add").textContent = t("newChat.pickOne");
          return;
        }
        finish(usernames);
      };
      const onCancel = () => finish(null);
      endCallPick = onCancel;
      const confirm = $("confirm-call-add");
      const cancel = $("cancel-call-add");
      confirm.addEventListener("click", onConfirm);
      cancel.addEventListener("click", onCancel);
    });
  }

  function openNewChatModal() {
    const list = $("new-chat-list");
    const nameInput = $("new-chat-name") as HTMLInputElement;
    nameInput.value = "";
    nameInput.classList.add("modal-hidden");
    $("warning-new-chat").textContent = "";
    friendCheckboxes(list, new Set());
    if (!friends.friends.length) {
      list.textContent = "";
      list.appendChild(h("p", { text: t("chat.noFriends") }));
    }
    openModal("new-chat-modal");
  }

  /** The group name is only needed when more than one friend is picked. */
  function updateNewChatName() {
    $("new-chat-name").classList.toggle("modal-hidden", checkedUsernames($("new-chat-list")).length < 2);
  }

  async function startNewChat() {
    const usernames = checkedUsernames($("new-chat-list"));
    const warning = $("warning-new-chat");
    if (!usernames.length) {
      warning.textContent = t("newChat.pickOne");
      return;
    }
    if (usernames.length === 1) return startDm(usernames[0]);
    let name = ($("new-chat-name") as HTMLInputElement).value.trim();
    if (!name) {
      // Without a name the group is called after its members.
      const names = usernames.map((u) => {
        const friend = friends.friends.find((f) => f.username === u);
        return friend ? nameOf(friend) : u;
      });
      name = [nameOf(me), ...names].join(", ").slice(0, 64);
    }
    try {
      const data = await post("/api/chats", { type: "group", name, usernames });
      closeAllModals();
      switchView("chats");
      chatsSignature = "";
      await loadChats();
      await openChat(data.chat_id);
    } catch (error) {
      warning.textContent = errorText(error);
    }
  }

  async function addFriend() {
    const input = $("friends-username-input") as HTMLInputElement;
    const warning = $("warning-add-friend");
    const username = input.value.trim();
    if (!username) return;
    warning.textContent = "";
    try {
      const data = await post("/api/friends/request", { username });
      input.value = "";
      closeAllModals();
      showAlert(t(data.status === "friends" ? "friends.nowFriends" : "friends.requestSent", { name: username }));
      await refreshAll();
    } catch (error) {
      warning.textContent = errorText(error);
    }
  }

  // ----------------------------------------------------------- chat info

  async function openChatInfo() {
    if (!current) return;
    try {
      await refreshCurrentDetails();
    } catch (error) {
      showAlert(errorText(error));
      return;
    }
    const opened = current;
    if (!opened || !opened.details) return;
    const details = opened.details;
    const body = $("chat-info-body");
    body.textContent = "";
    $("chat-info-title").textContent = details.name;

    const scheduled = await api(`/api/chats/${encodeURIComponent(details.id)}/scheduled`);
    if (scheduled.messages.length) {
      const section = h("div", { className: "settings-section" }, [h("p", { text: t("schedule.pending") })]);
      for (const item of scheduled.messages as { id: string; send_at: string }[]) {
        section.appendChild(h("div", { className: "info-actions" }, [
          h("span", { text: formatDateTime(item.send_at) }),
          button(t("schedule.cancel"), "pill-btn secondary", async () => {
            try {
              const response = await fetch(`/api/chats/${encodeURIComponent(details.id)}/scheduled/${encodeURIComponent(item.id)}`, { method: "DELETE", credentials: "same-origin" });
              if (!response.ok) throw new Error(t("common.requestFailed"));
              await openChatInfo();
            } catch (error) { showAlert(errorText(error)); }
          }),
        ]));
      }
      body.appendChild(section);
    }

    if (details.type === "group") {
      const picture = h("div", { className: "group-picture-settings" }, [
        avatarEl(details.name, { group: true, groupId: details.id, avatarUpdatedAt: details.avatar_updated_at, className: "avatar profile-avatar", label: details.name }),
      ]);
      if (details.role === "owner") {
        const input = h("input", { attrs: { type: "file", accept: "image/png,image/jpeg,image/gif,image/webp" } }) as HTMLInputElement;
        picture.appendChild(input);
        if (details.avatar_updated_at) picture.appendChild(button(t("groupPicture.remove"), "pill-btn secondary", async () => {
          try {
            const response = await fetch(`/api/chats/${encodeURIComponent(details.id)}/avatar`, { method: "DELETE", credentials: "same-origin" });
            const result = await response.json();
            if (!response.ok) throw new Error(result.error || result.message || "Remove failed");
            chatsSignature = "";
            await loadChats();
            await openChatInfo();
          } catch (error) { showAlert(errorText(error)); }
        }));
        picture.appendChild(button(t("settings.uploadButton"), "pill-btn secondary", async () => {
          if (!input.files?.[0]) { showAlert(t("settings.chooseFile")); return; }
          const form = new FormData(); form.append("avatar_img", input.files[0]);
          try {
            const response = await fetch(`/api/chats/${encodeURIComponent(details.id)}/avatar`, { method: "POST", body: form, credentials: "same-origin" });
            const result = await response.json();
            if (!response.ok) throw new Error(result.error || result.message || "Upload failed");
            chatsSignature = "";
            await loadChats();
            await refreshCurrentDetails();
            await openChatInfo();
          } catch (error) { showAlert(errorText(error)); }
        }));
      }
      body.appendChild(picture);
    }

    const myFp = await SeresCrypto.fingerprint(identity.pubEcdh, identity.pubSign);
    const verified = readStore("verified");
    const members = details.members || [];

    // Shortcuts and the disappearing messages timer (for groups only the owner may change it).
    body.appendChild(
      h("div", { className: "info-actions" }, [
        button(t("pins.title") + (details.pins && details.pins.length ? ` (${details.pins.length})` : ""), "pill-btn secondary", () => {
          closeAllModals();
          openPinsModal();
        }),
        button(t("search.open"), "pill-btn secondary", () => {
          closeAllModals();
          openSearch();
        }),
      ]),
    );
    const canChangeTimer = details.type === "dm" || details.role === "owner";
    const timer = h("select", { className: "language-select" }) as HTMLSelectElement;
    for (const seconds of DISAPPEAR_OPTIONS) {
      const option = h("option", { text: disappearLabel(seconds), attrs: { value: String(seconds) } }) as HTMLOptionElement;
      option.selected = seconds === (details.disappear_seconds || 0);
      timer.appendChild(option);
    }
    timer.disabled = !canChangeTimer;
    timer.addEventListener("change", async () => {
      try {
        await post(`/api/chats/${encodeURIComponent(details.id)}/disappearing`, { seconds: Number(timer.value) });
        await refreshCurrentDetails();
        await syncCurrent();
        chatsSignature = "";
        loadChats().catch(() => {});
      } catch (error) {
        showAlert(errorText(error));
      }
    });
    body.appendChild(
      h("div", { className: "settings-section" }, [
        h("p", { text: t("disappear.info") }),
        timer,
        canChangeTimer ? null : h("p", { className: "settings-hint", text: t("disappear.ownerOnly") }),
      ]),
    );

    if (details.type === "dm") {
      const other = members.find((m) => m.id !== me.id);
      if (other) {
        body.appendChild(h("div", { className: "info-user" }, [avatarEl(other.username, { label: nameOf(other) }), h("strong", { text: nameOf(other) })]));
        const fp = await memberFingerprint(other);
        if (fp) {
          const code = await SeresCrypto.safetyNumber(myFp, fp);
          body.appendChild(h("p", { text: t("info.securityCode") }));
          body.appendChild(h("code", { className: "safety-number", text: code }));
          body.appendChild(verifyToggle(other.id, fp, verified));
        }
        const isBlocked = friends.blocked.some((b) => b.id === other.id);
        body.appendChild(
          h("div", { className: "info-actions" }, [
            isBlocked
              ? button(t("friends.unblock"), "pill-btn", async () => {
                  await unblockUser(other);
                  openChatInfo();
                })
              : button(
                  t("friends.block"),
                  "pill-btn danger",
                  action("block", () => post("/api/block", { username: other.username }), t("friends.blockConfirm", { name: nameOf(other) })),
                ),
            button(
              t("info.deleteChat"),
              "pill-btn danger",
              action(
                "delete",
                async () => {
                  await post(`/api/chats/${encodeURIComponent(details.id)}/delete`);
                  closeAllModals();
                  closeChat();
                },
                t("info.deleteChatConfirm"),
              ),
            ),
          ]),
        );
      }
    } else {
      const isOwner = details.role === "owner";
      if (isOwner) {
        const nameInput = h("input", { attrs: { type: "text", maxlength: "64", value: details.name } });
        body.appendChild(
          h("div", { className: "info-row" }, [
            nameInput,
            button(t("info.rename"), "pill-btn", action("rename", () => post(`/api/chats/${encodeURIComponent(details.id)}/rename`, { name: nameInput.value }))),
          ]),
        );
      }
      body.appendChild(h("p", { text: t("info.groupMembers", { count: members.length }) }));
      for (const member of members) {
        const fp = await memberFingerprint(member);
        const isMe = member.id === me.id;
        const memberAvatar = avatarEl(member.username, { label: nameOf(member) });
        memberAvatar.addEventListener("click", () => openProfile(member.username));
        const row = h("div", { className: "member-row" }, [
          memberAvatar,
          h("div", { className: "item-info" }, [
            h("span", {
              className: "item-name",
              text: (isMe ? t("msg.you") : nameOf(member)) + (member.role === "owner" ? t("info.owner") : ""),
            }),
            h("span", {
              className: "item-status",
              text: fp ? t(isMe ? "info.yourKey" : "info.key") + fp.slice(0, 32).replace(/(.{4})/g, "$1 ").trim() : t("info.noKey"),
            }),
          ]),
        ]);
        if (!isMe && fp) {
          const code = await SeresCrypto.safetyNumber(myFp, fp);
          row.appendChild(
            button(t("info.code"), "request-action-btn more", () => {
              window.alert(t("info.codeAlert", { name: nameOf(member), code }));
            }),
          );
          row.appendChild(verifyToggle(member.id, fp, verified, true));
        }
        if (isOwner && !isMe) {
          row.appendChild(
            button(
              t("info.remove"),
              "request-action-btn discard",
              action(
                "remove",
                async () => {
                  await post(`/api/chats/${encodeURIComponent(details.id)}/members/remove`, { username: member.username });
                  await openChatInfo();
                },
                t("info.removeConfirm", { name: nameOf(member) }),
              ),
            ),
          );
        }
        body.appendChild(row);
      }

      const memberIds = new Set(members.map((m) => m.id));
      const addBox = h("div", { className: "picker-list" });
      friendCheckboxes(addBox, memberIds);
      body.appendChild(h("p", { text: t("info.addHint") }));
      body.appendChild(addBox);
      body.appendChild(
        h("div", { className: "info-actions" }, [
          button(
            t("info.addSelected"),
            "pill-btn",
            action("add", async () => {
              for (const username of checkedUsernames(addBox)) {
                await post(`/api/chats/${encodeURIComponent(details.id)}/members`, { username });
              }
              await openChatInfo();
            }),
          ),
          button(
            t("info.leave"),
            "pill-btn danger",
            action(
              "leave",
              async () => {
                await post(`/api/chats/${encodeURIComponent(details.id)}/leave`);
                closeAllModals();
                closeChat();
              },
              t("info.leaveConfirm"),
            ),
          ),
        ]),
      );
    }
    openModal("chat-info-modal");
  }

  function verifyToggle(
    userId: string,
    fp: string,
    verified: Record<string, string>,
    compact = false,
    onChange: () => void = openChatInfo,
  ) {
    const isVerified = verified[userId] === fp;
    return button(
      t(isVerified ? "info.verified" : compact ? "info.verify" : "info.markVerified"),
      "pill-btn" + (isVerified ? " verified" : " secondary"),
      () => {
        const store = readStore("verified");
        if (store[userId] === fp) delete store[userId];
        else store[userId] = fp;
        writeStore("verified", store);
        onChange();
      },
    );
  }

  // ------------------------------------------------------------ profile

  /** Asks, unblocks and tells whether the friendship came back. */
  async function unblockUser(user: UserRef) {
    if (!window.confirm(t("profile.unblockConfirm", { name: nameOf(user) }))) return;
    try {
      const data = await post("/api/unblock", { username: user.username });
      showAlert(t(data.friends ? "profile.unblockedFriend" : "profile.unblocked", { name: nameOf(user) }));
    } catch (error) {
      showAlert(errorText(error));
    }
    chatsSignature = "";
    await refreshAll();
  }

  async function openProfile(username: string, showCode = false) {
    closeFloatingMenus();
    let data: any;
    try {
      data = await api(`/api/users/${encodeURIComponent(username)}/profile`);
    } catch (error) {
      showAlert(errorText(error));
      return;
    }
    const user = data.user;
    const name = nameOf(user);
    const reopen = () => openProfile(username, showCode);
    const status = data.is_me
      ? t("profile.you")
      : data.blocked
        ? t("profile.blockedStatus")
        : data.friend
          ? t("profile.friend")
          : data.request === "outgoing"
            ? t("profile.requestOutgoing")
            : data.request === "incoming"
              ? t("profile.requestIncoming")
              : t("profile.notFriend");

    const head = $("profile-head");
    head.textContent = "";
    head.append(
      avatarEl(user.username, { className: "avatar profile-avatar", label: name }),
      h("h3", { className: "profile-name", text: name }),
      h("span", { className: "profile-username", text: "@" + user.username }),
      h("span", { className: "profile-status" }, [data.muted ? h("span", { className: "material-symbols-rounded", text: "notifications_off" }) : null, document.createTextNode(status)]),
    );
    if (data.presence) {
      head.appendChild(
        h("span", { className: "profile-presence" + (data.presence.online ? " online" : ""), text: presenceText(data.presence) }),
      );
    }

    const actions = $("profile-actions");
    actions.textContent = "";
    const codeBox = $("profile-code");
    codeBox.textContent = "";
    codeBox.classList.add("modal-hidden");

    if (!data.is_me) {
      if (data.friend) {
        actions.append(button(t("friends.messageMenu"), "pill-btn", () => startDm(user.username)));
      } else if (!data.blocked && data.request !== "outgoing") {
        actions.append(
          button(t("profile.addFriend"), "pill-btn", async () => {
            const url = data.request === "incoming" ? "/api/friends/accept" : "/api/friends/request";
            try {
              await post(url, { username: user.username });
            } catch (error) {
              showAlert(errorText(error));
            }
            await refreshAll();
            reopen();
          }),
        );
      }

      const fp = await memberFingerprint(user);
      if (fp) {
        actions.append(
          button(t(showCode ? "profile.hideCode" : "profile.showCode"), "pill-btn secondary", () =>
            openProfile(username, !showCode),
          ),
        );
        if (showCode) {
          const myFp = await SeresCrypto.fingerprint(identity.pubEcdh, identity.pubSign);
          codeBox.append(
            h("p", { text: t("info.securityCode") }),
            h("code", { className: "safety-number", text: await SeresCrypto.safetyNumber(myFp, fp) }),
            verifyToggle(user.id, fp, readStore("verified"), false, reopen),
          );
          codeBox.classList.remove("modal-hidden");
        }
      }

      actions.append(
        button(t(data.muted ? "profile.unmute" : "profile.mute"), "pill-btn secondary", async () => {
          try {
            await post("/api/users/mute", { username: user.username, muted: !data.muted });
            showAlert(t(data.muted ? "profile.unmuted" : "profile.muted", { name }));
          } catch (error) {
            showAlert(errorText(error));
          }
          chatsSignature = "";
          await refreshAll();
          reopen();
        }),
        data.blocked
          ? button(t("friends.unblock"), "pill-btn", async () => {
              await unblockUser(user);
              reopen();
            })
          : button(
              t("friends.block"),
              "pill-btn danger",
              action(
                "block",
                async () => {
                  await post("/api/block", { username: user.username });
                  reopen();
                },
                t("friends.blockConfirmLong", { name }),
              ),
            ),
      );
    }
    $("profile-modal").classList.remove("modal-hidden");
  }

  // ------------------------------------------------------------- modals

  function openModal(id: string) {
    closeFloatingMenus();
    $(id).classList.remove("modal-hidden");
    const input = $(id).querySelector<HTMLInputElement>("input[type=text]");
    if (input) setTimeout(() => input.focus(), 30);
  }

  function closeAllModals() {
    document.querySelectorAll(".modal-overlay").forEach((modal) => modal.classList.add("modal-hidden"));
  }

  // ------------------------------------------------------------ settings

  async function uploadAvatar() {
    const input = $("avatar-upload-input") as HTMLInputElement;
    const warning = $("avatar-warning");
    warning.textContent = "";
    const file = input.files && input.files[0];
    if (!file) {
      warning.textContent = t("settings.chooseFile");
      return;
    }
    if (file.size > 2 * 1024 * 1024) {
      warning.textContent = t("settings.fileTooLarge");
      return;
    }
    const form = new FormData();
    form.append("avatar_img", file);
    try {
      const response = await fetch("/api/upload_avatar", { method: "POST", body: form, credentials: "same-origin" });
      const data = await response.json().catch(() => ({}));
      if (!response.ok || !data.success) throw new Error(data.message || t("settings.uploadFailed"));
      input.value = "";
      avatarState.delete(me.username);
      loadOwnAvatar();
      showAlert(t("settings.avatarUpdated"));
    } catch (error) {
      warning.textContent = errorText(error);
    }
  }

  async function changePassword() {
    const warning = $("password-warning");
    const oldPw = ($("old-password") as HTMLInputElement).value;
    const newPw = ($("new-password") as HTMLInputElement).value;
    const repeat = ($("new-password-repeat") as HTMLInputElement).value;
    warning.textContent = "";
    if (newPw.length < 8) {
      warning.textContent = t("settings.passwordShort");
      return;
    }
    if (newPw !== repeat) {
      warning.textContent = t("settings.passwordMismatch");
      return;
    }
    warning.textContent = t("settings.changingPassword");
    try {
      const fresh: Me = (await api("/api/me")).user;
      const pre = await post("/api/prelogin", { nameomail: me.username });
      const oldKeys = await SeresCrypto.deriveAccountKeys(oldPw, pre.kdf_salt, pre.kdf_iterations);
      const salt = SeresCrypto.newSalt();
      const newKeys = await SeresCrypto.deriveAccountKeys(newPw, salt, SeresCrypto.DEFAULT_ITERATIONS);
      let encPrivate: string;
      try {
        encPrivate = await SeresCrypto.rewrapPrivateKeys(fresh.enc_private, oldKeys.wrapKey, newKeys.wrapKey);
      } catch {
        throw new Error(t("settings.wrongPassword"));
      }
      await post("/api/change_password", {
        old_auth_hash: oldKeys.authHash,
        auth_hash: newKeys.authHash,
        kdf_salt: salt,
        kdf_iterations: SeresCrypto.DEFAULT_ITERATIONS,
        enc_private: encPrivate,
      });
      ["old-password", "new-password", "new-password-repeat"].forEach((id) => (($(id) as HTMLInputElement).value = ""));
      warning.textContent = "";
      showAlert(t("settings.passwordChanged"));
    } catch (error) {
      warning.textContent = errorText(error);
    }
  }

  // ------------------------------------------------------------- invites

  function inviteUrl(token: string) {
    return new URL("/?invite=" + encodeURIComponent(token), window.location.origin).href;
  }

  async function openInviteModal(renew = false) {
    $("user-dropdown-menu").classList.add("modal-hidden");
    try {
      const data = renew ? await post("/api/invite/renew") : await api("/api/invite");
      const url = inviteUrl(data.token);
      ($("invite-link") as HTMLInputElement).value = url;
      const box = $("invite-qr");
      box.textContent = "";
      box.appendChild(SeresQR.toSvg(url));
      $("invite-share").style.display = typeof navigator.share === "function" ? "" : "none";
      closeAllModals();
      openModal("invite-modal");
    } catch (error) {
      showAlert(errorText(error));
    }
  }

  async function copyInvite() {
    const input = $("invite-link") as HTMLInputElement;
    try {
      await navigator.clipboard.writeText(input.value);
    } catch {
      // Older browsers or no clipboard permission.
      input.select();
      document.execCommand("copy");
    }
    showAlert(t("invite.copied"));
  }

  function shareInvite() {
    const url = ($("invite-link") as HTMLInputElement).value;
    navigator.share({ title: "SereS", text: t("invite.shareText"), url }).catch(() => {});
  }

  /** Asks whether to send a friend request to the owner of an opened invite link. */
  async function showInvite(token: string) {
    try {
      const data = await api("/api/invite/" + encodeURIComponent(token));
      const name = nameOf(data.user);
      if (data.status === "self") return showAlert(t("invite.self"));
      if (data.status === "friends") return showAlert(t("invite.alreadyFriends", { name }));
      inviteToAccept = { token, name };
      const userBox = $("invite-accept-user");
      userBox.textContent = "";
      userBox.append(avatarEl(data.user.username, { label: name }), h("strong", { text: name }));
      $("invite-accept-text").textContent = t("invite.acceptText", { name });
      $("warning-invite").textContent = "";
      openModal("invite-accept-modal");
    } catch (error) {
      showAlert(error instanceof ApiError && error.status === 404 ? t("invite.invalid") : errorText(error));
    }
  }

  async function acceptInvite() {
    if (!inviteToAccept) return;
    try {
      const { token, name } = inviteToAccept;
      const data = await post("/api/invite/" + encodeURIComponent(token) + "/accept");
      closeAllModals();
      showAlert(t(data.status === "friends" ? "friends.nowFriends" : "friends.requestSent", { name }));
      inviteToAccept = null;
      await refreshAll();
    } catch (error) {
      $("warning-invite").textContent = errorText(error);
    }
  }

  function showOwnName() {
    $("my-username-display").textContent = nameOf(me);
    ($("password-username") as HTMLInputElement).value = me.username;
    $("mobile-username").textContent = nameOf(me);
    if (!current) $("current-chat-name").textContent = t("app.welcomeUser", { name: nameOf(me) });
  }

  async function saveDisplayName() {
    const warning = $("display-name-warning");
    warning.textContent = "";
    try {
      const data = await post("/api/profile/display_name", {
        display_name: ($("display-name-input") as HTMLInputElement).value,
      });
      me.display_name = data.display_name;
      ($("display-name-input") as HTMLInputElement).value = data.display_name;
      showOwnName();
      loadOwnAvatar();
      showAlert(t("settings.displayNameSaved"));
    } catch (error) {
      warning.textContent = errorText(error);
    }
  }

  function showCookieStatus() {
    const consent = SeresI18n.getConsent();
    $("cookie-status").textContent = t(
      consent === "accepted" ? "settings.cookiesAccepted" : consent === "denied" ? "settings.cookiesDenied" : "settings.cookiesUndecided",
    );
  }

  /** Texts of the on/off switches in the settings. */
  function renderSettingsToggles() {
    const settings = readStore("settings");
    $("privacy-toggle").textContent = t(me.show_last_seen === false ? "privacy.showOff" : "privacy.showOn");
    $("notify-toggle").textContent = t(settings.notify === "on" && notificationsEnabled() ? "notify.on" : "notify.off");
    $("notify-preview-toggle").textContent = t(settings.preview === "off" ? "notify.previewOff" : "notify.previewOn");
    $("notify-preview-toggle").classList.toggle("modal-hidden", settings.notify !== "on");
  }

  async function togglePrivacy() {
    try {
      const data = await post("/api/profile/privacy", { show_last_seen: me.show_last_seen === false });
      me.show_last_seen = data.show_last_seen;
      renderSettingsToggles();
      showAlert(t(data.show_last_seen ? "privacy.savedOn" : "privacy.savedOff"));
    } catch (error) {
      showAlert(errorText(error));
    }
  }

  // ------------------------------------------------------------------ 2FA

  /** The current password from the 2FA section, turned into the hash the server checks. */
  async function twofaPasswordHash() {
    const input = $("twofa-password") as HTMLInputElement;
    if (!input.value) {
      input.focus();
      throw new Error(t("twofa.needPassword"));
    }
    const pre = await post("/api/prelogin", { nameomail: me.username });
    const keys = await SeresCrypto.deriveAccountKeys(input.value, pre.kdf_salt, pre.kdf_iterations);
    return keys.authHash;
  }

  async function loadTwofa() {
    const list = $("twofa-list");
    list.textContent = "";
    let data: any;
    try {
      data = await api("/api/2fa");
    } catch {
      return;
    }
    $("twofa-status").textContent = t(data.enabled ? "twofa.statusOn" : "twofa.statusOff");
    $("twofa-status").classList.toggle("on", data.enabled);
    for (const passkey of data.passkeys) {
      list.appendChild(
        h("div", { className: "twofa-item" }, [
          h("span", {}, [h("span", { className: "material-symbols-rounded", text: "passkey" }), document.createTextNode(" " + passkey.name)]),
          h("span", {
            className: "twofa-meta",
            text: passkey.last_used_at ? t("twofa.lastUsed", { date: formatDateTime(passkey.last_used_at) }) : t("twofa.neverUsed"),
          }),
          button(t("twofa.remove"), "request-action-btn discard", () => removePasskey(passkey.id, passkey.name)),
        ]),
      );
    }
    if (data.totp) {
      list.appendChild(
        h("div", { className: "twofa-item" }, [
          h("span", { text: t("twofa.totpOn") }),
          h("span", { className: "twofa-meta" }),
          button(t("twofa.remove"), "request-action-btn discard", disableTotp),
        ]),
      );
    }
    $("twofa-totp-button").classList.toggle("modal-hidden", data.totp);
    $("twofa-add-passkey").classList.toggle("modal-hidden", !SeresPasskeys.supported());
  }

  async function twofaAction(work: () => Promise<void>) {
    const warning = $("twofa-warning");
    warning.textContent = "";
    try {
      await work();
      ($("twofa-password") as HTMLInputElement).value = "";
    } catch (error) {
      warning.textContent =
        error instanceof DOMException ? t("twofa.passkeyCancelled") : errorText(error);
    }
    await loadTwofa();
  }

  function addPasskey() {
    return twofaAction(async () => {
      const authHash = await twofaPasswordHash();
      const name = window.prompt(t("twofa.passkeyName"), t("twofa.passkeyDefault")) || t("twofa.passkeyDefault");
      const start = await post("/api/2fa/passkeys/options", { old_auth_hash: authHash });
      const credential = await SeresPasskeys.create(start.options);
      await post("/api/2fa/passkeys/register", { token: start.token, credential, name });
      showAlert(t("twofa.passkeyAdded"));
    });
  }

  function removePasskey(id: string, name: string) {
    if (!window.confirm(t("twofa.removeConfirm", { name }))) return;
    return twofaAction(async () => {
      await post("/api/2fa/passkeys/delete", { id, old_auth_hash: await twofaPasswordHash() });
      showAlert(t("twofa.removed"));
    });
  }

  function startTotp() {
    return twofaAction(async () => {
      const data = await post("/api/2fa/totp/setup", { old_auth_hash: await twofaPasswordHash() });
      const qr = $("twofa-qr");
      qr.textContent = "";
      qr.appendChild(SeresQR.toSvg(data.uri));
      $("twofa-secret").textContent = data.secret.replace(/(.{4})/g, "$1 ").trim();
      ($("twofa-code") as HTMLInputElement).value = "";
      $("twofa-totp-setup").classList.remove("modal-hidden");
      ($("twofa-code") as HTMLInputElement).focus();
    });
  }

  function confirmTotp() {
    return twofaAction(async () => {
      await post("/api/2fa/totp/enable", { code: ($("twofa-code") as HTMLInputElement).value.replace(/\s/g, "") });
      $("twofa-totp-setup").classList.add("modal-hidden");
      $("twofa-qr").textContent = "";
      $("twofa-secret").textContent = "";
      showAlert(t("twofa.totpEnabled"));
    });
  }

  function disableTotp() {
    if (!window.confirm(t("twofa.totpRemoveConfirm"))) return;
    return twofaAction(async () => {
      await post("/api/2fa/totp/disable", { old_auth_hash: await twofaPasswordHash() });
      showAlert(t("twofa.removed"));
    });
  }

  async function loadCodesStatus() {
    try {
      const data = await api("/api/recovery/codes");
      $("codes-status").textContent = data.total
        ? t("settings.codesLeft", { unused: data.unused, total: data.total })
        : t("settings.codesNone");
      $("codes-status").classList.toggle("warn", !data.unused);
    } catch {
      $("codes-status").textContent = "";
    }
  }

  /** Makes 10 new backup codes (old ones stop working) and shows them once. */
  async function generateCodes() {
    const warning = $("codes-warning");
    const passwordInput = $("codes-password") as HTMLInputElement;
    const password = passwordInput.value;
    warning.textContent = "";
    if (!password) {
      warning.textContent = t("settings.codesNeedPassword");
      passwordInput.focus();
      return;
    }
    const button = $("codes-generate") as HTMLButtonElement;
    button.disabled = true;
    warning.textContent = t("settings.codesCreating");
    try {
      const fresh: Me = (await api("/api/me")).user;
      const pre = await post("/api/prelogin", { nameomail: me.username });
      const keys = await SeresCrypto.deriveAccountKeys(password, pre.kdf_salt, pre.kdf_iterations);
      let created: { codes: string[]; stored: object[] };
      try {
        created = await SeresCrypto.createRecoveryCodes(fresh.enc_private, keys.wrapKey);
      } catch {
        throw new Error(t("settings.codesWrongPassword"));
      }
      await post("/api/recovery/codes", { old_auth_hash: keys.authHash, codes: created.stored });
      passwordInput.value = "";
      warning.textContent = "";
      await loadCodesStatus();
      SeresCodes.show(created.codes, me.username);
    } catch (error) {
      warning.textContent = errorText(error);
    } finally {
      button.disabled = false;
    }
  }

  async function openSettings() {
    loadCodesStatus();
    loadTwofa();
    $("twofa-totp-setup").classList.add("modal-hidden");
    renderSettingsToggles();
    $("user-dropdown-menu").classList.add("modal-hidden");
    ["display-name-warning", "avatar-warning", "twofa-warning", "codes-warning", "password-warning"].forEach((id) => {
      $(id).textContent = "";
    });
    ($("display-name-input") as HTMLInputElement).value = nameOf(me);
    showCookieStatus();
    openModal("settings-modal");
    const fp = await SeresCrypto.fingerprint(identity.pubEcdh, identity.pubSign);
    $("my-fingerprint").textContent = fp.replace(/(.{4})/g, "$1 ").trim();
  }

  function loadOwnAvatar() {
    const text = $("user-avatar-text");
    const img = $("user-avatar-img") as HTMLImageElement;
    text.textContent = nameOf(me).charAt(0).toUpperCase();
    $("user-avatar").style.backgroundColor = colorFor(me.username);
    fetch("/api/get_avatar", { credentials: "same-origin" })
      .then((response) => {
        if (!response.ok) throw new Error("no avatar");
        return response.blob();
      })
      .then((blob) => {
        img.src = URL.createObjectURL(blob);
        img.classList.remove("hidden-el");
        text.style.display = "none";
      })
      .catch(() => {
        img.classList.add("hidden-el");
        text.style.display = "block";
      });
  }

  async function logout() {
    try {
      await fetch("/api/logout", { method: "POST", credentials: "same-origin" });
    } finally {
      await SeresCrypto.clearIdentities();
      window.location.href = "login.html";
    }
  }

  // --------------------------------------------------------------- theme

  function applyTheme() {
    const isBright = SeresI18n.getPreference("theme") === "bright";
    document.body.classList.toggle("bright-body", isBright);
    const single: [string, string][] = [
      [".sidebar", "bright-sidebar"],
      [".sidebar-header", "bright-sidebar-header"],
      [".main-chat", "bright-main-chat"],
      [".chat-header", "bright-chat-header"],
      [".input-container", "bright-input-container"],
      [".input-box", "bright-input-box"],
      [".user-menu-container", "bright-user-menu-container"],
      [".user-dropdown", "bright-user-dropdown"],
    ];
    single.forEach(([selector, cls]) => document.querySelector(selector)?.classList.toggle(cls, isBright));
    const many: [string, string][] = [
      [".section-title", "bright-section-title"],
      [".list-item", "bright-list-item"],
      [".item-name", "bright-item-name"],
      [".item-status", "bright-item-status"],
      [".dropdown-divider", "bright-dropdown-divider"],
      [".dropdown-item", "bright-dropdown-item"],
      [".modal-overlay", "bright-modal-overlay"],
      [".modal-box", "bright-modal-box"],
      [".cancel-btn", "bright-cancel-btn"],
    ];
    many.forEach(([selector, cls]) =>
      document.querySelectorAll(selector).forEach((el) => el.classList.toggle(cls, isBright)),
    );
  }

  function toggleTheme() {
    const newTheme = SeresI18n.getPreference("theme") === "bright" ? "dark" : "bright";
    SeresI18n.setPreference("theme", newTheme);
    applyTheme();
  }

  /** Renders all generated texts again after the language was switched. */
  function rerenderLanguage() {
    shownCache.clear();
    showCookieStatus();
    chatsSignature = "";
    friendsSignature = "";
    if (current) {
      refreshCurrentDetails().catch(() => {});
      renderMessages({}).catch(() => {});
    } else {
      closeChat();
    }
    refreshAll();
  }

  // --------------------------------------------------------------- intro

  // The intro animation (assets/animation.mp4/.mov) is no longer played; the
  // files are kept. Only the "?login=true" marker of the login redirect is removed.
  function cleanLoginRedirect() {
    if (new URLSearchParams(window.location.search).get("login") === "true") {
      window.history.replaceState({}, document.title, window.location.pathname);
    }
  }

  // ---------------------------------------------------------------- boot

  async function refreshAll() {
    await Promise.all([loadFriends(), loadChats()]).catch((error) => {
      if (!(error instanceof ApiError && error.status === 401)) console.error(error);
    });
    if (current) await refreshCurrentDetails().catch(() => {});
  }

  function bindEvents() {
    const resizer = $("pane-resizer");
    const savedWidth = Number(localStorage.getItem("seres-sidebar-width")) || 450;
    document.documentElement.style.setProperty("--sidebar-width", `${Math.min(640, Math.max(340, savedWidth))}px`);
    const resizeAt = (clientX: number) => {
      const width = Math.min(640, Math.max(340, clientX - 72));
      document.documentElement.style.setProperty("--sidebar-width", `${width}px`);
      resizer.setAttribute("aria-valuenow", String(width));
      localStorage.setItem("seres-sidebar-width", String(width));
    };
    resizer.addEventListener("pointerdown", (event) => {
      resizer.setPointerCapture(event.pointerId);
      resizeAt(event.clientX);
    });
    resizer.addEventListener("pointermove", (event) => {
      if (resizer.hasPointerCapture(event.pointerId)) resizeAt(event.clientX);
    });
    resizer.addEventListener("keydown", (event) => {
      if (!["ArrowLeft", "ArrowRight"].includes((event as KeyboardEvent).key)) return;
      event.preventDefault();
      const delta = (event as KeyboardEvent).key === "ArrowLeft" ? -20 : 20;
      const currentWidth = parseInt(getComputedStyle(document.documentElement).getPropertyValue("--sidebar-width"), 10) || 450;
      resizeAt(currentWidth + delta + 72);
    });
    $("btn-add-friend").addEventListener("click", () => {
      $("warning-add-friend").textContent = "";
      openModal("add-friend-modal");
    });
    $("confirm-add-friend").addEventListener("click", addFriend);
    $("friends-username-input").addEventListener("keydown", (event) => {
      if ((event as KeyboardEvent).key === "Enter") addFriend();
    });
    $("btn-new-chat").addEventListener("click", openNewChatModal);
    $("new-chat-list").addEventListener("change", updateNewChatName);
    $("confirm-new-chat").addEventListener("click", startNewChat);
    $("chat-info-btn").addEventListener("click", openChatInfo);
    document.querySelector(".chat-title")!.addEventListener("click", () => {
      if (current && current.details && current.details.type === "dm" && current.details.other_user) {
        openProfile(current.details.other_user);
      }
    });
    $("send-btn").addEventListener("click", sendMessage);
    $("poll-btn").addEventListener("click", createPoll);
    $("schedule-btn").addEventListener("click", scheduleMessage);
    $("edit-cancel").addEventListener("click", cancelEdit);
    $("reply-cancel").addEventListener("click", cancelReply);
    $("record-btn").addEventListener("click", startRecording);
    $("record-cancel").addEventListener("click", () => stopRecording(false));
    $("record-send").addEventListener("click", () => stopRecording(true));
    $("emoji-btn").addEventListener("click", (event) => {
      event.stopPropagation();
      toggleEmojiPicker();
    });
    $("attach-btn").addEventListener("click", () => ($("attach-input") as HTMLInputElement).click());
    $("attach-input").addEventListener("change", () => {
      const picker = $("attach-input") as HTMLInputElement;
      if (picker.files) addPendingFiles(picker.files);
      picker.value = "";
    });
    $("search-btn").addEventListener("click", openSearch);
    $("call-btn")?.addEventListener("click", () => {
      if (current && typeof SeresCalls !== "undefined") SeresCalls.start(current.id);
    });
    $("search-input").addEventListener("input", onSearchInput);
    $("search-input").addEventListener("keydown", (event) => {
      const key = (event as KeyboardEvent).key;
      if (key === "Enter") moveSearch((event as KeyboardEvent).shiftKey ? 1 : -1);
      if (key === "Escape") closeSearch();
    });
    $("search-prev").addEventListener("click", () => moveSearch(-1));
    $("search-next").addEventListener("click", () => moveSearch(1));
    $("search-close").addEventListener("click", closeSearch);
    $("pinned-bar").addEventListener("click", openPinsModal);
    $("confirm-forward").addEventListener("click", confirmForward);
    $("jump-bottom").addEventListener("click", () => {
      const container = $("messages");
      container.scrollTo({ top: container.scrollHeight, behavior: "smooth" });
    });
    $("messages").addEventListener("scroll", updateJumpButton, { passive: true });
    $("lightbox").addEventListener("click", () => $("lightbox").classList.add("modal-hidden"));
    $("privacy-toggle").addEventListener("click", togglePrivacy);
    $("notify-toggle").addEventListener("click", () => toggleNotifications().catch(() => {}));
    $("notify-preview-toggle").addEventListener("click", () => {
      const settings = readStore("settings");
      settings.preview = settings.preview === "off" ? "on" : "off";
      writeStore("settings", settings);
      renderSettingsToggles();
    });
    // Drop files onto the chat or paste images to attach them.
    const chatArea = document.querySelector(".main-chat") as HTMLElement;
    chatArea.addEventListener("dragover", (event) => {
      if (!current || !event.dataTransfer?.types.includes("Files")) return;
      event.preventDefault();
      chatArea.classList.add("drag-over");
    });
    chatArea.addEventListener("dragleave", (event) => {
      if (event.target === chatArea || !chatArea.contains(event.relatedTarget as Node)) chatArea.classList.remove("drag-over");
    });
    chatArea.addEventListener("drop", (event) => {
      chatArea.classList.remove("drag-over");
      if (!current || !event.dataTransfer?.files.length) return;
      event.preventDefault();
      addPendingFiles(event.dataTransfer.files);
    });
    document.querySelectorAll<HTMLElement>(".rail-nav[data-rail-view]").forEach((button) => button.addEventListener("click", () => switchView(button.dataset.railView as "chats" | "friends" | "requests")));
    $("rail-settings").addEventListener("click", openSettings);
    $("user-menu-trigger").addEventListener("click", () => $("user-dropdown-menu").classList.toggle("modal-hidden"));
    $("menu-logout").addEventListener("click", (event) => {
      event.preventDefault();
      logout();
    });
    $("menu-invite").addEventListener("click", (event) => {
      event.preventDefault();
      openInviteModal();
    });
    $("add-friend-invite").addEventListener("click", () => openInviteModal());
    $("confirm-invite").addEventListener("click", acceptInvite);
    $("invite-copy").addEventListener("click", copyInvite);
    $("invite-share").addEventListener("click", shareInvite);
    $("invite-renew").addEventListener("click", () => {
      if (window.confirm(t("invite.renewConfirm"))) openInviteModal(true);
    });
    $("invite-link").addEventListener("focus", () => ($("invite-link") as HTMLInputElement).select());
    $("profile-close").addEventListener("click", () => $("profile-modal").classList.add("modal-hidden"));
    $("save-display-name").addEventListener("click", saveDisplayName);
    $("display-name-input").addEventListener("keydown", (event) => {
      if ((event as KeyboardEvent).key === "Enter") saveDisplayName();
    });
    $("upload-avatar-btn").addEventListener("click", uploadAvatar);
    $("theme-toggle-btn").addEventListener("click", toggleTheme);
    $("twofa-form").addEventListener("submit", (event) => event.preventDefault());
    $("twofa-add-passkey").addEventListener("click", addPasskey);
    $("twofa-totp-button").addEventListener("click", startTotp);
    $("twofa-totp-confirm").addEventListener("click", confirmTotp);
    $("twofa-code").addEventListener("keydown", (event) => {
      if ((event as KeyboardEvent).key === "Enter") confirmTotp();
    });
    $("codes-form").addEventListener("submit", (event) => {
      event.preventDefault();
      if (window.confirm(t("settings.codesConfirm"))) generateCodes();
    });
    $("password-form").addEventListener("submit", (event) => {
      event.preventDefault();
      changePassword();
    });
    // Shows the cookie banner again (above the settings) to change the decision.
    $("cookie-settings-btn").addEventListener("click", () => {
      SeresConsent.show(() => {
        showCookieStatus();
        showAlert(t("settings.cookiesSaved"));
      });
    });
    $("language-select-slot").appendChild(SeresI18n.languageSelect(rerenderLanguage));

    document.querySelectorAll<HTMLElement>(".list-view-toggle").forEach((btn) => {
      btn.addEventListener("click", () => switchView(btn.dataset.view as "chats" | "friends" | "requests"));
    });
    $("list-search").addEventListener("input", () => {
      chatsSignature = "";
      loadChats().catch(() => {});
      renderFriends();
    });

    document.querySelectorAll<HTMLElement>("[data-close-modal]").forEach((btn) => {
      btn.addEventListener("click", closeAllModals);
    });
    document.querySelectorAll<HTMLElement>(".modal-overlay").forEach((overlay) => {
      overlay.addEventListener("click", (event) => {
        if (event.target === overlay) closeAllModals();
      });
    });

    const input = $("message-input-field") as HTMLTextAreaElement;
    input.addEventListener("keydown", (event) => {
      const mentionOpen = !$("mention-list").classList.contains("modal-hidden");
      if (mentionOpen && (event.key === "Enter" || event.key === "Tab")) {
        const first = $("mention-list").querySelector<HTMLElement>(".mention-item");
        if (first) {
          event.preventDefault();
          insertMention(first.dataset.username!);
          return;
        }
      }
      if (event.key === "Escape") {
        closeMentionList();
        if (replyTo) cancelReply();
        else if (editing) cancelEdit();
      }
      if (event.key === "Enter" && !event.shiftKey) {
        event.preventDefault();
        sendMessage();
      }
      // Arrow up in an empty field edits the own last message (like Discord).
      if (event.key === "ArrowUp" && !input.value && current) {
        const own = [...current.messages.values()]
          .filter((m) => m.sender_id === me.id && m.kind === "e2e" && !m.deleted && !m.silent)
          .sort((a, b) => b.seq - a.seq)[0];
        const opened = current;
        if (own) {
          event.preventDefault();
          showMessage(opened.id, own).then((view) => {
            if (view.type === "text" && current === opened) startEdit(opened, own, view);
          });
        }
      }
    });
    input.addEventListener("input", () => {
      autoGrow(input);
      updateSendButton();
      updateMentionList();
      sendTyping(input.value.trim().length > 0);
    });
    input.addEventListener("paste", (event) => {
      const files = [...(event.clipboardData?.files || [])];
      if (files.length) {
        event.preventDefault();
        addPendingFiles(files);
      }
    });

    document.addEventListener("click", (event) => {
      const target = event.target as Element;
      if (!target.closest(".floating-menu")) closeFloatingMenus();
      if (!target.closest("#emoji-slot") && !target.closest("#emoji-btn")) closeEmojiPicker();
      if (!target.closest(".user-menu-container")) $("user-dropdown-menu").classList.add("modal-hidden");
      const sidebar = document.querySelector(".sidebar");
      if (
        sidebar &&
        sidebar.classList.contains("open") &&
        window.innerWidth <= 768 &&
        !sidebar.contains(target) &&
        !target.closest(".menu-toggle") &&
        !target.closest(".modal-overlay") &&
        current
      ) {
        sidebar.classList.remove("open");
      }
    });
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        closeAllModals();
        closeFloatingMenus();
        closeEmojiPicker();
        $("lightbox").classList.add("modal-hidden");
      }
    });
    document.addEventListener("visibilitychange", () => {
      if (document.visibilityState === "visible") {
        refreshAll();
        syncCurrent().catch(() => {});
        markRead();
      }
    });
  }

  async function boot() {
    SeresI18n.apply();
    $("my-username-display").textContent = t("common.loading");
    $("mobile-username").textContent = t("common.loading");
    $("current-chat-name").textContent = t("app.welcome");
    cleanLoginRedirect();
    applyTheme();
    try {
      me = (await api("/api/me")).user;
    } catch {
      goToLogin();
      return;
    }
    const stored = await SeresCrypto.loadIdentity(me.id);
    if (!stored || stored.pubEcdh !== me.pub_ecdh || stored.pubSign !== me.pub_sign) {
      // No unlocked keys on this device (or they don't match the account): log in again.
      await fetch("/api/logout", { method: "POST", credentials: "same-origin" }).catch(() => {});
      await SeresCrypto.clearIdentities();
      goToLogin("keys");
      return;
    }
    identity = stored;
    userKeys.set(me.id, { id: me.id, username: me.username, pub_ecdh: me.pub_ecdh, pub_sign: me.pub_sign });

    showOwnName();
    loadOwnAvatar();
    bindEvents();
    switchView("chats");
    if (window.innerWidth <= 768) document.querySelector(".sidebar")?.classList.add("open");

    await refreshAll();
    if (recoveredBy === "code") {
      // Point to the backup codes, one of them was just used.
      await openSettings();
      $("codes-warning").textContent = t("recover.doneCode");
      $("codes-form").scrollIntoView({ block: "center" });
    }
    if (pendingInvite) {
      // Remove the token from the address bar so a reload doesn't ask again.
      window.history.replaceState({}, document.title, window.location.pathname);
      showInvite(pendingInvite);
    }

    // A cached page from before calls existed doesn't load calls.js.
    if (typeof SeresCalls !== "undefined") SeresCalls.init({
      api,
      post,
      me: () => me,
      identity: () => identity,
      showAlert,
      errorText,
      pickPeople: pickCallPeople,
      chatCreated: () => {
        chatsSignature = "";
        loadChats().catch(() => {});
      },
      openChat: (chatId) => {
        if (current?.id !== chatId) openChat(chatId);
      },
      avatar: (username, label) => avatarEl(username, { label }),
    });

    window.setInterval(() => {
      if (document.visibilityState === "visible") syncCurrent().catch(() => {});
    }, 2500);
    window.setInterval(() => {
      if (document.visibilityState === "visible") refreshAll();
    }, 6000);
    // In the background only the chat list is checked, for desktop notifications.
    window.setInterval(() => {
      if (document.visibilityState !== "visible" && notificationsEnabled()) loadChats().catch(() => {});
    }, 20000);
  }

  document.addEventListener("DOMContentLoaded", () => {
    boot().catch((error) => {
      console.error(error);
      showAlert(errorText(error));
    });
  });
})();
