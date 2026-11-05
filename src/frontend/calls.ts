// Voice calls in the browser.
//
// The server only knows who is called and who joined. The audio goes directly
// between the browsers with WebRTC (or through the TURN server when a direct
// connection isn't possible); WebRTC always encrypts it. In a group everyone
// is connected with everyone. Each connection offer is signed with the
// sender's account key (see SeresCrypto.signCall), so the server can't place
// itself in the middle.
//
// The browser asks the server every few seconds for calls and connection
// offers, every second while a call rings or runs.

interface CallParticipant {
  id: string;
  username: string;
  display_name: string;
  state: "ringing" | "joined" | "left" | "declined" | "missed";
}

interface CallInfo {
  id: string;
  chat_id: string;
  chat_name: string;
  chat_type: "dm" | "group";
  started_by: string;
  started_at: string;
  answered_at: string | null;
  participants: CallParticipant[];
}

interface CallSignal {
  id: number;
  call_id: string;
  from: string;
  kind: "offer" | "answer";
  data: { sdp: string; sig: string };
}

interface CallDeps {
  api(path: string): Promise<any>;
  post(path: string, body?: object): Promise<any>;
  me(): { id: string };
  identity(): SeresIdentity;
  showAlert(message: string): void;
  errorText(error: unknown): string;
  /** Friends to add to a call, or null when cancelled. */
  pickPeople(excludeIds: string[]): Promise<string[] | null>;
  /** A call moved to a new group chat: show it in the chat list. */
  chatCreated(chatId: string): void;
  openChat(chatId: string): void;
}

const SeresCalls = (() => {
  const t = SeresI18n.t;
  const ICE_WAIT_MS = 4000;
  let deps: CallDeps;
  let lastSignal = 0;
  let pollTimer: number | null = null;
  let polling = false;
  let calls: CallInfo[] = [];
  const signKeys = new Map<string, string>();
  // Calls I declined or that rang out here, so they don't ring again.
  const dismissed = new Set<string>();

  interface Peer {
    pc: RTCPeerConnection;
    audio: HTMLAudioElement;
    offerer: boolean;
  }

  interface Active {
    call: CallInfo;
    stream: MediaStream;
    ice: RTCIceServer[];
    peers: Map<string, Peer>;
    // Broken connections per person; after three tries it stops offering.
    failures: Map<string, number>;
    muted: boolean;
    timer: number;
  }
  let active: Active | null = null;

  // ------------------------------------------------------------- polling

  function schedule() {
    if (pollTimer !== null) clearTimeout(pollTimer);
    const busy = active || calls.some((call) => myState(call) === "ringing");
    pollTimer = window.setTimeout(poll, busy ? 1000 : 3000);
  }

  async function poll() {
    if (polling) return;
    polling = true;
    try {
      const data = await deps.api(`/api/calls?after=${lastSignal}`);
      calls = data.calls || [];
      await update();
      for (const signal of (data.signals || []) as CallSignal[]) {
        lastSignal = Math.max(lastSignal, signal.id);
        await handleSignal(signal).catch((error) => console.warn("Call signal failed", error));
      }
    } catch (error) {
      console.warn("Could not check for calls", error);
    } finally {
      polling = false;
      schedule();
    }
  }

  function myState(call: CallInfo) {
    return call.participants.find((p) => p.id === deps.me().id)?.state;
  }

  async function update() {
    if (active) {
      const call = calls.find((c) => c.id === active!.call.id);
      if (!call || myState(call) !== "joined") {
        stopActive();
        deps.showAlert(t("call.ended"));
      } else {
        active.call = call;
        syncPeers();
      }
    }
    renderIncoming();
    renderPanel();
  }

  // --------------------------------------------------------------- WebRTC

  /** Everyone is connected with everyone; the one with the smaller id offers. */
  function syncPeers() {
    if (!active) return;
    const meId = deps.me().id;
    const joined = new Set(active.call.participants.filter((p) => p.state === "joined").map((p) => p.id));
    for (const [id, peer] of active.peers) {
      if (!joined.has(id)) closePeer(id, peer);
    }
    for (const id of joined) {
      if (id !== meId && !active.peers.has(id) && meId < id && (active.failures.get(id) || 0) < 3) {
        sendOffer(id).catch((error) => console.warn("Could not call", id, error));
      }
    }
  }

  function newPeer(userId: string, offerer: boolean): Peer {
    const current = active!;
    const pc = new RTCPeerConnection({ iceServers: current.ice });
    current.stream.getTracks().forEach((track) => pc.addTrack(track, current.stream));
    const audio = document.createElement("audio");
    audio.autoplay = true;
    pc.ontrack = (event) => {
      audio.srcObject = event.streams[0];
      audio.play().catch(() => {});
    };
    const peer: Peer = { pc, audio, offerer };
    pc.onconnectionstatechange = () => {
      renderPanel();
      // A broken connection is closed; the side that offers starts a new one
      // with the next check (see syncPeers).
      if (pc.connectionState === "failed" && active === current && current.peers.get(userId) === peer) {
        current.failures.set(userId, (current.failures.get(userId) || 0) + 1);
        closePeer(userId, peer);
      }
    };
    current.peers.set(userId, peer);
    return peer;
  }

  function closePeer(userId: string, peer: Peer) {
    peer.pc.close();
    peer.audio.srcObject = null;
    if (active && active.peers.get(userId) === peer) active.peers.delete(userId);
  }

  /** Waits until all connection candidates are in the description (no trickling). */
  function gathered(pc: RTCPeerConnection) {
    return new Promise<void>((resolve) => {
      if (pc.iceGatheringState === "complete") return resolve();
      const timer = window.setTimeout(resolve, ICE_WAIT_MS);
      pc.addEventListener("icegatheringstatechange", () => {
        if (pc.iceGatheringState === "complete") {
          clearTimeout(timer);
          resolve();
        }
      });
    });
  }

  async function sendSignal(callId: string, to: string, kind: "offer" | "answer", pc: RTCPeerConnection) {
    await gathered(pc);
    const sdp = pc.localDescription!.sdp;
    const sig = await SeresCrypto.signCall(deps.identity(), callId, to, kind, sdp);
    await deps.post(`/api/calls/${encodeURIComponent(callId)}/signal`, { to, kind, data: { sdp, sig } });
  }

  async function sendOffer(userId: string) {
    if (!active) return;
    const current = active;
    const peer = newPeer(userId, true);
    await peer.pc.setLocalDescription(await peer.pc.createOffer());
    if (active !== current) return;
    await sendSignal(current.call.id, userId, "offer", peer.pc);
  }

  async function signKey(userId: string) {
    if (!signKeys.has(userId)) {
      const data = await deps.api("/api/users/keys?ids=" + encodeURIComponent(userId));
      const user = (data.users || [])[0];
      if (user?.pub_sign) signKeys.set(userId, user.pub_sign);
    }
    return signKeys.get(userId) || null;
  }

  async function handleSignal(signal: CallSignal) {
    if (!active || signal.call_id !== active.call.id) return;
    const current = active;
    const key = await signKey(signal.from);
    const meId = deps.me().id;
    const valid =
      key && (await SeresCrypto.verifyCall(key, signal.call_id, signal.from, meId, signal.kind, signal.data.sdp, signal.data.sig));
    if (!valid) {
      console.warn("Ignored a call signal with a wrong signature from", signal.from);
      return;
    }
    if (active !== current) return;
    if (signal.kind === "offer") {
      const old = current.peers.get(signal.from);
      if (old) closePeer(signal.from, old);
      const peer = newPeer(signal.from, false);
      await peer.pc.setRemoteDescription({ type: "offer", sdp: signal.data.sdp });
      await peer.pc.setLocalDescription(await peer.pc.createAnswer());
      await sendSignal(current.call.id, signal.from, "answer", peer.pc);
    } else {
      const peer = current.peers.get(signal.from);
      if (peer && peer.offerer && peer.pc.signalingState === "have-local-offer") {
        await peer.pc.setRemoteDescription({ type: "answer", sdp: signal.data.sdp });
      }
    }
    renderPanel();
  }

  // ------------------------------------------------------------- actions

  async function microphone() {
    try {
      return await navigator.mediaDevices.getUserMedia({
        audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true },
      });
    } catch (error) {
      throw new Error(t("call.noMicrophone"));
    }
  }

  async function enter(call: CallInfo, stream?: MediaStream) {
    const ice = (await deps.api("/api/calls/ice")).ice_servers as RTCIceServer[];
    if (active) stopActive(active.stream !== stream);
    active = {
      call,
      stream: stream || (await microphone()),
      ice,
      peers: new Map(),
      failures: new Map(),
      muted: false,
      timer: window.setInterval(renderPanel, 1000),
    };
    calls = calls.filter((c) => c.id !== call.id).concat(call);
    syncPeers();
    renderIncoming();
    renderPanel();
    schedule();
  }

  /** Calls everyone in the chat, or joins the call running there. */
  async function start(chatId: string) {
    if (active && active.call.chat_id === chatId) return;
    try {
      const stream = await microphone();
      const data = await deps.post(`/api/chats/${encodeURIComponent(chatId)}/call`);
      await enter(data.call, stream);
    } catch (error) {
      deps.showAlert(deps.errorText(error));
    }
  }

  async function answer(call: CallInfo) {
    try {
      const stream = await microphone();
      const data = await deps.post(`/api/calls/${encodeURIComponent(call.id)}/answer`);
      await enter(data.call, stream);
      deps.openChat(call.chat_id);
    } catch (error) {
      deps.showAlert(deps.errorText(error));
    }
  }

  async function decline(call: CallInfo) {
    dismissed.add(call.id);
    renderIncoming();
    await deps.post(`/api/calls/${encodeURIComponent(call.id)}/decline`).catch(() => {});
  }

  async function hangUp() {
    if (!active) return;
    const id = active.call.id;
    stopActive();
    renderPanel();
    await deps.post(`/api/calls/${encodeURIComponent(id)}/leave`).catch(() => {});
  }

  function stopActive(stopMicrophone = true) {
    if (!active) return;
    for (const [id, peer] of active.peers) closePeer(id, peer);
    if (stopMicrophone) active.stream.getTracks().forEach((track) => track.stop());
    clearInterval(active.timer);
    active = null;
    stopTone();
  }

  function toggleMute() {
    if (!active) return;
    active.muted = !active.muted;
    active.stream.getAudioTracks().forEach((track) => (track.enabled = !active!.muted));
    renderPanel();
  }

  /** More people: the server makes a group with everyone and calls it. */
  async function addPeople() {
    if (!active) return;
    const current = active;
    const exclude = current.call.participants.filter((p) => p.state === "joined").map((p) => p.id);
    const usernames = await deps.pickPeople(exclude);
    if (!usernames || !usernames.length || active !== current) return;
    try {
      const data = await deps.post(`/api/calls/${encodeURIComponent(current.call.id)}/add`, { usernames });
      deps.chatCreated(data.chat_id);
      await enter(data.call, current.stream);
      deps.openChat(data.chat_id);
    } catch (error) {
      deps.showAlert(deps.errorText(error));
    }
  }

  // --------------------------------------------------------------- tones

  let audioContext: AudioContext | null = null;
  let toneTimer: number | null = null;
  let tone: "ring" | "back" | null = null;

  /** Plays short beeps: "ring" for an incoming call, "back" while my call rings. */
  function playTone(kind: "ring" | "back") {
    if (tone === kind) return;
    stopTone();
    tone = kind;
    const beep = () => {
      try {
        audioContext = audioContext || new AudioContext();
        audioContext.resume().catch(() => {});
        const pattern = kind === "ring" ? [0, 0.4] : [0];
        for (const offset of pattern) {
          const osc = audioContext.createOscillator();
          const gain = audioContext.createGain();
          osc.frequency.value = kind === "ring" ? 480 : 425;
          gain.gain.value = 0.08;
          osc.connect(gain).connect(audioContext.destination);
          const at = audioContext.currentTime + offset;
          osc.start(at);
          osc.stop(at + (kind === "ring" ? 0.3 : 1));
        }
      } catch {
        // No sound possible (e.g. before the page was clicked once).
      }
    };
    beep();
    toneTimer = window.setInterval(beep, kind === "ring" ? 2000 : 4000);
  }

  function stopTone() {
    if (toneTimer !== null) clearInterval(toneTimer);
    toneTimer = null;
    tone = null;
  }

  // ------------------------------------------------------------------ UI

  function el<K extends keyof HTMLElementTagNameMap>(tag: K, className = "", text = "") {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text) element.textContent = text;
    return element;
  }

  function actionButton(label: string, className: string, title: string, fn: () => void) {
    const button = el("button", "call-btn " + className, label);
    button.type = "button";
    button.title = title;
    button.setAttribute("aria-label", title);
    button.addEventListener("click", fn);
    return button;
  }

  function nameOf(p: { username: string; display_name?: string | null }) {
    return p.display_name || p.username;
  }

  function callerName(call: CallInfo) {
    const caller = call.participants.find((p) => p.id === call.started_by);
    return caller ? nameOf(caller) : "";
  }

  function duration(since: string) {
    const seconds = Math.max(0, Math.floor((Date.now() - Date.parse(since)) / 1000));
    const m = Math.floor(seconds / 60);
    return m + ":" + String(seconds % 60).padStart(2, "0");
  }

  const notified = new Set<string>();

  function renderIncoming() {
    let box = document.getElementById("call-incoming");
    const ringing = calls.find(
      (call) => myState(call) === "ringing" && !dismissed.has(call.id) && call.id !== active?.call.id,
    );
    if (!ringing) {
      box?.remove();
      if (tone === "ring") stopTone();
      return;
    }
    if (!box) {
      box = el("div", "call-incoming");
      box.id = "call-incoming";
      document.body.appendChild(box);
    }
    if (box.dataset.call === ringing.id) return;
    box.dataset.call = ringing.id;
    box.textContent = "";
    const title =
      ringing.chat_type === "group"
        ? t("call.incomingGroup", { name: callerName(ringing), group: ringing.chat_name })
        : t("call.incoming", { name: callerName(ringing) });
    box.append(
      el("div", "call-incoming-icon", "📞"),
      el("div", "call-incoming-title", title),
      el("div", "call-buttons"),
    );
    box.lastElementChild!.append(
      actionButton("✕", "call-decline", t("call.decline"), () => decline(ringing)),
      actionButton("📞", "call-accept", t("call.accept"), () => answer(ringing)),
    );
    if (!active) playTone("ring");
    if (document.hidden && !notified.has(ringing.id) && "Notification" in window && Notification.permission === "granted") {
      notified.add(ringing.id);
      const note = new Notification("SereS", { body: title, tag: "call-" + ringing.id });
      note.onclick = () => window.focus();
    }
  }

  function renderPanel() {
    let panel = document.getElementById("call-panel");
    if (!active) {
      panel?.remove();
      if (tone === "back") stopTone();
      return;
    }
    if (!panel) {
      panel = el("div", "call-panel");
      panel.id = "call-panel";
      document.body.appendChild(panel);
    }
    const meId = deps.me().id;
    const others = active.call.participants.filter((p) => p.id !== meId && p.state !== "left");
    const joinedOthers = others.filter((p) => p.state === "joined");
    const connected = [...active.peers.values()].some((peer) => peer.pc.connectionState === "connected");
    let status: string;
    if (!joinedOthers.length) status = t("call.ringing");
    else if (!connected) status = t("call.connecting");
    else status = duration(active.call.answered_at || active.call.started_at);
    if (!joinedOthers.length && active.call.started_by === meId) playTone("back");
    else if (tone === "back") stopTone();

    panel.textContent = "";
    const head = el("div", "call-panel-head");
    const title = el("button", "call-panel-title", active.call.chat_name);
    title.type = "button";
    title.title = t("call.openChat");
    const chatId = active.call.chat_id;
    title.addEventListener("click", () => deps.openChat(chatId));
    head.append(title, el("span", "call-panel-status", status));
    const people = el("div", "call-people");
    for (const p of others) {
      const peer = active.peers.get(p.id);
      const state =
        p.state === "joined"
          ? peer?.pc.connectionState === "connected"
            ? ""
            : t("call.connectingShort")
          : p.state === "ringing"
            ? t("call.ringingShort")
            : t("call.notThere");
      const chip = el("span", "call-person" + (p.state === "joined" && !state ? " live" : ""), nameOf(p));
      if (state) chip.appendChild(el("small", "", " · " + state));
      people.appendChild(chip);
    }
    const buttons = el("div", "call-buttons");
    buttons.append(
      actionButton(active.muted ? "🔇" : "🎤", "call-mute" + (active.muted ? " on" : ""), t(active.muted ? "call.unmute" : "call.mute"), toggleMute),
      actionButton("👤+", "call-add", t("call.addPeople"), () => void addPeople()),
      actionButton("📞", "call-hangup", t("call.hangUp"), () => void hangUp()),
    );
    panel.append(head, people, buttons);
  }

  function init(dependencies: CallDeps) {
    deps = dependencies;
    window.addEventListener("beforeunload", () => {
      if (active) navigator.sendBeacon?.(`/api/calls/${encodeURIComponent(active.call.id)}/leave`);
    });
    poll();
  }

  return {
    init,
    start,
    hangUp,
    /** The chat that has a running call I'm in, if any. */
    activeChat: () => active?.call.chat_id || null,
  };
})();

(window as any).SeresCalls = SeresCalls;
