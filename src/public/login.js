"use strict";
(() => {
    const t = SeresI18n.t;
    let mode = "login";
    let busy = false;
    function el(id) {
        return document.getElementById(id);
    }
    function setWarning(message) {
        el("warning").textContent = message;
    }
    function setBusy(value, label) {
        busy = value;
        el("login").disabled = value;
        el("register_redirect").disabled =
            value || (mode === "register" && !el("tos-checkbox").checked);
        if (label !== undefined)
            setWarning(label);
    }
    async function postJson(url, body) {
        const response = await fetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/json", Accept: "application/json" },
            credentials: "include",
            body: JSON.stringify(body),
        });
        const data = await response.json().catch(() => ({}));
        return { ok: response.ok && data.success, status: response.status, data };
    }
    /** Logs in, unlocks the private keys locally and stores them for this browser. */
    async function loginWith(nameomail, password) {
        const pre = await postJson("/api/prelogin", { nameomail });
        if (!pre.ok)
            throw new Error(pre.data.message || t("login.failed"));
        const { authHash, wrapKey } = await SeresCrypto.deriveAccountKeys(password, pre.data.kdf_salt, pre.data.kdf_iterations);
        const body = { nameomail, auth_hash: authHash };
        if (pre.data.legacy) {
            // Account from before end-to-end encryption: upgrade it on this login.
            body.passwd = password;
            body.keys = await SeresCrypto.createKeyBundle(wrapKey);
        }
        const res = await postJson("/api/login", body);
        if (!res.ok) {
            throw new Error(res.status === 429
                ? res.data.message
                : t("login.failedCredentials"));
        }
        if (res.data.two_factor) {
            // Password is right; the session starts after the second factor.
            twofa = { ...res.data.two_factor, nameomail, wrapKey };
            showTwofa();
            return;
        }
        await finishLogin(res.data.user, wrapKey);
    }
    // ------------------------------------------------------------------ 2FA
    let twofa = null;
    function showTwofa() {
        if (!twofa)
            return;
        busy = false;
        showPanel("twofa");
        const passkey = twofa.methods.includes("passkey") && SeresPasskeys.supported();
        el("twofa-passkey").classList.toggle("modal-hidden", !passkey);
        el("twofa-totp-box").classList.toggle("modal-hidden", !twofa.methods.includes("totp"));
        el("twofa-backup-link").classList.toggle("modal-hidden", !twofa.backup_codes);
        el("twofa-backup-box").classList.add("modal-hidden");
        el("twofa-warning").textContent = "";
        if (twofa.methods.includes("totp"))
            el("twofa-login-code").focus();
    }
    /** Sends the second factor; on success the keys are unlocked and the chats open. */
    async function sendSecondFactor(body) {
        if (!twofa || busy)
            return;
        const current = twofa;
        busy = true;
        const warning = el("twofa-warning");
        warning.textContent = t("login.loggingIn");
        try {
            const res = await postJson("/api/login/2fa", { token: current.token, ...body });
            if (!res.ok) {
                if (res.status === 401) {
                    twofa = null;
                    throw new Error(t("twofa.expired"));
                }
                throw new Error(res.status === 429 ? res.data.message : t("twofa.wrong"));
            }
            await finishLogin(res.data.user, current.wrapKey);
        }
        catch (error) {
            warning.textContent = error instanceof Error ? error.message : t("common.unreachable");
            busy = false;
        }
    }
    async function usePasskey() {
        if (!twofa)
            return;
        const warning = el("twofa-warning");
        try {
            const res = await postJson("/api/login/2fa/options", { token: twofa.token });
            if (!res.ok)
                throw new Error(t("twofa.expired"));
            const credential = await SeresPasskeys.get(res.data.options);
            await sendSecondFactor({ method: "passkey", credential });
        }
        catch (error) {
            warning.textContent = error instanceof DOMException ? t("twofa.passkeyCancelled") : error instanceof Error ? error.message : String(error);
        }
    }
    async function useBackupCode() {
        if (!twofa)
            return;
        const parsed = SeresCrypto.normalizeCode(el("twofa-backup-code").value);
        if (!parsed) {
            el("twofa-warning").textContent = t("recover.invalidCode");
            return;
        }
        const pre = await postJson("/api/recovery/prelogin", { nameomail: twofa.nameomail, slot: parsed.slot });
        if (!pre.ok) {
            el("twofa-warning").textContent = pre.data.message || t("twofa.wrong");
            return;
        }
        const keys = await SeresCrypto.deriveCodeKeys(parsed.code, pre.data.kdf_salt);
        await sendSecondFactor({ method: "backup", slot: parsed.slot, auth_hash: keys.authHash });
    }
    /** Unlocks the private keys after a successful login and opens the chats. */
    async function finishLogin(user, wrapKey, extraParams = {}) {
        let identity;
        try {
            identity = await SeresCrypto.unlockIdentity(user.id, user.enc_private, wrapKey, user.pub_ecdh, user.pub_sign);
        }
        catch {
            await fetch("/api/logout", { method: "POST", credentials: "include" });
            throw new Error(t("login.unlockFailed"));
        }
        await SeresCrypto.clearIdentities();
        await SeresCrypto.saveIdentity(identity);
        const params = new URLSearchParams({ login: "true", ...extraParams });
        const invite = new URLSearchParams(window.location.search).get("invite");
        if (invite)
            params.set("invite", invite);
        window.location.href = "index.html?" + params.toString();
    }
    async function login() {
        if (busy)
            return;
        const nameomail = el("email").value.trim();
        const password = el("password").value;
        if (!nameomail || !password) {
            setWarning(t("login.missingFields"));
            return;
        }
        setBusy(true, t("login.loggingIn"));
        try {
            await loginWith(nameomail, password);
        }
        catch (error) {
            setBusy(false, error instanceof Error ? error.message : t("common.unreachable"));
        }
    }
    async function register() {
        if (busy)
            return;
        const username = el("username").value.trim();
        const email = el("email").value.trim();
        const password = el("password").value;
        if (!/^[A-Za-z0-9_-]{3,20}$/.test(username)) {
            setWarning(t("login.invalidUsername"));
            return;
        }
        if (password.length < 8) {
            setWarning(t("login.passwordTooShort"));
            return;
        }
        setBusy(true, t("login.creating"));
        try {
            const kdfSalt = SeresCrypto.newSalt();
            const iterations = SeresCrypto.DEFAULT_ITERATIONS;
            const { authHash, wrapKey } = await SeresCrypto.deriveAccountKeys(password, kdfSalt, iterations);
            const keys = await SeresCrypto.createKeyBundle(wrapKey);
            // Like Discord: hand out the backup codes right away, shown only this once.
            // They are sent with the registration, which also starts the session, so
            // there is no second key derivation or login request.
            const created = await SeresCrypto.createRecoveryCodes(keys.enc_private, wrapKey).catch(() => null);
            const res = await postJson("/api/register", {
                username,
                email,
                auth_hash: authHash,
                kdf_salt: kdfSalt,
                kdf_iterations: iterations,
                keys,
                recovery_codes: created ? created.stored : null,
            });
            if (!res.ok) {
                setBusy(false, res.data.message || t("login.registerFailed"));
                return;
            }
            setWarning(t("login.created"));
            if (created && res.data.recovery_codes_saved) {
                // Without codes they can still be created later in the settings.
                await new Promise((resolve) => SeresCodes.show(created.codes, username, resolve));
            }
            await finishLogin(res.data.user, wrapKey);
        }
        catch (error) {
            setBusy(false, error instanceof Error ? error.message : t("login.registerFailed"));
        }
    }
    // ------------------------------------------------------ forgot password
    function showPanel(panel) {
        el("twofa-panel").classList.toggle("modal-hidden", panel !== "twofa");
        el("login-panel").classList.toggle("modal-hidden", panel !== "login");
        el("recover-panel").classList.toggle("modal-hidden", panel !== "recover");
        el("reset-panel").classList.toggle("modal-hidden", panel !== "reset");
        el("landr").textContent = t(panel === "twofa" ? "twofa.loginTitle" : panel !== "login" ? "recover.title" : mode === "register" ? "login.registerTitle" : "login.title");
        el("recover-warning").textContent = "";
        if (panel === "recover") {
            const typed = el("email").value.trim();
            if (typed)
                el("recover-name").value = typed;
            el(typed ? "recover-code" : "recover-name").focus();
        }
    }
    /** Asks the server to e-mail a reset link. */
    async function requestResetMail() {
        if (busy)
            return;
        const warning = el("recover-warning");
        const nameomail = el("reset-mail-name").value.trim();
        if (!nameomail) {
            warning.textContent = t("login.missingFields");
            return;
        }
        busy = true;
        el("reset-mail-submit").disabled = true;
        try {
            const res = await postJson("/api/password_reset/request", { nameomail, lang: SeresI18n.getLanguage() });
            warning.textContent = res.ok
                ? t("recover.mailSent")
                : res.status === 503
                    ? t("recover.mailDisabled")
                    : res.data.message || t("common.requestFailed");
        }
        catch {
            warning.textContent = t("common.unreachable");
        }
        finally {
            busy = false;
            el("reset-mail-submit").disabled = false;
        }
    }
    /** The page was opened from the reset e-mail (?reset=TOKEN). */
    async function openResetLink(token) {
        showPanel("reset");
        const res = await postJson("/api/password_reset/check", { token }).catch(() => null);
        if (!res || !res.ok) {
            el("reset-warning").textContent = t(res && res.data.two_factor ? "twofa.resetBlocked" : "reset.invalid");
            el("reset-submit").disabled = true;
            return;
        }
        el("reset-account").textContent = t("reset.account", { name: res.data.display_name, username: res.data.username });
        el("reset-new").focus();
    }
    /** New password and brand-new keys; the old ones can't be recovered without the password. */
    async function confirmReset(token) {
        if (busy)
            return;
        const warning = el("reset-warning");
        const password = el("reset-new").value;
        if (password.length < 8) {
            warning.textContent = t("login.passwordTooShort");
            return;
        }
        if (password !== el("reset-new2").value) {
            warning.textContent = t("recover.mismatch");
            return;
        }
        if (!window.confirm(t("reset.confirm")))
            return;
        busy = true;
        el("reset-submit").disabled = true;
        warning.textContent = t("login.creating");
        try {
            const salt = SeresCrypto.newSalt();
            const iterations = SeresCrypto.DEFAULT_ITERATIONS;
            const { authHash, wrapKey } = await SeresCrypto.deriveAccountKeys(password, salt, iterations);
            const keys = await SeresCrypto.createKeyBundle(wrapKey);
            const res = await postJson("/api/password_reset/confirm", {
                token,
                auth_hash: authHash,
                kdf_salt: salt,
                kdf_iterations: iterations,
                keys,
            });
            if (!res.ok)
                throw new Error(res.status === 404 ? t("reset.invalid") : res.data.message || t("common.requestFailed"));
            const user = res.data.user;
            // The old backup codes belonged to the old keys: hand out new ones right away.
            try {
                const created = await SeresCrypto.createRecoveryCodes(user.enc_private, wrapKey);
                const saved = await postJson("/api/recovery/codes", { old_auth_hash: authHash, codes: created.stored });
                if (saved.ok)
                    await new Promise((resolve) => SeresCodes.show(created.codes, user.username, resolve));
            }
            catch {
                /* codes can still be created later in the settings */
            }
            await finishLogin(user, wrapKey, { recovered: "mail" });
        }
        catch (error) {
            warning.textContent = error instanceof Error ? error.message : t("common.unreachable");
            busy = false;
            el("reset-submit").disabled = false;
        }
    }
    function selectRecoverTab(tab) {
        document.querySelectorAll(".recover-tab").forEach((b) => b.classList.toggle("active", b.dataset.tab === tab));
        document.querySelectorAll(".recover-pane").forEach((p) => p.classList.toggle("modal-hidden", p.dataset.pane !== tab));
        el("recover-warning").textContent = "";
    }
    /**
     * Sets a new password with a backup code. The code unlocks the private keys
     * in the browser, they are encrypted again with the new password, so all
     * chats stay readable.
     */
    async function recoverWithCode() {
        if (busy)
            return;
        const warning = el("recover-warning");
        const nameomail = el("recover-name").value.trim();
        const parsed = SeresCrypto.normalizeCode(el("recover-code").value);
        const password = el("recover-new").value;
        if (!nameomail) {
            warning.textContent = t("login.missingFields");
            return;
        }
        if (!parsed) {
            warning.textContent = t("recover.invalidCode");
            return;
        }
        if (password.length < 8) {
            warning.textContent = t("login.passwordTooShort");
            return;
        }
        if (password !== el("recover-new2").value) {
            warning.textContent = t("recover.mismatch");
            return;
        }
        busy = true;
        el("recover-submit").disabled = true;
        warning.textContent = t("recover.working");
        try {
            const pre = await postJson("/api/recovery/prelogin", { nameomail, slot: parsed.slot });
            if (!pre.ok)
                throw new Error(pre.data.message || t("recover.failed"));
            const codeKeys = await SeresCrypto.deriveCodeKeys(parsed.code, pre.data.kdf_salt);
            const check = { nameomail, slot: parsed.slot, auth_hash: codeKeys.authHash };
            const unlocked = await postJson("/api/recovery/unlock", check);
            if (!unlocked.ok)
                throw new Error(unlocked.status === 429 ? unlocked.data.message : t("recover.failed"));
            const salt = SeresCrypto.newSalt();
            const iterations = SeresCrypto.DEFAULT_ITERATIONS;
            const newKeys = await SeresCrypto.deriveAccountKeys(password, salt, iterations);
            let encPrivate;
            try {
                encPrivate = await SeresCrypto.rewrapPrivateKeys(unlocked.data.enc_private, codeKeys.wrapKey, newKeys.wrapKey);
            }
            catch {
                throw new Error(t("recover.failed"));
            }
            const reset = await postJson("/api/recovery/reset", {
                ...check,
                new_auth_hash: newKeys.authHash,
                kdf_salt: salt,
                kdf_iterations: iterations,
                enc_private: encPrivate,
            });
            if (!reset.ok)
                throw new Error(reset.status === 429 ? reset.data.message : t("recover.failed"));
            await finishLogin(reset.data.user, newKeys.wrapKey, { recovered: "code" });
        }
        catch (error) {
            warning.textContent = error instanceof Error ? error.message : t("common.unreachable");
            busy = false;
            el("recover-submit").disabled = false;
        }
    }
    function showMode(next) {
        mode = next;
        const isRegister = next === "register";
        const loginButton = el("login");
        const mainButton = el("register_redirect");
        el("landr").textContent = t(isRegister ? "login.registerTitle" : "login.title");
        el("username").style.display = isRegister ? "block" : "none";
        el("tos-container").style.display = isRegister ? "flex" : "none";
        loginButton.style.display = isRegister ? "none" : "block";
        el("forgot-link").style.display = isRegister ? "none" : "block";
        mainButton.className = isRegister ? "action-button" : "";
        mainButton.disabled = isRegister && !el("tos-checkbox").checked;
        el("email").placeholder = t(isRegister ? "login.email" : "login.usernameOrEmail");
        el("password").placeholder = t(isRegister ? "login.passwordNew" : "login.password");
        const switchLink = el("ahaa");
        switchLink.textContent = "";
        if (isRegister) {
            const link = document.createElement("a");
            link.textContent = t("login.haveAccount");
            link.href = "#";
            link.addEventListener("click", (event) => {
                event.preventDefault();
                showMode("login");
            });
            switchLink.appendChild(link);
        }
        setWarning("");
    }
    function applyLoginTheme() {
        const isBright = SeresI18n.getPreference("theme") === "bright";
        document.body.classList.toggle("bright-body", isBright);
        document.querySelector(".login")?.classList.toggle("bright-login", isBright);
        document.querySelector(".landr")?.classList.toggle("bright-landr", isBright);
        document.querySelector(".login-f")?.classList.toggle("bright-login-f", isBright);
        document.querySelector("#ahaa")?.classList.toggle("bright-ahaa", isBright);
        document
            .querySelector(".tos-container")
            ?.classList.toggle("bright-tos-container", isBright);
    }
    function toggleLoginTheme() {
        const newTheme = SeresI18n.getPreference("theme") === "bright" ? "dark" : "bright";
        SeresI18n.setPreference("theme", newTheme);
        applyLoginTheme();
    }
    document.addEventListener("DOMContentLoaded", () => {
        SeresI18n.apply();
        showMode("login");
        el("login").addEventListener("click", login);
        el("register_redirect").addEventListener("click", () => {
            if (mode === "register")
                register();
            else
                showMode("register");
        });
        el("tos-checkbox").addEventListener("change", () => {
            el("register_redirect").disabled =
                busy || !el("tos-checkbox").checked;
        });
        el("tos-link").addEventListener("click", (event) => {
            event.preventDefault();
            el("tos-modal").style.display = "flex";
        });
        el("tos-close").addEventListener("click", () => {
            el("tos-modal").style.display = "none";
        });
        el("tos-modal").addEventListener("click", (event) => {
            if (event.target === el("tos-modal"))
                el("tos-modal").style.display = "none";
        });
        el("forgot-link").addEventListener("click", (event) => {
            event.preventDefault();
            showPanel("recover");
        });
        el("recover-back").addEventListener("click", (event) => {
            event.preventDefault();
            showPanel("login");
        });
        document.querySelectorAll(".recover-tab").forEach((tab) => {
            tab.addEventListener("click", () => selectRecoverTab(tab.dataset.tab));
        });
        el("recover-submit").addEventListener("click", recoverWithCode);
        el("twofa-passkey").addEventListener("click", usePasskey);
        el("twofa-totp-submit").addEventListener("click", () => sendSecondFactor({ method: "totp", code: el("twofa-login-code").value.replace(/\s/g, "") }));
        el("twofa-login-code").addEventListener("keydown", (event) => {
            if (event.key === "Enter")
                el("twofa-totp-submit").click();
        });
        el("twofa-backup-link").addEventListener("click", (event) => {
            event.preventDefault();
            el("twofa-backup-box").classList.remove("modal-hidden");
            el("twofa-backup-code").focus();
        });
        el("twofa-backup-submit").addEventListener("click", useBackupCode);
        el("reset-mail-submit").addEventListener("click", requestResetMail);
        el("recover-new2").addEventListener("keydown", (event) => {
            if (event.key === "Enter")
                recoverWithCode();
        });
        el("password").addEventListener("keydown", (event) => {
            if (event.key === "Enter") {
                if (mode === "register")
                    register();
                else
                    login();
            }
        });
        const params = new URLSearchParams(window.location.search);
        const reason = params.get("reason");
        const resetToken = params.get("reset");
        if (resetToken) {
            // Keep the token out of the address bar (and browser history) from now on.
            window.history.replaceState({}, document.title, window.location.pathname);
            el("reset-submit").addEventListener("click", () => confirmReset(resetToken));
            openResetLink(resetToken);
        }
        if (params.get("invite"))
            setWarning(t("invite.loginHint"));
        if (reason === "keys") {
            setWarning(t("login.reloginKeys"));
        }
        const toggleBtn = document.createElement("button");
        toggleBtn.className = "theme-toggle-floating";
        toggleBtn.type = "button";
        toggleBtn.dataset.i18n = "common.themeToggle";
        toggleBtn.textContent = t("common.themeToggle");
        toggleBtn.addEventListener("click", toggleLoginTheme);
        // Switching the language re-renders the texts that depend on the mode.
        const languageSelect = SeresI18n.languageSelect(() => showMode(mode));
        const controls = document.createElement("div");
        controls.className = "floating-controls";
        controls.append(languageSelect, toggleBtn);
        document.body.appendChild(controls);
        applyLoginTheme();
    });
})();
