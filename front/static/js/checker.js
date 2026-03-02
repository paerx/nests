(() => {
  const apiBase = document.body.dataset.apiBase || "";
  const params = new URLSearchParams(window.location.search);
  const wid = params.get("wid");
  const name = params.get("name");
  const elements = {
    wid: document.querySelector("[data-wid]"),
    name: document.querySelector("[data-name]"),
    statusMini: document.querySelector("[data-status-mini]"),
    status: document.querySelector("[data-status]"),
    timer: document.querySelector("[data-timer]"),
    gkInput: document.querySelector("[data-gk-input]"),
    confirm: document.querySelector("[data-confirm]"),
    otpInput: document.querySelector("[data-otp-input]"),
    otpVerify: document.querySelector("[data-otp-verify]"),
    toast: document.querySelector("[data-toast]"),
  };

  let expireAt = null;
  let poller = null;
  let otpVerified = false;

  const GK_LOCK_KEY = "gk_lock_until";
  const GK_FAIL_KEY = "gk_fail_count";
  const GK_FAIL_TS = "gk_fail_ts";

  function isLocked() {
    const until = Number(localStorage.getItem(GK_LOCK_KEY) || 0);
    return Date.now() < until;
  }

  function recordFailure() {
    const now = Date.now();
    const last = Number(localStorage.getItem(GK_FAIL_TS) || 0);
    let count = Number(localStorage.getItem(GK_FAIL_KEY) || 0);
    if (now - last > 10 * 60 * 1000) {
      count = 0;
    }
    count += 1;
    localStorage.setItem(GK_FAIL_KEY, String(count));
    localStorage.setItem(GK_FAIL_TS, String(now));
    if (count >= 5) {
      const lockUntil = now + 10 * 60 * 1000;
      localStorage.setItem(GK_LOCK_KEY, String(lockUntil));
    }
  }

  function showToast(message) {
    elements.toast.textContent = message;
    elements.toast.classList.add("show");
    setTimeout(() => elements.toast.classList.remove("show"), 2400);
  }

  function isValidGlobalKey(val) {
    return (
      val.length >= 16 &&
      /[A-Z]/.test(val) &&
      /[a-z]/.test(val) &&
      /[0-9]/.test(val) &&
      /[^A-Za-z0-9]/.test(val)
    );
  }

  function apiGet(path) {
    return fetch(apiBase + path).then((res) => res.json());
  }

  function apiPost(path, body) {
    return fetch(apiBase + path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }).then((res) => res.json());
  }

  function updateTimer() {
    if (!expireAt) {
      elements.timer.textContent = "--:--";
      return;
    }
    const diff = expireAt * 1000 - Date.now();
    if (diff <= 0) {
      elements.timer.textContent = "00:00";
      return;
    }
    const mins = Math.floor(diff / 60000);
    const secs = Math.floor((diff % 60000) / 1000);
    elements.timer.textContent = `${String(mins).padStart(2, "0")}:${String(secs).padStart(2, "0")}`;
  }

  function pollStatus() {
    if (!wid) return;
    apiGet(`/api/nests/server/windows/check?wid=${encodeURIComponent(wid)}`).then((res) => {
      if (res.code !== 0) {
        elements.status.textContent = res.msg || "error";
        return;
      }
      const status = res.data.status;
      elements.status.textContent = `Status: ${status}`;
      if (elements.statusMini) {
        elements.statusMini.textContent = status.toUpperCase();
      }
      if (status === "expired") {
        clearInterval(poller);
      }
    });
  }

  function submitConfirm() {
    if (!wid) {
      showToast("Missing wid");
      return;
    }
    if (!otpVerified) {
      showToast("Verify Google Auth first");
      return;
    }
    const gk = elements.gkInput.value.trim();
    if (isLocked()) {
      showToast("GlobalKey locked. Try later.");
      return;
    }
    if (!isValidGlobalKey(gk)) {
      showToast("GlobalKey format invalid");
      recordFailure();
      return;
    }
    if (!name) {
      showToast("Missing name");
      return;
    }

    apiGet(`/api/nests/config/get?name=${encodeURIComponent(name)}`).then((cfgRes) => {
      if (cfgRes.code !== 0) {
        showToast(cfgRes.msg || "Load config failed");
        return;
      }
      const kdfSalt = cfgRes.data.kdf_salt || "";
      const envKey = NestsCrypto.deriveEnvKey(gk, kdfSalt, name);
      const envKeyB64 = NestsCrypto.base64Encode(envKey);

      apiPost("/api/nests/server/windows", {
        wid,
        encrypted_temp_key: "ok",
        env_key: envKeyB64,
      }).then((res) => {
      if (res.code !== 0) {
        showToast(res.msg || "Failed");
        return;
      }
      showToast("Confirmed");
      elements.gkInput.value = "";
      pollStatus();
    });
    });
  }

  elements.wid.textContent = wid || "-";
  if (elements.name) {
    elements.name.textContent = name || "-";
  }
  elements.confirm.addEventListener("click", submitConfirm);
  elements.otpVerify.addEventListener("click", () => {
    if (!name) {
      showToast("Missing name");
      return;
    }
    const code = elements.otpInput.value.trim();
    if (!code) {
      showToast("Enter Google Auth code");
      return;
    }
    apiPost("/api/nests/config/otp/verify", { name, code }).then((res) => {
      if (res.code !== 0) {
        showToast(res.msg || "OTP invalid");
        return;
      }
      otpVerified = true;
      elements.gkInput.disabled = false;
      elements.confirm.disabled = false;
      showToast("OTP verified");
    });
  });

  if (!wid) {
    showToast("Missing wid in URL");
    elements.status.textContent = "Invalid wid";
    return;
  }

  if (!expireAt) {
    expireAt = Math.floor(Date.now() / 1000) + 300;
  }
  pollStatus();
  poller = setInterval(pollStatus, 5000);
  setInterval(updateTimer, 1000);
})();
