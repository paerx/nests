(() => {
  const apiBase = document.body.dataset.apiBase || "";
  const state = {
    globalKey: "",
    envKey: null,
    current: null,
    decrypted: [],
  };

  const elements = {
    envList: document.querySelector("[data-env-list]"),
    detailTitle: document.querySelector("[data-detail-title]"),
    detailSub: document.querySelector("[data-detail-sub]"),
    detailTable: document.querySelector("[data-detail-table]"),
    searchInput: document.querySelector("[data-search]"),
    gkIndicator: document.querySelector("[data-gk-indicator]"),
    gkEdit: document.querySelector("[data-gk-edit]"),
    modalGK: document.querySelector("[data-modal-gk]"),
    gkInput: document.querySelector("[data-gk-input]"),
    gkSubmit: document.querySelector("[data-gk-submit]"),
    modalCreate: document.querySelector("[data-modal-create]"),
    createName: document.querySelector("[data-create-name]"),
    createKey: document.querySelector("[data-create-key]"),
    createValue: document.querySelector("[data-create-value]"),
    createSubmit: document.querySelector("[data-create-submit]"),
    createCancel: document.querySelector("[data-create-cancel]"),
    modalEntry: document.querySelector("[data-modal-entry]"),
    entryKey: document.querySelector("[data-entry-key]"),
    entryValue: document.querySelector("[data-entry-value]"),
    entrySubmit: document.querySelector("[data-entry-submit]"),
    entryCancel: document.querySelector("[data-entry-cancel]"),
    toast: document.querySelector("[data-toast]"),
  };

  let idleTimer = null;

  function showToast(message) {
    elements.toast.textContent = message;
    elements.toast.classList.add("show");
    setTimeout(() => elements.toast.classList.remove("show"), 2400);
  }

  function requireGlobalKey() {
    if (state.globalKey) {
      return Promise.resolve(true);
    }
    elements.modalGK.classList.add("active");
    elements.gkInput.focus();
    return Promise.resolve(false);
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

  function resetIdleTimer() {
    if (idleTimer) {
      clearTimeout(idleTimer);
    }
    idleTimer = setTimeout(() => {
      state.globalKey = "";
      state.envKey = null;
      elements.gkIndicator.classList.remove("active");
      showToast("GlobalKey cleared (idle)");
    }, 5 * 60 * 1000);
  }

  function setGlobalKey(value) {
    state.globalKey = value;
    elements.gkIndicator.classList.add("active");
    resetIdleTimer();
    NestsCrypto.sha256Hex(value).then((hash) => {
      localStorage.setItem("gk_hash", hash);
    });
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

  function renderList(items) {
    elements.envList.innerHTML = "";
    if (!items.length) {
      const empty = document.createElement("div");
      empty.className = "empty";
      empty.textContent = "No environments yet.";
      elements.envList.appendChild(empty);
      return;
    }

    items.forEach((item) => {
      const row = document.createElement("div");
      row.className = "table-row";
      row.innerHTML = `
        <div class="col name">${item.name}</div>
        <div class="col version">v${item.version}</div>
        <div class="col updated">${formatTime(item.updated_at)}</div>
        <div class="col action"><button class="btn ghost" data-open>Open</button></div>
      `;
      row.querySelector("[data-open]").addEventListener("click", () => loadConfig(item.name));
      elements.envList.appendChild(row);
    });
  }

  function formatTime(ts) {
    if (!ts) return "--";
    const d = new Date(ts * 1000);
    return d.toLocaleString();
  }

  function loadList() {
    apiGet("/api/nests/config/list").then((res) => {
      if (res.code !== 0) {
        showToast(res.msg || "Load failed");
        return;
      }
      const search = elements.searchInput.value.trim().toLowerCase();
      const filtered = res.data.filter((item) => item.name.toLowerCase().includes(search));
      renderList(filtered);
    });
  }

  function renderDetail() {
    elements.detailTable.innerHTML = "";
    if (!state.decrypted.length) {
      const empty = document.createElement("div");
      empty.className = "detail-empty";
      empty.textContent = "No data loaded.";
      elements.detailTable.appendChild(empty);
      return;
    }

    state.decrypted.forEach((entry, idx) => {
      const row = document.createElement("div");
      row.className = "detail-row";
      row.innerHTML = `
        <input data-key value="${entry.key}" />
        <input data-value class="value-mask" type="password" value="${entry.value}" />
        <button class="btn ghost" data-toggle>Show</button>
        <button class="btn ghost" data-copy>Copy</button>
      `;
      row.querySelector("[data-toggle]").addEventListener("click", (e) => {
        const input = row.querySelector("[data-value]");
        input.type = input.type === "password" ? "text" : "password";
        e.target.textContent = input.type === "password" ? "Show" : "Hide";
      });
      row.querySelector("[data-copy]").addEventListener("click", async () => {
        const val = row.querySelector("[data-value]").value;
        await navigator.clipboard.writeText(val);
        row.querySelector("[data-value]").type = "password";
        showToast("Copied");
      });
      row.querySelector("[data-key]").addEventListener("input", (e) => {
        state.decrypted[idx].key = e.target.value;
      });
      row.querySelector("[data-value]").addEventListener("input", (e) => {
        state.decrypted[idx].value = e.target.value;
      });
      elements.detailTable.appendChild(row);
    });
  }

  function decryptConfig(cfg) {
    if (!state.globalKey) {
      return;
    }
    const envKey = NestsCrypto.deriveEnvKey(state.globalKey, cfg.kdf_salt, cfg.name);
    const eDatas = cfg.e_datas || [];
    const sign = NestsCrypto.signEDatas(eDatas, envKey);
    if (sign !== cfg.sign) {
      showToast("Signature mismatch");
      return;
    }
    const decrypted = eDatas.map((e) => ({
      id: e.id,
      key: NestsCrypto.decryptValue(e.e_key, envKey),
      value: NestsCrypto.decryptValue(e.e_value, envKey),
    }));
    state.envKey = envKey;
    state.decrypted = decrypted;
    renderDetail();
  }

  function loadConfig(name) {
    requireGlobalKey().then((ready) => {
      if (!ready) return;
      apiGet(`/api/nests/config/get?name=${encodeURIComponent(name)}`).then((res) => {
        if (res.code !== 0) {
          showToast(res.msg || "Load failed");
          return;
        }
        state.current = res.data;
        elements.detailTitle.textContent = res.data.name;
        elements.detailSub.textContent = `version ${res.data.version}`;
        decryptConfig(res.data);
      });
    });
  }

  function collectEncrypted() {
    const envKey = state.envKey;
    const eDatas = state.decrypted.map((entry) => {
      return {
        id: entry.id || "",
        e_key: NestsCrypto.encryptValue(entry.key, envKey),
        e_value: NestsCrypto.encryptValue(entry.value, envKey),
      };
    });
    const sign = NestsCrypto.signEDatas(eDatas, envKey);
    return { eDatas, sign };
  }

  function saveCurrent() {
    if (!state.current) {
      showToast("Select environment first");
      return;
    }
    if (!state.envKey) {
      showToast("Unlock GlobalKey first");
      return;
    }
    const { eDatas, sign } = collectEncrypted();
    apiPost("/api/nests/config/update", {
      name: state.current.name,
      kdf_salt: state.current.kdf_salt,
      sign,
      e_datas: eDatas,
    }).then((res) => {
      if (res.code !== 0) {
        showToast(res.msg || "Save failed");
        return;
      }
      showToast("Saved");
      state.current = res.data;
      elements.detailSub.textContent = `version ${res.data.version}`;
      loadList();
    });
  }

  function createEnv() {
    requireGlobalKey().then((ready) => {
      if (!ready) return;
      const name = elements.createName.value.trim();
      const key = elements.createKey.value.trim();
      const value = elements.createValue.value.trim();
      if (!name || !key || !value) {
        showToast("name/key/value required");
        return;
      }
      const kdfSalt = NestsCrypto.base64Encode(NestsCrypto.randomBytes(16));
      const envKey = NestsCrypto.deriveEnvKey(state.globalKey, kdfSalt, name);
      const eDatas = [
        {
          e_key: NestsCrypto.encryptValue(key, envKey),
          e_value: NestsCrypto.encryptValue(value, envKey),
        },
      ];
      const sign = NestsCrypto.signEDatas(eDatas, envKey);
      apiPost("/api/nests/config/add", {
        name,
        "e-key": eDatas[0].e_key,
        "e-value": eDatas[0].e_value,
        sign,
        kdf_salt: kdfSalt,
      }).then((res) => {
        if (res.code !== 0) {
          showToast(res.msg || "Create failed");
          return;
        }
        elements.modalCreate.classList.remove("active");
        elements.createName.value = "";
        elements.createKey.value = "";
        elements.createValue.value = "";
        showToast("Created");
        loadList();
      });
    });
  }

  function addEntryToState() {
    const key = elements.entryKey.value.trim();
    const value = elements.entryValue.value.trim();
    if (!key || !value) {
      showToast("key/value required");
      return;
    }
    state.decrypted.push({ key, value });
    elements.entryKey.value = "";
    elements.entryValue.value = "";
    elements.modalEntry.classList.remove("active");
    renderDetail();
  }

  elements.gkSubmit.addEventListener("click", () => {
    const val = elements.gkInput.value.trim();
    if (!isValidGlobalKey(val)) {
      showToast("GlobalKey format invalid");
      return;
    }
    setGlobalKey(val);
    elements.gkInput.value = "";
    elements.modalGK.classList.remove("active");
    if (state.current) {
      decryptConfig(state.current);
    }
  });

  elements.gkEdit.addEventListener("click", () => {
    elements.modalGK.classList.add("active");
    elements.gkInput.focus();
  });

  document.querySelector("[data-open-create]").addEventListener("click", () => {
    elements.modalCreate.classList.add("active");
  });

  elements.createCancel.addEventListener("click", () => {
    elements.modalCreate.classList.remove("active");
  });

  elements.createSubmit.addEventListener("click", createEnv);

  document.querySelector("[data-add-entry]").addEventListener("click", () => {
    if (!state.current) {
      showToast("Select environment first");
      return;
    }
    elements.modalEntry.classList.add("active");
  });

  elements.entryCancel.addEventListener("click", () => {
    elements.modalEntry.classList.remove("active");
  });

  elements.entrySubmit.addEventListener("click", addEntryToState);

  document.querySelector("[data-save]").addEventListener("click", saveCurrent);
  document.querySelector("[data-refresh]").addEventListener("click", loadList);

  elements.searchInput.addEventListener("input", loadList);

  document.addEventListener("mousemove", resetIdleTimer);
  document.addEventListener("keydown", resetIdleTimer);

  loadList();
})();
