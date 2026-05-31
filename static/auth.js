// auth.js — all auth functions in one place

async function signup() {
  const username  = document.getElementById("username").value.trim();
  const password  = document.getElementById("password").value;
  const full_name = document.getElementById("full_name").value.trim();
  const mobile    = document.getElementById("mobile").value.trim();
  const dob       = document.getElementById("dob").value;
  const msgEl     = document.getElementById("msg");

  if (!full_name || !username || !mobile || !dob || !password) {
    msgEl.innerText = "Please fill in all fields";
    msgEl.style.color = "#e74c3c"; return;
  }
  if (password.length < 8) {
    msgEl.innerText = "Password must be at least 8 characters";
    msgEl.style.color = "#e74c3c"; return;
  }
  if (!/^\d{10}$/.test(mobile)) {
    msgEl.innerText = "Enter a valid 10-digit mobile number";
    msgEl.style.color = "#e74c3c"; return;
  }

  try {
    const res  = await fetch("/signup", {
      method: "POST", headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ username, password, full_name, mobile, dob })
    });
    const data = await res.json();
    msgEl.style.color = data.success ? "#27ae60" : "#e74c3c";
    msgEl.innerText   = data.message;
    if (data.success) setTimeout(() => window.location.href = "/signin", 1200);
  } catch (err) {
    msgEl.style.color = "#e74c3c";
    msgEl.innerText   = "Cannot reach server — is Flask running?";
  }
}


async function signin() {
  const username = document.getElementById("username").value.trim();
  const password = document.getElementById("password").value;
  const msgEl    = document.getElementById("msg");

  if (!username || !password) {
    msgEl.innerText = "Please fill in both fields";
    msgEl.style.color = "#e74c3c"; return;
  }

  try {
    const res  = await fetch("/signin", {
      method: "POST", headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ username, password })
    });
    const data = await res.json();
    msgEl.style.color = data.success ? "#27ae60" : "#e74c3c";
    msgEl.innerText   = data.message;
    if (data.success) setTimeout(() => window.location.href = "/dashboard", 1000);
  } catch (err) {
    msgEl.style.color = "#e74c3c";
    msgEl.innerText   = "Cannot reach server — is Flask running?";
  }
}


async function signinWithPasskey() {
  const username = document.getElementById("username").value.trim();
  const msgEl    = document.getElementById("msg");

  if (!username) {
    msgEl.innerText = "Enter your username first";
    msgEl.style.color = "#e74c3c"; return;
  }

  msgEl.style.color = "#00e5a0";
  msgEl.innerText   = "Starting passkey login...";

  try {
    const beginRes = await fetch("/fido2/auth/begin", {
      method: "POST", headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ username })
    });
    const options = await beginRes.json();

    if (!beginRes.ok) {
      msgEl.style.color = "#e74c3c";
      msgEl.innerText   = options.message || "Could not start passkey login";
      return;
    }

    options.challenge = _b64ToBuffer(options.challenge);
    if (options.allowCredentials) {
      options.allowCredentials = options.allowCredentials.map(c => ({
        ...c, id: _b64ToBuffer(c.id)
      }));
    }

    msgEl.innerText = "Waiting for Windows Hello...";
    const assertion = await navigator.credentials.get({ publicKey: options });

      const payload = {
      username,
      id:    assertion.id,
      rawId: assertion.id,          // ← same as id, already base64url
      type:  assertion.type,
      response: {
      authenticatorData: _bufferToB64(assertion.response.authenticatorData),
      clientDataJSON:    _bufferToB64(assertion.response.clientDataJSON),
      signature:         _bufferToB64(assertion.response.signature),
      userHandle: assertion.response.userHandle
        ? _bufferToB64(assertion.response.userHandle) : null,
    }
    };

    const completeRes = await fetch("/fido2/auth/complete", {
      method: "POST", headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify(payload)
    });
    const result = await completeRes.json();

    msgEl.style.color = result.success ? "#27ae60" : "#e74c3c";
    msgEl.innerText   = result.message;
    if (result.success) setTimeout(() => window.location.href = "/dashboard", 1000);

  } catch (err) {
    msgEl.style.color = "#e74c3c";
    msgEl.innerText   = err.name === "NotAllowedError"
      ? "Passkey cancelled or timed out"
      : "Passkey error — " + err.message;
    console.error(err);
  }
}


async function signout() {
  await fetch("/logout", {
    method: "POST",
    credentials: "include"
  });
  window.location.href = "/signin";
}


function _b64ToBuffer(b64) {
  const bin = atob(b64.replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(bin, c => c.charCodeAt(0)).buffer;
}
function _bufferToB64(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}