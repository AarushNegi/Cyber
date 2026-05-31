// auth.js — all auth functions in one place
// Uses RELATIVE URLs (/signup, /signin etc.) so this works
// identically on localhost AND on your live hosted domain.
// DO NOT define these functions again in any HTML file.

async function signup() {
  const username  = document.getElementById("username").value.trim();
  const password  = document.getElementById("password").value;
  const full_name = document.getElementById("full_name").value.trim();
  const mobile    = document.getElementById("mobile").value.trim();
  const dob       = document.getElementById("dob").value;
  const msgEl     = document.getElementById("msg");

  // Client-side validation
  if (!full_name || !username || !mobile || !dob || !password) {
    msgEl.innerText   = "Please fill in all fields";
    msgEl.style.color = "#e74c3c";
    return;
  }
  if (password.length < 8) {
    msgEl.innerText   = "Password must be at least 8 characters";
    msgEl.style.color = "#e74c3c";
    return;
  }
  if (!/^\d{10}$/.test(mobile)) {
    msgEl.innerText   = "Enter a valid 10-digit mobile number";
    msgEl.style.color = "#e74c3c";
    return;
  }

  try {
    const res  = await fetch("/signup", {          // ← relative URL
      method:      "POST",
      headers:     { "Content-Type": "application/json" },
      credentials: "include",
      body:        JSON.stringify({ username, password, full_name, mobile, dob })
    });
    const data = await res.json();
    msgEl.style.color = data.success ? "#27ae60" : "#e74c3c";
    msgEl.innerText   = data.message;
    if (data.success) {
      setTimeout(() => window.location.href = "/signin", 1200);
    }
  } catch (err) {
    msgEl.style.color = "#e74c3c";
    msgEl.innerText   = "Cannot reach server — is Flask running?";
    console.error(err);
  }
}


async function signin() {
  const username = document.getElementById("username").value.trim();
  const password = document.getElementById("password").value;
  const msgEl    = document.getElementById("msg");

  if (!username || !password) {
    msgEl.innerText   = "Please fill in both fields";
    msgEl.style.color = "#e74c3c";
    return;
  }

  try {
    const res  = await fetch("/signin", {          // ← relative URL
      method:      "POST",
      headers:     { "Content-Type": "application/json" },
      credentials: "include",
      body:        JSON.stringify({ username, password })
    });
    const data = await res.json();
    msgEl.style.color = data.success ? "#27ae60" : "#e74c3c";
    msgEl.innerText   = data.message;
    if (data.success) {
      setTimeout(() => window.location.href = "/dashboard", 1000);
    }
  } catch (err) {
    msgEl.style.color = "#e74c3c";
    msgEl.innerText   = "Cannot reach server — is Flask running?";
    console.error(err);
  }
}


async function signout() {
  await fetch("/signout", {                         // ← relative URL
    method:      "POST",
    credentials: "include"
  });
  window.location.href = "/signin";
}