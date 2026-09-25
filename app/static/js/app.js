/**
 * SessionGuard Dummy App client logic.
 * Implements pure frontend JavaScript authentication, storage management,
 * mode switching, and client-side hijacking simulations.
 */

// Restore saved credentials if previously remembered
document.addEventListener("DOMContentLoaded", () => {
    const savedUser = localStorage.getItem("sg_saved_username");
    const savedPass = localStorage.getItem("sg_saved_password");
    const userInput = document.getElementById("login-username");
    const passInput = document.getElementById("login-password");
    const rememberBox = document.getElementById("remember-me");

    if (savedUser && userInput) {
        userInput.value = savedUser;
        if (savedPass && passInput) passInput.value = savedPass;
        if (rememberBox) rememberBox.checked = true;
    }
});

// Tab Switching
function switchAuthTab(tab) {
    const loginSection = document.getElementById("login-section");
    const regSection = document.getElementById("register-section");
    const forgotSection = document.getElementById("forgot-section");
    const tabLogin = document.getElementById("tab-login");
    const tabReg = document.getElementById("tab-register");
    const alertBox = document.getElementById("auth-alert");

    if (alertBox) alertBox.style.display = "none";

    if (loginSection) loginSection.style.display = tab === "login" ? "block" : "none";
    if (regSection) regSection.style.display = tab === "register" ? "block" : "none";
    if (forgotSection) forgotSection.style.display = tab === "forgot" ? "block" : "none";

    if (tabLogin) tabLogin.classList.toggle("active", tab === "login");
    if (tabReg) tabReg.classList.toggle("active", tab === "register");
}

async function handleForgotPasswordSubmit(event) {
    event.preventDefault();

    const username = document.getElementById("forgot-username").value.trim();
    const newPassword = document.getElementById("forgot-new-password").value.trim();
    const btn = document.getElementById("forgot-btn");
    const alertBox = document.getElementById("auth-alert");

    if (!username || !newPassword) return;

    btn.disabled = true;
    btn.textContent = "Updating Password...";
    if (alertBox) alertBox.style.display = "none";

    try {
        const response = await fetch("/forgot-password", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            body: JSON.stringify({ username, new_password: newPassword })
        });

        const data = await response.json();

        btn.disabled = false;
        btn.textContent = "Update & Reset Password";

        if (response.ok && data.success) {
            switchAuthTab("login");
            const userField = document.getElementById("login-username");
            const passField = document.getElementById("login-password");
            if (userField) userField.value = username;
            if (passField) passField.value = "";

            // Clear any previously saved password for this user
            if (localStorage.getItem("sg_saved_username") === username) {
                localStorage.removeItem("sg_saved_password");
                const remBox = document.getElementById("remember-me");
                if (remBox) remBox.checked = false;
            }

            if (alertBox) {
                alertBox.className = "alert alert-success";
                alertBox.style.display = "block";
                alertBox.innerHTML = `<strong>Success:</strong> Password updated successfully. Please sign in with your new password.`;
            }
        } else {
            if (alertBox) {
                alertBox.className = "alert alert-danger";
                alertBox.style.display = "block";
                alertBox.innerHTML = `<strong>Reset Failed:</strong> ${data.error}`;
            }
        }
    } catch (err) {
        btn.disabled = false;
        btn.textContent = "Update & Reset Password";
        if (alertBox) {
            alertBox.className = "alert alert-danger";
            alertBox.style.display = "block";
            alertBox.innerHTML = `<strong>Network Error:</strong> ${err.message}`;
        }
    }
}

function togglePasswordVisibility(fieldId, btnId) {
    const field = document.getElementById(fieldId);
    const btn = document.getElementById(btnId);
    if (!field) return;

    if (field.type === "password") {
        field.type = "text";
        if (btn) {
            btn.innerHTML = `
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M9.88 9.88a3 3 0 1 0 4.24 4.24"/>
                    <path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68"/>
                    <path d="M6.61 6.61A13.526 13.526 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61"/>
                    <line x1="2" x2="22" y1="2" y2="22"/>
                </svg>`;
            btn.title = "Hide password";
        }
    } else {
        field.type = "password";
        if (btn) {
            btn.innerHTML = `
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/>
                    <circle cx="12" cy="12" r="3"/>
                </svg>`;
            btn.title = "Show password";
        }
    }
}

function fillCredentials(username, password) {
    const userField = document.getElementById("login-username");
    const passField = document.getElementById("login-password");
    if (userField && passField) {
        userField.value = username;
        passField.value = password;
    }
}

// 1. JavaScript Login Workflow (Matches User Diagram)
// User fills form -> JS sends JSON to Flask -> Flask creates JWT -> JS receives & stores -> Navigates to dashboard
async function handleLoginSubmit(event) {
    event.preventDefault();

    const username = document.getElementById("login-username").value.trim();
    const password = document.getElementById("login-password").value.trim();
    const btn = document.getElementById("login-btn");
    const alertBox = document.getElementById("auth-alert");
    const transitCard = document.getElementById("token-transit-card");
    const transitSteps = document.getElementById("transit-steps");

    if (!username || !password) return;

    btn.disabled = true;
    btn.textContent = "Signing In...";
    alertBox.style.display = "none";

    try {
        const response = await fetch("/login", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (response.ok && data.success) {
            // Check remember me setting
            const rememberCheckbox = document.getElementById("remember-me");
            if (rememberCheckbox && rememberCheckbox.checked) {
                localStorage.setItem("sg_saved_username", username);
                localStorage.setItem("sg_saved_password", password);
            } else {
                localStorage.removeItem("sg_saved_username");
                localStorage.removeItem("sg_saved_password");
            }

            if (data.storage === "localStorage") {
                localStorage.setItem("session_token", data.token);
            } else {
                localStorage.removeItem("session_token");
            }

            window.location.href = data.redirect_url || "/dashboard";
        } else {
            btn.disabled = false;
            btn.textContent = "Sign In";
            alertBox.className = "alert alert-danger";
            alertBox.style.display = "block";
            alertBox.innerHTML = `<strong>Login Failed:</strong> ${data.error || "Invalid username or password"}`;
        }
    } catch (err) {
        btn.disabled = false;
        btn.textContent = "Sign In";
        alertBox.className = "alert alert-danger";
        alertBox.style.display = "block";
        alertBox.innerHTML = `<strong>Network Error:</strong> ${err.message}`;
    }
}

// 2. JavaScript Registration Workflow
async function handleRegisterSubmit(event) {
    event.preventDefault();

    const username = document.getElementById("reg-username").value.trim();
    const password = document.getElementById("reg-password").value.trim();
    const btn = document.getElementById("reg-btn");
    const alertBox = document.getElementById("auth-alert");

    if (!username || !password) return;

    btn.disabled = true;
    btn.textContent = "Creating Account...";
    alertBox.style.display = "none";

    try {
        const response = await fetch("/register", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            body: JSON.stringify({ username, password, role: "user" })
        });

        const data = await response.json();

        if (response.ok && data.success) {
            btn.disabled = false;
            btn.textContent = "Create Account";
            
            // Switch to Login tab, only fill username, keep password empty
            switchAuthTab("login");
            const userField = document.getElementById("login-username");
            const passField = document.getElementById("login-password");
            if (userField) userField.value = username;
            if (passField) passField.value = "";
            
            alertBox.className = "alert alert-success";
            alertBox.style.display = "block";
            alertBox.innerHTML = `<strong>Success!</strong> Account created successfully. Please enter your password to sign in.`;
        } else {
            btn.disabled = false;
            btn.textContent = "Create Account";
            alertBox.className = "alert alert-danger";
            alertBox.style.display = "block";
            alertBox.innerHTML = `<strong>Registration Failed:</strong> ${data.error}`;
        }
    } catch (err) {
        btn.disabled = false;
        btn.textContent = "Create Account";
        alertBox.className = "alert alert-danger";
        alertBox.style.display = "block";
        alertBox.innerHTML = `<strong>Network Error:</strong> ${err.message}`;
    }
}

// 3. Security Mode Dropdown & Toast Notification (No Browser Alerts!)
function toggleModeDropdown(event) {
    if (event) event.stopPropagation();
    const menu = document.getElementById("mode-dropdown-menu");
    if (menu) {
        menu.style.display = menu.style.display === "block" ? "none" : "block";
    }
}

// Close dropdown when clicking outside
window.addEventListener("click", (e) => {
    const menu = document.getElementById("mode-dropdown-menu");
    const btn = document.getElementById("mode-dropdown-btn");
    if (menu && menu.style.display === "block" && btn && !btn.contains(e.target) && !menu.contains(e.target)) {
        menu.style.display = "none";
    }
});

function showToast(message, icon = "🛡️") {
    const toast = document.getElementById("toast-notification");
    const toastMsg = document.getElementById("toast-message");
    const toastIcon = document.getElementById("toast-icon");
    if (!toast) return;

    if (toastMsg) toastMsg.textContent = message;
    if (toastIcon) toastIcon.textContent = icon;
    toast.style.display = "flex";

    setTimeout(() => {
        toast.style.display = "none";
    }, 2500);
}

async function selectSecurityMode(mode) {
    const menu = document.getElementById("mode-dropdown-menu");
    if (menu) menu.style.display = "none";

    try {
        const response = await fetch("/api/set-mode", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ mode: mode })
        });
        const data = await response.json();
        if (data.success) {
            const modeText = document.getElementById("header-mode-text");
            const modeDot = document.getElementById("header-mode-dot");
            const optVuln = document.getElementById("mode-opt-vulnerable");
            const optHard = document.getElementById("mode-opt-secure");

            if (modeText) modeText.textContent = mode.toUpperCase();
            if (modeDot) modeDot.style.backgroundColor = mode === "vulnerable" ? "var(--danger)" : "var(--success)";
            if (optVuln) optVuln.classList.toggle("active", mode === "vulnerable");
            if (optHard) optHard.classList.toggle("active", mode === "secure");

            showToast(`Switched to ${mode.toUpperCase()} mode!`, mode === "vulnerable" ? "⚠️" : "🛡️");

            // Brief delay to let user see toast before reloading
            setTimeout(() => {
                window.location.reload();
            }, 650);
        }
    } catch (err) {
        showToast("Failed to switch mode: " + err.message, "❌");
    }
}

// 4. Logout Handler
async function performLogout() {
    const token = localStorage.getItem("session_token");
    const headers = { "Content-Type": "application/json", "Accept": "application/json" };
    if (token) {
        headers["Authorization"] = `Bearer ${token}`;
    }

    try {
        await fetch("/logout", {
            method: "POST",
            headers: headers
        });
    } catch (err) {
        // Proceed with client cleanup
    }

    // Remove token from client storage and redirect
    localStorage.removeItem("session_token");
    sessionStorage.removeItem("session_token");
    window.location.href = "/login";
}

// 5. Attacker Simulation Sandbox Functions
async function testReplayHijack() {
    const outputBox = document.getElementById("sim-result-box");
    const outputContent = document.getElementById("sim-output-content");
    outputBox.style.display = "block";
    outputContent.innerHTML = "<em>Simulating token replay from attacker machine (different User-Agent, spoofed IP)...</em>";

    const token = document.getElementById("raw-jwt")?.innerText.trim() || localStorage.getItem("session_token");
    if (!token) {
        outputContent.innerHTML = "<span class='text-danger'>Error: No token available for replay.</span>";
        return;
    }

    try {
        const response = await fetch("/dashboard", {
            headers: {
                "Authorization": `Bearer ${token}`,
                "Accept": "application/json",
                "X-Forwarded-For": "198.51.100.42"
            }
        });
        const data = await response.json();

        if (response.ok) {
            outputContent.innerHTML = `
                <div class="text-danger">
                    <strong>⚠️ VULNERABILITY CONFIRMED: Token Replay Succeeded!</strong><br>
                    The server accepted the token without client binding resistance.<br>
                    Response: <code>${JSON.stringify(data, null, 2)}</code>
                </div>
            `;
        } else {
            outputContent.innerHTML = `
                <div class="text-success">
                    <strong>🛡️ DEFENDED: Replay Rejected!</strong><br>
                    Server rejected the replayed request: <code>${data.details || data.error}</code>
                </div>
            `;
        }
    } catch (err) {
        outputContent.innerHTML = `<span class="text-danger">Request failed: ${err.message}</span>`;
    }
}

async function testAlgNoneTamper() {
    const outputBox = document.getElementById("sim-result-box");
    const outputContent = document.getElementById("sim-output-content");
    outputBox.style.display = "block";
    outputContent.innerHTML = "<em>Crafting forged token with alg:none and stripped signature...</em>";

    const token = document.getElementById("raw-jwt")?.innerText.trim() || localStorage.getItem("session_token");
    if (!token) {
        outputContent.innerHTML = "<span class='text-danger'>Error: No token available.</span>";
        return;
    }

    try {
        const parts = token.split(".");
        // Modify header to alg: none
        const forgedHeader = btoa(JSON.stringify({ alg: "none", typ: "JWT" })).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
        const forgedToken = `${forgedHeader}.${parts[1]}.`;

        const response = await fetch("/dashboard", {
            headers: {
                "Authorization": `Bearer ${forgedToken}`,
                "Accept": "application/json"
            }
        });
        const data = await response.json();

        if (response.ok) {
            outputContent.innerHTML = `
                <div class="text-danger">
                    <strong>🚨 CRITICAL FLAW (CWE-347): alg:none Accepted!</strong><br>
                    The server accepted the unsigned forged token without checking cryptographic signature!<br>
                    Payload accepted: <code>${JSON.stringify(data.token_claims, null, 2)}</code>
                </div>
            `;
        } else {
            outputContent.innerHTML = `
                <div class="text-success">
                    <strong>🛡️ DEFENDED: alg:none Rejected!</strong><br>
                    Server strictly verified signature: <code>${data.details || data.error}</code>
                </div>
            `;
        }
    } catch (err) {
        outputContent.innerHTML = `<span class="text-danger">Test failed: ${err.message}</span>`;
    }
}

async function testPostLogoutReuse() {
    const outputBox = document.getElementById("sim-result-box");
    const outputContent = document.getElementById("sim-output-content");
    outputBox.style.display = "block";
    outputContent.innerHTML = "<em>Testing token reuse post-logout (checking server-side blacklist)...</em>";

    const token = document.getElementById("raw-jwt")?.innerText.trim() || localStorage.getItem("session_token");
    if (!token) {
        outputContent.innerHTML = "<span class='text-danger'>Error: No token available.</span>";
        return;
    }

    try {
        // Step 1: Call logout endpoint
        const logoutResp = await fetch("/logout", {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${token}`,
                "Accept": "application/json"
            }
        });
        const logoutData = await logoutResp.json();

        // Step 2: Retry the exact same token immediately
        const testResp = await fetch("/dashboard", {
            headers: {
                "Authorization": `Bearer ${token}`,
                "Accept": "application/json"
            }
        });
        const testData = await testResp.json();

        if (testResp.ok) {
            outputContent.innerHTML = `
                <div class="text-danger">
                    <strong>⚠️ FLAW DETECTED: Token Still Valid Post-Logout (CWE-613)!</strong><br>
                    User logged out, but server did not blacklist the token. An attacker with a captured token can still access the account.<br>
                    Server response: <code>${JSON.stringify(testData, null, 2)}</code>
                </div>
            `;
        } else {
            outputContent.innerHTML = `
                <div class="text-success">
                    <strong>🛡️ DEFENDED: Token Successfully Revoked (OWASP ASVS V3)!</strong><br>
                    Server rejected the revoked token: <code>${testData.details || testData.error}</code>
                </div>
            `;
        }
    } catch (err) {
        outputContent.innerHTML = `<span class="text-danger">Test failed: ${err.message}</span>`;
    }
}
