//go:build windows

package main

import (
	"html"
	"strings"
)

const offlineHTMLTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Homelab RMM - Offline</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
    body { background-color: #090a0d; color: #f3f4f6; display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 24px; user-select: none; }
    .card { background-color: #111216; border: 1px solid #1c1e24; border-radius: 12px; padding: 36px; max-width: 500px; width: 100%; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.6); text-align: center; }
    .icon { width: 56px; height: 56px; margin: 0 auto 20px; background-color: rgba(239, 68, 68, 0.1); border-radius: 50%; display: flex; align-items: center; justify-content: center; color: #ef4444; }
    h1 { font-size: 20px; font-weight: 600; margin-bottom: 10px; color: #f3f4f6; }
    p { color: #9ca3af; font-size: 14px; line-height: 1.6; margin-bottom: 24px; }
    .url-badge { background: #171920; padding: 6px 14px; border-radius: 6px; font-family: monospace; font-size: 13px; color: #9ca3af; display: inline-block; margin-bottom: 20px; border: 1px solid #272a33; word-break: break-all; }
    .btn { background-color: #3b82f6; color: #fff; border: none; border-radius: 6px; padding: 10px 20px; font-size: 14px; font-weight: 500; cursor: pointer; transition: background-color 0.15s; width: 100%; }
    .btn:hover { background-color: #2563eb; }
    .btn:disabled { opacity: 0.6; cursor: not-allowed; }
    .status-text { margin-top: 16px; font-size: 12px; color: #5b6270; }
    .advanced-toggle { margin-top: 20px; font-size: 13px; color: #9ca3af; background: none; border: none; cursor: pointer; text-decoration: underline; }
    .input-group { margin-top: 16px; display: none; text-align: left; }
    .input-group.visible { display: block; }
    .input-group label { display: block; font-size: 12px; color: #9ca3af; margin-bottom: 6px; }
    .input-group input { width: 100%; padding: 8px 12px; border-radius: 6px; border: 1px solid #272a33; background: #0c0d10; color: #f3f4f6; font-size: 14px; margin-bottom: 12px; }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">
      <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="12" cy="12" r="10"></circle>
        <line x1="12" y1="8" x2="12" y2="12"></line>
        <line x1="12" y1="16" x2="12.01" y2="16"></line>
      </svg>
    </div>
    <h1>Cannot Connect to Server</h1>
    <p>Unable to connect to the Homelab RMM server.<br>Please ensure the Windows Service is installed and running.</p>
    <div class="url-badge" id="currentUrl"></div>
    <button class="btn" id="retryBtn" onclick="doRetry()">Retry Connection</button>
    <div class="status-text" id="statusText">Checking automatically...</div>
    
    <button class="advanced-toggle" onclick="toggleServerInput()">Change Server Address</button>
    <div class="input-group" id="inputGroup">
      <label for="serverInput">Server URL:</label>
      <input type="text" id="serverInput" spellcheck="false">
      <button class="btn" style="background-color: #475569;" onclick="setCustomUrl()">Save &amp; Connect</button>
    </div>
  </div>

  <script>
    let countdown = 5;
    let targetUrl = "TARGET_URL_PLACEHOLDER";
    document.getElementById("currentUrl").innerText = targetUrl;
    document.getElementById("serverInput").value = targetUrl;

    async function checkConnection(url) {
      if (window.probeServer) {
        try {
          return await window.probeServer(url);
        } catch (e) {
          return false;
        }
      }
      return false;
    }

    async function doRetry() {
      const btn = document.getElementById("retryBtn");
      const status = document.getElementById("statusText");
      btn.disabled = true;
      btn.innerText = "Checking...";
      status.innerText = "Connecting to server...";
      
      const success = await checkConnection(targetUrl);
      if (success) {
        status.innerText = "Connected! Loading...";
        if (window.navigateTo) {
          window.navigateTo(targetUrl);
        } else {
          window.location.href = targetUrl;
        }
      } else {
        btn.disabled = false;
        btn.innerText = "Retry Connection";
        countdown = 5;
        status.innerText = "Still unreachable. Retrying automatically in 5s...";
      }
    }

    async function setCustomUrl() {
      const val = document.getElementById("serverInput").value.trim();
      if (val) {
        targetUrl = val;
        document.getElementById("currentUrl").innerText = targetUrl;
        doRetry();
      }
    }

    function toggleServerInput() {
      const ig = document.getElementById("inputGroup");
      ig.classList.toggle("visible");
    }

    setInterval(async () => {
      const btn = document.getElementById("retryBtn");
      if (btn.disabled) return;
      countdown--;
      if (countdown <= 0) {
        doRetry();
      } else {
        document.getElementById("statusText").innerText = "Retrying automatically in " + countdown + "s...";
      }
    }, 1000);
  </script>
</body>
</html>`

func renderOfflinePage(serverURL string) string {
	return strings.ReplaceAll(offlineHTMLTemplate, "TARGET_URL_PLACEHOLDER", serverURL)
}

const portalErrorHTMLTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Homelab Support - Unavailable</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
    body { background-color: #090a0d; color: #f3f4f6; display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 24px; user-select: none; }
    .card { background-color: #111216; border: 1px solid #1c1e24; border-radius: 12px; padding: 36px; max-width: 500px; width: 100%; text-align: center; }
    h1 { font-size: 20px; font-weight: 600; margin-bottom: 10px; }
    p { color: #9ca3af; font-size: 14px; line-height: 1.6; margin-bottom: 24px; }
    .btn { background-color: #3b82f6; color: #fff; border: none; border-radius: 6px; padding: 10px 20px; font-size: 14px; font-weight: 500; cursor: pointer; width: 100%; }
    .btn:hover { background-color: #2563eb; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Support is unavailable right now</h1>
    <p>REASON_PLACEHOLDER</p>
    <button class="btn" onclick="window.openPortal && window.openPortal()">Try again</button>
  </div>
</body>
</html>`

// renderPortalErrorPage explains why the portal could not be opened: most
// often the agent service is stopped or cannot reach the server.
func renderPortalErrorPage(reason string) string {
	return strings.ReplaceAll(portalErrorHTMLTemplate, "REASON_PLACEHOLDER", html.EscapeString(reason))
}
