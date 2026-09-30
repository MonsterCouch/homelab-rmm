// End-to-end smoke test for the operator console against a running
// rmm-server (plain HTTP, fresh data dir). Usage:
//
//   export RMM_DATA_DIR=/tmp/rmm-ui-test
//   ./rmm-server run --insecure --listen 127.0.0.1:18080 &
//   node web/e2e/smoke.mjs            # PW_BASE overrides the URL
//
// First-run setup always asks for the one-time code the server prints at
// startup (there is no loopback exemption any more), so this needs the code
// too: RMM_SETUP_CODE, or RMM_DATA_DIR so it can be read out of server.log.
//
// It completes first-run setup, walks every page, exercises the main create
// flows and fails on any console error, page error or failed/4xx+ request.

import { createRequire } from 'node:module';
import { execFileSync, spawn } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, openSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { hostname, tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const here = dirname(fileURLToPath(import.meta.url));
const BASE = process.env.PW_BASE || 'http://127.0.0.1:18080';
const SHOTS = join(here, 'shots');
mkdirSync(SHOTS, { recursive: true });

// The first-run setup code. Whoever completes setup has to prove they can read
// the server's console or log, which is the whole point of the code: a browser
// that merely reaches the port - loopback included - cannot claim the account.
function setupCode() {
  if (process.env.RMM_SETUP_CODE) return process.env.RMM_SETUP_CODE.trim();
  const dir = process.env.RMM_DATA_DIR;
  if (dir && existsSync(join(dir, 'server.log'))) {
    const log = readFileSync(join(dir, 'server.log'), 'utf8');
    const hits = [...log.matchAll(/setup_code=([0-9a-f]{8})/g)];
    if (hits.length) return hits[hits.length - 1][1];
  }
  return '';
}
const SETUP_CODE = setupCode();

function loadPlaywright() {
  const candidates = ['playwright', 'playwright-core', '/opt/node22/lib/node_modules/playwright', '/usr/lib/node_modules/playwright', '/usr/local/lib/node_modules/playwright'];
  for (const c of candidates) {
    try {
      return require(c);
    } catch {
      /* next */
    }
  }
  throw new Error('playwright is not installed (tried: ' + candidates.join(', ') + ')');
}

function findChromium() {
  const root = process.env.PLAYWRIGHT_BROWSERS_PATH || '/opt/pw-browsers';
  if (!existsSync(root)) return undefined;
  const dirs = readdirSync(root)
    .filter((d) => /^chromium-\d+$/.test(d))
    .sort()
    .reverse();
  for (const d of dirs) {
    for (const rel of ['chrome-linux/chrome', 'chrome-linux64/chrome', 'chrome-mac/Chromium.app/Contents/MacOS/Chromium']) {
      const p = join(root, d, rel);
      if (existsSync(p)) return p;
    }
  }
  return undefined;
}

const { chromium } = loadPlaywright();
const executablePath = findChromium();
const problems = [];
const covered = [];
let shotN = 0;
// Set while a step deliberately provokes a 401 (wrong-password login).
let expectAuthFailure = false;
// Set while the setup step deliberately submits a wrong one-time code (403).
let expectSetupFailure = false;
// Set while the viewer-role step deliberately provokes 403s on the endpoints a
// read-only account must not reach.
let expectViewerDenials = false;
// A real Linux agent is enrolled when a binary is available (AGENT_BIN or the
// repo-root build) so the device pages, terminal and run streaming are tested
// against live data instead of an empty table.
// Set once GET /api/baselines has answered 200. Until then the console's own
// probe requests may 404 (they are not counted as problems); an API that never
// answers IS a problem - server, console and agent all ship the feature now.
let baselinesReady = false;
const AGENT_BIN = process.env.AGENT_BIN || join(here, '..', '..', 'rmm-agent');
const haveAgent = process.platform === 'linux' && existsSync(AGENT_BIN);
let agentProc = null;
const skipped = [];
// The temp directory the baseline walk asks the agent to manage.
let baselineDir = null;

function startAgent(token) {
  const dir = mkdtempSync(join(tmpdir(), 'rmm-ui-agent-'));
  const env = { ...process.env, RMM_AGENT_DIR: dir };
  execFileSync(AGENT_BIN, ['install', '--server', BASE, '--token', token, '--no-service'], { env, stdio: 'pipe' });
  const log = openSync(join(dir, 'agent.stdout.log'), 'a');
  agentProc = spawn(AGENT_BIN, ['run'], { env, stdio: ['ignore', log, log] });
  console.log(`  agent started (pid ${agentProc.pid}, dir ${dir})`);
}

function stopAgent() {
  // SIGKILL rather than SIGTERM: the test wants the socket to drop right now so
  // the server's agent_offline event can be observed, not a graceful shutdown.
  if (agentProc && !agentProc.killed) agentProc.kill('SIGKILL');
  agentProc = null;
}

// Drives the Remote Desktop tab against an in-page fake of the server's
// bridged helper socket: window.WebSocket is swapped for a class that plays
// the docs/DESKTOP-PROTOCOL.md helper side (connected, screen, one PNG tile,
// frame end) and records everything the viewer sends. This checks tile
// decoding and painting, the ack after the frame, coordinate mapping and
// every control message without needing a display in the container.
async function desktopViewerWithFakeHelper(page, ctx) {
  await ctx.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: BASE });
  await page.evaluate(() => {
    const Real = window.WebSocket;
    window.__realWebSocket = Real;
    class FakeWS extends EventTarget {
      static CONNECTING = 0;
      static OPEN = 1;
      static CLOSING = 2;
      static CLOSED = 3;
      constructor(url) {
        super();
        this.url = url;
        this.readyState = 0;
        this.binaryType = 'blob';
        window.__fakeSent = [];
        window.__fakeWs = this;
        setTimeout(() => {
          this.readyState = 1;
          this.onopen?.(new Event('open'));
          this.text({ t: 'connected' });
          this.text({ t: 'note', message: 'fake helper' });
          this.text({
            t: 'screen',
            w: 640,
            h: 400,
            monitor: 0,
            monitors: [
              { index: 0, x: 0, y: 0, w: 640, h: 400, primary: true },
              { index: 1, x: 640, y: 0, w: 800, h: 600 },
            ],
          });
          void this.frame();
        }, 10);
      }
      text(o) {
        this.onmessage?.({ data: JSON.stringify(o) });
      }
      async frame() {
        // one PNG tile covering the monitor: blue with a yellow box at (100,100)-(300,200)
        const c = document.createElement('canvas');
        c.width = 640;
        c.height = 400;
        const g = c.getContext('2d');
        g.fillStyle = '#3366cc';
        g.fillRect(0, 0, 640, 400);
        g.fillStyle = '#ffcc00';
        g.fillRect(100, 100, 200, 100);
        const blob = await new Promise((r) => c.toBlob(r, 'image/png'));
        const png = new Uint8Array(await blob.arrayBuffer());
        const tile = new Uint8Array(10 + png.length);
        const dv = new DataView(tile.buffer);
        tile[0] = 0x01;
        dv.setUint16(1, 0, true);
        dv.setUint16(3, 0, true);
        dv.setUint16(5, 640, true);
        dv.setUint16(7, 400, true);
        tile[9] = 1; // PNG
        tile.set(png, 10);
        this.onmessage?.({ data: tile.buffer });
        const end = new Uint8Array(5);
        end[0] = 0x02;
        new DataView(end.buffer).setUint32(1, 7, true);
        this.onmessage?.({ data: end.buffer });
        this.text({ t: 'clipboard', text: 'from-remote' });
      }
      send(d) {
        window.__fakeSent.push(JSON.parse(d));
      }
      close() {
        if (this.readyState === 3) return;
        this.readyState = 3;
        this.onclose?.({ code: 1000, wasClean: true });
      }
    }
    window.WebSocket = FakeWS;
  });
  const sent = () => page.evaluate(() => window.__fakeSent ?? []);
  const has = async (pred) => (await sent()).some(pred);
  const waitSent = (name, pred = () => true) =>
    page.waitForFunction(([n]) => (window.__fakeSent ?? []).some((m) => m.t === n), [name], { timeout: 10000 }).then(async () => {
      if (!(await has((m) => m.t === name && pred(m)))) problems.push(`desktop viewer sent ${name} with unexpected fields: ${JSON.stringify((await sent()).filter((m) => m.t === name))}`);
    });

  await page.click('button:has-text("Reconnect")');
  await page.waitForSelector('.statusline:has-text("Connected · 640×400")', { timeout: 10000 });
  await waitSent('ack', (m) => m.frame === 7);
  const px = await page.evaluate(() => {
    const c = document.querySelector('.desktop-wrap canvas');
    const g = c.getContext('2d');
    return { yellow: Array.from(g.getImageData(150, 150, 1, 1).data), blue: Array.from(g.getImageData(10, 10, 1, 1).data), w: c.width, h: c.height };
  });
  if (px.w !== 640 || px.h !== 400) problems.push(`desktop canvas not sized to the screen message: ${px.w}x${px.h}`);
  if (px.yellow.slice(0, 3).join(',') !== '255,204,0') problems.push(`tile not painted where expected (got ${px.yellow})`);
  if (px.blue.slice(0, 3).join(',') !== '51,102,204') problems.push(`tile background not painted (got ${px.blue})`);
  if (!(await page.locator('.statusline:has-text("fake helper")').count())) problems.push('helper note not shown in the status line');
  step('desktop viewer: decoded a PNG tile, painted it at the right place and acked the frame');

  // Mouse: pointer coordinates map from the scaled canvas back to remote pixels.
  const box = await page.locator('.desktop-wrap canvas').boundingBox();
  const at = (fx, fy) => ({ x: box.x + box.width * fx, y: box.y + box.height * fy });
  const p1 = at(0.25, 0.5);
  await page.mouse.move(p1.x, p1.y);
  await waitSent('mousemove', (m) => Math.abs(m.x - 160) <= 2 && Math.abs(m.y - 200) <= 2);
  await page.mouse.down();
  await page.mouse.up();
  await waitSent('mousedown', (m) => m.button === 0);
  await waitSent('mouseup', (m) => m.button === 0);
  await page.mouse.click(p1.x, p1.y, { button: 'right' });
  await waitSent('mousedown', (m) => m.button === 2);
  await page.mouse.wheel(0, 120);
  await waitSent('wheel', (m) => m.dy === 100 && m.dx === 0);
  step('desktop viewer: mouse move/click/right-click/wheel forwarded in remote pixel space');

  // Wheel normalisation (docs/DESKTOP-PROTOCOL.md): whatever a browser calls a
  // notch leaves the viewer as a whole ±100, in pixel, line and page mode
  // alike; only trackpad-sized pixel deltas go through raw for the helper to
  // accumulate. Synthetic events because Playwright only produces deltaMode 0.
  const wheelCase = async (init, want) => {
    await page.evaluate(() => (window.__fakeSent = []));
    await page.evaluate(
      ([i, x, y]) => document.querySelector('.desktop-wrap canvas').dispatchEvent(new WheelEvent('wheel', { ...i, clientX: x, clientY: y, bubbles: true, cancelable: true })),
      [init, p1.x, p1.y],
    );
    await page.waitForFunction(() => (window.__fakeSent ?? []).some((m) => m.t === 'wheel'), null, { timeout: 5000 }).catch(() => {});
    const got = (await sent()).filter((m) => m.t === 'wheel');
    if (got.length !== 1 || got[0].dx !== want.dx || got[0].dy !== want.dy) {
      problems.push(`wheel ${JSON.stringify(init)} should send ${JSON.stringify(want)}, sent ${JSON.stringify(got)}`);
    }
  };
  await wheelCase({ deltaY: 53, deltaMode: 0 }, { dx: 0, dy: 100 }); // Chrome on Linux
  await wheelCase({ deltaY: -120, deltaMode: 0 }, { dx: 0, dy: -100 }); // Chrome on Windows
  await wheelCase({ deltaY: 250, deltaMode: 0 }, { dx: 0, dy: 300 }); // a fast flick is whole notches
  await wheelCase({ deltaY: 8, deltaMode: 0 }, { dx: 0, dy: 8 }); // trackpad: the helper accumulates
  await wheelCase({ deltaY: 3, deltaMode: 1 }, { dx: 0, dy: 100 }); // Firefox: 3 lines to the notch
  await wheelCase({ deltaX: -1, deltaMode: 2 }, { dx: -100, dy: 0 }); // page mode, horizontal
  step('desktop viewer: wheel sent as whole notches in pixel/line/page mode, trackpad deltas untouched');

  // A drag released outside the canvas must still release the remote button.
  await page.evaluate(() => (window.__fakeSent = []));
  await page.mouse.move(p1.x, p1.y);
  await page.mouse.down();
  await page.mouse.move(box.x + box.width + 40, box.y - 40, { steps: 3 }); // off the canvas
  await page.mouse.up();
  await waitSent('mouseup', (m) => m.button === 0);
  step('desktop viewer: mouse released outside the canvas still sends mouseup (no sticky click)');

  // Keyboard: keys go to the remote and never move focus off the viewer.
  await page.mouse.click(p1.x, p1.y);
  await page.evaluate(() => (window.__fakeSent = []));
  await page.keyboard.press('Tab');
  await page.keyboard.press('F5');
  await page.keyboard.press('Control+w');
  await waitSent('keydown', (m) => m.code === 'Tab');
  await waitSent('keyup', (m) => m.code === 'F5');
  await waitSent('keydown', (m) => m.code === 'KeyW' && m.ctrl === true);
  const focused = await page.evaluate(() => document.activeElement?.classList.contains('desktop-wrap'));
  if (!focused) problems.push('Tab moved focus away from the desktop viewer instead of going to the remote');
  step('desktop viewer: Tab, F5 and Ctrl+W captured and forwarded while focused');

  // Controls: monitor switch, quality, refresh, Ctrl+Alt+Del, paste, remote clipboard.
  await page.selectOption('select[aria-label="Monitor"]', '1');
  await waitSent('monitor', (m) => m.index === 1);
  await page.locator('input[aria-label="JPEG quality"]').fill('40');
  await waitSent('quality', (m) => m.q === 40);
  await page.click('button:has-text("Refresh")');
  await waitSent('refresh');
  await page.click('button:has-text("Ctrl+Alt+Del")');
  await waitSent('ctrlaltdel');
  await page.evaluate(() => navigator.clipboard.writeText('paste-me'));
  await page.click('button:has-text("Paste")');
  await waitSent('paste', (m) => m.text === 'paste-me');
  if (!(await page.locator('button:has-text("Remote clipboard")').count())) problems.push('remote clipboard message did not surface a copy button');
  step('desktop viewer: monitor, quality, refresh, Ctrl+Alt+Del and clipboard paste messages match the protocol');

  // ux-05: the toast the paste just raised must clear this page's own read-out.
  // The "fps · B/s" figure at the right end of the status line is the number you
  // watch while judging the connection, and it was being covered.
  await page.waitForSelector('.toast');
  const overlap = await page.evaluate(() => {
    const line = document.querySelector('.fill-page .statusline');
    if (!line) return 'no-statusline';
    const b = line.getBoundingClientRect();
    const toasts = [...document.querySelectorAll('.toast')].map((t) => t.getBoundingClientRect());
    return { toasts: toasts.length, covering: toasts.filter((a) => a.bottom > b.top && a.top < b.bottom && a.right > b.left && a.left < b.right).length };
  });
  if (overlap === 'no-statusline') problems.push('the remote desktop lost its status line');
  else if (!overlap.toasts) skipped.push('toast/status-line overlap not checked (the toast had already expired)');
  else if (overlap.covering) problems.push(`${overlap.covering} toast(s) cover the remote desktop status line`);
  step('toasts clear the remote desktop status line instead of covering the fps read-out');

  await page.click('button:has-text("Disconnect")');
  await page.waitForSelector('.statusline:has-text("Disconnected")');
  await page.evaluate(() => {
    window.WebSocket = window.__realWebSocket;
  });
  await shot(page, 'device-desktop-fake');
}

// ---- baselines: desired state, drift detection, self-healing ----
//
// The whole loop against the real Linux agent: build a baseline in the
// editor, dry-run it, save it, watch the first pass land, break the desired
// state from outside the product and watch the agent put it back, and read
// the drift alert open and resolve. Everything the agent is asked to manage
// lives in a temp directory this function owns.
function diskFreePct() {
  try {
    const out = execFileSync('df', ['-P', '/'], { encoding: 'utf8' }).trim().split('\n');
    const cols = out[out.length - 1].split(/\s+/);
    const total = Number(cols[1]);
    const avail = Number(cols[3]);
    const used = Number(String(cols[4]).replace('%', ''));
    // The agent measures free/total; df's capacity column measures
    // used/(used+available), which on a filesystem with reserved blocks is a
    // much rosier number. Take whichever is smaller so the threshold the
    // test picks is below both.
    const byTotal = total > 0 ? (avail / total) * 100 : 100;
    const byCapacity = Number.isFinite(used) ? 100 - used : 100;
    return Math.min(byTotal, byCapacity);
  } catch {
    /* fall through */
  }
  return 50;
}

async function baselineWalk(page) {
  const dir = mkdtempSync(join(tmpdir(), 'rmm-baseline-'));
  const target = join(dir, 'desired.conf');
  const marker = join(dir, 'marker');
  const sentinel = join(dir, 'sentinel');
  const CONTENT = 'SMOKE_BASELINE=1\n';
  // A threshold the root filesystem certainly satisfies: the point of the
  // disk check here is that a passing check renders, not that it trips.
  const free = diskFreePct();
  const minFree = Math.max(1, Math.min(90, Math.floor(free / 2)));
  if (free < 3) skipped.push(`the root filesystem is only ${free.toFixed(1)}% free, so the disk_free check is testing a 1% threshold`);

  // The agent binary is whatever is on disk (AGENT_BIN, or the gitignored
  // repo-root build). One that predates the baselines API answers
  // "unknown request baseline.preview", which otherwise surfaces 200 lines
  // later as a 60 s selector timeout that reads exactly like a product bug.
  // Ask the device directly, and say what is actually wrong.
  {
    const probe = await page.evaluate(async () => {
      const h = { 'Content-Type': 'application/json', 'X-Requested-With': 'fetch' };
      try {
        const agents = await fetch('/api/agents', { headers: h }).then((r) => r.json());
        const id = agents?.[0]?.id;
        if (!id) return { devices: [{ status: 'error', error: 'no device is enrolled' }] };
        return await fetch('/api/baselines/preview', {
          method: 'POST',
          headers: h,
          body: JSON.stringify({
            spec: { name: 'agent capability probe', enforce: false, interval_sec: 3600, checks: [{ name: 'probe', kind: 'disk_free', params: { mount: '/', min_free_pct: 1 }, remediate: false, severity: 'info', os_filter: 'linux', timeout_sec: 10 }] },
            agent_ids: [id],
          }),
        }).then((r) => r.json());
      } catch (e) {
        return { devices: [{ status: 'error', error: String(e) }] };
      }
    });
    const dev = probe?.devices?.[0] ?? { status: 'error', error: 'no device in the preview response' };
    if (dev.status !== 'ok') {
      throw new Error(
        `the enrolled agent cannot run baseline.preview (${dev.status}: ${dev.error}). ` +
          `AGENT_BIN is ${AGENT_BIN} - rebuild it (make build, or go build -o rmm-agent ./cmd/rmm-agent) before running the smoke.`,
      );
    }
  }

  await page.click('nav a[href="/baselines"]');
  await page.waitForSelector('h1:has-text("Baselines")');
  await page.locator('.tbl tbody tr').first().or(page.locator('.empty')).first().waitFor();
  const seededRows = await page.locator('.tbl tbody tr').count();
  if (seededRows) {
    const enabled = await page.locator('.tbl tbody tr [role=switch][aria-checked="true"]').count();
    if (enabled) problems.push(`${enabled} seeded baseline(s) arrived enabled; seeds must ship disabled and unenforced`);
    if (await page.locator('.tbl tbody tr .chip:has-text("enforcing")').count()) problems.push('a seeded baseline arrived enforcing');
    step(`baselines page lists ${seededRows} seeded baseline(s), all disabled and report-only`);
  } else skipped.push('no seeded baselines in this database, so the seed-safety assertions were skipped');
  await shot(page, 'baselines');

  // ---- editor ----
  await page.click('button:has-text("New baseline")');
  await page.waitForURL(/\/baselines\/new$/);
  await page.fill('#bl-name', 'Smoke desired state');
  await page.fill('#bl-desc', 'created by the console smoke test');
  await page.click('[data-testid="bl-enabled"] button[role=switch]');
  await page.click('[data-testid="bl-enforce"] button[role=switch]');
  await page.waitForSelector('.banner.warn:has-text("will change these devices without asking")');
  step('baseline editor: the enforce toggle carries the "the agent will change these devices without asking" warning');

  const addCheck = async (fill) => {
    await page.click('.card-head:has-text("Checks") button:has-text("Add check")');
    await page.waitForSelector('.modal:has-text("Add check")');
    await fill();
    await page.click('.modal-foot button:has-text("Add check")');
    await page.waitForSelector('.modal', { state: 'detached' });
  };

  await addCheck(async () => {
    await page.fill('#chk-name', 'Smoke file present');
    await page.selectOption('#chk-kind', 'file');
    await page.fill('#p-path', target);
    await page.fill('#p-content', CONTENT);
    await page.fill('#p-mode', '0644');
    await page.click('[data-testid="chk-remediate"] button[role=switch]');
  });
  await addCheck(async () => {
    await page.fill('#chk-name', 'Smoke marker present');
    await page.selectOption('#chk-kind', 'command');
    await page.waitForSelector('.modal .banner.danger:has-text("runs as SYSTEM")');
    await page.fill('#p-expected', 'marker present');
    await page.fill('#p-check', `#!/usr/bin/env bash\ntest -f ${marker}\n`);
    await page.fill('#p-fix', `#!/usr/bin/env bash\ntouch ${marker}\n`);
    await page.click('[data-testid="chk-remediate"] button[role=switch]');
  });
  await addCheck(async () => {
    await page.fill('#chk-name', 'Root disk free');
    await page.selectOption('#chk-kind', 'disk_free');
    await page.fill('#p-mount', '/');
    await page.fill('#p-min-free', String(minFree));
  });
  await addCheck(async () => {
    await page.fill('#chk-name', 'Smoke drift sentinel');
    await page.selectOption('#chk-kind', 'command');
    await page.fill('#p-expected', 'sentinel present');
    await page.fill('#p-check', `#!/usr/bin/env bash\ntest -f ${sentinel}\n`);
  });
  await page.waitForSelector('.tbl tbody tr:has-text("Smoke drift sentinel")');
  step('four checks added through the typed forms (file, two command scripts, disk free) with per-check remediation, severity, OS filter and timeout');

  // Client-side validation mirrors the server's: a path that is not absolute
  // is refused here, before a 400 can happen.
  await page.click('.tbl tbody tr:has-text("Smoke file present") button:has-text("Edit")');
  await page.waitForSelector('.modal:has-text("Edit check")');
  await page.fill('#p-path', 'relative/path.conf');
  await page.waitForSelector('.form-error:has-text("absolute path")');
  const saveDisabled = await page.locator('.modal-foot button:has-text("Save check")').isDisabled();
  if (!saveDisabled) problems.push('the check dialog let an invalid path be saved');
  // and the raw-JSON editor is checked against the same shapes
  await page.click('.modal button:has-text("Raw JSON")');
  await page.fill('#chk-raw', '{"path":"/tmp/x","state":"present","contentt":"oops"}');
  await page.waitForSelector('.field .err:has-text("does not take")');
  await page.fill('#chk-raw', JSON.stringify({ path: target, state: 'present', content: CONTENT, mode: '0644' }, null, 2));
  await page.waitForSelector('.modal-foot button:has-text("Save check"):not([disabled])');
  await page.click('.modal-foot button:has-text("Save check")');
  await page.waitForSelector('.modal', { state: 'detached' });
  step('check dialog validates against the same rules as the server (bad path refused, unknown params key refused in raw JSON mode)');
  await shot(page, 'baseline-editor');

  // ---- preview: a dry run that never fixes and never stores ----
  await page.click('button:has-text("Preview on devices")');
  await page.waitForSelector('.modal:has-text("Preview on devices")');
  await page.click('.modal-foot button:has-text("Run preview")');
  await page.waitForSelector('.modal .card:has-text("Smoke file present")', { timeout: 60000 });
  const previewStates = await page.$$eval('.modal .tbl tbody tr', (rows) => rows.map((r) => `${r.children[0].textContent.trim()}=${r.children[1].textContent.trim()}`));
  const wantPreview = ['Smoke file present=fail', 'Smoke marker present=fail', 'Root disk free=pass', 'Smoke drift sentinel=fail'];
  if (previewStates.join(' | ') !== wantPreview.join(' | ')) problems.push(`preview reported ${previewStates.join(' | ')}, expected ${wantPreview.join(' | ')}`);
  if (existsSync(target) || existsSync(marker)) problems.push('the preview fixed something: a dry run must never remediate or write');
  await shot(page, 'baseline-preview');
  await page.click('.modal-foot button:has-text("Close")');
  await page.waitForSelector('.modal', { state: 'detached' });
  step('preview dry-ran the unsaved draft on the live device: drift reported as fail, nothing fixed, nothing stored');

  // ---- save ----
  await page.click('button:has-text("Create baseline")');
  await page.waitForSelector('.modal:has-text("Enforce this baseline?")');
  await page.click('.modal button:has-text("Enforce")');
  await page.waitForURL(/\/baselines\/\d+$/, { timeout: 30000 });
  await page.waitForSelector('.toast:has-text("Baseline created")');
  const baselineURL = page.url();
  step('baseline saved (enforced, enabled) and the status view opened');

  // ---- the first pass ----
  const states = () => page.$$eval('.baseline-matrix tbody tr:first-child button.cell-btn .chip', (els) => els.map((e) => e.textContent.trim()));
  const waitStates = async (want, what, timeout = 180000) => {
    const deadline = Date.now() + timeout;
    let got = [];
    let i = 0;
    while (Date.now() < deadline) {
      got = await states().catch(() => []);
      if (got.length === want.length && want.every((w, n) => w === '*' || got[n] === w)) return true;
      await page.waitForTimeout(2500);
      if (++i % 3 === 0) await page.click('button[aria-label="Refresh"]').catch(() => {});
    }
    problems.push(`${what}: the matrix never reached [${want.join(', ')}] (last [${got.join(', ')}])`);
    return false;
  };
  await page.waitForSelector('.baseline-matrix', { timeout: 30000 });
  const first = await waitStates(['fixed', 'fixed', 'pass', 'fail'], 'first pass');
  if (first) {
    if (!existsSync(target)) problems.push('the file check reported fixed but the file was not written');
    else if (readFileSync(target, 'utf8') !== CONTENT) problems.push('the file check wrote the wrong content');
    if (!existsSync(marker)) problems.push('the command check reported fixed but its fix script did not run');
  }
  step('first pass landed: the enforced checks fixed themselves on the device, the disk check passed and the sentinel reported drift');
  await shot(page, 'baseline-status');

  // expected vs observed is one click away, and so is the fix
  await page.click('.baseline-matrix tbody tr:first-child button.cell-btn >> nth=3');
  await page.waitForSelector('.drawer:has-text("Smoke drift sentinel")');
  await page.waitForSelector('.drawer dt:has-text("Observed")');
  await page.keyboard.press('Escape');
  await page.waitForSelector('.drawer', { state: 'detached' });
  await page.click('.baseline-matrix tbody tr:first-child button:has-text("History")');
  await page.waitForSelector('.drawer:has-text("History")');
  await page.waitForSelector('.drawer .tbl tbody tr, .drawer .empty', { timeout: 20000 });
  await shot(page, 'baseline-history');
  await page.keyboard.press('Escape');
  await page.waitForSelector('.drawer', { state: 'detached' });
  step('status matrix: a cell opens expected/observed/since/detail with a fix button, and the device history drawer lists the transitions');

  // ---- the drift alert ----
  await page.click('nav a[href="/alerts"]');
  await page.waitForSelector('h1:has-text("Alerts")');
  await page.selectOption('select[aria-label="Source"]', 'drift');
  const driftRow = page.locator('.tbl tbody tr:has-text("Smoke drift sentinel")');
  await driftRow.first().waitFor({ timeout: 60000 });
  if (!(await page.locator('.tbl tbody tr:has-text("Smoke drift sentinel") .chip:has-text("drift")').count())) {
    problems.push('the drift alert does not say it came from a baseline check');
  }
  await shot(page, 'alerts-drift');
  step('the failing check opened a drift alert, readable in Alerts with its check name and a drift source filter');

  // ---- break it from outside the product, then watch the agent fix it ----
  rmSync(target, { force: true });
  rmSync(marker, { force: true });
  await page.goto(baselineURL);
  await page.waitForSelector('.baseline-matrix');
  await page.click('.baseline-matrix tbody tr:first-child button:has-text("Evaluate")');
  await page.waitForSelector('.toast:has-text("Evaluation requested")');
  const back = await waitFile(() => existsSync(target) && existsSync(marker), 120000);
  if (!back) problems.push('the files deleted out of band were not put back by the enforced baseline');
  await waitStates(['fixed', 'fixed', 'pass', 'fail'], 'after the out-of-band deletion');
  step('deleting the managed file and the marker outside the product and asking for an evaluation put both back and reported them fixed');

  // ---- the drift clears and the alert resolves ----
  writeFileSync(sentinel, 'ok\n');
  await page.click('.baseline-matrix tbody tr:first-child button:has-text("Evaluate")');
  await page.waitForSelector('.toast:has-text("Evaluation requested")');
  await waitStates(['*', '*', 'pass', 'pass'], 'after the sentinel appeared');
  await page.click('nav a[href="/alerts"]');
  await page.waitForSelector('h1:has-text("Alerts")');
  await page.selectOption('select[aria-label="Source"]', 'drift');
  await page.click('.btn-group button:has-text("Resolved")');
  await page.locator('.tbl tbody tr:has-text("Smoke drift sentinel")').first().waitFor({ timeout: 60000 });
  step('the check going back to pass resolved its drift alert');

  // ---- editing keeps the results (PUT is a merge, not a delete + reinsert) ----
  await page.goto(baselineURL);
  await page.waitForSelector('.baseline-matrix');
  await page.click('.page-head button:has-text("Edit")');
  await page.waitForURL(/\/baselines\/\d+\/edit$/);
  await page.fill('#bl-desc', 'edited by the console smoke test');
  await page.click('button:has-text("Save baseline")');
  await page.waitForSelector('.modal:has-text("Enforce this baseline?")');
  await page.click('.modal button:has-text("Enforce")');
  await page.waitForURL(/\/baselines\/\d+$/, { timeout: 30000 });
  await page.waitForSelector('.baseline-matrix');
  const afterEdit = await states();
  if (afterEdit.filter((s) => s === 'unknown').length) problems.push(`saving the baseline lost results: ${afterEdit.join(', ')}`);
  step('saving an edit keeps every check id, so the matrix keeps its results instead of emptying');

  // ---- manual remediation: the path enforcement does not cover ----
  // With enforcement off the agent reports drift and leaves it alone, so the
  // operator's "Remediate" button is the only thing that changes the device.
  await page.click('.page-head button:has-text("Edit")');
  await page.waitForURL(/\/baselines\/\d+\/edit$/);
  await page.click('[data-testid="bl-enforce"] button[role=switch]');
  await page.click('button:has-text("Save baseline")');
  await page.waitForURL(/\/baselines\/\d+$/, { timeout: 30000 });
  await page.waitForSelector('.baseline-matrix');
  rmSync(target, { force: true });
  await page.click('.baseline-matrix tbody tr:first-child button:has-text("Evaluate")');
  await page.waitForSelector('.toast:has-text("Evaluation requested")');
  await waitStates(['fail', '*', '*', '*'], 'with enforcement off');
  if (existsSync(target)) problems.push('a baseline that is not enforced fixed the device anyway');
  await page.click('.baseline-matrix tbody tr:first-child button:has-text("Remediate")');
  await page.waitForSelector('.modal:has-text("Remediate failing checks")');
  await page.click('.modal-foot button:has-text("Remediate")');
  await page.waitForSelector('.toast:has-text("Remediation requested")');
  if (!(await waitFile(() => existsSync(target), 120000))) problems.push('manual remediation did not put the managed file back');
  await waitStates(['fixed', '*', '*', '*'], 'after manual remediation');
  step('with enforcement off drift is reported and left alone, and the device row\u2019s Remediate button runs the fixes on demand');

  // ---- device compliance tab ----
  await page.click('.baseline-matrix tbody tr:first-child a');
  await page.waitForURL(/\/devices\/[0-9a-f]+\/compliance$/);
  await page.waitForSelector('.card-head:has-text("Smoke desired state")');
  await page.waitForSelector('.tbl tbody tr:has-text("Smoke file present")');
  await page.waitForSelector('.tbl td:has-text("SMOKE_BASELINE"), .tbl tbody tr:has-text("Smoke file present") .chip');
  step('device Compliance tab shows the assigned baseline, every check and its expected vs observed');
  await shot(page, 'device-compliance');

  // ---- dashboard tile ----
  await page.click('nav a[href="/"]');
  await page.waitForSelector('h1:has-text("Dashboard")');
  await page.waitForSelector('[data-testid="tile-compliance"]', { timeout: 30000 });
  const tile = (await page.locator('[data-testid="tile-compliance"]').textContent()) ?? '';
  if (!/%/.test(tile)) problems.push(`the dashboard compliance tile shows no percentage: ${tile.slice(0, 120)}`);
  if (!/drift alert/.test(tile)) problems.push('the dashboard compliance tile does not link the open drift alerts');
  step('dashboard tile reports fleet compliance, drifted devices and open drift alerts');
  await shot(page, 'dashboard-compliance');
  await baselineEditorGuards(page, baselineURL);
  return dir;
}

// Controls that were each a dead end for the operator, exercised on the
// baseline the walk has already saved. Nothing here saves: every dialog is
// cancelled, so the baseline the rest of the run asserts on is untouched.
async function baselineEditorGuards(page, baselineURL) {
  await page.goto(`${baselineURL}/edit`);
  await page.waitForSelector('#bl-name');

  // A custom interval is a mode of its own: picking "Custom…" used to snap the
  // select back to the preset the interval already was, so the seconds field
  // never appeared and no custom interval could be entered at all.
  await page.selectOption('#bl-interval', 'custom');
  if (!(await page.locator('#bl-interval-sec').count())) problems.push('the editor’s "Custom…" evaluation interval shows no seconds field, so a custom interval cannot be entered');
  await page.selectOption('#bl-interval', '3600');

  // The raw-JSON box and the typed form are one state: a JSON typo must not
  // keep Save disabled after the operator goes back to the form, where the
  // message is not even on screen.
  await page.click('.tbl tbody tr:has-text("Smoke file present") button:has-text("Edit")');
  await page.waitForSelector('.modal:has-text("Edit check")');
  await page.click('.modal button:has-text("Raw JSON")');
  await page.fill('#chk-raw', '{"path": "/etc/x", ');
  await page.waitForSelector('.field .err');
  await page.click('.modal button:has-text("Typed form")');
  if (await page.locator('.modal-foot button:has-text("Save check")').isDisabled()) {
    problems.push('a JSON syntax error typed in raw mode keeps Save disabled after switching back to the typed form, with no message on screen');
  }
  // `file` hides content/sha256/contains/mode/owner for state absent, so they
  // have to go with the switch: keeping them left the check permanently
  // invalid with nothing on screen to clear.
  await page.selectOption('#p-state', 'absent');
  if (await page.locator('.modal-foot button:has-text("Save check")').isDisabled()) {
    const why = (await page.locator('.modal .form-error').textContent().catch(() => '')) ?? '';
    problems.push(`switching a file check to "absent" leaves the present-only params behind and Save is stuck (${why.trim()})`);
  }
  // Changing the kind of a SAVED check is a delete + insert on the server: the
  // check loses its id, its results and its open drift alert, so the dialog
  // says so before Save is pressed.
  await page.selectOption('#chk-kind', 'firewall');
  if (!(await page.locator('.modal .banner:has-text("Changing the kind replaces this check")').count())) {
    problems.push('changing the kind of a saved check does not warn that the server deletes it and inserts a new one');
  }
  await page.click('.modal-foot button:has-text("Cancel")');
  await page.waitForSelector('.modal', { state: 'detached' });
  step('editor guards: a custom interval can be typed, a raw-JSON typo does not wedge Save, a file check switched to absent stays savable, and changing a saved check’s kind warns it is a replacement');

  // The list row opens the status view, so its own buttons have to keep their
  // clicks: Edit used to land on the status view and Delete on the baseline it
  // had just deleted.
  await page.click('nav a[href="/baselines"]');
  await page.waitForSelector('h1:has-text("Baselines")');
  await page.click('.tbl tbody tr:has-text("Smoke desired state") button:has-text("Edit")');
  await page.waitForTimeout(800);
  if (!/\/edit$/.test(page.url())) problems.push(`the baselines list Edit button lands on ${page.url()} instead of the editor: the row click runs after it`);
  else step('the baselines list Edit button opens the editor rather than the row’s status view');
  await page.goto(baselineURL);
  await page.waitForSelector('.baseline-matrix');
}

/** Poll a predicate about the filesystem the agent is managing. */
async function waitFile(pred, timeout) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    if (pred()) return true;
    await new Promise((r) => setTimeout(r, 1000));
  }
  return false;
}

function step(name) {
  covered.push(name);
  console.log(`- ${name}`);
}

async function settle(page) {
  // Never capture a dialog mid-transition: a screenshot taken inside the drawer's
  // 160 ms slide catches it half-way with the scrim not yet painted, which is what
  // made shot 30 look like a double exposure. Infinite animations (the spinner,
  // the skeleton shimmer) never finish, so only bounded ones are awaited.
  await page
    .evaluate(() =>
      Promise.race([
        Promise.all(
          document
            .getAnimations()
            .filter((a) => {
              const t = a.effect?.getComputedTiming?.();
              return t && t.iterations !== Infinity && Number.isFinite(t.endTime ?? Infinity);
            })
            .map((a) => a.finished.catch(() => {})),
        ),
        new Promise((r) => setTimeout(r, 1500)),
      ]),
    )
    .catch(() => {});
}

async function shot(page, name) {
  shotN++;
  const file = join(SHOTS, `${String(shotN).padStart(2, '0')}-${name}.png`);
  await settle(page);
  await page.screenshot({ path: file, fullPage: true });
}

async function main() {
  const browser = await chromium.launch({ executablePath, headless: true });
  // A dark OS preference: the console follows prefers-color-scheme until the user picks a theme.
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true, colorScheme: 'dark' });
  const page = await ctx.newPage();
  page.setDefaultTimeout(15000);

  // Every Content-Security-Policy violation is collected in the page as well
  // as from the console below: the event fires for blocks that Chromium may
  // log at a level the console filter drops. sessionStorage carries them
  // across the full page loads this test does (init scripts run again on each).
  await page.addInitScript(() => {
    addEventListener('securitypolicyviolation', (e) => {
      const line = `${e.violatedDirective} blocked ${e.blockedURI || 'inline'} at ${e.sourceFile || 'document'}:${e.lineNumber || 0}`;
      try {
        sessionStorage.setItem('__csp', (sessionStorage.getItem('__csp') || '') + line + '\n');
      } catch {
        /* storage disabled: the console listener still catches it */
      }
    });
  });

  page.on('console', (msg) => {
    // A Content-Security-Policy violation is reported here and nowhere else, so
    // it is matched before any filtering and whatever its level.
    if (/Refused to (load|execute|apply|connect|frame|run)|Content Security Policy/i.test(msg.text())) {
      problems.push(`CSP violation: ${msg.text()}`);
      return;
    }
    if (msg.type() !== 'error') return;
    // Chromium logs every 4xx fetch as "Failed to load resource"; the response
    // handler below already judges each status, so skip the duplicate line.
    if (/Failed to load resource/.test(msg.text())) return;
    // The viewer-role step expects these handshakes to be refused.
    if (expectViewerDenials && /WebSocket connection to .*\/ws\/(shell|desktop)\/probe.* 403/.test(msg.text())) return;
    problems.push(`console.error: ${msg.text()}`);
  });
  page.on('pageerror', (err) => problems.push(`pageerror: ${err.message}`));
  page.on('requestfailed', (req) => {
    const why = req.failure()?.errorText ?? '';
    // EventSource teardown and fetches cancelled by navigation/unmount are not failures.
    if (req.url().includes('/api/events') || why === 'net::ERR_ABORTED') return;
    problems.push(`requestfailed: ${req.method()} ${req.url()} (${why})`);
  });
  page.on('response', (res) => {
    if (res.status() < 400) return;
    if (expectAuthFailure && res.status() === 401 && res.url().endsWith('/api/auth/login')) return;
    if (expectSetupFailure && res.status() === 403 && res.url().endsWith('/api/auth/setup')) return;
    // Until the probe has seen /api/baselines answer, the feature is not in
    // this build: its 404s are expected, not failures.
    if (!baselinesReady && res.status() === 404 && /\/api\/(baselines|compliance)/.test(res.url())) return;
    // Inside a container without systemd the agent cannot list units or read
    // the journal; the API reports that as 400 and the UI must show it, not crash.
    if (res.status() === 400 && /\/api\/agents\/[^/]+\/(services|eventlog)/.test(res.url())) {
      skipped.push(`${res.url().replace(/.*\/api/, '/api')} returned 400 (no systemd in this container) — UI error state checked instead`);
      return;
    }
    problems.push(`http ${res.status()}: ${res.request().method()} ${res.url()}`);
  });

  // ---- setup ----
  const firstResponse = await page.goto(BASE + '/');
  const csp = firstResponse?.headers()['content-security-policy'] ?? '';
  for (const directive of ["default-src 'self'", "script-src 'self'", "object-src 'none'", "frame-ancestors 'none'"]) {
    if (!csp.includes(directive)) problems.push(`the document is missing CSP ${directive} (got: ${csp || 'no header'})`);
  }
  if (/script-src[^;]*unsafe-(inline|eval)/.test(csp)) problems.push(`CSP allows inline/eval script: ${csp}`);
  step('Content-Security-Policy served on the console document and the UI renders under it');
  await page.waitForURL(/\/setup$/);
  step('first-run setup page shown for empty database');
  await page.fill('#su-user', 'admin');
  await page.fill('#su-pw', 'password123!');
  await page.fill('#su-pw2', 'password123!');
  await shot(page, 'setup');
  await page.click('button[type=submit]');
  await page.waitForURL(BASE + '/');
  await page.waitForSelector('h1:has-text("Dashboard")');
  await page.waitForSelector('.stat .value');
  step('setup created admin and landed on the dashboard with stat tiles');
  await shot(page, 'dashboard');

  // ---- baselines readiness ----
  // The server, the console and the agent all ship the feature now, so a
  // missing API is a broken build, not a build the walk politely skips.
  {
    const status = await page.evaluate(() => fetch('/api/baselines', { headers: { 'X-Requested-With': 'fetch' } }).then((r) => r.status).catch(() => 0));
    baselinesReady = status === 200;
    if (baselinesReady) step('baselines API answers, so the desired-state walk runs');
    else problems.push(`GET /api/baselines returned ${status}: this build has no baselines API, so the desired-state walk cannot run`);
  }

  // ---- theme toggle ----
  const before = await page.evaluate(() => document.documentElement.dataset.theme);
  if (before !== 'dark') problems.push(`expected dark theme by default under a dark OS preference (got ${before})`);
  await page.click('button[aria-label="Toggle theme"]');
  await page.waitForFunction(() => document.documentElement.dataset.theme === 'light');
  const stored = await page.evaluate(() => localStorage.getItem('rmm.theme'));
  if (stored !== 'light') problems.push(`theme choice not persisted to localStorage (got ${stored})`);
  await shot(page, 'dashboard-light');
  await page.click('button[aria-label="Toggle theme"]');
  await page.waitForFunction(() => document.documentElement.dataset.theme === 'dark');
  step('theme toggle switches dark/light and persists the choice');

  // ---- devices + enroll ----
  await page.click('nav a[href="/devices"]');
  await page.waitForSelector('h1:has-text("Devices")');
  await page.waitForSelector('text=No devices enrolled yet');
  step('devices page renders with empty state');
  await page.click('button:has-text("Enroll device")');
  await page.waitForSelector('.drawer');
  // ux-02: a drawer must never paint translucent over the page. Nothing in its
  // ancestor chain may animate opacity (fading the host fades the panel with
  // it), and the scrim has to be painted while the panel slides in.
  const drawerPaint = await page.evaluate(() => {
    const panel = document.querySelector('.drawer');
    const host = document.querySelector('.drawer-host');
    const chain = [];
    for (let el = panel; el; el = el.parentElement) chain.push(el);
    const fading = document
      .getAnimations()
      // A ::before scrim may fade — it is behind the panel, not around it.
      .filter((a) => !a.effect?.pseudoElement && chain.includes(a.effect?.target) && a.effect.getKeyframes().some((k) => 'opacity' in k))
      .map((a) => a.effect.target.className);
    return {
      fading,
      opacity: Math.min(...chain.map((el) => Number(getComputedStyle(el).opacity))),
      scrim: getComputedStyle(host, '::before').backgroundColor,
    };
  });
  if (drawerPaint.fading.length) problems.push(`the drawer or an ancestor animates opacity (${drawerPaint.fading.join(', ')}), so it paints translucent over the page`);
  if (drawerPaint.opacity < 1) problems.push(`drawer painted at opacity ${drawerPaint.opacity}`);
  if (!/rgba\(0, 0, 0, 0\.4/.test(drawerPaint.scrim)) problems.push(`the drawer scrim is not painted (got ${drawerPaint.scrim})`);
  step('drawer opens opaque over a dimmed page (no mid-animation double exposure)');
  await page.fill('.drawer input[placeholder="workshop-pc"]', 'smoke-token');
  await page.click('.drawer button:has-text("Create token")');
  const win = await page.waitForSelector('[data-testid="enroll-windows"]');
  const winText = await win.textContent();
  if (!winText || !winText.includes('iex') || !winText.includes('/install/')) problems.push(`windows one-liner missing or malformed: ${winText}`);
  const linText = await (await page.waitForSelector('[data-testid="enroll-linux"]')).textContent();
  if (!linText || !linText.includes('curl') || !linText.includes('sudo bash')) problems.push(`linux one-liner missing or malformed: ${linText}`);
  await page.waitForSelector('.drawer .list-item:has-text("smoke-token")');
  step('enrollment token created; Windows and Linux one-liners and active token list shown');
  const token = (await (await page.waitForSelector('[data-testid="enroll-token"]')).textContent())?.trim() ?? '';
  if (haveAgent && token) {
    startAgent(token);
    step('linux agent enrolled with the token and started in the background');
  } else skipped.push(`agent flow skipped (binary ${AGENT_BIN} not found or not linux)`);
  await shot(page, 'enroll-drawer');
  // Escape must close only the topmost dialog: the delete confirm on top of the drawer, not both.
  await page.click('.drawer .list-item:has-text("smoke-token") button[aria-label="Delete token"]');
  await page.waitForSelector('.modal:has-text("Delete token")');
  await page.keyboard.press('Escape');
  await page.waitForSelector('.modal', { state: 'detached' });
  if (!(await page.locator('.drawer').count())) problems.push('Escape on a nested confirm dialog also closed the drawer underneath');
  step('Escape closes only the topmost dialog (confirm over drawer)');
  // Tab must cycle inside the open dialog.
  for (let i = 0; i < 40; i++) {
    await page.keyboard.press('Tab');
    const inside = await page.evaluate(() => !!document.activeElement?.closest('.drawer'));
    if (!inside) {
      problems.push(`focus escaped the drawer after ${i + 1} Tab presses`);
      break;
    }
  }
  step('focus stays trapped inside the open drawer while tabbing');
  await page.keyboard.press('Escape');
  await page.waitForSelector('.drawer', { state: 'detached' });

  // groups
  await page.click('button:has-text("Groups")');
  await page.fill('.modal input[placeholder="New group name"]', 'Lab');
  await page.click('.modal button:has-text("Add")');
  await page.waitForSelector('.modal .list-item:has-text("Lab")');
  step('device group created inline');
  await shot(page, 'groups');
  await page.click('.modal button:has-text("Done")');

  // ---- scripts ----
  await page.click('nav a[href="/scripts"]');
  await page.waitForSelector('h1:has-text("Scripts")');
  await shot(page, 'scripts-empty');
  await page.click('button:has-text("New script")');
  await page.waitForURL(/\/scripts\/new$/);
  await page.fill('#sc-name', 'Smoke hello');
  await page.fill('#sc-cat', 'Testing');
  await page.selectOption('#sc-lang', 'bash');
  await page.fill('.editor textarea', '#!/usr/bin/env bash\necho "hello $1"\n');
  await page.click('.card-head:has-text("Parameters") button:has-text("Add")');
  await page.fill('input[aria-label="Parameter name"]', 'name');
  await page.click('button:has-text("Create")');
  await page.waitForURL(/\/scripts\/\d+$/);
  await page.waitForSelector('.toast:has-text("Script created")');
  step('script created via editor (name, category, language, body, parameter)');
  await shot(page, 'script-editor');
  await page.click('nav a[href="/scripts"]');
  await page.waitForSelector('.tbl a:has-text("Smoke hello")');
  await shot(page, 'scripts');

  // ---- runs ----
  await page.click('nav a[href="/runs"]');
  await page.waitForSelector('h1:has-text("Runs")');
  await page.waitForSelector('text=No runs yet');
  step('runs page renders');
  await shot(page, 'runs');

  // ---- tasks ----
  await page.click('nav a[href="/tasks"]');
  await page.waitForSelector('h1:has-text("Scheduled tasks")');
  await page.click('button:has-text("New task")');
  await page.waitForSelector('.modal');
  await page.fill('.modal input >> nth=0', 'Nightly hello');
  await page.selectOption('.modal select >> nth=1', { label: 'Smoke hello (bash)' });
  // schedule: daily at 03:00
  const cronSelect = page.locator('.modal select').filter({ hasText: 'Manual only' });
  await cronSelect.selectOption('daily');
  await page.click('.modal button:has-text("Create")');
  await page.waitForSelector('.toast:has-text("Task created")');
  await page.waitForSelector('.tbl b:has-text("Nightly hello")');
  await page.waitForSelector('.tbl td:has-text("At 3:00 AM, every day")');
  step('scheduled task created (script kind, daily preset) and listed with human-readable schedule');
  await shot(page, 'tasks');

  // invalid cron is rejected by the server and surfaced
  await page.click('button:has-text("New task")');
  await page.fill('.modal input >> nth=0', 'Bad cron');
  await page.selectOption('.modal select >> nth=1', { label: 'Smoke hello (bash)' });
  await page.locator('.modal select').filter({ hasText: 'Manual only' }).selectOption('custom');
  await page.fill('.modal input.mono', '99 99 * * *');
  await page.waitForSelector('.modal >> text=/outside/');
  step('client-side cron validation flags an out-of-range field');
  await page.keyboard.press('Escape');
  await page.waitForSelector('.modal', { state: 'detached' });

  // ---- automations ----
  await page.click('nav a[href="/automations"]');
  await page.waitForSelector('h1:has-text("Automations")');
  await page.click('button:has-text("New automation")');
  await page.fill('.modal input >> nth=0', 'Email on critical');
  await page.selectOption('.modal select >> nth=1', 'email');
  await page.click('.modal button:has-text("Create")');
  await page.waitForSelector('.toast:has-text("Automation created")');
  await page.waitForSelector('.tbl b:has-text("Email on critical")');
  step('automation created (alert_opened -> email)');
  await shot(page, 'automations');

  // ---- alerts + rules ----
  await page.click('nav a[href="/alerts"]');
  await page.waitForSelector('h1:has-text("Alerts")');
  // seeded rules may already have fired on the real agent (a full mount, a
  // pending reboot): either the empty state or a populated table is fine
  await page.locator('text=No open alerts').or(page.locator('table.tbl tbody tr').first()).first().waitFor();
  await shot(page, 'alerts');
  await page.click('.tabs button:has-text("Alert rules")');
  await page.click('button:has-text("New rule")');
  await page.fill('.modal input >> nth=0', 'High CPU');
  await page.click('.modal button:has-text("Create")');
  await page.waitForSelector('.toast:has-text("Rule created")');
  await page.waitForSelector('.tbl b:has-text("High CPU")');
  step('alert rule created (cpu >= 90% for 5 min)');
  await shot(page, 'alert-rules');

  // ---- patches + policies ----
  await page.click('nav a[href="/patches"]');
  await page.waitForSelector('h1:has-text("Patches")');
  await page.waitForSelector('text=No patch data');
  await shot(page, 'patches');
  await page.click('.tabs button:has-text("Policies")');
  await page.click('button:has-text("New policy")');
  await page.fill('.modal input >> nth=0', 'Security weekly');
  await page.click('.modal button:has-text("Create")');
  await page.waitForSelector('.toast:has-text("Policy created")');
  await page.waitForSelector('.tbl b:has-text("Security weekly")');
  step('patch policy created (scan every 6 hours, manual install)');
  await shot(page, 'patch-policies');

  // ---- settings ----
  await page.click('nav a[href="/settings"]');
  await page.waitForSelector('h1:has-text("Settings")');
  {
    // the system card shows whatever version the binary was stamped with
    const state = await page.evaluate(() => fetch('/api/auth/state').then((r) => r.json()));
    await page.waitForSelector(`dl.kv dd:has-text("${state.version}")`);
  }
  // Clearing first guarantees an input event even when the field already
  // holds the value being typed (React only fires change when the value
  // really changes, and a save landing mid-edit can put the old one back).
  const setPublicURL = async (url) => {
    await page.fill('input[type=url]', '');
    await page.fill('input[type=url]', url);
    await page.click('button:has-text("Save changes")');
  };
  await setPublicURL('http://127.0.0.1:18080');
  await page.waitForSelector('.toast:has-text("Settings saved")');
  step('settings page renders system card; public URL saved');
  await shot(page, 'settings');

  // ux-01: a burst of toasts must not bury the page. Six saves in a row leave
  // three on screen at most, and they clear themselves without a click.
  let maxToasts = 0;
  for (let i = 0; i < 6; i++) {
    // Save is disabled until the form is dirty, so each pass changes the public
    // URL; the last one puts the value the step above saved back.
    await setPublicURL(i < 5 ? `http://127.0.0.1:1810${i}` : 'http://127.0.0.1:18080');
    maxToasts = Math.max(maxToasts, await page.locator('.toast').count());
  }
  maxToasts = Math.max(maxToasts, await page.locator('.toast').count());
  await shot(page, 'toast-cap');
  if (maxToasts > 3) problems.push(`${maxToasts} toasts stacked at once (at most 3 may be visible)`);
  if (maxToasts < 3) problems.push(`the toast burst never stacked (${maxToasts} at most), so the cap is untested`);
  await page.waitForFunction(() => document.querySelectorAll('.toast').length === 0, null, { timeout: 9000 });
  step('toasts cap at three on screen and expire on their own');

  // ux-03: the messages the cap dropped are still readable afterwards.
  await page.click('button[aria-label^="Activity"]');
  await page.waitForSelector('.notif-menu .notif-item');
  const logged = await page.locator('.notif-menu .notif-item:has-text("Settings saved")').count();
  if (logged < 4) problems.push(`the activity log kept ${logged} of the 7 "Settings saved" messages`);
  await page.keyboard.press('Escape');
  await page.waitForSelector('.notif-menu', { state: 'detached' });
  step('activity log keeps the messages the toast cap dropped');

  // ---- users ----
  await page.click('nav a[href="/users"]');
  await page.waitForSelector('h1:has-text("Users")');
  await page.waitForSelector('.tbl b:has-text("admin")');
  await page.click('button:has-text("New user")');
  await page.fill('.modal input >> nth=0', 'viewer1');
  await page.fill('.modal input[type=password]', 'viewerpass1');
  await page.selectOption('.modal select', 'viewer');
  await page.click('.modal button:has-text("Create")');
  await page.waitForSelector('.tbl b:has-text("viewer1")');
  step('user created with viewer role');
  await shot(page, 'users');

  // ---- audit ----
  await page.click('nav a[href="/audit"]');
  await page.waitForSelector('h1:has-text("Audit log")');
  await page.waitForSelector('.tbl .chip:has-text("script.create")');
  step('audit log lists the actions performed above');
  await shot(page, 'audit');

  // ux-04: every grid can leave the browser. The file is what is on screen.
  const [csv] = await Promise.all([page.waitForEvent('download'), page.click('.tbl-foot button:has-text("Export CSV")')]);
  const csvName = csv.suggestedFilename();
  const csvPath = await csv.path();
  const csvText = csvPath ? readFileSync(csvPath, 'utf8') : '';
  if (!/^audit-\d{4}-\d{2}-\d{2}\.csv$/.test(csvName)) problems.push(`unexpected CSV filename: ${csvName}`);
  const header = csvText.replace(/^\uFEFF/, '').split('\r\n')[0];
  if (header !== 'Time,User,IP,Action,Target,Details') problems.push(`unexpected CSV header: ${header}`);
  if (!/script\.create/.test(csvText)) problems.push('the exported audit CSV is missing the rows on screen');
  // The file must be what is on screen, not the whole table: filter, export again.
  await page.fill('input[aria-label="Filter audit"]', 'script.create');
  await page.waitForFunction(() => document.querySelectorAll('table.tbl tbody tr').length < 8);
  const [csv2] = await Promise.all([page.waitForEvent('download'), page.click('.tbl-foot button:has-text("Export CSV")')]);
  const csv2Path = await csv2.path();
  const rows2 = (csv2Path ? readFileSync(csv2Path, 'utf8') : '').replace(/^\uFEFF/, '').split('\r\n').filter(Boolean).slice(1);
  const rows1 = csvText.replace(/^\uFEFF/, '').split('\r\n').filter(Boolean).slice(1);
  if (!rows2.length || rows2.length >= rows1.length) problems.push(`the filtered CSV has ${rows2.length} rows against ${rows1.length} unfiltered`);
  if (rows2.some((l) => !l.includes('script.create'))) problems.push('the filtered CSV contains rows the filter had hidden');
  await page.fill('input[aria-label="Filter audit"]', '');
  step('audit grid exports the rows on screen as CSV, filters included');

  // ---- account + totp begin ----
  await page.click('nav a[href="/account"]');
  await page.waitForSelector('h1:has-text("Account")');
  await page.click('button:has-text("Set up authenticator")');
  await page.waitForSelector('img[alt="TOTP QR code"]');
  step('account page: TOTP setup shows QR code and secret');
  await shot(page, 'account-totp');
  await page.click('button:has-text("Cancel")');

  // ---- keyboard shortcuts ----
  await page.click('nav a[href="/"]');
  await page.waitForSelector('h1:has-text("Dashboard")');
  await page.keyboard.press('g');
  await page.keyboard.press('d');
  await page.waitForURL(/\/devices$/);
  await page.keyboard.press('g');
  await page.keyboard.press('r');
  await page.waitForURL(/\/runs$/);
  step('g-prefixed shortcuts navigate between pages');
  await page.keyboard.press('?');
  await page.waitForSelector('.modal:has-text("Keyboard shortcuts")');
  await page.keyboard.press('Escape');
  await page.waitForSelector('.modal', { state: 'detached' });
  step('? opens the shortcut sheet and Escape closes it');
  // Typing into a field must not navigate away mid-word.
  await page.fill('input[aria-label="Search runs"]', 'grd');
  if (!/\/runs$/.test(new URL(page.url()).pathname)) problems.push('a shortcut fired while typing in a search box');
  await page.fill('input[aria-label="Search runs"]', '');
  step('shortcuts stay out of the way while typing');

  // ---- global search + device search ----
  await page.fill('input[aria-label="Search devices"]', 'nothing');
  await page.waitForSelector('.search-results:has-text("No matching devices")');
  await page.keyboard.press('Escape');
  step('global search opens and reports no matches');


  // ---- live device (real agent) ----
  if (agentProc) {
    const host = hostname();
    await page.click('nav a[href="/devices"]');
    await page.waitForSelector(`.tbl a:has-text("${host}")`, { timeout: 60000 });
    await page.waitForSelector('.tbl tr:has(.dot.on)', { timeout: 60000 });
    step('enrolled agent appears online in the device list via live events');
    await shot(page, 'devices-online');

    // global search finds it and navigates
    await page.fill('input[aria-label="Search devices"]', host.slice(0, 4));
    await page.waitForSelector(`.search-results .item:has-text("${host}")`);
    await page.keyboard.press('Enter');
    await page.waitForURL(/\/devices\/[0-9a-f]+$/);
    step('global search finds the device and Enter opens it');

    await page.waitForSelector('h1:has-text("' + host + '")');
    await page.waitForSelector('.card-head:has-text("Hardware")');
    await page.waitForSelector('dl.kv dd:has-text("c/")', { timeout: 60000 }); // cpu cores/threads from inventory
    await page.waitForSelector('.card-head:has-text("Metrics")');
    step('device overview shows inventory (hardware, OS, disks, network) and the metrics panel');
    await shot(page, 'device-overview');

    // identity edits round-trip
    await page.fill('.card-head:has-text("Identity") ~ .card-body input >> nth=0', 'Smoke Box');
    await page.click('.card-head:has-text("Identity") ~ .card-body .tag-input');
    await page.keyboard.type('smoke');
    await page.keyboard.press('Enter');
    await page.click('.card-head:has-text("Identity") button:has-text("Save")');
    await page.waitForSelector('.toast:has-text("Device saved")');
    await page.waitForSelector('h1:has-text("Smoke Box")');
    step('identity card: display name and tag saved and reflected in the header');

    const tabs = async (label) => {
      await page.click(`.tabs a:has-text("${label}")`);
    };
    await tabs('Processes');
    await page.waitForSelector('.tbl tbody tr td.num', { timeout: 30000 });
    step('processes tab lists live processes');
    await shot(page, 'device-processes');

    await tabs('Services');
    await Promise.race([page.waitForSelector('.tbl tbody tr .chip', { timeout: 30000 }), page.waitForSelector('.banner.danger', { timeout: 30000 })]);
    step('services tab renders rows or a clear error (no systemd here)');
    await shot(page, 'device-services');

    await tabs('Software');
    await page.waitForSelector('.tbl tbody tr', { timeout: 30000 });
    step('software tab lists installed packages from inventory');

    await tabs('Files');
    await page.waitForSelector('.tbl tbody tr', { timeout: 30000 });
    await page.click('.tbl tbody tr:first-child a'); // roots list: "/" first on Linux
    await page.waitForSelector('.tbl a:has-text("etc")', { timeout: 30000 });
    await page.click('.tbl a:has-text("etc")');
    await page.waitForSelector('.tbl a:has-text("hostname"), .tbl td:has-text("hostname")', { timeout: 30000 });
    step('file browser lists / and navigates into /etc');
    await shot(page, 'device-files');

    await tabs('Event log');
    await Promise.race([page.waitForSelector('.tbl tbody tr', { timeout: 30000 }), page.waitForSelector('.banner.danger', { timeout: 30000 }), page.waitForSelector('.empty', { timeout: 30000 })]);
    step('event log tab queries the journal and renders rows, empty state or a clear error');

    await tabs('Terminal');
    await page.waitForSelector('.statusline:has-text("Connected")', { timeout: 30000 });
    // wait for the shell prompt so the keystrokes land in a live line discipline
    await page.waitForFunction(() => /[$#]\s*$/.test((document.querySelector('.xterm-rows')?.textContent ?? '').trimEnd()), null, { timeout: 30000 });
    await page.focus('.xterm-helper-textarea');
    await page.keyboard.type('echo SMOKE_$((40+2))', { delay: 10 });
    await page.keyboard.press('Enter');
    await page.waitForFunction(() => (document.querySelector('.xterm-rows')?.textContent ?? '').includes('SMOKE_42'), null, { timeout: 30000 });
    step('terminal: shell opened over /ws/shell, command typed and its output rendered');
    await shot(page, 'device-terminal');
    await page.click('button:has-text("Disconnect")');
    await page.waitForSelector('.statusline:has-text("Session closed"), .statusline:has-text("Disconnected")');

    await tabs('Remote Desktop');
    await page.waitForSelector('.desktop-status', { timeout: 10000 });
    await page.waitForSelector('.statusline:has-text("Error"), .statusline:has-text("Disconnected"), .statusline:has-text("Connected ·")', { timeout: 70000 });
    step('remote desktop viewer connects over /ws/desktop and reports the helper outcome without crashing (headless container has no display)');
    await shot(page, 'device-desktop');
    await desktopViewerWithFakeHelper(page, ctx);

    // run the library script from the device header and watch the output stream
    await tabs('Overview');
    await page.click('.page-head button:has-text("Run script")');
    await page.waitForSelector('.modal');
    await page.click('.modal label:has-text("Smoke hello") input[type=radio]');
    await page.fill('.modal .field:has-text("name") input', 'world');
    await page.click('.modal button:has-text("Run on 1 device")');
    await page.waitForSelector('.modal .list-item .chip:has-text("done")', { timeout: 60000 });
    await page.waitForFunction(() => (document.querySelector('.modal .output')?.textContent ?? '').includes('hello world'), null, { timeout: 30000 });
    step('run dialog: library script with parameter executed on the device, live status and stdout shown');
    await shot(page, 'device-run-results');
    await page.click('.modal-foot button:has-text("Close")');

    await tabs('Runs');
    await page.waitForSelector('.tbl tbody tr:has-text("Smoke hello")');
    await page.click('.tbl tbody tr:has-text("Smoke hello")');
    await page.waitForSelector('.drawer');
    await page.waitForFunction(() => (document.querySelector('.drawer .output')?.textContent ?? '').includes('hello world'));
    step('device runs tab and run drawer show the stored output');
    await shot(page, 'device-run-drawer');
    await page.keyboard.press('Escape');
    await page.waitForSelector('.drawer', { state: 'detached' });
    // Row click is the only way to open a run, so the row must also open from the keyboard.
    await page.focus('.tbl tbody tr:has-text("Smoke hello")');
    await page.keyboard.press('Enter');
    await page.waitForSelector('.drawer');
    step('clickable table rows open with Enter from the keyboard');
    await page.keyboard.press('Escape');
    await page.waitForSelector('.drawer', { state: 'detached' });

    await tabs('Events');
    await page.waitForSelector('.table-wrap');
    await tabs('Patches');
    await page.waitForSelector('button:has-text("Scan now")');
    step('events and patches tabs render for the device');

    if (baselinesReady) baselineDir = await baselineWalk(page);

    // stop the agent: the device must go offline live
    stopAgent();
    await page.click('nav a[href="/devices"]');
    await page.waitForSelector('.tbl tr:has(.dot.off):has-text("Smoke Box")', { timeout: 60000 });
    step('stopping the agent flips the device offline in the list via agent_offline');

    // dashboard reflects the fleet
    await page.click('nav a[href="/"]');
    await page.waitForSelector('.stat:has-text("Devices online") .foot:has-text("1 offline")');
    step('dashboard fleet counters reflect the enrolled device');
    await shot(page, 'dashboard-with-device');

    // delete the device
    await page.click('nav a[href="/devices"]');
    await page.click('.tbl a:has-text("Smoke Box")');
    await page.waitForSelector('h1:has-text("Smoke Box")');
    await page.click('button[aria-label="More"]');
    await page.click('.menu button:has-text("Delete device")');
    await page.click('.modal button:has-text("Delete device")');
    await page.waitForURL(/\/devices$/);
    await page.waitForSelector('text=No devices enrolled yet');
    step('device deleted with confirmation; list returns to empty state');
  }

  // ---- narrow layout (~1000px): nav collapses to icons, nothing scrolls sideways ----
  await page.setViewportSize({ width: 1000, height: 800 });
  await page.click('nav a[href="/devices"]');
  await page.waitForSelector('h1:has-text("Devices")');
  const narrow = await page.evaluate(() => ({
    nav: document.querySelector('nav.nav')?.getBoundingClientRect().width ?? 0,
    overflow: document.documentElement.scrollWidth > document.documentElement.clientWidth,
    navLabel: document.querySelector('nav a[href="/devices"]')?.getAttribute('aria-label') ?? '',
  }));
  if (narrow.nav > 80) problems.push(`nav did not collapse at 1000px (width ${narrow.nav})`);
  if (narrow.overflow) problems.push('page scrolls horizontally at 1000px');
  if (narrow.navLabel !== 'Devices') problems.push('collapsed nav link lost its accessible name');
  await shot(page, 'devices-1000px');
  await page.setViewportSize({ width: 1440, height: 900 });
  step('1000px viewport: nav collapses to labelled icons and nothing overflows horizontally');

  // ---- phone (390px): off-canvas nav, no sideways scrolling ----
  await page.setViewportSize({ width: 390, height: 780 });
  await page.goto(BASE + '/devices');
  await page.waitForSelector('h1:has-text("Devices")');
  const phone = await page.evaluate(() => ({
    nav: document.querySelector('nav.nav')?.getBoundingClientRect().right ?? 0,
    overflow: document.documentElement.scrollWidth > document.documentElement.clientWidth + 1,
    toggle: !!document.querySelector('.nav-toggle') && getComputedStyle(document.querySelector('.nav-toggle')).display !== 'none',
  }));
  if (phone.nav > 1) problems.push(`the nav rail still takes ${phone.nav}px at 390px instead of sliding off-canvas`);
  if (phone.overflow) problems.push('page scrolls horizontally at 390px');
  if (!phone.toggle) problems.push('no menu button at 390px, so the nav is unreachable');
  await shot(page, 'devices-390px');
  await page.click('.nav-toggle');
  await page.waitForFunction(() => (document.querySelector('nav.nav')?.getBoundingClientRect().left ?? -1) >= 0);
  await shot(page, 'devices-390px-nav');
  await page.click('nav a[href="/scripts"]');
  await page.waitForSelector('h1:has-text("Scripts")');
  await page.waitForFunction(() => (document.querySelector('nav.nav')?.getBoundingClientRect().right ?? 1) <= 1);
  step('390px viewport: nav is an off-canvas drawer that opens, navigates and closes; no horizontal scrolling');
  await page.setViewportSize({ width: 1440, height: 900 });

  // ---- viewer role: read-only UI ----
  await page.click('button[aria-label="User menu"]');
  await page.click('.menu button:has-text("Sign out")');
  await page.waitForURL(/\/login$/);
  step('sign out returns to login');
  await page.fill('#li-user', 'viewer1');
  await page.fill('#li-pw', 'wrongpassword');
  expectAuthFailure = true;
  await page.click('button[type=submit]');
  await page.waitForSelector('.form-error:has-text("Invalid username or password")');
  expectAuthFailure = false;
  step('login rejects a wrong password with a clear message');
  await page.fill('#li-pw', 'viewerpass1');
  await page.click('button[type=submit]');
  await page.waitForURL(BASE + '/');
  await page.waitForSelector('h1:has-text("Dashboard")');
  if (await page.locator('nav a[href="/settings"]').count()) problems.push('viewer can see the admin Settings nav item');
  await page.click('nav a[href="/scripts"]');
  await page.waitForSelector('h1:has-text("Scripts")');
  if (await page.locator('button:has-text("New script")').count()) problems.push('viewer sees the New script button');
  if (baselinesReady) {
    await page.click('nav a[href="/baselines"]');
    await page.waitForSelector('h1:has-text("Baselines")');
    if (await page.locator('button:has-text("New baseline")').count()) problems.push('viewer sees the New baseline button');
    if (await page.locator('.cell-actions button:has-text("Delete")').count()) problems.push('viewer sees the baseline delete buttons');
    await page.click('nav a[href="/scripts"]');
    await page.waitForSelector('h1:has-text("Scripts")');
  }
  step('viewer login: admin nav hidden and mutating buttons absent');
  await shot(page, 'viewer-scripts');
  await page.goto(BASE + '/settings');
  await page.waitForURL(BASE + '/');
  step('viewer is redirected away from /settings');

  // A viewer may look at everything and touch nothing: a terminal, a remote
  // desktop session and a file download are refused by the server, not just
  // hidden by the UI.
  expectViewerDenials = true;
  const viewerDenied = await page.evaluate(async () => {
    const out = {};
    out.download = (await fetch('/api/agents/probe/fs/download?path=/etc/shadow', { headers: { 'X-Requested-With': 'fetch' } })).status;
    // An enrollment token is a bearer credential for adding a device to the
    // fleet, so the listing that carries the token values is writer-only too.
    const enroll = await fetch('/api/enroll', { headers: { 'X-Requested-With': 'fetch' } });
    out.enroll = enroll.status;
    out.enrollBody = await enroll.text();
    const sock = (path) =>
      new Promise((resolve) => {
        const ws = new WebSocket(new URL(path, location.href).href.replace(/^http/, 'ws'));
        ws.onopen = () => { ws.close(); resolve('opened'); };
        ws.onerror = () => resolve('refused');
        ws.onclose = (e) => resolve(e.wasClean && e.code === 1000 ? 'opened' : 'refused');
      });
    out.shell = await sock('/ws/shell/probe');
    out.desktop = await sock('/ws/desktop/probe');
    return out;
  });
  expectViewerDenials = false;
  if (viewerDenied.download !== 403) problems.push(`viewer could request a file download (status ${viewerDenied.download}, want 403)`);
  if (viewerDenied.enroll !== 403) problems.push(`viewer could list enrollment tokens (status ${viewerDenied.enroll}, want 403)`);
  if (/"token"\s*:/.test(viewerDenied.enrollBody)) problems.push('enrollment token values were returned to a read-only account');
  if (viewerDenied.shell !== 'refused') problems.push('viewer opened a terminal WebSocket');
  if (viewerDenied.desktop !== 'refused') problems.push('viewer opened a remote desktop WebSocket');
  step('viewer is refused the terminal, the remote desktop, file downloads and enrollment tokens by the server');

  // ---- deep link + SPA fallback ----
  await page.goto(BASE + '/tasks');
  await page.waitForSelector('h1:has-text("Scheduled tasks")');
  step('deep link to /tasks served by SPA fallback');

  // csp-01: nothing the console did along the way was refused by the policy.
  const cspSeen = (await page.evaluate(() => sessionStorage.getItem('__csp') || '')).split('\n').filter(Boolean);
  for (const v of cspSeen) problems.push(`CSP violation: ${v}`);
  step('no Content-Security-Policy violation anywhere in the walk');

  await browser.close();
  stopAgent();
  if (baselineDir) rmSync(baselineDir, { recursive: true, force: true });
}

main()
  .then(() => {
    // The viewer is expected to be denied on the settings API; drop those.
    // Deliberate probes: the viewer is expected to be denied on the settings
    // API and on the three endpoints the viewer-role check above pokes.
    const real = problems.filter(
      (p) => !/http 403: GET .*\/api\/settings/.test(p) && !/http 403: GET .*(\/fs\/download|\/api\/enroll|\/ws\/shell\/probe|\/ws\/desktop\/probe)/.test(p),
    );
    console.log('\nCovered:');
    for (const c of covered) console.log(`  ✓ ${c}`);
    if (skipped.length) {
      console.log('\nNotes:');
      for (const c of skipped) console.log(`  · ${c}`);
    }
    if (real.length) {
      console.log('\nProblems:');
      for (const p of real) console.log(`  ✗ ${p}`);
      process.exit(1);
    }
    console.log(`\nOK — ${covered.length} checks, ${shotN} screenshots in ${SHOTS}`);
  })
  .catch((err) => {
    stopAgent();
    console.error('\nSMOKE FAILED:', err);
    if (problems.length) {
      console.log('Problems so far:');
      for (const p of problems) console.log(`  ✗ ${p}`);
    }
    process.exit(1);
  });
