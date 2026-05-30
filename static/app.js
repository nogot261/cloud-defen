const $ = (id) => document.getElementById(id);
const HISTORY_KEY = "cloudRiskMonitor.history.v2";

const presets = {
  high: {
    ip: "31.170.22.211",
    country: "LV",
    asn: "Sia Nano IT hosting network",
    previous_countries: "RU, AM",
    failed_logins: 17,
    downloads: 42,
    protected_requests: 180,
    device_seen: true,
    webrtc_leak: false,
    ipv6_enabled: false,
  },
  low: {
    ip: "87.249.41.10",
    country: "RU",
    asn: "Residential ISP",
    previous_countries: "RU",
    failed_logins: 0,
    downloads: 3,
    protected_requests: 18,
    device_seen: true,
    webrtc_leak: false,
    ipv6_enabled: true,
  },
};

let lastDeviceProfile = {};
let lastNetworkProfile = {};
let lastFingerprintHash = "";
let lastPublicIpSource = "";

function detectBrowserFields() {
  $("timezone").value = Intl.DateTimeFormat().resolvedOptions().timeZone || "unknown";
  $("accept_language").value = navigator.languages?.join(", ") || navigator.language || "unknown";
}

function setAutofillStatus(text) {
  $("autofillStatus").textContent = text;
}

function timeout(ms) {
  return new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), ms));
}

async function fetchJsonWithTimeout(url, ms = 3500) {
  const response = await Promise.race([
    fetch(url, { cache: "no-store" }),
    timeout(ms),
  ]);
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
}

async function sha256(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function getHistory() {
  try {
    return JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
  } catch {
    return [];
  }
}

function saveSnapshot(snapshot) {
  const history = [snapshot, ...getHistory()].slice(0, 8);
  localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
}

function previousSnapshot() {
  return getHistory()[0] || null;
}

function formatChange(label, before, after) {
  const oldValue = before || "нет";
  const newValue = after || "нет";
  const changed = oldValue !== newValue;
  return `<div class="change ${changed ? "changed" : ""}">
    <span>${escapeHtml(label)}</span>
    <strong>${escapeHtml(oldValue)} -> ${escapeHtml(newValue)}</strong>
  </div>`;
}

async function getUserAgentHints() {
  if (!navigator.userAgentData?.getHighEntropyValues) {
    return { available: false };
  }
  try {
    return {
      available: true,
      ...(await navigator.userAgentData.getHighEntropyValues([
        "architecture",
        "bitness",
        "brands",
        "fullVersionList",
        "mobile",
        "model",
        "platform",
        "platformVersion",
        "wow64",
      ])),
    };
  } catch {
    return { available: false };
  }
}

function formatBytes(value) {
  if (!Number.isFinite(value)) return "unknown";
  const units = ["B", "KB", "MB", "GB"];
  let size = value;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${size.toFixed(unit ? 1 : 0)} ${units[unit]}`;
}

async function getBatteryProfile() {
  if (!navigator.getBattery) {
    return {
      supported: false,
      note: "Battery API hidden or unsupported",
      capacity_mah: "not exposed by browsers",
    };
  }
  try {
    const battery = await navigator.getBattery();
    return {
      supported: true,
      level_percent: Math.round(battery.level * 100),
      charging: battery.charging,
      charging_time_sec: Number.isFinite(battery.chargingTime) ? battery.chargingTime : "unknown",
      discharging_time_sec: Number.isFinite(battery.dischargingTime) ? battery.dischargingTime : "unknown",
      capacity_mah: "not exposed by browsers",
    };
  } catch {
    return {
      supported: false,
      note: "Battery API blocked",
      capacity_mah: "not exposed by browsers",
    };
  }
}

async function getClockProfile() {
  const localBefore = Date.now();
  const perfBefore = performance.now();
  try {
    const data = await fetchJsonWithTimeout(`/api/time?t=${Date.now()}`, 2500);
    const localAfter = Date.now();
    const roundTripMs = localAfter - localBefore;
    const estimatedServerMs = Number(data.server_epoch_ms) + roundTripMs / 2;
    return {
      local_epoch_ms: localAfter,
      local_iso: new Date(localAfter).toISOString(),
      local_string: new Date(localAfter).toString(),
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "unknown",
      timezone_offset_min: new Date().getTimezoneOffset(),
      server_epoch_ms: data.server_epoch_ms,
      server_timezone: data.server_timezone,
      round_trip_ms: roundTripMs,
      server_skew_ms: Math.round(localAfter - estimatedServerMs),
      performance_time_origin_ms: Math.round(performance.timeOrigin || 0),
      performance_now_ms: Math.round(performance.now()),
      performance_elapsed_ms: Math.round(performance.now() - perfBefore),
    };
  } catch {
    return {
      local_epoch_ms: Date.now(),
      local_iso: new Date().toISOString(),
      local_string: new Date().toString(),
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "unknown",
      timezone_offset_min: new Date().getTimezoneOffset(),
      server_skew_ms: "unknown",
    };
  }
}

function getMemoryProfile() {
  const memory = performance.memory;
  if (!memory) {
    return {
      supported: false,
      note: "performance.memory is Chrome-only and non-standard",
      total_system_ram: "not exposed by browsers",
    };
  }
  const used = memory.usedJSHeapSize || 0;
  const limit = memory.jsHeapSizeLimit || 0;
  return {
    supported: true,
    used_js_heap_size: used,
    total_js_heap_size: memory.totalJSHeapSize,
    js_heap_size_limit: limit,
    used_js_heap_size_human: formatBytes(used),
    total_js_heap_size_human: formatBytes(memory.totalJSHeapSize),
    js_heap_size_limit_human: formatBytes(limit),
    js_heap_usage_percent: limit ? Math.round((used / limit) * 1000) / 10 : "unknown",
    total_system_ram: "not exposed by browsers",
  };
}

async function measureEventLoopLag() {
  const samples = [];
  for (let i = 0; i < 5; i += 1) {
    const start = performance.now();
    await new Promise((resolve) => setTimeout(resolve, 50));
    samples.push(performance.now() - start - 50);
  }
  return Math.max(0, Math.round(Math.max(...samples)));
}

async function measureFps(durationMs = 700) {
  return new Promise((resolve) => {
    let frames = 0;
    const start = performance.now();
    const tick = () => {
      frames += 1;
      if (performance.now() - start >= durationMs) {
        resolve(Math.round((frames * 1000) / (performance.now() - start)));
      } else {
        requestAnimationFrame(tick);
      }
    };
    requestAnimationFrame(tick);
  });
}

function runCpuBenchmark(durationMs = 220) {
  const start = performance.now();
  let iterations = 0;
  let acc = 0;
  while (performance.now() - start < durationMs) {
    for (let i = 1; i < 1200; i += 1) {
      acc += Math.sqrt(i * 13.37) % 7;
    }
    iterations += 1200;
  }
  const elapsed = performance.now() - start;
  return {
    duration_ms: Math.round(elapsed),
    iterations,
    iterations_per_ms: Math.round(iterations / elapsed),
    checksum: Math.round(acc),
    note: "synthetic JS benchmark, not real OS CPU utilization",
  };
}

async function getPerformanceProfile() {
  const [eventLoopLagMs, fps] = await Promise.all([
    measureEventLoopLag(),
    measureFps(),
  ]);
  return {
    memory: getMemoryProfile(),
    event_loop_lag_ms: eventLoopLagMs,
    approximate_fps: fps,
    cpu_benchmark: runCpuBenchmark(),
    cpu_load_percent: "not exposed by browsers",
    gpu_load_percent: "not exposed by browsers",
    ram_load_percent: "not exposed by browsers",
  };
}

function getWebglProfile() {
  const canvas = document.createElement("canvas");
  const gl = canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
  if (!gl) return { webgl_supported: false };

  const debug = gl.getExtension("WEBGL_debug_renderer_info");
  const params = {
    webgl_supported: true,
    webgl_vendor: gl.getParameter(gl.VENDOR),
    webgl_renderer: gl.getParameter(gl.RENDERER),
    webgl_version: gl.getParameter(gl.VERSION),
    webgl_shading_language: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
    max_texture_size: gl.getParameter(gl.MAX_TEXTURE_SIZE),
    max_viewport_dims: Array.from(gl.getParameter(gl.MAX_VIEWPORT_DIMS) || []),
  };

  if (debug) {
    params.webgl_unmasked_vendor = gl.getParameter(debug.UNMASKED_VENDOR_WEBGL);
    params.webgl_unmasked_renderer = gl.getParameter(debug.UNMASKED_RENDERER_WEBGL);
    params.webgl_renderer = params.webgl_unmasked_renderer || params.webgl_renderer;
  }

  return params;
}

async function getCanvasHash() {
  const canvas = document.createElement("canvas");
  canvas.width = 280;
  canvas.height = 80;
  const ctx = canvas.getContext("2d");
  if (!ctx) return "unavailable";
  ctx.textBaseline = "top";
  ctx.fillStyle = "#f4f7f5";
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.font = "16px Arial";
  ctx.fillStyle = "#17211b";
  ctx.fillText("CloudRiskMonitor VPN fingerprint 12345", 8, 12);
  ctx.fillStyle = "rgba(14,124,102,0.62)";
  ctx.beginPath();
  ctx.arc(220, 42, 28, 0, Math.PI * 2);
  ctx.fill();
  return sha256(canvas.toDataURL());
}

async function getAudioHash() {
  const AudioCtx = window.OfflineAudioContext || window.webkitOfflineAudioContext;
  if (!AudioCtx) return "unavailable";
  try {
    const ctx = new AudioCtx(1, 5000, 44100);
    const oscillator = ctx.createOscillator();
    const compressor = ctx.createDynamicsCompressor();
    oscillator.type = "triangle";
    oscillator.frequency.value = 10000;
    compressor.threshold.value = -50;
    compressor.knee.value = 40;
    compressor.ratio.value = 12;
    compressor.attack.value = 0;
    compressor.release.value = 0.25;
    oscillator.connect(compressor);
    compressor.connect(ctx.destination);
    oscillator.start(0);
    const buffer = await ctx.startRendering();
    const sample = Array.from(buffer.getChannelData(0).slice(4500, 4600)).join(",");
    return sha256(sample);
  } catch {
    return "blocked";
  }
}

function classifyDevice(profile) {
  const ua = profile.user_agent.toLowerCase();
  if (profile.ua_hints?.mobile || /android|iphone|ipad|mobile/.test(ua)) return "phone/tablet";
  if (profile.touch_points > 0 && profile.screen_width < 1100) return "phone/tablet";
  if (/mac|win|linux|x11/.test(ua)) return "desktop/laptop";
  return "unknown";
}

async function collectDeviceProfile() {
  const webgl = getWebglProfile();
  const uaHints = await getUserAgentHints();
  const [battery, clock, performanceProfile] = await Promise.all([
    getBatteryProfile(),
    getClockProfile(),
    getPerformanceProfile(),
  ]);
  const profile = {
    collected_at: new Date().toISOString(),
    user_agent: navigator.userAgent,
    ua_hints: uaHints,
    platform: navigator.platform || "unknown",
    vendor: navigator.vendor || "unknown",
    languages: navigator.languages || [navigator.language],
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "unknown",
    timezone_offset_min: new Date().getTimezoneOffset(),
    hardware_concurrency: navigator.hardwareConcurrency || "unknown",
    device_memory_gb: navigator.deviceMemory || "unknown",
    touch_points: navigator.maxTouchPoints || 0,
    cookie_enabled: navigator.cookieEnabled,
    do_not_track: navigator.doNotTrack || "unknown",
    screen_width: screen.width,
    screen_height: screen.height,
    avail_width: screen.availWidth,
    avail_height: screen.availHeight,
    color_depth: screen.colorDepth,
    pixel_depth: screen.pixelDepth,
    device_pixel_ratio: window.devicePixelRatio || 1,
    viewport_width: window.innerWidth,
    viewport_height: window.innerHeight,
    orientation: screen.orientation?.type || "unknown",
    plugins: Array.from(navigator.plugins || []).map((plugin) => plugin.name).slice(0, 12),
    mime_types_count: navigator.mimeTypes?.length || 0,
    local_storage: Boolean(window.localStorage),
    session_storage: Boolean(window.sessionStorage),
    indexed_db: Boolean(window.indexedDB),
    canvas_hash: await getCanvasHash(),
    audio_hash: await getAudioHash(),
    battery,
    clock,
    performance: performanceProfile,
    ...webgl,
  };
  profile.device_class = classifyDevice(profile);
  return profile;
}

function collectNetworkProfile() {
  const connection = navigator.connection || navigator.mozConnection || navigator.webkitConnection || {};
  return {
    connection_type: connection.type || "unknown",
    effective_type: connection.effectiveType || "unknown",
    downlink_mbps: connection.downlink || "unknown",
    rtt_ms: connection.rtt || "unknown",
    save_data: Boolean(connection.saveData),
    online: navigator.onLine,
  };
}

async function detectIpv6() {
  try {
    const data = await fetchJsonWithTimeout(`https://api64.ipify.org?format=json&t=${Date.now()}`, 2500);
    return String(data.ip || "").includes(":");
  } catch {
    return false;
  }
}

async function detectWebRtcAddressLeak() {
  if (!window.RTCPeerConnection) return false;
  return new Promise((resolve) => {
    const found = new Set();
    const pc = new RTCPeerConnection({ iceServers: [{ urls: "stun:stun.l.google.com:19302" }] });
    const done = () => {
      pc.close();
      const visibleIps = [...found].filter((value) => /^\d{1,3}(\.\d{1,3}){3}$/.test(value));
      resolve(visibleIps.length > 0);
    };
    pc.createDataChannel("probe");
    pc.onicecandidate = (event) => {
      const candidate = event.candidate?.candidate || "";
      const match = candidate.match(/(\d{1,3}(?:\.\d{1,3}){3})/);
      if (match) found.add(match[1]);
      if (!event.candidate) done();
    };
    pc.createOffer().then((offer) => pc.setLocalDescription(offer)).catch(() => resolve(false));
    setTimeout(done, 2200);
  });
}

async function lookupPublicIp() {
  const providers = [
    {
      name: "ipapi.co",
      url: `https://ipapi.co/json/?t=${Date.now()}`,
      map: (data) => ({
        ip: data.ip,
        country: data.country_code || data.country,
        asn: data.org || data.asn,
        timezone: data.timezone,
      }),
    },
    {
      name: "ipwho.is",
      url: `https://ipwho.is/?t=${Date.now()}`,
      map: (data) => ({
        ip: data.ip,
        country: data.country_code,
        asn: data.connection?.org || data.connection?.asn,
        timezone: data.timezone?.id,
      }),
    },
    {
      name: "ipify",
      url: `https://api.ipify.org?format=json&t=${Date.now()}`,
      map: (data) => ({ ip: data.ip }),
    },
  ];

  for (const provider of providers) {
    try {
      const data = await fetchJsonWithTimeout(provider.url, 4500);
      const mapped = provider.map(data);
      if (mapped.ip) return { source: provider.name, ...mapped };
    } catch {
      continue;
    }
  }
  throw new Error("all public IP lookups failed");
}

async function detectSession({ analyzeAfter = false } = {}) {
  detectBrowserFields();
  setAutofillStatus("Собираю расширенный fingerprint устройства и сети...");

  let backendInfo = {};
  try {
    backendInfo = await fetchJsonWithTimeout("/api/client-info", 2000);
    $("ip").value = backendInfo.observed_ip || "";
  } catch {
    backendInfo = {};
  }

  lastDeviceProfile = await collectDeviceProfile();
  lastNetworkProfile = collectNetworkProfile();
  lastFingerprintHash = await sha256(JSON.stringify({
    ua: lastDeviceProfile.user_agent,
    platform: lastDeviceProfile.platform,
    gpu: lastDeviceProfile.webgl_renderer,
    screen: `${lastDeviceProfile.screen_width}x${lastDeviceProfile.screen_height}x${lastDeviceProfile.device_pixel_ratio}`,
    cores: lastDeviceProfile.hardware_concurrency,
    memory: lastDeviceProfile.device_memory_gb,
    canvas: lastDeviceProfile.canvas_hash,
    audio: lastDeviceProfile.audio_hash,
    languages: lastDeviceProfile.languages,
  }));

  try {
    const publicInfo = await lookupPublicIp();
    $("ip").value = publicInfo.ip || $("ip").value;
    $("country").value = publicInfo.country || $("country").value || "UNKNOWN";
    $("asn").value = publicInfo.asn || $("asn").value || "unknown";
    $("timezone").value = publicInfo.timezone || $("timezone").value;
    lastPublicIpSource = publicInfo.source;
    setAutofillStatus(`Автосбор готов: IP lookup ${publicInfo.source}, fingerprint ${lastFingerprintHash.slice(0, 12)}..., устройство: ${lastDeviceProfile.device_class}.`);
  } catch {
    $("country").value = $("country").value || "UNKNOWN";
    $("asn").value = $("asn").value || "external lookup unavailable";
    lastPublicIpSource = "backend-fallback";
    const urls = (backendInfo.server_lan_urls || []).join(", ");
    setAutofillStatus(`Внешний lookup недоступен. Backend видит IP: ${$("ip").value || "unknown"}. Адреса сервера: ${urls || "не определены"}.`);
  }

  $("ipv6_enabled").checked = await detectIpv6();
  $("webrtc_leak").checked = await detectWebRtcAddressLeak();
  renderFingerprintPreview();
  renderChangePreview();
  if (analyzeAfter) await analyze();
}

function applyPreset(name) {
  const preset = presets[name];
  $("ip").value = preset.ip;
  $("country").value = preset.country;
  $("asn").value = preset.asn;
  $("previous_countries").value = preset.previous_countries;
  $("failed_logins").value = preset.failed_logins;
  $("downloads").value = preset.downloads;
  $("protected_requests").value = preset.protected_requests;
  $("device_seen").checked = preset.device_seen;
  $("webrtc_leak").checked = preset.webrtc_leak;
  $("ipv6_enabled").checked = preset.ipv6_enabled;
}

function currentSnapshot() {
  return {
    ip: $("ip").value.trim(),
    country: $("country").value.trim(),
    asn: $("asn").value.trim(),
    timezone: $("timezone").value.trim(),
    accept_language: $("accept_language").value.trim(),
    browser_fingerprint_hash: lastFingerprintHash,
    device_profile: lastDeviceProfile,
    network_profile: lastNetworkProfile,
    checked_at: new Date().toISOString(),
  };
}

function payload() {
  return {
    ...currentSnapshot(),
    user_agent: navigator.userAgent,
    screen: `${window.screen.width}x${window.screen.height}`,
    previous_countries: $("previous_countries").value.split(",").map((item) => item.trim()).filter(Boolean),
    failed_logins_last_5_min: Number($("failed_logins").value || 0),
    downloaded_docs_last_10_min: Number($("downloads").value || 0),
    protected_requests_last_2_min: Number($("protected_requests").value || 0),
    device_seen_before: $("device_seen").checked,
    webrtc_leak: $("webrtc_leak").checked,
    ipv6_enabled: $("ipv6_enabled").checked,
    public_ip_source: lastPublicIpSource,
    previous_snapshot: previousSnapshot(),
  };
}

function levelText(level) {
  return {
    critical: "Критический риск",
    high: "Высокий риск",
    medium: "Средний риск",
    low: "Низкий риск",
  }[level] || level;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function renderFingerprintPreview() {
  const p = lastDeviceProfile;
  const rows = [
    ["Device", p.device_class],
    ["Platform", p.ua_hints?.platform || p.platform],
    ["Model", p.ua_hints?.model || "browser hides it"],
    ["CPU threads", p.hardware_concurrency],
    ["RAM", `${p.device_memory_gb} GB bucket`],
    ["GPU", p.webgl_renderer || "hidden"],
    ["Screen", `${p.screen_width}x${p.screen_height} DPR ${p.device_pixel_ratio}`],
    ["Viewport", `${p.viewport_width}x${p.viewport_height}`],
    ["Touch", p.touch_points],
    ["Battery", p.battery?.supported ? `${p.battery.level_percent}% ${p.battery.charging ? "charging" : "battery"}` : "hidden"],
    ["Clock skew", p.clock?.server_skew_ms === "unknown" ? "unknown" : `${p.clock?.server_skew_ms} ms`],
    ["JS heap", p.performance?.memory?.supported ? `${p.performance.memory.used_js_heap_size_human} / ${p.performance.memory.js_heap_size_limit_human}` : "hidden"],
    ["FPS", p.performance?.approximate_fps || "unknown"],
    ["Event lag", `${p.performance?.event_loop_lag_ms ?? "unknown"} ms`],
    ["CPU bench", p.performance?.cpu_benchmark?.iterations_per_ms || "unknown"],
    ["Canvas", String(p.canvas_hash || "").slice(0, 12)],
    ["Audio", String(p.audio_hash || "").slice(0, 12)],
    ["Fingerprint", lastFingerprintHash.slice(0, 16)],
  ];
  $("fingerprint").innerHTML = rows.map(([label, value]) => `
    <div class="metric compact"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>
  `).join("");
}

function renderChangePreview() {
  const prev = previousSnapshot();
  if (!prev) {
    $("changes").innerHTML = `<div class="change"><span>История</span><strong>Это первая проверка в этом браузере</strong></div>`;
    return;
  }
  const now = currentSnapshot();
  $("changes").innerHTML = [
    formatChange("IP", prev.ip, now.ip),
    formatChange("Country", prev.country, now.country),
    formatChange("ASN", prev.asn, now.asn),
    formatChange("Timezone", prev.timezone, now.timezone),
    formatChange("Fingerprint", String(prev.browser_fingerprint_hash || "").slice(0, 12), String(now.browser_fingerprint_hash || "").slice(0, 12)),
    formatChange("GPU", prev.device_profile?.webgl_renderer, now.device_profile?.webgl_renderer),
  ].join("");
}

function render(data) {
  const { report, explanation } = data;
  const deg = Math.round((report.risk_score / 100) * 360);
  const color = report.risk_score >= 75 ? "#b73535" : report.risk_score >= 50 ? "#d95f32" : report.risk_score >= 25 ? "#c88a14" : "#0e7c66";

  $("score").textContent = report.risk_score;
  $("scoreRing").style.background = `conic-gradient(${color} ${deg}deg, #e6ece8 ${deg}deg)`;
  $("riskLevel").textContent = levelText(report.risk_level);
  $("networkType").textContent = `Тип сети: ${report.network_type}; exposure ${report.exposure_level || "low"} ${report.exposure_score || 0}/100`;
  $("provider").textContent = `Метод анализа: ${explanation.provider}`;
  $("explanation").textContent = explanation.text;

  const summary = report.summary;
  $("metrics").innerHTML = [
    ["IP", summary.ip],
    ["Country", summary.country],
    ["ASN", summary.asn || "не указан"],
    ["Timezone", summary.timezone],
    ["Language", summary.accept_language],
    ["Lookup", summary.public_ip_source || "unknown"],
    ["Device", summary.device_profile?.device_class || "unknown"],
    ["GPU", summary.device_profile?.webgl_renderer || "hidden"],
    ["Battery", summary.device_profile?.battery?.supported ? `${summary.device_profile.battery.level_percent}%` : "hidden"],
    ["Clock skew", summary.device_profile?.clock?.server_skew_ms ?? "unknown"],
    ["JS heap", summary.device_profile?.performance?.memory?.used_js_heap_size_human || "hidden"],
    ["FPS", summary.device_profile?.performance?.approximate_fps || "unknown"],
    ["Hash", String(summary.browser_fingerprint_hash || "").slice(0, 16)],
    ["Exposure", `${report.exposure_level || "low"} ${report.exposure_score || 0}/100`],
  ].map(([label, value]) => `<div class="metric"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`).join("");

  $("signals").innerHTML = report.signals.length
    ? report.signals.map((signal) => `
        <article class="signal">
          <div class="signal-header">
            <span>${escapeHtml(signal.title)}</span>
            <span class="severity-${escapeHtml(signal.severity)}">+${escapeHtml(signal.points)}</span>
          </div>
          <p>${escapeHtml(signal.explanation)}</p>
        </article>
      `).join("")
    : `<article class="signal"><strong>Сильных сигналов риска нет</strong><p>Текущие признаки выглядят нормально для учебной модели.</p></article>`;

  $("exposures").innerHTML = report.exposures?.length
    ? report.exposures.map((finding) => `
        <article class="signal">
          <div class="signal-header">
            <span>${escapeHtml(finding.title)}</span>
            <span class="severity-${escapeHtml(finding.severity)}">+${escapeHtml(finding.points)}</span>
          </div>
          <p><strong>${escapeHtml(finding.category)}</strong>: ${escapeHtml(finding.evidence)}</p>
          <p>${escapeHtml(finding.recommendation)}</p>
        </article>
      `).join("")
    : `<article class="signal"><strong>Существенных экспозиций нет</strong><p>По доступным данным браузер и сеть не раскрыли сильных дополнительных признаков.</p></article>`;
}

async function analyze() {
  $("analyze").disabled = true;
  $("analyze").textContent = "Анализирую...";
  try {
    const body = payload();
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    render(await response.json());
    saveSnapshot(currentSnapshot());
    renderChangePreview();
  } finally {
    $("analyze").disabled = false;
    $("analyze").textContent = "Проверить сессию";
  }
}

detectBrowserFields();
$("detectSession").addEventListener("click", () => detectSession());
$("demoHigh").addEventListener("click", () => applyPreset("high"));
$("demoLow").addEventListener("click", () => applyPreset("low"));
$("analyze").addEventListener("click", analyze);
$("refreshAnalyze").addEventListener("click", () => detectSession({ analyzeAfter: true }));
detectSession();
