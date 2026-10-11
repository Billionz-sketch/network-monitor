(function () {
  "use strict";
  var API = "";
  var $ = function (id) { return document.getElementById(id); };
  var token = "";
  try { token = sessionStorage.getItem("nm_token") || ""; } catch (e) {}
  var S = null;            // latest state
  var selected = null;     // client id shown in detail
  var rulesDirty = false;

  function esc(v) {
    return String(v == null ? "" : v).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function ago(t) {
    var s = Math.max(0, Math.round(Date.now() / 1000 - t));
    if (s < 60) return s + "s ago";
    if (s < 3600) return Math.floor(s / 60) + "m ago";
    return Math.floor(s / 3600) + "h ago";
  }
  function clock(t) { return new Date(t * 1000).toLocaleTimeString([], { hour12: false }); }
  function fmt(v, d) { return v == null ? "—" : Number(v).toFixed(d == null ? 0 : d); }

  function api(path, opts) {
    opts = opts || {};
    var h = { "Content-Type": "application/json" };
    if (token) h["X-Admin-Token"] = token;
    return fetch(API + path, { method: opts.method || "GET", headers: h, body: opts.body ? JSON.stringify(opts.body) : undefined })
      .then(function (r) { return r.json().then(function (j) { j._status = r.status; return j; }); });
  }

  // ------------------------------------------------------------ charts
  function setup(c) {
    var dpr = window.devicePixelRatio || 1, w = c.clientWidth, h = c.clientHeight;
    if (c.width !== w * dpr) { c.width = w * dpr; c.height = h * dpr; }
    var x = c.getContext("2d"); x.setTransform(dpr, 0, 0, dpr, 0, 0); x.clearRect(0, 0, w, h);
    return { x: x, w: w, h: h };
  }
  function lineChart(c, vals) {
    var g = setup(c), x = g.x, w = g.w, h = g.h, pad = 28;
    x.font = "11px monospace"; x.fillStyle = "#5C6675"; x.strokeStyle = "#28323F"; x.lineWidth = 1;
    var max = Math.max.apply(null, vals.concat([10])) * 1.15;
    for (var i = 0; i <= 3; i++) {
      var y = 8 + (h - 8 - 20) * i / 3;
      x.beginPath(); x.moveTo(pad + 20, y); x.lineTo(w, y); x.stroke();
      x.fillText(Math.round(max * (1 - i / 3)), 0, y + 4);
    }
    if (vals.length < 2) { x.fillText("waiting for data…", w / 2 - 50, h / 2); return; }
    var n = vals.length, px = function (i) { return pad + 20 + (w - pad - 24) * i / (n - 1); }, py = function (v) { return 8 + (h - 28) * (1 - v / max); };
    x.beginPath(); x.moveTo(px(0), h - 20);
    vals.forEach(function (v, i) { x.lineTo(px(i), py(v)); });
    x.lineTo(px(n - 1), h - 20); x.closePath(); x.fillStyle = "rgba(79,182,174,.14)"; x.fill();
    x.beginPath(); vals.forEach(function (v, i) { i ? x.lineTo(px(i), py(v)) : x.moveTo(px(i), py(v)); });
    x.strokeStyle = "#4FB6AE"; x.lineWidth = 2; x.stroke();
  }
  function barChart(c, obj) {
    var g = setup(c), x = g.x, w = g.w, h = g.h, keys = Object.keys(obj).sort(function (a, b) { return obj[b] - obj[a]; });
    x.font = "12px monospace";
    if (!keys.length) { x.fillStyle = "#5C6675"; x.fillText("no connections yet", 10, h / 2); return; }
    var max = obj[keys[0]], bh = Math.min(24, (h - 10) / keys.length - 6);
    keys.slice(0, 6).forEach(function (k, i) {
      var y = 6 + i * (bh + 8);
      x.fillStyle = "#8B96A5"; x.fillText(k, 0, y + bh * 0.75);
      x.fillStyle = i ? "#4FB6AE" : "#E8A33D";
      x.fillRect(52, y, (w - 100) * obj[k] / max, bh);
      x.fillStyle = "#E7EBF0"; x.fillText(obj[k], 58 + (w - 100) * obj[k] / max, y + bh * 0.75);
    });
  }

  // ------------------------------------------------------------ render
  function render() {
    if (!S) return;
    var admin = S.admin, on = S.summary;
    $("connPill").innerHTML = '<span class="dot live"></span>live';
    $("viewPill").textContent = admin ? "Full view (admin)" : "Basic view";
    $("viewPill").className = "pill " + (admin ? "admin" : "public");
    $("viewHint").textContent = admin ? "You are signed in: full details and commands are visible."
      : "You are seeing the basic view. Sign in under Manage for IP addresses, hostnames and commands.";
    $("loginBox").hidden = admin; $("adminBox").hidden = !admin;
    var lb = $("loginBox"); if (!S.admin_enabled) $("loginMsg").textContent = "Admin login is not enabled on this server (set ADMIN_PASSWORD).";

    // KPIs
    $("kOnline").innerHTML = on.online + "<small> / " + on.total + "</small>";
    $("kOnlineD").textContent = on.total - on.online > 0 ? (on.total - on.online) + " offline" : (on.total ? "all present" : "no clients yet");
    $("kBw").innerHTML = fmt(on.bw, 0) + "<small> KB/s</small>";
    $("kLat").innerHTML = fmt(on.latency, 0) + "<small> ms</small>";
    var cutoff = S.now - 3600;
    $("kAlerts").textContent = S.events.filter(function (e) { return e.level === "warn" && e.t > cutoff; }).length;
    $("bwNow").textContent = fmt(on.bw, 0) + " KB/s";
    lineChart($("cBw"), S.fleet.map(function (f) { return f.bw; }));
    var protos = {};
    S.clients.forEach(function (c) { if (c.status === "online") for (var k in c.protocols) protos[k] = (protos[k] || 0) + c.protocols[k]; });
    barChart($("cProto"), protos);

    renderClients(admin);
    renderFeed();
    renderRules();
    renderDetail(admin);
    if (admin) loadQr(); else qrLoaded = false;
  }

  function renderClients(admin) {
    var ae = document.activeElement;
    if (ae && $("clientRows").contains(ae) && /INPUT|SELECT/.test(ae.tagName)) return; // don't wipe what the admin is typing
    document.querySelectorAll("th.adm").forEach(function (th) { th.style.display = admin ? "" : "none"; });
    if (!S.clients.length) {
      $("clientRows").innerHTML = '<tr><td colspan="8" class="empty">No clients yet. Follow “Connect a client” below and this table will fill up within seconds.</td></tr>';
      return;
    }
    $("clientRows").innerHTML = S.clients.map(function (c) {
      var st = c.stats, up = c.status === "online";
      var sub = admin ? '<span class="sub">' + esc(c.hostname) + " · " + esc(c.ip) + "</span>" : '<span class="sub">' + esc(c.os) + "</span>";
      var act = "";
      if (admin) {
        act = '<td><div class="act" data-id="' + esc(c.id) + '">' +
          '<select class="cmdSel"><option value="status">Status check</option><option value="shutdown">Shutdown</option>' +
          '<option value="cancel_shutdown">Cancel shutdown</option><option value="logoff">Log off</option>' +
          '<option value="block_ip">Block IP</option><option value="unblock_ip">Unblock IP</option></select>' +
          '<input class="cmdArg" type="text" placeholder="IP or seconds" hidden>' +
          '<button class="btn sendBtn">Send</button>' +
          '<button class="btn ghost danger rmBtn" title="Remove from list">✕</button>' +
          (c.pending ? '<span class="tt">' + c.pending + " queued</span>" : "") + "</div></td>";
      }
      return "<tr><td><a href='#detail' class='pick' data-id='" + esc(c.id) + "' style='color:inherit;font-weight:600;text-decoration:none'>" + esc(c.name) + "</a>" + sub + "</td>" +
        '<td><span class="status ' + c.status + '">' + c.status + "</span></td>" +
        '<td class="num">' + (up ? fmt(st.bw_in, 0) + " / " + fmt(st.bw_out, 0) + " KB/s" : "—") + "</td>" +
        '<td class="num">' + (up ? fmt(st.latency, 0) + " ms" : "—") + "</td>" +
        '<td class="num">' + (up ? fmt(st.loss, 0) + "%" : "—") + "</td>" +
        '<td class="num">' + (up ? fmt(st.cpu, 0) + "% / " + fmt(st.mem, 0) + "%" : "—") + "</td>" +
        '<td class="num">' + ago(c.last_seen) + "</td>" + act + "</tr>";
    }).join("");
  }

  function renderFeed() {
    $("feed").innerHTML = S.events.length ? S.events.slice(0, 40).map(function (e) {
      return '<div class="row ' + esc(e.level) + '"><span class="t">' + clock(e.t) + '</span><span class="m">' + esc(e.msg) + "</span></div>";
    }).join("") : '<div class="row info"><span class="m">No events yet.</span></div>';
  }

  function renderRules() {
    if (!S.admin || rulesDirty || $("rules").contains(document.activeElement)) return;
    $("rules").innerHTML = Object.keys(S.rules).map(function (k) {
      var r = S.rules[k];
      return '<div class="rule"><label><input type="checkbox" data-k="' + esc(k) + '" class="rEn"' + (r.enabled ? " checked" : "") + "> " + esc(r.label) +
        '</label><input type="number" min="0" class="rLim" data-k="' + esc(k) + '" value="' + esc(r.limit) + '"></div>';
    }).join("");
  }

  function renderDetail(admin) {
    var c = S.clients.filter(function (x) { return x.id === selected; })[0];
    if (!c) { $("detail").innerHTML = ""; return; }
    var h = '<div class="box" style="margin-top:14px"><div class="panel-title"><span>' + esc(c.name) + " — detail</span><span>" + c.beats + " check-ins</span></div>";
    h += '<div class="tt">Protocols: ' + (Object.keys(c.protocols).map(function (k) { return esc(k) + " " + c.protocols[k]; }).join(" · ") || "none") + "</div>";
    if (admin) {
      h += '<div class="tt" style="margin-top:8px">Top remote hosts: ' + (c.top_talkers.map(function (t) { return esc(t.host) + " (" + t.conns + ")"; }).join(" · ") || "none") + "</div>";
      h += '<div class="tt" style="margin-top:8px">Recent commands: ' + (c.results.map(function (r) { return (r.ok ? "✓ " : "✗ ") + esc(r.cmd) + " — " + esc(r.msg); }).join(" | ") || "none") + "</div>";
    } else {
      h += '<div class="tt" style="margin-top:8px">Remote hosts, IP addresses and command history are hidden in the basic view.</div>';
    }
    $("detail").innerHTML = h + "</div>";
  }

  // ------------------------------------------------------------ events
  document.addEventListener("click", function (ev) {
    var t = ev.target;
    if (t.classList.contains("pick")) { selected = t.getAttribute("data-id"); renderDetail(S && S.admin); }
    if (t.classList.contains("sendBtn")) {
      var box = t.closest(".act"), cmd = box.querySelector(".cmdSel").value, arg = box.querySelector(".cmdArg").value.trim();
      var body = { client_id: box.getAttribute("data-id"), cmd: cmd };
      if (cmd === "shutdown") body.delay = arg || 60;
      if (cmd === "block_ip" || cmd === "unblock_ip") body.ip = arg;
      if ((cmd === "shutdown" || cmd === "logoff") && !confirm("Really send '" + cmd + "' to this client?")) return;
      api("/api/command", { method: "POST", body: body }).then(function (j) {
        $("cmdMsg").className = "note " + (j.ok ? "msg-ok" : "msg-err");
        $("cmdMsg").textContent = j.ok ? j.note : (j.error || "failed");
        if (j._status === 401) signedOut();
        t.blur(); poll();
      });
    }
    if (t.classList.contains("rmBtn")) {
      var id = t.closest(".act").getAttribute("data-id");
      if (confirm("Remove this client from the list? (It reappears if its agent is still running.)"))
        api("/api/clients/" + encodeURIComponent(id), { method: "DELETE" }).then(function () { t.blur(); poll(); });
    }
  });
  document.addEventListener("change", function (ev) {
    var t = ev.target;
    if (t.classList.contains("cmdSel")) {
      var inp = t.closest(".act").querySelector(".cmdArg"), v = t.value;
      inp.hidden = !(v === "shutdown" || v === "block_ip" || v === "unblock_ip");
      inp.placeholder = v === "shutdown" ? "seconds (default 60)" : "IP address";
    }
    if (t.classList.contains("rEn") || t.classList.contains("rLim")) rulesDirty = true;
  });
  document.addEventListener("input", function (ev) { if (ev.target.classList.contains("rLim")) rulesDirty = true; });

  $("loginForm").addEventListener("submit", function (ev) {
    ev.preventDefault();
    api("/api/login", { method: "POST", body: { password: $("pw").value } }).then(function (j) {
      if (j.token) {
        token = j.token; try { sessionStorage.setItem("nm_token", token); } catch (e) {}
        $("pw").value = ""; $("loginMsg").textContent = ""; poll();
      } else $("loginMsg").textContent = j.error || "login failed";
    });
  });
  function signedOut() { token = ""; try { sessionStorage.removeItem("nm_token"); } catch (e) {} poll(); }
  $("logoutBtn").addEventListener("click", function () { api("/api/logout", { method: "POST" }).then(signedOut); });
  $("saveRules").addEventListener("click", function () {
    var body = {};
    document.querySelectorAll(".rEn").forEach(function (e) { var k = e.getAttribute("data-k"); body[k] = body[k] || {}; body[k].enabled = e.checked; });
    document.querySelectorAll(".rLim").forEach(function (e) { var k = e.getAttribute("data-k"); body[k] = body[k] || {}; body[k].limit = Number(e.value); });
    api("/api/rules", { method: "POST", body: body }).then(function (j) {
      rulesDirty = false; $("rulesMsg").textContent = j.ok ? "Saved." : (j.error || "failed"); setTimeout(function () { $("rulesMsg").textContent = ""; }, 2500); poll();
    });
  });

  // QR + launcher (admin only)
  var joinUrl = "", qrLoaded = false;
  function loadQr() {
    if (qrLoaded || !S || !S.admin) return;
    qrLoaded = true;
    api("/api/join-qr").then(function (r) {
      if (r.svg) { $("qrBox").innerHTML = r.svg; joinUrl = r.url; }
      else { qrLoaded = false; $("qrBox").textContent = r.error || "unavailable"; }
    }).catch(function () { qrLoaded = false; });
  }
  $("batBtn").addEventListener("click", function () {
    fetch(API + "/api/join-bat", { headers: { "X-Admin-Token": token } }).then(function (r) {
      if (!r.ok) throw new Error("denied"); return r.blob();
    }).then(function (b) {
      var a = document.createElement("a"); a.href = URL.createObjectURL(b); a.download = "Join-Monitor.bat";
      document.body.appendChild(a); a.click(); a.remove();
    }).catch(function () { $("joinMsg").className = "msg-err"; $("joinMsg").textContent = "Sign in again."; });
  });
  $("copyJoin").addEventListener("click", function () {
    if (!joinUrl) return;
    function done() { $("joinMsg").className = "msg-ok"; $("joinMsg").textContent = "Copied."; setTimeout(function () { $("joinMsg").textContent = ""; }, 1800); }
    if (navigator.clipboard) navigator.clipboard.writeText(joinUrl).then(done, function () {}); else done();
  });

  // CSV report (built in the browser from the live state)
  $("csvBtn").addEventListener("click", function () {
    if (!S) return;
    function q(v) { v = String(v == null ? "" : v); if (/^[=+\-@]/.test(v)) v = "'" + v; return '"' + v.replace(/"/g, '""') + '"'; }
    var rows = [["Client", "Status", "In KB/s", "Out KB/s", "Latency ms", "Loss %", "CPU %", "Mem %", "Last seen"]];
    S.clients.forEach(function (c) { rows.push([c.name, c.status, c.stats.bw_in, c.stats.bw_out, c.stats.latency, c.stats.loss, c.stats.cpu, c.stats.mem, new Date(c.last_seen * 1000).toISOString()]); });
    rows.push([]); rows.push(["Time", "Level", "Event"]);
    S.events.forEach(function (e) { rows.push([new Date(e.t * 1000).toISOString(), e.level, e.msg]); });
    var blob = new Blob([rows.map(function (r) { return r.map(q).join(","); }).join("\r\n")], { type: "text/csv" });
    var a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "network-report-" + new Date().toISOString().slice(0, 10) + ".csv";
    document.body.appendChild(a); a.click(); a.remove();
  });

  // connect instructions
  function cmdText() {
    return "python agent.py --server " + location.origin + ' --name "My Laptop"' + (S && S.key_required ? " --key YOUR_CLIENT_KEY" : "") + " --interval 20";
  }
  $("copyBtn").addEventListener("click", function () {
    var b = this;
    function done() { b.textContent = "Copied"; setTimeout(function () { b.textContent = "Copy"; }, 1500); }
    if (navigator.clipboard) navigator.clipboard.writeText(cmdText()).then(done, function () {}); else done();
  });

  // ------------------------------------------------------------ poll
  var inflight = false;
  function poll() {
    if (inflight) return;
    inflight = true;
    api("/api/state").then(function (j) { S = j; $("cmdText").textContent = cmdText(); render(); })
      .catch(function () { $("connPill").innerHTML = '<span class="dot off"></span>server unreachable'; })
      .then(function () { inflight = false; });
  }
  poll();
  setInterval(poll, 2000);
  window.addEventListener("resize", function () { if (S) render(); });
})();
