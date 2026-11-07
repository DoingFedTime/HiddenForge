/* HiddenForge setup wizard: the page. Builds DOM with textContent only (no
 * innerHTML of anything a user typed), keeps nothing between visits, and makes
 * no network request (the page's CSP refuses them anyway). The files come from
 * render.js, which produces exactly what `hiddenforge setup` writes. */
(function () {
  "use strict";
  var R = window.HFRender;
  var state = {
    services: [{ name: "myapp", onion: "80", host: "web", port: "80" }],
    runtime: "docker", noRoot: false, encryptKeys: false, passphraseFile: "./key-passphrase.txt",
    keys: "./tor-keys", container: "tor", image: "sambent.dev/sam/hiddenforge:latest",
    out: "hiddenforge-deploy"
  };
  var STEPS = ["Services", "Engine", "Hardening", "Paths", "Generate"];
  var step = 0;
  var app = document.getElementById("app");

  function el(tag, attrs, kids) {
    var e = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      if (k === "text") e.textContent = attrs[k];
      else if (k === "class") e.className = attrs[k];
      else if (k.slice(0, 2) === "on") e.addEventListener(k.slice(2), attrs[k]);
      else e.setAttribute(k, attrs[k]);
    });
    (kids || []).forEach(function (c) { if (c) e.appendChild(c); });
    return e;
  }

  function typeText(node, text, delay, done) {
    var i = 0, cur = el("span", { class: "cursor" });
    node.appendChild(cur);
    (function tick() {
      if (i < text.length) {
        node.insertBefore(document.createTextNode(text[i++]), cur);
        setTimeout(tick, delay + Math.random() * 20);
      } else if (done) { done(cur); }
    })();
  }

  var io = new IntersectionObserver(function (entries) {
    entries.forEach(function (en) { if (en.isIntersecting) en.target.classList.add("visible"); });
  }, { threshold: 0.15, rootMargin: "0px 0px -40px 0px" });
  function reveal(node) { node.classList.add("reveal"); io.observe(node); return node; }

  function field(label, key, type) {
    var inp = el("input", { type: type || "text", value: state[key], spellcheck: "false", autocomplete: "off",
      oninput: function () { state[key] = inp.value; } });
    return el("div", {}, [el("label", { text: label }), inp]);
  }
  function opt(type, name, checked, title, desc, onchange) {
    var inp = el("input", { type: type, name: name, onchange: onchange });
    inp.checked = checked;
    return el("label", { class: "opt" }, [inp, el("div", {}, [el("b", { text: title }), el("span", { text: desc })])]);
  }
  function card(tag, title, desc, kids) {
    return reveal(el("div", { class: "card" }, [el("div", { class: "tag", text: tag }), el("h2", { text: title }),
      el("p", { text: desc })].concat(kids)));
  }

  function servicesStep() {
    var list = el("div");
    state.services.forEach(function (s, i) {
      function inp(k, ph) {
        var x = el("input", { type: "text", value: s[k], placeholder: ph, spellcheck: "false",
          oninput: function () { s[k] = x.value; } });
        return x;
      }
      list.appendChild(el("div", { class: "row" }, [
        el("div", {}, [el("label", { text: "service name" }), inp("name", "myapp")]),
        el("div", {}, [el("label", { text: "onion port" }), inp("onion", "80")]),
        el("div", {}, [el("label", { text: "backend host" }), inp("host", "web")]),
        el("div", {}, [el("label", { text: "backend port" }), inp("port", "80")]),
        state.services.length > 1 ? el("button", { class: "act ghost", text: "remove",
          onclick: function () { state.services.splice(i, 1); render(); } }) : null
      ]));
    });
    return card("step 1", "What should the .onion serve?",
      "Each service gets its own .onion address. The backend is reached by its compose service name on an internal network with no internet access.",
      [list, el("div", { class: "nav" }, [el("button", { class: "act ghost", text: "+ add a service",
        onclick: function () { state.services.push({ name: "", onion: "80", host: "web", port: "80" }); render(); } })])]);
  }

  function engineStep() {
    function set(v) { return function () { state.runtime = v; }; }
    return card("step 2", "Which engine runs it?", "Rootless Podman is the recommended runtime for high-risk deployments: container root is your own unprivileged user on the host.",
      [opt("radio", "rt", state.runtime === "podman", "Podman (rootless)", "Recommended. A container escape lands in your user account, not root.", set("podman")),
       opt("radio", "rt", state.runtime === "docker", "Docker", "Supported. Needs two more capabilities than rootless Podman.", set("docker"))]);
  }

  function hardeningStep() {
    var ppWrap = el("div", { class: state.encryptKeys ? "" : "hidden" }, [field("passphrase file (on the host)", "passphraseFile"),
      el("div", { class: "warnbox", text: "deploy.sh creates a random passphrase if this file does not exist. Back it up separately from the key directory: without it the address is lost for good. Kept on the same disk it only protects backups." })]);
    return card("step 3", "How hard?", "Both are opt-in. The defaults are already hardened; these remove the last root process and keep the key encrypted on disk.",
      [opt("checkbox", "nr", state.noRoot, "No-root mode", "The container runs as the tor user (100:101) with zero capabilities, even at start. deploy.sh hands the key directory to 100:101 once.", function (e) { state.noRoot = e.target.checked; }),
       opt("checkbox", "ek", state.encryptKeys, "Encrypt the key at rest", "The onion key is stored only as an AES-256-GCM envelope (scrypt passphrase) and decrypted into RAM at each start.", function (e) { state.encryptKeys = e.target.checked; ppWrap.className = e.target.checked ? "" : "hidden"; }),
       ppWrap]);
  }

  function pathsStep() {
    return card("step 4", "Where things live", "Paths are written into the compose fragment and deploy.sh exactly as typed, safely quoted.",
      [field("key directory (host)", "keys"), field("container name", "container"), field("image", "image"),
       field("output folder name (where you will save these files)", "out")]);
  }

  function collect() {
    var services = {};
    state.services.forEach(function (s) {
      var name = (s.name || "").trim();
      R.validateName(name);
      if (!R.portOk((s.onion || "").trim())) throw new Error("bad onion port for " + name);
      var hp = R.parseBackend((s.host || "").trim() + ":" + (s.port || "").trim());
      (services[name] = services[name] || []).push(s.onion.trim() + ":" + hp[0] + ":" + hp[1]);
    });
    return R.generate({ services: services, image: state.image.trim(), keys: state.keys, container: state.container.trim(),
      runtime: state.runtime, noRoot: state.noRoot, encryptKeys: state.encryptKeys, passphraseFile: state.passphraseFile,
      onionPort: 80, out: state.out.trim() || "hiddenforge-deploy", outputDir: state.out.trim() || "hiddenforge-deploy" });
  }

  function download(name, text, mode) {
    var blob = new Blob([text], { type: "application/octet-stream" });
    var a = el("a", { href: URL.createObjectURL(blob), download: name });
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
  }

  function generateStep() {
    var err = el("div", { class: "err" }), files = el("div", { class: "files" });
    try {
      var out = collect().files;
      Object.keys(out).forEach(function (name, i) {
        var node = el("div", { class: "file reveal" }, [
          el("div", { class: "fhead" }, [el("span", { text: name }),
            el("button", { class: "act", text: "download", onclick: function () { download(name, out[name]); } })]),
          el("pre", { text: out[name] })]);
        // Staggered, not scroll-gated: all four files must be visible at once.
        setTimeout(function () { node.classList.add("visible"); }, 80 + i * 120);
        files.appendChild(node);
      });
      err.className = "err ok"; err.textContent = "Generated. Save all four files in one folder, then run ./deploy.sh (chmod +x it first).";
    } catch (e) { err.textContent = "error: " + e.message; }
    return card("step 5", "Your files", "Identical to what `hiddenforge setup` writes for the same answers.",
      [err, files, el("div", { class: "warnbox", text: "Before trusting this page, check its SHA-256 against signatures/ in the signed release. A tampered copy could write a different deploy.sh." })]);
  }

  function render() {
    app.textContent = "";
    var bar = el("div", { class: "steps" });
    STEPS.forEach(function (s, i) {
      bar.appendChild(el("button", { class: "stepbtn" + (i === step ? " on" : ""), text: (i + 1) + " " + s,
        onclick: function () { step = i; render(); } }));
    });
    app.appendChild(bar);
    app.appendChild([servicesStep, engineStep, hardeningStep, pathsStep, generateStep][step]());
    app.appendChild(el("div", { class: "nav" }, [
      step > 0 ? el("button", { class: "act ghost", text: "back", onclick: function () { step--; render(); } }) : el("span"),
      step < STEPS.length - 1 ? el("button", { class: "act", text: "next", onclick: function () { step++; render(); } }) : el("span")]));
  }

  var line = document.getElementById("typed");
  typeText(line, "hiddenforge setup --offline", 38, function (cur) { cur.remove(); });
  render();
})();
