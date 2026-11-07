/* HiddenForge setup wizard: file generation.
 *
 * Pure functions, no DOM, no network. They produce exactly the files
 * `hiddenforge setup` writes (scripts/hiddenforge render_*), byte for byte;
 * tests/test_wizard_diff.py runs them under Node against the CLI to prove it.
 */
(function (root) {
  "use strict";

  var VERSION = "3.0.0";
  var CONTRACT_VERSION = 1;
  var SECRET_FILE = "hs_ed25519_secret_key";

  // ── validators (scripts/hiddenforge) ─────────────────────────────────────
  var NAME_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;
  var CONTAINER_RE = /^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/;
  var IMAGE_RE = /^[a-zA-Z0-9][a-zA-Z0-9._\/:@-]{0,254}$/;
  var HOST_RE = /^[a-zA-Z0-9._-]{1,253}$/;

  function pyRepr(s) {
    var q = (s.indexOf("'") >= 0 && s.indexOf('"') < 0) ? '"' : "'";
    var out = q;
    for (var i = 0; i < s.length; i++) {
      var c = s[i], cp = s.charCodeAt(i);
      if (c === "\\") out += "\\\\";
      else if (c === "\n") out += "\\n";
      else if (c === "\r") out += "\\r";
      else if (c === "\t") out += "\\t";
      else if (c === q) out += "\\" + c;
      else if (cp < 0x20 || cp === 0x7f) out += "\\x" + ("0" + cp.toString(16)).slice(-2);
      else out += c;
    }
    return out + q;
  }

  function validateName(n) {
    if (!NAME_RE.test(n)) {
      throw new Error("invalid service name " + pyRepr(n) + ": lowercase letters, digits and hyphens " +
        "only, must start alphanumeric, max 63 chars (it becomes a directory under the key volume)");
    }
    return n;
  }
  function validateContainer(n) {
    if (!CONTAINER_RE.test(n)) throw new Error("invalid container name " + pyRepr(n));
    return n;
  }
  function validateImage(v) {
    if (!IMAGE_RE.test(v || "")) {
      throw new Error("invalid image reference " + pyRepr(v) + ": expected registry/name[:tag]" +
        "[@sha256:...] with no spaces, newlines, or leading '-'");
    }
    return v;
  }
  function validateKeysDir(v) {
    if (!v || Array.from(v).length > 4096) throw new Error("key directory path must be 1-4096 characters");
    var chars = Array.from(v);
    for (var i = 0; i < chars.length; i++) {
      var cp = chars[i].codePointAt(0);
      if (cp < 0x20 || cp === 0x7f) {
        throw new Error("key directory path contains a control character (" + pyRepr(chars[i]) +
          "); it is written into a compose file and a shell script");
      }
    }
    return v;
  }
  function portOk(s) { return /^[0-9]+$/.test(s) && +s >= 1 && +s <= 65535; }
  function parseBackend(b) {
    var i = b.lastIndexOf(":");
    if (i < 0) throw new Error("--backend must be host:port, got " + pyRepr(b));
    var host = b.slice(0, i), port = b.slice(i + 1);
    if (!host || !portOk(port)) throw new Error("--backend must be host:port with port 1-65535, got " + pyRepr(b));
    if (!HOST_RE.test(host)) throw new Error("invalid backend host " + pyRepr(host));
    return [host, port];
  }

  // ── quoting ───────────────────────────────────────────────────────────────
  function shlexQuote(s) {
    if (s === "") return "''";
    if (/^[A-Za-z0-9@%+=:,.\/_-]+$/.test(s)) return s;
    return "'" + s.split("'").join("'\"'\"'") + "'";
  }
  function yamlDq(v) {
    var out = '"';
    for (var ch of v) {
      var cp = ch.codePointAt(0);
      if (ch === '"' || ch === "\\") out += "\\" + ch;
      else if (cp >= 0x20 && cp < 0x7f) out += ch;
      else if (cp <= 0xffff) out += "\\u" + ("000" + cp.toString(16)).slice(-4);
      else out += "\\U" + ("0000000" + cp.toString(16)).slice(-8);
    }
    return out + '"';
  }
  function envVar(n) { return n.toUpperCase().split("-").join("_") + "_TOR_SERVICE_HOSTS"; }
  function isIpLiteral(h) {
    if (/^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/.test(h)) return true;
    return h.indexOf(":") >= 0 && /^[0-9a-fA-F:.]+$/.test(h);
  }

  // ── Python json.dumps(indent=2, sort_keys=True), ensure_ascii ─────────────
  function jsonStr(s) {
    var out = '"';
    for (var i = 0; i < s.length; i++) {
      var c = s[i], cp = s.charCodeAt(i);
      if (c === '"') out += '\\"';
      else if (c === "\\") out += "\\\\";
      else if (c === "\n") out += "\\n";
      else if (c === "\r") out += "\\r";
      else if (c === "\t") out += "\\t";
      else if (c === "\b") out += "\\b";
      else if (c === "\f") out += "\\f";
      else if (cp < 0x20 || cp > 0x7e) out += "\\u" + ("000" + cp.toString(16)).slice(-4);
      else out += c;
    }
    return out + '"';
  }
  function pyDumps(v, level) {
    level = level || 0;
    var pad = function (n) { return "\n" + new Array(n * 2 + 1).join(" "); };
    if (v === null) return "null";
    if (v === true) return "true";
    if (v === false) return "false";
    if (typeof v === "number") return String(v);
    if (typeof v === "string") return jsonStr(v);
    if (Array.isArray(v)) {
      if (!v.length) return "[]";
      return "[" + v.map(function (x) { return pad(level + 1) + pyDumps(x, level + 1); }).join(",") + pad(level) + "]";
    }
    var keys = Object.keys(v).sort();
    if (!keys.length) return "{}";
    return "{" + keys.map(function (k) { return pad(level + 1) + jsonStr(k) + ": " + pyDumps(v[k], level + 1); }).join(",") + pad(level) + "}";
  }

  function sortedServices(services) {
    return Object.keys(services).sort().map(function (n) { return [n, services[n]]; });
  }

  // ── the three files + descriptor ──────────────────────────────────────────
  function renderCompose(services, o) {
    var svc = sortedServices(services);
    var envLines = svc.map(function (s) { return "      " + envVar(s[0]) + ': "' + s[1].join(",") + '"\n'; }).join("");
    var secretUse = "", secretDef = "";
    if (o.passphraseFile !== null) {
      envLines += "      HIDDENFORGE_KEY_PASSPHRASE_FILE: /run/secrets/hiddenforge_key_passphrase\n";
      secretUse = "    secrets:\n      - hiddenforge_key_passphrase\n";
      secretDef = "\nsecrets:\n  hiddenforge_key_passphrase:\n    file: " + yamlDq(o.passphraseFile) + "\n";
    }
    var hostSet = {};
    svc.forEach(function (s) {
      s[1].forEach(function (m) { var p = m.split(":"); if (p.length === 3 && p[1]) hostSet[p[1]] = 1; });
    });
    var hosts = Object.keys(hostSet).sort().filter(function (h) { return CONTAINER_RE.test(h) && !isIpLiteral(h); });
    var depBlock = hosts.length ? "    depends_on:\n" + hosts.map(function (h) { return "      - " + h + "\n"; }).join("") : "";
    var docker = o.runtime === "docker";
    var apparmor = docker ? "      - apparmor=docker-default\n" : "";
    var torTmpfs = "- /var/lib/tor:rw,noexec,nosuid,nodev,size=64m";
    var etcTmpfs = "- /etc/tor:rw,noexec,nosuid,nodev,size=8m";
    if (docker) torTmpfs += ",uid=100,gid=101,mode=0700";
    if (o.noRoot) {
      if (docker) etcTmpfs += ",uid=100,gid=101";
      else { torTmpfs += ",mode=0700,U"; etcTmpfs += ",U"; }
    }
    var composeCmd = o.runtime === "podman" ? "podman-compose" : "docker compose";
    var restart = o.runtime === "podman" ? "always" : "unless-stopped";
    var healthcheck = o.runtime === "podman" ? "" :
      '    healthcheck:\n      test: ["CMD", "su-exec", "tor", "python3", "/usr/local/bin/healthcheck.py"]\n' +
      "      interval: 60s\n      timeout: 10s\n      start_period: 120s\n      retries: 3\n";
    var header = "# hiddenforge compose fragment (hiddenforge v" + VERSION + ", contract " + CONTRACT_VERSION + ").";
    if (o.noRoot) header += "\n# No-root mode: the container runs as the tor user (100:101) with no capabilities at all.";
    var userLine = o.noRoot ? '    user: "100:101"\n' : "";
    var caps = o.noRoot ? "    cap_drop: [ALL]\n" : "    cap_drop: [ALL]\n    cap_add: [CHOWN, DAC_OVERRIDE, FOWNER, SETUID, SETGID]\n";
    var keysMount = yamlDq(o.keys + ":/var/lib/tor/hidden_service");
    return header + "\n" +
      "# Merge it into YOUR compose file; do not edit it:\n#\n" +
      "#   " + composeCmd + " -f compose.yml -f compose.service.yml up -d\n#\n" +
      "# Your backend service must join the `tor-internal` network below and must NOT\n" +
      "# publish any ports. hiddenforge reaches it by service name; the resolved IP is\n" +
      "# pinned into the torrc at container start.\n#\n" +
      "# Address:  hiddenforge show --json --name " + svc[0][0] + "\n" +
      "# Ready:    hiddenforge status --json   (poll the `ready` field)\n#\n" +
      "# Threat model: state-level adversary. Do not weaken these flags.\n\n" +
      "networks:\n  tor-internal:\n    internal: true\n  tor-external: {}\n\n" +
      "services:\n  " + o.container + ":\n    image: " + o.image + "\n    restart: " + restart + "\n" +
      userLine + caps +
      "    security_opt:\n      - no-new-privileges:true\n" + apparmor +
      "    read_only: true\n    pids_limit: 256\n    mem_limit: 512m\n    memswap_limit: 512m\n    cpus: 1.0\n" +
      "    ulimits:\n      nofile:\n        soft: 8192\n        hard: 8192\n" +
      "    tmpfs:\n      - /tmp:rw,noexec,nosuid,nodev,size=64m\n      " + etcTmpfs + "\n      " + torTmpfs + "\n" +
      "    logging:\n      driver: none\n    environment:\n" + envLines +
      "    volumes:\n      - " + keysMount + "\n    networks:\n      - tor-internal\n      - tor-external\n" +
      "    # No DNS leaves the container: backend names still resolve on the internal\n" +
      "    # network, but a name that does not (a backend down or not up yet) is never\n" +
      "    # forwarded upstream. Tor itself needs no DNS.\n    dns: 127.0.0.1\n" +
      secretUse + healthcheck + depBlock + secretDef;
  }

  function renderDeploy(services, o) {
    var names = sortedServices(services).map(function (s) { return shlexQuote(s[0]); }).join(" ");
    var keysQ = shlexQuote(o.keys);
    var disp = o.keys.split("\\").join("\\\\").split('"').join("'").split("$").join("\\$").split("`").join("'");
    var engineCheck, up;
    if (o.runtime === "podman") {
      engineCheck = 'COMPOSE=""\n' +
        'SOCK="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/podman/podman.sock"\n' +
        "for p in /usr/libexec/docker/cli-plugins/docker-compose \\\n" +
        "         /usr/lib/docker/cli-plugins/docker-compose \\\n" +
        "         /usr/local/lib/docker/cli-plugins/docker-compose \\\n" +
        '         "$HOME/.docker/cli-plugins/docker-compose"; do\n' +
        '    if [ -x "$p" ] && [ -S "$SOCK" ]; then\n' +
        '        COMPOSE="$p"\n        export DOCKER_HOST="unix://$SOCK"\n        break\n    fi\ndone\n' +
        'if [ -z "$COMPOSE" ]; then\n    if command -v podman-compose >/dev/null 2>&1; then\n' +
        "        COMPOSE=podman-compose\n" +
        '        echo "note: podman-compose does not apply pids_limit (before 1.1) or" >&2\n' +
        '        echo "memswap_limit; Docker Compose on the Podman socket does (README)." >&2\n' +
        "    else\n" +
        '        echo "Neither Docker Compose (with podman.socket) nor podman-compose found." >&2\n' +
        "        exit 1\n    fi\nfi";
      up = '"$COMPOSE"';
    } else {
      engineCheck = "if ! command -v docker >/dev/null 2>&1; then\n" +
        '    echo "docker not installed. Install Docker Engine first." >&2\n    exit 1\nfi';
      up = "docker compose";
    }
    var containerQ = shlexQuote(o.container);
    var ownStep = "";
    if (o.noRoot) {
      ownStep = o.runtime === "podman" ?
        'echo "==> Handing the key directory to the tor user (100:101)"\npodman unshare chown -R 100:101 ' + keysQ + "\n" :
        'if [ "$(stat -c %u:%g ' + keysQ + ')" != "100:101" ]; then\n' +
        '    echo "==> Handing the key directory to the tor user (100:101); sudo asks once"\n' +
        "    sudo chown -R 100:101 " + keysQ + "\nfi\n";
    }
    if (o.passphraseFile !== null) {
      var ppQ = shlexQuote(o.passphraseFile);
      ownStep += "if [ ! -s " + ppQ + " ]; then\n" +
        '    echo "==> Creating a random key passphrase (keys are encrypted at rest)"\n' +
        "    (umask 077; head -c 32 /dev/urandom | base64 > " + ppQ + ")\n" +
        '    echo "    BACK IT UP, separately from the key directory: without it the"\n' +
        '    echo "    address is lost. Kept on this disk it protects backups only."\nfi\n';
      if (o.noRoot) {
        ownStep += o.runtime === "podman" ? "podman unshare chown 100:101 " + ppQ + "\n" :
          'if [ "$(stat -c %u:%g ' + ppQ + ')" != "100:101" ]; then\n    sudo chown 100:101 ' + ppQ + "\nfi\n";
      }
    }
    var statusLine = shlexQuote("  hiddenforge status --container " + o.container + " --keys " + keysQ);
    var persisted = o.runtime === "podman" ? disp + "/$svc/hostname (read it with the exec command above)" :
      disp + "/$svc/hostname and " + disp + "/$svc.onion";
    return "#!/usr/bin/env bash\n" +
      "# hiddenforge, one-shot deploy. Generated by `hiddenforge setup`.\n" +
      "# Usage: ./deploy.sh [path/to/your-compose.yml]\nset -euo pipefail\n" +
      'cd "$(dirname "$0")"\n\nBASE="${1:-compose.yml}"\n' + engineCheck + "\n\n" +
      'echo "==> Preparing key directory ' + disp + '"\nmkdir -p ' + keysQ + "\nchmod 700 " + keysQ + " 2>/dev/null || :\n" +
      ownStep + "\n" +
      'echo "==> Bringing the stack up"\n' + up + ' -f "$BASE" -f compose.service.yml up -d\n\n' +
      'echo "==> Waiting for the .onion address(es) (up to 180s each)"\n' +
      "for svc in " + names + "; do\n" +
      '    onion=""\n    for _ in $(seq 1 180); do\n' +
      "        onion=$(" + up + ' -f "$BASE" -f compose.service.yml exec -T ' + containerQ + " \\\n" +
      "            su-exec tor cat /var/lib/tor/hidden_service/$svc/hostname 2>/dev/null || true)\n" +
      '        if [ -n "$onion" ]; then break; fi\n        sleep 1\n    done\n    echo\n' +
      '    echo "================================================================="\n' +
      '    if [ -n "$onion" ]; then\n        echo "$svc .onion: $onion"\n' +
      '        echo "Persisted to: ' + persisted + '"\n    else\n' +
      '        echo "$svc: no address yet. Container logging is off by design; run"\n' +
      "        printf '%s\\n' " + statusLine + "\n    fi\ndone\n" +
      "echo \"The address WORKS only once 'hiddenforge status' reports ready: true (Tor\"\n" +
      'echo "must publish it to the network first; a few minutes on a first boot)."\n' +
      'echo "BACK UP THE ENTIRE ' + disp + ' DIRECTORY. It IS your address."\n' +
      'echo "================================================================="\n';
  }

  function renderReadme(services, o) {
    var svc = sortedServices(services);
    var block = svc.map(function (s) { return "  " + s[0] + ": " + envVar(s[0]) + '="' + s[1].join(",") + '"'; }).join("\n");
    var names = svc.map(function (s) { return s[0]; }).join(", ");
    var composeCmd = o.runtime === "podman" ? "podman-compose" : "docker compose";
    return "hiddenforge, your setup\n=========================\n\nServices:\n" + block + "\n" +
      "Image:     " + o.image + "\nKeys:      " + o.keys + "\n\n" +
      "How to bring it up\n------------------\n" +
      "1. Make sure every backend service joins the `tor-internal` network and has no\n   published ports.\n" +
      "2. ./deploy.sh   (or: " + composeCmd + " -f compose.yml -f compose.service.yml up -d)\n\n" +
      "Where the addresses live\n------------------------\n" +
      "  " + o.keys + "/<service>/hostname   <- Tor's own hostname file\n" +
      "  " + o.keys + "/<service>.onion      <- world-readable copy written at startup\n\n" +
      "Read one any time:\n  hiddenforge show --keys " + shlexQuote(o.keys) + " --name <service> --json\n\n" +
      "Services: " + names + "\n\n" +
      "BACK UP THE ENTIRE " + o.keys + " DIRECTORY. A key IS a .onion address.\n" +
      "Losing it loses that address permanently.\n\n" +
      "If a backend is recreated on a different IP, hiddenforge notices and restarts\n" +
      "itself to follow it (this needs the restart policy the fragment sets).\n";
  }

  function renderDescriptor(services, o) {
    var svc = sortedServices(services);
    var composeCmd = o.runtime === "podman" ? "podman-compose" : "docker compose";
    var merge = composeCmd + " -f compose.yml -f " + shlexQuote(o.out + "/compose.service.yml") + " up -d";
    var list = svc.map(function (s) {
      return {
        name: s[0], env_var: envVar(s[0]), env_value: s[1].join(","),
        address_command: "hiddenforge show --json --name " + s[0],
        address_file: o.keys + "/" + s[0] + ".onion",
        key_path: o.keys + "/" + s[0] + "/" + SECRET_FILE
      };
    });
    var first = list[0];
    var d = {
      name: first.name, env_var: first.env_var, env_value: first.env_value, services: list,
      backend: svc[0][1][0].split(":")[1], image: o.image, keys: o.keys, container: o.container,
      runtime: o.runtime, onion_port: o.onionPort, output_dir: o.outputDir, merge: merge,
      address_command: "hiddenforge show --json --name " + first.name,
      ready_command: "hiddenforge status --json", bare_command: merge,
      address_file: first.address_file, key_path: first.key_path,
      contract_version: CONTRACT_VERSION, hiddenforge_version: VERSION
    };
    if (o.noRoot) d.no_root = true;
    if (o.passphraseFile !== null) { d.encrypt_keys = true; d.passphrase_file = o.passphraseFile; }
    return pyDumps(d) + "\n";
  }

  /* opts: {services: {name: ["onion:host:port", ...]}, image, keys, container,
   *        runtime, noRoot, encryptKeys, passphraseFile, onionPort, out, outputDir}
   * Returns {files: {name: text}} or throws Error(message) exactly as setup would. */
  function generate(opts) {
    var services = {};
    Object.keys(opts.services || {}).forEach(function (n) {
      validateName(n);
      services[n] = [];
      opts.services[n].forEach(function (m) {
        if (services[n].indexOf(m) < 0) services[n].push(m);
      });
    });
    if (!Object.keys(services).length) throw new Error("--backend service:port is required (or --service/--services)");
    var o = {
      image: validateImage(opts.image),
      keys: validateKeysDir(opts.keys),
      container: validateContainer(opts.container),
      runtime: opts.runtime === "podman" ? "podman" : "docker",
      noRoot: !!opts.noRoot,
      passphraseFile: opts.encryptKeys ? validateKeysDir(opts.passphraseFile || "./key-passphrase.txt") : null,
      onionPort: opts.onionPort || 80,
      out: opts.out || "hiddenforge-deploy",
      outputDir: opts.outputDir || opts.out || "hiddenforge-deploy"
    };
    if (!(o.onionPort >= 1 && o.onionPort <= 65535)) {
      throw new Error("--onion-port must be 1-65535, got " + o.onionPort + ". Emitting it anyway would write a " +
        "compose file whose service the container drops at boot, with the reason only in the container log.");
    }
    return {
      files: {
        "compose.service.yml": renderCompose(services, o),
        "deploy.sh": renderDeploy(services, o),
        "README.txt": renderReadme(services, o),
        "hiddenforge.json": renderDescriptor(services, o)
      }
    };
  }

  var api = {
    VERSION: VERSION, generate: generate, parseBackend: parseBackend, portOk: portOk,
    validateName: validateName, shlexQuote: shlexQuote, yamlDq: yamlDq, pyDumps: pyDumps
  };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.HFRender = api;
})(this);
