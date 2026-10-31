// Single-file VLESS + Reality server for panel hosts (Pterodactyl style).
// No npm packages needed. Upload this file, set the startup file to start.js
// and start the server. It downloads Xray, writes a config on the port the
// panel gives you, and prints your vless:// link in the console.
//
// Optional: set PUBLIC_HOST below (or as an env var) to your server's
// address/domain if the printed IP is wrong.

const fs = require("fs");
const os = require("os");
const path = require("path");
const https = require("https");
const zlib = require("zlib");
const crypto = require("crypto");
const { spawn, execFileSync } = require("child_process");

const PUBLIC_HOST = process.env.PUBLIC_HOST || ""; // e.g. "node1.example.com"
const PORT = parseInt(process.env.SERVER_PORT || process.env.PORT || "443", 10);
const SNI = "www.microsoft.com";

const BASE = __dirname;
const XRAY = path.join(BASE, "xray");
const STATE = path.join(BASE, "state.json");
const CONFIG = path.join(BASE, "config.json");

function get(url, redirects = 8) {
  return new Promise((resolve, reject) => {
    https
      .get(url, { headers: { "User-Agent": "node" } }, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          res.resume();
          if (redirects <= 0) return reject(new Error("too many redirects"));
          return resolve(get(new URL(res.headers.location, url).toString(), redirects - 1));
        }
        if (res.statusCode !== 200) {
          res.resume();
          return reject(new Error("HTTP " + res.statusCode + " for " + url));
        }
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => resolve(Buffer.concat(chunks)));
        res.on("error", reject);
      })
      .on("error", reject);
  });
}

// Minimal zip reader: returns the contents of one named entry.
function unzipEntry(buf, wanted) {
  let eocd = -1;
  for (let i = buf.length - 22; i >= 0; i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error("bad zip");
  const count = buf.readUInt16LE(eocd + 10);
  let p = buf.readUInt32LE(eocd + 16);
  for (let n = 0; n < count; n++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) throw new Error("bad zip directory");
    const method = buf.readUInt16LE(p + 10);
    const csize = buf.readUInt32LE(p + 20);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const localOff = buf.readUInt32LE(p + 42);
    const name = buf.slice(p + 46, p + 46 + nameLen).toString();
    if (name === wanted) {
      const lNameLen = buf.readUInt16LE(localOff + 26);
      const lExtraLen = buf.readUInt16LE(localOff + 28);
      const start = localOff + 30 + lNameLen + lExtraLen;
      const data = buf.slice(start, start + csize);
      return method === 0 ? data : zlib.inflateRawSync(data);
    }
    p += 46 + nameLen + extraLen + commentLen;
  }
  throw new Error(wanted + " not found in zip");
}

async function downloadXray() {
  if (fs.existsSync(XRAY)) return;
  const arch = os.arch();
  const name = arch === "arm64" ? "Xray-linux-arm64-v8a.zip" : "Xray-linux-64.zip";
  const url = "https://github.com/XTLS/Xray-core/releases/latest/download/" + name;
  console.log("Downloading " + url + " ...");
  const zip = await get(url);
  fs.writeFileSync(XRAY, unzipEntry(zip, "xray"));
  fs.chmodSync(XRAY, 0o755);
}

function makeKeys() {
  const out = execFileSync(XRAY, ["x25519"]).toString();
  const priv = out.match(/private\s*key\s*:\s*(\S+)/i)[1];
  const pub = out.match(/(?:public\s*key|password)[^:\n]*:\s*(\S+)/i)[1];
  return { priv, pub };
}

function loadState() {
  if (fs.existsSync(STATE)) return JSON.parse(fs.readFileSync(STATE, "utf8"));
  const { priv, pub } = makeKeys();
  const state = {
    uuid: crypto.randomUUID(),
    private: priv,
    public: pub,
    short_id: crypto.randomBytes(8).toString("hex"),
  };
  fs.writeFileSync(STATE, JSON.stringify(state));
  return state;
}

async function publicHost() {
  if (PUBLIC_HOST) return PUBLIC_HOST;
  for (const u of ["https://api.ipify.org", "https://ifconfig.me/ip"]) {
    try {
      return (await get(u)).toString().trim();
    } catch (e) {}
  }
  return "YOUR_SERVER_IP";
}

(async () => {
  await downloadXray();
  const s = loadState();

  const config = {
    log: { loglevel: "warning" },
    inbounds: [
      {
        listen: "0.0.0.0",
        port: PORT,
        protocol: "vless",
        settings: {
          clients: [{ id: s.uuid, flow: "xtls-rprx-vision" }],
          decryption: "none",
        },
        streamSettings: {
          network: "tcp",
          security: "reality",
          realitySettings: {
            show: false,
            dest: SNI + ":443",
            xver: 0,
            serverNames: [SNI],
            privateKey: s.private,
            shortIds: [s.short_id],
          },
        },
        sniffing: { enabled: true, destOverride: ["http", "tls", "quic"] },
      },
    ],
    outbounds: [{ protocol: "freedom" }],
  };
  fs.writeFileSync(CONFIG, JSON.stringify(config, null, 2));

  const host = await publicHost();
  const link =
    "vless://" + s.uuid + "@" + host + ":" + PORT +
    "?encryption=none&flow=xtls-rprx-vision&security=reality" +
    "&sni=" + SNI + "&fp=chrome&pbk=" + s.public + "&sid=" + s.short_id +
    "&type=tcp#katabump";

  console.log("\n================ YOUR VLESS LINK ================");
  console.log(link);
  console.log("=================================================\n");
  console.log(
    "Listening on port " + PORT + ". If the host/port above is wrong, use the " +
      "address and port shown in your panel's Network tab."
  );

  const child = spawn(XRAY, ["run", "-config", CONFIG], { stdio: "inherit" });
  child.on("exit", (code) => process.exit(code === null ? 1 : code));
  for (const sig of ["SIGINT", "SIGTERM"]) process.on(sig, () => child.kill(sig));
})().catch((e) => {
  console.error("Error: " + e.message);
  process.exit(1);
});
