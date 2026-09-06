// client-portal — VULNERABLE. The exact breach failure modes a Lovable/Bolt
// builder ships straight to deploy (PROJECT_BRIEF.md §5). The gate must BLOCK it.
const { createServer } = require("node:http");
const { DatabaseSync } = require("node:sqlite");

// ❌ VULN 1 — hardcoded secrets committed to source (gitleaks + semgrep catch).
const STRIPE_SECRET_KEY = "sk_live_FAKEKEY_REPLACED_BEFORE_PUSH_00000000000000000";
const API_KEY = "abcdef0123456789abcdef0123456789abcdef01";
const DB_ADMIN_PASSWORD = "sup3r-s3cret-admin-pw";

const db = new DatabaseSync(":memory:");
db.exec("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT, role TEXT)");
const seed = db.prepare("INSERT INTO users (name, email, role) VALUES (?, ?, ?)");
seed.run("alice", "alice@example.com", "admin");
seed.run("bob", "bob@example.com", "user");

const server = createServer((req, res) => {
  const url = new URL(req.url, "http://localhost");

  if (url.pathname === "/health") {
    res.writeHead(200, { "content-type": "application/json" });
    return res.end(JSON.stringify({ ok: true }));
  }

  if (url.pathname === "/users") {
    const name = url.searchParams.get("name") ?? "";
    // ❌ VULN 2 — SQL built by string interpolation: classic SQL injection (CWE-89).
    const rows = db.prepare(`SELECT id, name, email, role FROM users WHERE name = '${name}'`).all();
    res.writeHead(200, { "content-type": "application/json" });
    return res.end(JSON.stringify(rows));
  }

  res.writeHead(404);
  res.end("not found");
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`client-portal listening on ${PORT}`));
