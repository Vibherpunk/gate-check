// client-portal — REMEDIATED. Same app, three fixes the gate forced.
const { createServer } = require("node:http");
const { DatabaseSync } = require("node:sqlite");

// ✅ FIX 1 — secrets read from the environment, never committed to source.
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || "";
const DB_ADMIN_PASSWORD = process.env.DB_ADMIN_PASSWORD || "";

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
    // ✅ FIX 2 — parameterized query: input is data, never SQL.
    const rows = db.prepare("SELECT id, name, email, role FROM users WHERE name = ?").all(name);
    res.writeHead(200, { "content-type": "application/json" });
    return res.end(JSON.stringify(rows));
  }

  res.writeHead(404);
  res.end("not found");
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`client-portal listening on ${PORT}`));
