
/**
 * OWASP Top 10 (2021) - Vulnerable Demo App
 * Purpose: Trigger GitHub Advanced Security (GHAS) CodeQL SAST findings
 * for training / live demo use only. Do NOT deploy.
 */

const express = require("express");
const mysql = require("mysql");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const http = require("http");
const { exec } = require("child_process");
const fs = require("fs");

const app = express();
app.use(express.json());

// ---------------------------------------------------------------
// A01:2021 - Broken Access Control
// No authorization check - any logged-in user can access any account
// ---------------------------------------------------------------
app.get("/api/account/:id", (req, res) => {
  const accountId = req.params.id;
  db.query("SELECT * FROM accounts WHERE id = " + accountId, (err, result) => {
    res.json(result); // missing check: does req.user own this account?
  });
});

// ---------------------------------------------------------------
// A02:2021 - Cryptographic Failures
// Weak hashing (MD5) and hardcoded secret key
// ---------------------------------------------------------------
const SECRET_KEY = "super-secret-key-123"; // hardcoded secret

function hashPassword(password) {
  return crypto.createHash("md5").update(password).digest("hex"); // weak algorithm
}

// ---------------------------------------------------------------
// A03:2021 - Injection (SQL Injection + Command Injection + XSS)
// ---------------------------------------------------------------
const db = mysql.createConnection({ host: "localhost", user: "root", password: "" });

app.get("/api/user", (req, res) => {
  const username = req.query.username;
  // SQL Injection - string concatenation
  const query = "SELECT * FROM users WHERE username = '" + username + "'";
  db.query(query, (err, result) => res.json(result));
});

app.get("/api/ping", (req, res) => {
  const host = req.query.host;
  // Command Injection - unsanitized input passed to shell
  exec("ping -c 1 " + host, (err, stdout) => res.send(stdout));
});

app.get("/api/greet", (req, res) => {
  const name = req.query.name;
  // Reflected XSS - unsanitized input written directly into HTML response
  res.send("<h1>Hello, " + name + "</h1>");
});

// ---------------------------------------------------------------
// A04:2021 - Insecure Design
// Password reset relies on a guessable, sequential token
// ---------------------------------------------------------------
let resetTokenCounter = 1000;
app.post("/api/reset-password", (req, res) => {
  const token = resetTokenCounter++; // predictable, not cryptographically random
  res.json({ resetToken: token });
});

// ---------------------------------------------------------------
// A05:2021 - Security Misconfiguration
// Verbose error handler leaks stack traces, debug mode left on
// ---------------------------------------------------------------
app.set("debug", true);
app.use((err, req, res, next) => {
  res.status(500).send("Error: " + err.stack); // leaks internal implementation details
});

// ---------------------------------------------------------------
// A06:2021 - Vulnerable and Outdated Components
// (Demonstrated via package.json - see note below)
// Example: pinning an old, CVE-affected version intentionally
// "lodash": "4.17.15"  <-- known prototype pollution CVE
// ---------------------------------------------------------------

// ---------------------------------------------------------------
// A07:2021 - Identification and Authentication Failures
// JWT verification accepts the "none" algorithm - signature bypass
// ---------------------------------------------------------------
app.post("/api/verify-token", (req, res) => {
  const decoded = jwt.verify(req.body.token, SECRET_KEY, { algorithms: ["none", "HS256"] });
  res.json(decoded);
});

// ---------------------------------------------------------------
// A08:2021 - Software and Data Integrity Failures
// Insecure deserialization - eval() on user-controlled input
// ---------------------------------------------------------------
app.post("/api/load-config", (req, res) => {
  const config = eval("(" + req.body.configString + ")"); // arbitrary code execution
  res.json(config);
});

// ---------------------------------------------------------------
// A09:2021 - Security Logging and Monitoring Failures
// Sensitive data (passwords) written to logs; failed logins not logged
// ---------------------------------------------------------------
app.post("/api/login", (req, res) => {
  console.log("Login attempt:", req.body.username, req.body.password); // logs plaintext password
  // no logging/alerting on repeated failed login attempts
  res.send("OK");
});

// ---------------------------------------------------------------
// A10:2021 - Server-Side Request Forgery (SSRF)
// Application fetches a URL directly from user input, no allow-list
// ---------------------------------------------------------------
app.get("/api/fetch-url", (req, res) => {
  const targetUrl = req.query.url;
  http.get(targetUrl, (response) => {
    let data = "";
    response.on("data", (chunk) => (data += chunk));
    response.on("end", () => res.send(data));
  });
});

app.listen(3000, () => console.log("Vulnerable demo app running on port 3000"));
