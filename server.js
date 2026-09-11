const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
require("dotenv").config();

const app = express();
const db = new Database("investment.db");

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "test-secret-change-later";

app.use(express.json());
app.use(express.static("public"));

db.exec(`
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    balance REAL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    type TEXT,
    amount REAL,
    status TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS investments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    plan TEXT,
    amount REAL,
    status TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
`);

function authenticate(req, res, next) {
    const token = req.headers.authorization?.replace("Bearer ", "");

    if (!token) {
        return res.status(401).json({ error: "Not logged in" });
    }

    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch {
        res.status(401).json({ error: "Invalid token" });
    }
}

app.post("/api/register", async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({
            error: "All fields are required"
        });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        const result = db.prepare(`
            INSERT INTO users (name, email, password)
            VALUES (?, ?, ?)
        `).run(name, email, hashedPassword);

        res.json({
            message: "Account created",
            userId: result.lastInsertRowid
        });

    } catch {
        res.status(400).json({
            error: "Email already exists"
        });
    }
});

app.post("/api/login", async (req, res) => {
    const { email, password } = req.body;

    const user = db.prepare(`
        SELECT * FROM users WHERE email = ?
    `).get(email);

    if (!user) {
        return res.status(401).json({
            error: "Invalid email or password"
        });
    }

    const valid = await bcrypt.compare(password, user.password);

    if (!valid) {
        return res.status(401).json({
            error: "Invalid email or password"
        });
    }

    const token = jwt.sign(
        { id: user.id, email: user.email },
        JWT_SECRET,
        { expiresIn: "7d" }
    );

    res.json({ token });
});

app.get("/api/dashboard", authenticate, (req, res) => {
    const user = db.prepare(`
        SELECT id, name, email, balance
        FROM users
        WHERE id = ?
    `).get(req.user.id);

    const transactions = db.prepare(`
        SELECT *
        FROM transactions
        WHERE user_id = ?
        ORDER BY id DESC
    `).all(req.user.id);

    const investments = db.prepare(`
        SELECT *
        FROM investments
        WHERE user_id = ?
        ORDER BY id DESC
    `).all(req.user.id);

    res.json({
        user,
        transactions,
        investments
    });
});

/* TEST DEPOSIT ONLY */
app.post("/api/deposit", authenticate, (req, res) => {
    const amount = Number(req.body.amount);

    if (!amount || amount <= 0) {
        return res.status(400).json({
            error: "Enter a valid amount"
        });
    }

    db.prepare(`
        UPDATE users
        SET balance = balance + ?
        WHERE id = ?
    `).run(amount, req.user.id);

    db.prepare(`
        INSERT INTO transactions
        (user_id, type, amount, status)
        VALUES (?, 'TEST DEPOSIT', ?, 'COMPLETED')
    `).run(req.user.id, amount);

    res.json({
        message: "Test deposit completed",
        amount
    });
});

/* TEST INVESTMENT */
app.post("/api/invest", authenticate, (req, res) => {
    const { plan, amount } = req.body;
    const value = Number(amount);

    const user = db.prepare(`
        SELECT balance
        FROM users
        WHERE id = ?
    `).get(req.user.id);

    if (!value || value <= 0) {
        return res.status(400).json({
            error: "Invalid investment amount"
        });
    }

    if (user.balance < value) {
        return res.status(400).json({
            error: "Insufficient test balance"
        });
    }

    db.prepare(`
        UPDATE users
        SET balance = balance - ?
        WHERE id = ?
    `).run(value, req.user.id);

    db.prepare(`
        INSERT INTO investments
        (user_id, plan, amount, status)
        VALUES (?, ?, ?, 'ACTIVE TEST')
    `).run(req.user.id, plan, value);

    db.prepare(`
        INSERT INTO transactions
        (user_id, type, amount, status)
        VALUES (?, 'TEST INVESTMENT', ?, 'COMPLETED')
    `).run(req.user.id, value);

    res.json({
        message: "Test investment created"
    });
});

/* TEST WITHDRAWAL */
app.post("/api/withdraw", authenticate, (req, res) => {
    const amount = Number(req.body.amount);

    const user = db.prepare(`
        SELECT balance
        FROM users
        WHERE id = ?
    `).get(req.user.id);

    if (!amount || amount <= 0) {
        return res.status(400).json({
            error: "Invalid withdrawal amount"
        });
    }

    if (user.balance < amount) {
        return res.status(400).json({
            error: "Insufficient test balance"
        });
    }

    db.prepare(`
        UPDATE users
        SET balance = balance - ?
        WHERE id = ?
    `).run(amount, req.user.id);

    db.prepare(`
        INSERT INTO transactions
        (user_id, type, amount, status)
        VALUES (?, 'TEST WITHDRAWAL', ?, 'PENDING')
    `).run(req.user.id, amount);

    res.json({
        message: "Test withdrawal request created"
    });
});

app.get("*", (req, res) => {
    res.sendFile(__dirname + "/public/index.html");
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
