require("dotenv").config();
const express = require("express");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const { Pool } = require("pg");

const app = express();
app.use(cookieParser());
app.use(express.json());
app.use(cors({ origin: "http://localhost:3000", credentials: true }));

const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI;
const JWT_SECRET = process.env.JWT_SECRET;

const db = new Pool({
    user: "pimogbu",
    host: "localhost",
    database: "postgredb",
    password: "PLqFN7UmE",
    port: 5432,
});

// -----------------
// Google OAuth
// -----------------

app.get("/", async (req, res) => {
    const user = await getUserFromCookies({ cookies: req.cookies, res });
    if (user) {
        res.send(`
      <h2>Hoşgeldin, ${user.name}!</h2>
      <p>Email: ${user.email}</p>
      <a href="/profile">Profile</a> | <a href="/logout">Logout</a>
    `);
    } else {
        res.send(`
      <h2>Google OAuth + JWT Demo</h2>
      <a href="/auth/google"><button>Google ile Giriş Yap</button></a>
    `);
    }
});
app.get("/auth/google", (req, res) => {
    const url =
        "https://accounts.google.com/o/oauth2/v2/auth" +
        `?client_id=${CLIENT_ID}` +
        `&redirect_uri=${REDIRECT_URI}` +
        "&response_type=code" +
        "&scope=openid%20email%20profile";
    res.redirect(url);
});

app.get("/auth/google/callback", async (req, res) => {
    const code = req.query.code;
    if (!code) return res.send("No code received");

    try {
        const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                code,
                client_id: CLIENT_ID,
                client_secret: CLIENT_SECRET,
                redirect_uri: REDIRECT_URI,
                grant_type: "authorization_code",
            }),
        });
        const tokenData = await tokenRes.json();
        if (tokenData.error) return res.send(tokenData);

        const userRes = await fetch("https://www.googleapis.com/oauth2/v3/userinfo", {
            headers: { Authorization: `Bearer ${tokenData.access_token}` },
        });
        const user = await userRes.json();

        const accessToken = jwt.sign({ email: user.email, name: user.name }, JWT_SECRET, { expiresIn: "15m" });

        const refreshToken = jwt.sign({ email: user.email, name: user.name }, JWT_SECRET, { expiresIn: "30d" });

        const result = await db.query(
            "INSERT INTO refresh_tokens (token, user_email, expires_at) VALUES ($1, $2, $3) RETURNING id",
            [refreshToken, user.email, new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)]
        );
        const refreshId = result.rows[0].id;

        res
            .cookie("access_token", accessToken, { httpOnly: true, sameSite: "lax", maxAge: 15 * 60 * 1000 })
            .cookie("refresh_token_id", refreshId, { httpOnly: true, sameSite: "lax", expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) })
            .send(`<h2>Login başarılı</h2><p>${user.name} (${user.email})</p><a href="/profile">Profile</a> | <a href="/logout">Logout</a>`);
    } catch (err) {
        console.error(err);
        res.status(500).send("Server error");
    }
});

// -----------------
// Middleware
// -----------------
async function auth(req, res, next) {
    const token = req.cookies.access_token;
    if (!token) return res.sendStatus(401);

    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch {
        const id = req.cookies.refresh_token_id;
        if (!id) return res.sendStatus(403);

        const result = await db.query("SELECT * FROM refresh_tokens WHERE id = $1", [id]);
        const row = result.rows[0];
        if (!row) return res.sendStatus(403);

        try {
            const decoded = jwt.verify(row.token, JWT_SECRET);
            const newAccessToken = jwt.sign({ email: decoded.email, name: decoded.name }, JWT_SECRET, { expiresIn: "15m" });
            res.cookie("access_token", newAccessToken, { httpOnly: true, sameSite: "lax", maxAge: 15 * 60 * 1000 });
            req.user = decoded;
            next();
        } catch {
            return res.sendStatus(403);
        }
    }
}

// -----------------
// Endpoints
// -----------------
app.get("/profile", auth, (req, res) => {
    res.json({ message: "Protected endpoint", user: req.user });
});

app.get("/refresh", async (req, res) => {
    const id = req.cookies.refresh_token_id;
    if (!id) return res.sendStatus(401);

    const result = await db.query("SELECT * FROM refresh_tokens WHERE id = $1", [id]);
    const row = result.rows[0];
    if (!row) return res.sendStatus(403);

    try {
        const decoded = jwt.verify(row.token, JWT_SECRET);
        const newAccessToken = jwt.sign({ email: decoded.email, name: decoded.name }, JWT_SECRET, { expiresIn: "15m" });
        res.cookie("access_token", newAccessToken, { httpOnly: true, sameSite: "lax", maxAge: 15 * 60 * 1000 });
        res.json({ message: "Access token yenilendi" });
    } catch {
        res.sendStatus(403);
    }
});

app.get("/logout", async (req, res) => {
    const id = req.cookies.refresh_token_id;
    if (id) await db.query("DELETE FROM refresh_tokens WHERE id = $1", [id]);

    res.clearCookie("access_token").clearCookie("refresh_token_id").send("Çıkış yapıldı ✅");
});

async function getUserFromCookies(req) {
    const accessToken = req.cookies.access_token;
    if (accessToken) {
        try {
            return jwt.verify(accessToken, JWT_SECRET);
        } catch {
            const id = req.cookies.refresh_token_id;
            if (!id) return null;
            const result = await db.query("SELECT * FROM refresh_tokens WHERE id = $1", [id]);
            const row = result.rows[0];
            if (!row) return null;

            try {
                const decoded = jwt.verify(row.token, JWT_SECRET);
                const newAccessToken = jwt.sign(
                    { email: decoded.email, name: decoded.name },
                    JWT_SECRET,
                    { expiresIn: "15m" }
                );
                req.res.cookie("access_token", newAccessToken, {
                    httpOnly: true,
                    sameSite: "lax",
                    maxAge: 15 * 60 * 1000,
                });
                return decoded;
            } catch {
                return null;
            }
        }
    }
    return null;
}

// -----------------
app.listen(3000, () => console.log("Server: http://localhost:3000"));
