const bcrypt = require("bcrypt");
const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const multer = require("multer");
const fs = require("fs");
const jwt = require("jsonwebtoken");

const app = express();

// ================= JWT SECRET =================
const JWT_SECRET = "course_platform_secret_key_2026";

// ================= MIDDLEWARE =================
app.use(cors());
app.use(express.json());
app.use("/uploads", express.static("uploads"));

// ================= DATABASE =================
const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "",
    database: "course_platform"
});

db.connect((err) => {
    if (err) console.log("❌ DB Error:", err);
    else console.log("✅ Connected to MySQL");
});

// ================= NOTIFICATIONS =================
let notifications = [];

app.get("/notifications", (req, res) => {
    res.json(notifications);
});

// ================= UPLOAD FOLDER =================
if (!fs.existsSync("uploads")) fs.mkdirSync("uploads");

// ================= MULTER =================
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, "uploads/"),
    filename: (req, file, cb) =>
        cb(null, Date.now() + "-" + file.originalname)
});

const upload = multer({ storage });

// ================= AUTH =================
function verifyToken(req, res, next) {
    const authHeader = req.headers["authorization"];

    if (!authHeader) return res.status(401).json({ message: "No token" });

    const token = authHeader.split(" ")[1];

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ message: "Invalid token" });
        req.user = decoded;
        next();
    });
}

// ================= ROLE CHECK =================
function isAdmin(req, res, next) {
    if (!req.user || req.user.role !== "admin") {
        return res.status(403).json({ message: "Admins only" });
    }
    next();
}

// ================= REGISTER =================
app.post("/register", async (req, res) => {

    const { name, email, university, password } = req.body;

    const hash = await bcrypt.hash(password, 10);

    db.query(
        "INSERT INTO users (name,email,university,password,role) VALUES (?,?,?,?, 'user')",
        [name, email, university, hash],
        (err) => {

            if (err) return res.json({ message: "Error" });

            notifications.push({ message: "👤 New user registered" });

            res.json({ message: "User registered successfully" });
        }
    );
});

// ================= LOGIN =================
app.post("/login", (req, res) => {

    const { email, password } = req.body;

    db.query("SELECT * FROM users WHERE email = ?", [email], async (err, result) => {

        if (err || result.length === 0)
            return res.json({ message: "User not found" });

        const user = result[0];

        const match = await bcrypt.compare(password, user.password);

        if (!match) return res.json({ message: "Wrong password" });

        // 🚫 BLOCK CHECK (IMPORTANT FIX)
        if (user.is_blocked === 1) {
            return res.json({ message: "Account blocked" });
        }

        const token = jwt.sign(
            { id: user.id, role: user.role },
            JWT_SECRET,
            { expiresIn: "1d" }
        );

        res.json({ message: "Login successful", token, user });
    });
});

// ================= UPLOAD =================
app.post("/upload", verifyToken, upload.single("file"), (req, res) => {

    const { course, university } = req.body;
    const user_id = req.user.id;
    const file = req.file;

    if (!file) return res.json({ message: "No file" });

    db.query(
        "INSERT INTO files (user_id,filename,original_name,filepath,course,university) VALUES (?,?,?,?,?,?)",
        [user_id, file.filename, file.originalname, file.path, course, university],
        (err) => {

            if (err) return res.json({ message: "Upload failed" });

            notifications.push({ message: "📁 New file uploaded" });

            res.json({ message: "File uploaded" });
        }
    );
});

// ================= FILES =================
app.get("/files", (req, res) => {
    db.query("SELECT * FROM files ORDER BY id DESC", (err, result) => {
        res.json(result || []);
    });
});

// ================= STATS =================
app.get("/stats/users", (req, res) => {
    db.query("SELECT COUNT(*) AS totalUsers FROM users", (err, result) => {
        res.json(result[0]);
    });
});

app.get("/stats/files", (req, res) => {
    db.query("SELECT COUNT(*) AS totalFiles FROM files", (err, result) => {
        res.json(result[0]);
    });
});

// ================= ADMIN FILES =================
app.get("/admin/files", verifyToken, isAdmin, (req, res) => {
    db.query("SELECT * FROM files ORDER BY id DESC", (err, result) => {
        res.json(result || []);
    });
});

// ================= CREATE ADMIN =================
app.post("/admin/create", verifyToken, isAdmin, async (req, res) => {

    const { name, email, university, password } = req.body;

    const hash = await bcrypt.hash(password, 10);

    db.query(
        "INSERT INTO users (name,email,university,password,role) VALUES (?,?,?,?, 'admin')",
        [name, email, university, hash],
        (err) => {

            if (err) return res.json({ message: "Error" });

            notifications.push({ message: "👑 New admin created" });

            res.json({ message: "Admin created" });
        }
    );
});

// ================= DELETE FILE =================
app.delete("/admin/file/:id", verifyToken, isAdmin, (req, res) => {

    db.query("DELETE FROM files WHERE id = ?", [req.params.id], (err) => {

        if (err) return res.json({ message: "Delete failed" });

        notifications.push({ message: "🗑️ File deleted by admin" });

        res.json({ message: "Deleted" });
    });
});

// ================= START =================
app.listen(3000, () => {
    console.log("🚀 Server running on port 3000");
});