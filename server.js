// =============================================================================
//  SERWER APLIKACJI VELORIE - WERSJA ZJEDNOCZONA
// =============================================================================

// -----------------------------------------------------------------------------
//  1. Importowanie modułów i konfiguracja wstępna
// -----------------------------------------------------------------------------
require('dotenv').config();
const express = require('express');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const session = require('express-session');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const DiscordStrategy = require('passport-discord').Strategy;
const cors = require('cors');
const sqlite3 = require('sqlite3');
const { open } = require('sqlite');

const app = express();
const PORT = process.env.PORT || 3000;

// -----------------------------------------------------------------------------
//  2. Konfiguracja bazy danych SQLite
// -----------------------------------------------------------------------------
let db;
(async () => {
    try {
        db = await open({ filename: './database.db', driver: sqlite3.Database });
        console.log('Połączono z bazą danych SQLite.');

        await db.exec(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                email TEXT UNIQUE,
                password_hash TEXT,
                google_id TEXT UNIQUE,
                discord_id TEXT UNIQUE,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log('Tabela "users" jest gotowa.');
    } catch (error) {
        console.error('Błąd podczas inicjalizacji bazy danych:', error);
    }
})();

// -----------------------------------------------------------------------------
//  3. Konfiguracja middleware
// -----------------------------------------------------------------------------
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serwujemy tylko jeden główny plik HTML z roota
app.use(express.static(__dirname));

app.use(session({
    secret: process.env.SESSION_SECRET || 'domyslny_sekret_sesji_zmien_go',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: process.env.NODE_ENV === 'production' }
}));

app.use(passport.initialize());
app.use(passport.session());

// -----------------------------------------------------------------------------
//  4. Konfiguracja Passport.js (Strategie logowania)
// -----------------------------------------------------------------------------
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
    try {
        const user = await db.get('SELECT id, username, email FROM users WHERE id = ?', [id]);
        done(null, user);
    } catch (err) {
        done(err, null);
    }
});

// -- Strategia Google --
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/api/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
    try {
        const email = profile.emails[0].value;
        let user = await db.get('SELECT * FROM users WHERE google_id = ? OR email = ?', [profile.id, email]);
        if (user) {
            if (!user.google_id) {
                await db.run('UPDATE users SET google_id = ? WHERE id = ?', [profile.id, user.id]);
            }
            return done(null, user);
        }
        const result = await db.run('INSERT INTO users (google_id, username, email) VALUES (?, ?, ?)', [profile.id, profile.displayName, email]);
        return done(null, { id: result.lastID, username: profile.displayName, email });
    } catch (err) {
        return done(err, null);
    }
}));

// -- Strategia Discord --
passport.use(new DiscordStrategy({
    clientID: process.env.DISCORD_CLIENT_ID,
    clientSecret: process.env.DISCORD_CLIENT_SECRET,
    callbackURL: "/api/auth/discord/callback",
    scope: ['identify', 'email']
}, async (accessToken, refreshToken, profile, done) => {
    try {
        let user = await db.get('SELECT * FROM users WHERE discord_id = ? OR email = ?', [profile.id, profile.email]);
        if (user) {
            if (!user.discord_id) {
                await db.run('UPDATE users SET discord_id = ? WHERE id = ?', [profile.id, user.id]);
            }
            return done(null, user);
        }
        const result = await db.run('INSERT INTO users (discord_id, username, email) VALUES (?, ?, ?)', [profile.id, profile.username, profile.email]);
        return done(null, { id: result.lastID, username: profile.username, email: profile.email });
    } catch (err) {
        return done(err, null);
    }
}));


// -----------------------------------------------------------------------------
//  5. Definicja endpointów API
// -----------------------------------------------------------------------------
app.post('/api/register', async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) return res.status(400).json({ message: 'Wszystkie pola są wymagane.' });
    try {
        const existingUser = await db.get('SELECT * FROM users WHERE email = ? OR username = ?', [email, username]);
        if (existingUser) return res.status(409).json({ message: 'Użytkownik z tym adresem e-mail lub nazwą już istnieje.' });

        const password_hash = await bcrypt.hash(password, 10);
        await db.run('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)', [username, email, password_hash]);
        res.status(201).json({ message: 'Rejestracja zakończona sukcesem! Możesz się teraz zalogować.' });
    } catch (error) {
        res.status(500).json({ message: 'Wystąpił błąd serwera.' });
    }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Proszę podać login i hasło.' });
    try {
        const user = await db.get('SELECT * FROM users WHERE email = ? OR username = ?', [email, email]);
        if (!user || !user.password_hash || !await bcrypt.compare(password, user.password_hash)) {
            return res.status(401).json({ message: 'Nieprawidłowy login lub hasło.' });
        }
        const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '1d' });
        res.json({ message: 'Zalogowano pomyślnie!', token });
    } catch (error) {
        res.status(500).json({ message: 'Wystąpił błąd serwera.' });
    }
});

const generateTokenAndRedirect = (req, res) => {
    const token = jwt.sign({ id: req.user.id, username: req.user.username }, process.env.JWT_SECRET, { expiresIn: '1d' });
    res.send(`<script>localStorage.setItem('authToken', '${token}'); window.location.href = '/';</script>`);
};

app.get('/api/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/api/auth/google/callback', passport.authenticate('google', { failureRedirect: '/' }), generateTokenAndRedirect);
app.get('/api/auth/discord', passport.authenticate('discord'));
app.get('/api/auth/discord/callback', passport.authenticate('discord', { failureRedirect: '/' }), generateTokenAndRedirect);

// Endpoint do pobierania danych użytkownika na podstawie tokenu
app.get('/api/user', (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
        if (err) return res.sendStatus(403);
        try {
            const user = await db.get('SELECT id, username, email FROM users WHERE id = ?', [decoded.id]);
            if (!user) return res.sendStatus(404);
            // Tutaj możesz dodać pobieranie salda portfela itp.
            res.json({
                id: user.id,
                username: user.username,
                vpln: 123.45, // Przykładowe dane
                vc: 500 // Przykładowe dane
            });
        } catch (dbError) {
            res.status(500).json({ message: 'Błąd bazy danych' });
        }
    });
});


// -----------------------------------------------------------------------------
//  6. Serwowanie pliku frontendu i start serwera
// -----------------------------------------------------------------------------
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
    console.log(`🚀 Serwer uruchomiony na porcie ${PORT}. Dostępny pod adresem: http://localhost:${PORT}`);
});