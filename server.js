// Wymagane biblioteki
const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs'); // Używamy bcryptjs dla lepszej kompatybilności
const passport = require('passport');
const session = require('express-session');
const DiscordStrategy = require('passport-discord').Strategy;
const LocalStrategy = require('passport-local').Strategy;
const cors = require('cors');
const sqlite3 = require('sqlite3');
const { open } = require('sqlite');
const SQLiteStore = require('connect-sqlite3')(session);

const app = express();
const PORT = process.env.PORT || 3000;

// Sprawdzenie kluczowych zmiennych środowiskowych
const requiredEnv = ['SESSION_SECRET', 'DISCORD_CLIENT_ID', 'DISCORD_CLIENT_SECRET'];
for (const env of requiredEnv) {
    if (!process.env[env]) {
        console.error(`[BŁĄD KRYTYCZNY] Brakująca zmienna środowiskowa: ${env}.`);
        process.exit(1);
    }
}

let db;
// Inicjalizacja bazy danych
(async () => {
    try {
        db = await open({ filename: './database.db', driver: sqlite3.Database });
        console.log('Połączono z bazą danych SQLite.');

        await db.exec(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT,
                discord_id TEXT UNIQUE,
                avatar TEXT
            )
        `);
        // Możesz dodać tabelę dla serwerów w przyszłości
        console.log('Tabela "users" jest gotowa.');
    } catch (error) {
        console.error('Błąd podczas inicjalizacji bazy danych:', error);
    }
})();

// Konfiguracja Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public')); // Dla favicon.png

app.use(session({
    store: new SQLiteStore({ db: 'database.db', dir: './' }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: 'auto', // Działa poprawnie na Railway
        maxAge: 1000 * 60 * 60 * 24 * 7 // Sesja ważna 7 dni
    }
}));

app.use(passport.initialize());
app.use(passport.session());

// Konfiguracja Passport.js
passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const user = await db.get('SELECT * FROM users WHERE id = ?', [id]);
        done(null, user);
    } catch (err) {
        done(err, null);
    }
});

// Strategia logowania lokalnego (email/hasło)
passport.use(new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
    try {
        const user = await db.get('SELECT * FROM users WHERE email = ?', [email]);
        if (!user) { return done(null, false, { message: 'Nieprawidłowy email lub hasło.' }); }
        if (!user.password_hash) { return done(null, false, { message: 'To konto loguje się przez Discorda.' }); }
        
        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (isMatch) { return done(null, user); } 
        else { return done(null, false, { message: 'Nieprawidłowy email lub hasło.' }); }
    } catch (err) { return done(err); }
}));

// Strategia logowania przez Discord
passport.use(new DiscordStrategy({
    clientID: process.env.DISCORD_CLIENT_ID,
    clientSecret: process.env.DISCORD_CLIENT_SECRET,
    callbackURL: "/auth/discord/callback", // Uproszczona, poprawna ścieżka
    scope: ['identify', 'email']
}, async (accessToken, refreshToken, profile, done) => {
    try {
        let user = await db.get('SELECT * FROM users WHERE discord_id = ?', [profile.id]);
        if (user) { return done(null, user); }
        
        user = await db.get('SELECT * FROM users WHERE email = ?', [profile.email]);
        if (user) {
            await db.run('UPDATE users SET discord_id = ?, avatar = ? WHERE id = ?', [profile.id, `https://cdn.discordapp.com/avatars/${profile.id}/${profile.avatar}.png`, user.id]);
            const updatedUser = await db.get('SELECT * FROM users WHERE id = ?', [user.id]);
            return done(null, updatedUser);
        }

        const result = await db.run('INSERT INTO users (discord_id, username, email, avatar) VALUES (?, ?, ?, ?)', [
            profile.id,
            profile.username,
            profile.email,
            `https://cdn.discordapp.com/avatars/${profile.id}/${profile.avatar}.png`
        ]);
        const newUser = { id: result.lastID, discord_id: profile.id, username: profile.username, email: profile.email };
        return done(null, newUser);
    } catch (err) { return done(err, null); }
}));

// --- TRASY APLIKACJI (ROUTES) ---

// Serwowanie plików HTML
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/panel', (req, res) => res.sendFile(path.join(__dirname, 'panel.html')));

// API do autentykacji
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        const existingUser = await db.get('SELECT * FROM users WHERE email = ? OR username = ?', [email, username]);
        if (existingUser) return res.status(400).json({ message: 'Użytkownik o tym emailu lub nazwie już istnieje.' });

        const password_hash = await bcrypt.hash(password, 10);
        await db.run('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)', [username, email, password_hash]);
        res.status(201).json({ message: 'Rejestracja pomyślna! Możesz się teraz zalogować.' });
    } catch (err) {
        res.status(500).json({ message: 'Błąd serwera.' });
    }
});

app.post('/api/login', passport.authenticate('local'), (req, res) => {
    res.status(200).json({ message: 'Zalogowano pomyślnie!' });
});

app.get('/api/logout', (req, res, next) => {
    req.logout(err => {
        if (err) { return next(err); }
        res.redirect('/');
    });
});

// Trasy logowania przez Discord
app.get('/auth/discord', passport.authenticate('discord'));
app.get('/auth/discord/callback',
    passport.authenticate('discord', {
        successRedirect: '/panel', // Po sukcesie przenieś do panelu
        failureRedirect: '/'      // Po porażce wróć na stronę główną
    })
);

// API do pobierania danych o zalogowanym użytkowniku
app.get('/api/me', (req, res) => {
    if (req.isAuthenticated()) {
        res.json({
            loggedIn: true,
            id: req.user.id,
            username: req.user.username,
            avatar: req.user.avatar
        });
    } else {
        res.json({ loggedIn: false });
    }
});

// Tutaj w przyszłości dodasz API do obsługi serwerów Minecraft
// np. app.get('/api/servers', ...)
// np. app.post('/api/servers', ...)

// --- URUCHOMIENIE SERWERA ---
app.listen(PORT, () => {
    console.log(`🚀 Serwer uruchomiony na porcie ${PORT}.`);
});
