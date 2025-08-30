const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const DiscordStrategy = require('passport-discord').Strategy;
const bcrypt = require('bcryptjs');
const path = require('path');
const crypto = require('crypto');
const cors = require('cors');
const MongoStore = require('connect-mongo');

// --- 1. SCHEMATY I MODELE BAZY DANYCH (MONGOOSE) ---
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String },
    discordId: { type: String },
    googleId: { type: String },
    avatar: { type: String }
});
const User = mongoose.model('User', UserSchema);

const ServerSchema = new mongoose.Schema({
    owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    uniqueId: { type: String, required: true, unique: true },
    ipAddress: { type: String, required: true },
    version: { type: String, required: true },
    gameMode: { type: String, required: true },
    onlinePlayers: { type: Number, default: 0 },
    maxPlayers: { type: Number, default: 0 },
    motd: { type: String, default: 'Serwer oczekuje na weryfikację...' },
    logo: { type: String },
    isVerified: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});
const Server = mongoose.model('Server', ServerSchema);

// --- 2. KONFIGURACJA APLIKACJI EXPRESS ---
const app = express();
const PORT = process.env.PORT || 3000;

// Sprawdzenie kluczowych zmiennych środowiskowych
const requiredEnv = ['MONGO_URI', 'SESSION_SECRET', 'DISCORD_CLIENT_ID', 'DISCORD_CLIENT_SECRET'];
for (const env of requiredEnv) {
    if (!process.env[env]) {
        console.error(`[BŁĄD KRYTYCZNY] Brakująca zmienna środowiskowa: ${env}.`);
        process.exit(1);
    }
}

// Konfiguracja middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Konfiguracja sesji z zapisem w MongoDB
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: process.env.MONGO_URI }),
    cookie: {
        secure: 'auto',
        maxAge: 1000 * 60 * 60 * 24 * 7 // Sesja ważna 7 dni
    }
}));

// Inicjalizacja Passport.js
app.use(passport.initialize());
app.use(passport.session());

// --- 3. KONFIGURACJA PASSPORT.JS (STRATEGIE LOGOWANIA) ---
passport.use(new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
    try {
        // Logika pozwala na logowanie przez email lub nazwę użytkownika
        const user = await User.findOne({ $or: [{ email: email }, { username: email }] });
        if (!user) { return done(null, false, { message: 'Nie znaleziono użytkownika.' }); }
        if (!user.password) { return done(null, false, { message: 'To konto loguje się przez Discord/Google.' }); }

        const isMatch = await bcrypt.compare(password, user.password);
        if (isMatch) { return done(null, user); } 
        else { return done(null, false, { message: 'Nieprawidłowe hasło.' }); }
    } catch (err) { return done(err); }
}));

passport.use(new DiscordStrategy({
    clientID: process.env.DISCORD_CLIENT_ID,
    clientSecret: process.env.DISCORD_CLIENT_SECRET,
    callbackURL: "/auth/discord/callback",
    scope: ['identify', 'email']
}, async (accessToken, refreshToken, profile, done) => {
    try {
        let user = await User.findOne({ discordId: profile.id });
        if (user) { return done(null, user); }

        user = await User.findOne({ email: profile.email });
        if (user) {
            user.discordId = profile.id;
            user.avatar = user.avatar || `https://cdn.discordapp.com/avatars/${profile.id}/${profile.avatar}.png`;
            await user.save();
            return done(null, user);
        }

        const newUser = new User({
            discordId: profile.id,
            username: profile.username,
            email: profile.email,
            avatar: `https://cdn.discordapp.com/avatars/${profile.id}/${profile.avatar}.png`
        });
        await newUser.save();
        done(null, newUser);
    } catch (err) { return done(err, null); }
}));

passport.serializeUser((user, done) => { done(null, user.id); });
passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (err) { done(err); }
});

const isAuthenticated = (req, res, next) => {
    if (req.isAuthenticated()) { return next(); }
    res.status(401).json({ message: 'Brak autoryzacji.' });
};

// --- 4. TRASY (ROUTES) - PUBLICZNE I API ---

// Serwowanie plików HTML
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/panel', (req, res) => res.sendFile(path.join(__dirname, 'panel.html')));

// API do autentykacji
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        let user = await User.findOne({ $or: [{ email: email }, { username: username }] });
        if (user) { return res.status(400).json({ message: 'Użytkownik o tym emailu lub nazwie już istnieje.' }); }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, email, password: hashedPassword });
        await newUser.save();
        res.status(201).json({ message: 'Rejestracja pomyślna! Możesz się teraz zalogować.' });
    } catch (err) { res.status(500).json({ message: 'Błąd serwera podczas rejestracji.' }); }
});

app.post('/api/login', passport.authenticate('local'), (req, res) => {
    res.status(200).json({ message: 'Zalogowano pomyślnie!' });
});

app.get('/logout', (req, res, next) => {
    req.logout(err => {
        if (err) { return next(err); }
        res.redirect('/');
    });
});

// Trasy OAuth
app.get('/auth/discord', passport.authenticate('discord'));
app.get('/auth/discord/callback', passport.authenticate('discord', { failureRedirect: '/' }), (req, res) => res.redirect('/panel'));

// API do pobierania danych o zalogowanym użytkowniku
app.get('/api/me', (req, res) => {
    if (req.isAuthenticated()) {
        res.json({
            id: req.user._id,
            username: req.user.username,
            avatar: req.user.avatar || null
        });
    } else {
        res.status(401).json({ message: 'Brak autoryzacji.' });
    }
});

// API do serwerów
app.get('/api/servers', async (req, res) => {
    try {
        const servers = await Server.find().populate('owner', 'username').sort({ createdAt: -1 });
        res.json(servers);
    } catch (err) { res.status(500).json({ message: 'Błąd pobierania serwerów.' }); }
});

app.post('/api/servers', isAuthenticated, async (req, res) => {
    try {
        const { ipAddress, version, gameMode } = req.body;
        const uniqueId = crypto.randomBytes(16).toString('hex');
        
        const newServer = new Server({
            owner: req.user.id,
            uniqueId,
            ipAddress,
            version,
            gameMode
        });
        
        await newServer.save();
        res.status(201).json({ message: `Serwer dodany pomyślnie! Twoje unikalne ID dla pluginu to: ${uniqueId}`, server: newServer });
    } catch (err) { 
        console.error("Błąd dodawania serwera:", err);
        res.status(500).json({ message: 'Błąd dodawania serwera.' }); 
    }
});

// --- 5. POŁĄCZENIE Z BAZĄ I URUCHOMIENIE SERWERA ---
mongoose.connect(process.env.MONGO_URI)
    .then(() => {
        console.log('Połączono z bazą danych MongoDB.');
        app.listen(PORT, () => console.log(`Serwer McList nasłuchuje na porcie ${PORT}`));
    })
    .catch(err => {
        console.error('Błąd połączenia z MongoDB:', err);
        process.exit(1);
    });
