require("dotenv").config();

const express = require("express");
const bcrypt = require("bcrypt");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const mysql = require("mysql");
const session = require("express-session");
const MySQLStore = require("express-mysql-session")(session);

// ---------------------- GENERAL SETUP ----------------------
const app = express();
const port = process.env.PORT || 3000;
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
const saltRound = 10;
// ---------------------- DATABASE SETUP ----------------------
connectionOptions = {
    host: process.env.HOST,
    user: process.env.USER,
    password: process.env.PASSWORD,
    database: process.env.DATABASE,
};

const db = mysql.createConnection(connectionOptions);
db.connect((err) => {
    if (err) throw err;
    console.log("Established connection with database");
});

// ---------------------- SESSION STORE SETUP ----------------------
const sessionStore = new MySQLStore({}, db);
app.use(
    session({
        secret: process.env.SESSION_SECRET_KEY,
        resave: false,
        saveUninitialized: false,
        store: sessionStore,
        cookie: {
            maxAge: 1000 * 60 * 60,
        },
    })
);

// ---------------------- PASSPORT CONFIGURATION ----------------------

app.use(passport.initialize());
app.use(passport.session());

passport.use(
    new LocalStrategy(
        {
            usernameField: "username",
            passwordField: "password",
        },
        (username, password, done) => {
            // Check if username existed in database
            db.query(
                "SELECT * FROM user WHERE username = ?",
                [username],
                async (err, result) => {
                    if (result.length === 0) {
                        return done(null, false);
                    }
                    const user = result[0];
                    const hashedPassword = user.hash;

                    isPasswordCorrect = await bcrypt.compare(
                        password,
                        hashedPassword
                    );

                    if (isPasswordCorrect) {
                        return done(null, user);
                    } else {
                        return done(null, false);
                    }
                }
            );
        }
    )
);

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    db.query("SELECT * FROM user WHERE id=?", [id], (err, result) => {
        if (err) {
            done(err);
            return;
        }
        user = result[0];
        done(err, user.id);
    });
});

// ---------------------- ROUTES ----------------------
app.post("/register", (req, res) => {
    // Check if user existed
    isUserExisted = false;
    db.query(
        "SELECT * FROM user WHERE username = ?",
        [req.body.username],
        async (err, result) => {
            if (result.length > 0) {
                res.status(400).send("Username taken");
                return;
            }

            // Create a new user
            try {
                const salt = await bcrypt.genSalt(saltRound);
                const hashedPassword = await bcrypt.hash(
                    req.body.password,
                    salt
                );

                db.query(
                    "INSERT INTO user (username, hash) VALUES (?, ?)",
                    [req.body.username, hashedPassword],
                    (err, result) => {
                        res.status(201).send("USER CREATED");
                    }
                );
            } catch {
                // Code 500 something wrong on server
                throw res
                    .status(500)
                    .send("Something went wrong, please try again");
            }
        }
    );
});

app.post(
    "/login",
    passport.authenticate("local", {
        successRedirect: "/login-sucess",
        failureRedirect: "/login-failure",
    })
);

app.get("/login-sucess", (req, res) => {
    res.send("Login success");
});

app.get("login-failure", (req, res) => {
    res.send("Login failure");
});

app.get("/logout", (req, res) => {
    req.logout();
    res.status(200).send("Logged out");
});

app.get("/secret", (req, res) => {
    if (req.isAuthenticated()) {
        res.status(200).send("PRIVATE INFO");
    } else {
        res.status(400).send("You need to sign in");
    }
});

app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});
