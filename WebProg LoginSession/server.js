
const express = require("express");
const crypto = require("crypto");
const mysql = require("mysql2");

// Import express-session to remember logged-in users
const session = require("express-session");

const app = express();

// Allows Express to read HTML form data
app.use(express.urlencoded({ extended: true }));

// Allows Express to serve HTML files from public
app.use(express.static("public"));

// Configure session storage
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 60000 * 60,
        httpOnly: true,
        secure: false
    }
}));


app.get("/", function(req, res) {
    res.redirect("/login.html");
});

// Connect to the MySQL database with the database name "login_db"
const conn = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: process.env.ROOTPASS,
    database: "login_db",
    port: 3306
});

// Password hashing settings
const hashRounds = 100000;
const hashLength = 64;

// Connect to MySQL
conn.connect(function(err) {
    if (err) {
        console.log("Could not connect to MySQL", err);
    } else {
        console.log("Database connection established");
    }
});

// REGISTER ENDPOINT
app.post("/register", function(req, res) {

    let username = req.body.username;
    let email = req.body.email;
    let plainPass = req.body.password;

    // Validate submitted information
    if (!username || !email || !plainPass) {
        return res.status(400).send("All fields are required.");
    }

    // Generate a random salt for this user
    let salt = crypto.randomBytes(16).toString("hex");

    // Hash the password before storing it
    let hashedPass = crypto.pbkdf2Sync(
        plainPass,
        salt,
        hashRounds,
        hashLength,
        "sha512"
    ).toString("hex");

    // Insert the new user into the database
    let sql = "INSERT INTO users (username, email, password, salt) VALUES (?, ?, ?, ?)";

    conn.query(sql, [username, email, hashedPass, salt], function(err, result) {

        if (err) {
            console.log("Registration error:", err);

            if (err.code === "ER_DUP_ENTRY") {
                return res.status(409).send(
                    '<p>Username or email already exists.</p>' +
                    '<a href="register.html">Try again</a>'
                );
            }

            return res.status(500).send("Registration failed.");
        }

        res.send(
            '<p>You have successfully registered!</p>' +
            '<a href="login.html">Go to Login</a>'
        );
    });
});

// LOGIN ENDPOINT
app.post("/login", function(req, res) {

    let username = req.body.username;
    let plainPass = req.body.password;

    if (!username || !plainPass) {
        return res.status(400).send(
            '<p>Login credentials were incorrect.</p>' +
            '<a href="login.html">Try again</a>'
        );
    }

    // Find the user by username
    let sql = "SELECT * FROM users WHERE username = ?";

    conn.query(sql, [username], function(err, result) {

        if (err) {
            console.log("Login error:", err);
            return res.status(500).send("Login failed.");
        }

        // Check whether the username exists
        if (result.length === 0) {
            return res.send(
                '<p>Login credentials were incorrect.</p>' +
                '<a href="login.html">Try again</a>'
            );
        }

        let user = result[0];

        // Hash the submitted password with the saved salt
        let hashedPass = crypto.pbkdf2Sync(
            plainPass,
            user.salt,
            hashRounds,
            hashLength,
            "sha512"
        ).toString("hex");

        // Compare the hashed passwords
        let submittedHash = Buffer.from(hashedPass, "hex");
        let storedHash = Buffer.from(user.password, "hex");

        if (
    submittedHash.length === storedHash.length &&
    crypto.timingSafeEqual(submittedHash, storedHash)
) {

    // Regenerate the session after successful login
    req.session.regenerate(function(err) {

        if (err) {
            return res.status(500).send("Session error.");
        }

        // Store the username in the session
        req.session.username = username;

        // Save the session before responding
        req.session.save(function(err) {

            if (err) {
                return res.status(500).send("Session error.");
            }

            // Display a successful login message
            res.send(
                '<p>You have logged in successfully!</p>' +
                '<a href="/profile">View Profile</a>'
            );
        });
    });
} 
        else {
            res.send(
                '<p>Login credentials were incorrect.</p>' +
                '<a href="login.html">Try again</a>'
            );
        }
    });
});



// PROFILE ENDPOINT
app.get("/profile", function(req, res) {

    // Check if the user has logged in
    if (!req.session.username) {

        // If no session exists, ask the user to log in
        return res.send(
            '<p>You are not logged in.</p>' +
            '<a href="/login.html">Login here</a>'
        );
    }

    // Display the username stored in the session
    res.send(
        '<h2>Welcome to your profile!</h2>' +
        '<p>Username: ' + req.session.username + '</p>' +
        '<a href="/logout">Logout</a>'
    );
});

// LOGOUT ENDPOINT
app.get("/logout", function(req, res) {

    // Destroy the current user's session
    req.session.destroy(function(err) {

        // Handle any error while destroying the session
        if (err) {
            return res.send("Error logging out.");
        }

        // Clear the session cookie from the browser
        res.clearCookie("connect.sid");

        // Show a logout message and login link
        res.send(
            '<p>You have logged out successfully!</p>' +
            '<a href="/login.html">Login again</a>'
        );
    });
});



// Start the server
app.listen(3000, function() {
    console.log("Server running on http://localhost:3000");
});
