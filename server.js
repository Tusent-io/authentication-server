const config = require("./config.json");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const express = require("express");
const authMiddleware = require("@tusent.io/authentication-middleware")();

mongoose.connect(config.databaseUri, { useNewUrlParser: true, useUnifiedTopology: true });
const Token = mongoose.model("Token", { id: String, user: Object, created: Date });
const User = mongoose.model("User", { id: String, email: String, pword_hash: String, profile: Object });

const generateSSOID = function () {
    return crypto.randomBytes(72).toString('base64');
}

const app = express();
app.use(cookieParser());

app.get("/", authMiddleware.authenticate, (req, res) => {
    req.status(200);

    if (req.user) {
        res.sendFile("views/userpage.html", { root: __dirname });
    } else {
        res.sendFile("views/signin.html", { root: __dirname });
    }
});

app.get("/authenticate", (req, res) => {
    let origin;

    if (!req.query["origin"]) {
        return res.status(400).send("Bad Request");
    } else {
        origin = decodeURIComponent(req.query["origin"]);
    }

    let id = generateSSOID();
    let user = null;

    try {
        user = jwt.verify(req.cookies["session_token"], config.jwt.key, { algorithms: [ config.jwt.alg ] });
    } catch (err) {
        res.cookie("session_token", "", { maxAge: 0, httpOnly: true, secure: true });
    }

    Token.create({ id: id, user: user, created: Date.now() }, (err, token) => {
        if (err) return res.status(500).send("Internal Server Error");

        let escapedTokenID = encodeURIComponent(token.id);
        res.redirect(`${origin}?ssoid=${escapedTokenID}`);
    });
});

app.post("/login", (req, res) => {
    let email = req.body["email"];
    let uncheckedPword = req.body["password"];

    if (email == null || password == null) {
        return res.status(400).send("Bad Request");
    }

    User.findOne({ email: email }, (err, userDoc) => {
        if (err) return res.status(500).send("Internal Server Error");
        if (userDoc == null) return res.status(403).send("Forbidden");

        bcrypt.compare(uncheckedPword, userDoc.pword_hash, (err, same) => {
            if (err) return res.status(500).send("Internal Server Error");
            if (!same) return res.status(403).send("Forbidden");

            let user = userDoc.profile;
            let sessionToken = jwt.sign(user, config.jwt.key, { algorithm: config.jwt.alg });

            res.cookie("session_token", sessionToken, { httpOnly: true, secure: true });
            res.status(200).send("OK");
        });
    });
});

app.post("/logout", (_, res) => {
    res.cookie("session_token", "", { maxAge: 0, httpOnly: true, secure: true });
    res.status(200).send("OK");
});

app.post("/register", (_, res) => {
    // Placeholder
    res.status(501).send("Not Implemented");
});

app.listen(config.port, () => {
    console.log(`Server listening on port ${config.port}.`);
});