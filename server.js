const config = require("./config.json");
const mailTemplates = require("./mail-templates.json");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const express = require("express");
const sendgrid = require("@sendgrid/mail");
const authMiddleware = require("@tusent.io/authentication-middleware")({
    secure: config.secure,
    databaseUri: config.databaseUri,
    ssoHostname:
        `${config.hostname}`
        + (config.port != 443 && config.port != 80 ? `:${config.port}` : "")
});

mongoose.connect(config.databaseUri, { useNewUrlParser: true, useUnifiedTopology: true });

const Token = mongoose.model("Token"); // Already compiled in '@tusent.io/authentication-middleware'.
const User = mongoose.model("User", {
    id: String,
    email: String,
    pword_hash: String,
    profile: Object
});
const RegRequest = mongoose.model("RegRequest", {
    created: Date,
    confirmation_code: String,
    email: String,
    pword_hash: String
});

sendgrid.setApiKey(config.sendgrid.key);

const app = express();
app.use(express.static("static"))
app.use(cookieParser());

function generateSSOID() {
    return crypto.randomBytes(72).toString('base64');
}

function format(format, objects) {
    let result = format;

    for (let key of Object.keys(objects)) {
        let identifier = `$${key.toUpperCase().replace(/(?!\w)./g, "_").replace(/(_$)|(^_)/g, "").replace(/_{2,}/g, "_")}`;
        let regex = new RegExp(`\\${identifier.split("").join("\\")}`, "g");

        result = result.replace(regex, objects[key].toString());
    }

    return result;
}

function normalizeEmailAddress(address) {
    let addressParts = address.split(/@/g);

    if (addressParts.length != 2) {
        throw new Error("Invalid email address!");
    } else {
        address = address.toLowerCase();
    }

    return address;
}

function isNullOrEmpty(obj) {
    if (typeof obj == "undefined") {
        return true;
    }
    
    if (obj === null) {
        return true;
    }
    
    if (typeof obj.length != "undefined") {
        return obj.length == 0;
    }

    if (typeof obj.size != "undefined") {
        return obj.size == 0;
    }

    return false;
}

function cleanupDB() {
    Token.remove({ created: { $lt: Date.now() - config.ssoTokenLifetime } });
    RegRequest.remove({ created: { $lt: Date.now() - config.regRequestLifetime } });
}

app.get("/", authMiddleware.authenticate, (req, res) => {
    res.status(200);

    if (req.user) {
        res.sendFile("views/userpage.html", { root: __dirname });
    } else {
        res.sendFile("views/index.html", { root: __dirname });
    }
});

app.get("/authenticate", (req, res) => {
    let origin;

    if (isNullOrEmpty(req.query["origin"])) {
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

    if (isNullOrEmpty(email) || isNullOrEmpty(uncheckedPword)) {
        return res.status(400).send("Bad Request");
    }

    try {
        email = normalizeEmailAddress(email);
    } catch (_) {
        return res.status(400).send("Bad Request");
    }

    User.findOne({ email: email }, (err, userDoc) => {
        if (err) return res.status(500).send("Internal Server Error");
        if (isNullOrEmpty(userDoc)) return res.status(403).send("Forbidden");

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

app.post("/register", (req, res) => {
    let email = req.body["email"];
    let pword = req.body["password"];

    if (isNullOrEmpty(email) || isNullOrEmpty(pword)) {
        return res.status(400).send("Bad Request");
    }

    try {
        email = normalizeEmailAddress(email);
    } catch (_) {
        return res.status(400).send("Bad Request");
    }

    User.findOne({ email: email }, (err, userDoc) => {
        if (err) return res.status(500).send("Internal Server Error");
        if (!isNullOrEmpty(userDoc)) return res.status(403).send("Forbidden");

        bcrypt.hash(pword, config.pwordSaltRounds).then((pwordHash) => {
            let confirmationCode = (crypto.randomBytes(8).readBigUInt64BE() + BigInt(11111111111)).toString().substr(1, 10);
            let confirmationTemplate = mailTemplates["confirm_email"];

            const message = {
                to: email,
                from: {
                    email: config.sendgrid.email,
                    name: config.sendgrid.name
                },
                subject: confirmationTemplate.subject,
                html: format(confirmationTemplate.html, { confirmation_code: confirmationCode })
            }
            
            sendgrid.send(message).then(() => {
                RegRequest.create({
                    created: Date.now(),
                    email: email,
                    pword_hash: pwordHash,
                    confirmation_code: confirmationCode
                }, (err) => {
                    if (err) return res.status(500).send("Internal Server Error");
                    else return res.status(201).send("Created");
                });
            }).catch(() => {
                return res.status(400).send("Bad Request");
            });
        });
    });
});

app.post("/confirm", (req, res) => {
    let email = req.body["email"];
    let pword = req.body["password"];
    let confirmationCode = req.body["confirmation_code"];

    if (isNullOrEmpty(email) || isNullOrEmpty(pword) || isNullOrEmpty(confirmationCode)) {
        return res.status(400).send("Bad Request");
    }

    try {
        email = normalizeEmailAddress(email);
    } catch (_) {
        return res.status(400).send("Bad Request");
    }

    User.findOne({ email: email }, (err, userDoc) => {
        if (err) return res.status(500).send("Internal Server Error");
        if (!isNullOrEmpty(userDoc)) return res.status(403).send("Forbidden");

        RegRequest.findOne({ email: email, confirmation_code: confirmationCode }, (err, regreq) => {
            if (err) return res.status(500).send("Internal Server Error");
            if (!isNullOrEmpty(regreq)) return res.status(403).send("Forbidden");

            bcrypt.compare(pword, regreq.pword_hash, (err, same) => {
                if (err) return res.status(500).send("Internal Server Error");
                if (!same) return res.status(403).send("Forbidden");

                let pwordHash = regreq.pword_hash;

                RegRequest.remove({ email: email }, (err) => {
                    if (err) return res.status(500).send("Internal Server Error");

                    let id = generateSSOID();
                    let emailNamePart = email.split(/@/ig)[0];
                    
                    User.create({ id: id, email: email, pword_hash: pwordHash, profile: { username: emailNamePart } }, (err) => {
                        if (err) return res.status(500).send("Internal Server Error");
                        else return res.status(201).send("Created");
                    })
                });
            });
        });
    });
});

app.listen(config.port, () => {
    console.log(`Server listening on port ${config.port}.`);

    (function cleanupLoop() {
        cleanupDB();
        setTimeout(cleanupLoop, config.dbCleanupInterval);
    })();
});