const config = require("./config.json");
const crypto = require("crypto");
const cookieParser = require("cookie-parser");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const express = require("express");

mongoose.connect(config.databaseUri, { useNewUrlParser: true, useUnifiedTopology: true });
const Token = mongoose.model("Token", { id: String, user: Object, created: Date });

const generateTokenID = function () {
    return crypto.randomBytes(72).toString('base64');
}

const app = express();
app.use(cookieParser());

app.get("/authenticate", (req, res) => {
    let origin;

    if (!req.query["origin"]) {
        return res.status(400).send("Bad Request");
    } else {
        origin = decodeURIComponent(req.query["origin"]);
    }

    let id = generateTokenID();
    let user = null;

    try {
        user = jwt.verify(req.cookies["session_token"], config.jwt.key, { algorithms: [ config.jwt.alg ] });
    } catch (err) {
        res.cookie("session_token", "", { maxAge: 0, httpOnly: true, secure: true });
    }

    Token.create({ id: id, user: user, created: Date.now() }, (_, token) => {
        let escapedTokenID = encodeURIComponent(token.id);
        res.redirect(`${origin}?tokenid=${escapedTokenID}`);
    });
});

app.listen(config.port, () => {
    console.log(`Server listening on port ${config.port}.`);
});