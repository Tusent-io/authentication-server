require("dotenv").config();

const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const express = require("express");
const filterQueries = require("@tusent.io/filter-queries")();
const tokenStore = require("./token-store.js");

const app = express();
app.use(cookieParser());

const apiKeys = new Set(process.env.API_KEYS.split(/;\s*/));

/**
 * Identify user (if logged in, else assign guest user) and register temporary authentication token.
 * Redirect to origin with an additional SSO query string containing the token ID.
 */
app.get("/authenticate", filterQueries("origin"), (req, res) => {
    let user = {};

    try {
        user = jwt.verify(req.cookies["session"], process.env.JWT_KEY, { algorithms: ["HS256"] });
    } catch {
        res.cookie("session", "", { maxAge: 0, httpOnly: true, secure: process.env.PORT === 443 });
    }

    try {
        const origin = new URL(req.query["origin"]);
        const ssoid = tokenStore.register(user);
        origin.searchParams.set("sso", ssoid);

        return res.redirect(origin.href);
    } catch {
        return res.status(400).send("Bad Request");
    }
});

// API
app.get("/verify", filterQueries("sso", "api_key"), (req, res) => {
    const apiKey = req.query["api_key"];

    if (!apiKeys.has(apiKey)) {
        return res.status(403).send("Forbidden");
    }

    const ssoid = req.query["sso"];
    const user = tokenStore.use(ssoid);

    if (user == null) {
        return res.status(404).send("Not Found");
    }

    return res.status(200).json(user);
});

app.listen(process.env.PORT, () => {
    console.log(`Server listening on port ${process.env.PORT}.`);
});
