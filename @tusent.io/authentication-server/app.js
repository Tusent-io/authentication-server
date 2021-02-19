require("dotenv").config();

const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const express = require("express");
const filterQueries = require("@tusent.io/filter-queries")();
const tokenStore = require("./token-store.js");

const app = express();
app.use(cookieParser());

const apiKeys = new Set(process.env.API_KEYS.split(/\s*;\s*/));

/**
 * Identify user (if logged in, else assign guest user) and create a temporary authentication token.
 * Redirect to origin with an additional SSO query string containing the token ID.
 */
app.get("/authenticate", filterQueries("origin"), (req, res) => {
    let user = {};

    try {
        user = jwt.verify(req.cookies["session"], process.env.JWT_SECRET);
    } catch {
        res.cookie("session", "", { maxAge: 0, httpOnly: true, secure: process.env.PORT === 443 });
    }

    try {
        const origin = new URL(req.query["origin"]);
        const ssoid = tokenStore.create(user);
        origin.searchParams.set("sso", ssoid);

        return res.redirect(origin.href);
    } catch {
        return res.sendStatus(400);
    }
});

// API
app.get("/verify", filterQueries("sso", "api_key"), (req, res) => {
    const apiKey = req.query["api_key"];

    if (!apiKeys.has(apiKey)) {
        return res.sendStatus(403);
    }

    const ssoid = req.query["sso"];
    const user = tokenStore.consume(ssoid);

    if (user == null) {
        return res.sendStatus(404);
    }

    return res.status(200).json(user);
});

app.listen(process.env.PORT, () => {
    console.log(`Server listening on port ${process.env.PORT}.`);
});
