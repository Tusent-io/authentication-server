const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const express = require("express");
const filterQueries = require("@tusent.io/filter-queries")();

const tokenStore = require("./token-store.js");

const config = require("./config.json");
const apiKeys = new Set(config.apiKeys);

const app = express();
app.use(cookieParser());

/**
 * Identify user (if logged in, else assign guest user) and register temporary authentication token.
 * Redirect to origin with an additional SSO query string containing the token ID.
 */
app.get("/authenticate", filterQueries("origin"), (req, res) => {
    let user = Object.freeze(config.guestUser);

    try {
        user = jwt.verify(req.cookies["session"], config.jwt.key, {
            algorithms: [config.jwt.alg],
        });
    } catch {
        res.cookie("session", "", { maxAge: 0, httpOnly: true, secure: config.port === 443 });
    }

    try {
        const origin = new URL(decodeURIComponent(req.query["origin"]));
        const ssoid = tokenStore.register(user, {
            keylength: config.tokenIdLength,
            lifetime: config.tokenLifetime,
        });

        origin.searchParams.set("sso", encodeURIComponent(ssoid));

        return res.redirect(origin.href);
    } catch {
        return res.status(400).send("Bad Request");
    }
});

// API
app.get("/verify", filterQueries("sso", "api_key"), (req, res) => {
    const apiKey = decodeURIComponent(req.query["api_key"]);

    if (!apiKeys.has(apiKey)) {
        return res.status(403).send("Forbidden");
    }

    const ssoid = decodeURIComponent(req.query["sso"]);
    const user = tokenStore.use(ssoid);

    if (user == null) {
        return res.status(404).send("Not Found");
    }

    return res.status(200).json(user);
});

app.listen(config.port, () => {
    console.log(`Server listening on port ${config.port}.`);
});
