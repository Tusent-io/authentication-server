const cookieParser = require("cookie-parser")();
const axios = require("axios").default;
const util = require("util");

/**
 * Get the full requested URL and filter out any query strings with the name "sso".
 */
function getOrigin(req) {
    let origin = `${req.protocol}://${req.get("host")}${req.baseUrl + req.path}?`;

    for (let [key, value] of Object.entries(req.query)) {
        if (key != "sso") origin += `${key}=${value}&`;
    }

    return origin.substr(0, origin.length - 1);
}

/**
 * @param {object} [options]
 * @param {string} options.authenticateUrl
 * @param {string} options.verifyUrl
 * @param {number} [options.ssoCookieLifetime=10000]
 * @param {string} [options.apiKey="none"]
 * @param {function (any, any, function () : void) : void} [options.errorHandler]
 */
module.exports = function (options = {}) {
    const {
        ssoCookieLifetime = 10000,
        apiKey = "none",
        errorHandler = (_, res) => {
            res.sendStatus(400);
        },
    } = options;

    const authenticateUrl = new URL(options.authenticateUrl);
    const verifyUrl = new URL(options.verifyUrl);

    const secure = authenticateUrl.protocol.toLowerCase() === "https";

    return async function authenticate(req, res, next) {
        res.axiosRedirect = function (path) {
            const wantsJSON = req.accepts(["application/json", "*/*"]) === "application/json";

            if (wantsJSON) {
                this.json({
                    __redirect: path,
                });
            } else {
                this.redirect(307, path);
            }
        };

        const origin = getOrigin(req);

        if (req.query["sso"] != null && req.query["sso"].length > 0) {
            let ssoid = req.query["sso"];

            res.cookie("sso", ssoid, {
                httpOnly: true,
                maxAge: ssoCookieLifetime,
                secure,
            });

            return res.axiosRedirect(origin);
        }

        try {
            let cookies = req.cookies;

            // Get cookies using cookie-parser but leave nothing behind in req.
            if (typeof cookies != "object") {
                await util.promisify(cookieParser)(req, res);
                cookies = req.cookies;

                delete req.secret;
                delete req.cookies;
                delete req.signedCookies;
            }

            let ssoid = cookies["sso"];
            if (ssoid == null) {
                authenticateUrl.searchParams.set("origin", origin);

                return res.axiosRedirect(authenticateUrl.href);
            }

            res.cookie("sso", "", { httpOnly: true, maxAge: 0, secure });

            let user;
            try {
                verifyUrl.searchParams.set("sso", ssoid);
                verifyUrl.searchParams.set("api_key", apiKey);

                const response = await axios.get(verifyUrl.href);
                user = response.data;
            } catch (err) {
                if (err.response && err.response.status === 404) {
                    authenticateUrl.searchParams.set("origin", origin);

                    return res.axiosRedirect(authenticateUrl.href);
                } else {
                    throw err;
                }
            }

            req.user = user;
        } catch {
            return errorHandler(req, res, next);
        }

        return next();
    };
};
