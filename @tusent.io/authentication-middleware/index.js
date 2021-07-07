const cookie = require("cookie");
const axios = require("axios").default;

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
        errorHandler = (req, res) => {
            console.error(req.error);
            res.sendStatus(500);
        },
    } = options;

    const authenticateUrl = new URL(options.authenticateUrl);
    const verifyUrl = new URL(options.verifyUrl);

    const secure = authenticateUrl.protocol === "https:";

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

        const originUrl = new URL(`${authenticateUrl.protocol}//${req.hostname}${req.originalUrl}`);
        originUrl.searchParams.delete("sso");

        const origin = originUrl.href;

        if (req.query["sso"] != null && req.query["sso"].length > 0) {
            const ssoid = req.query["sso"];

            res.cookie("sso", ssoid, {
                httpOnly: true,
                maxAge: ssoCookieLifetime,
                secure,
            });

            return res.axiosRedirect(origin);
        }

        try {
            const cookies = cookie.parse(req.headers.cookie ?? "");
            const ssoid = cookies["sso"];

            if (ssoid == null) {
                authenticateUrl.searchParams.set("origin", origin);
                return res.axiosRedirect(authenticateUrl.href);
            }

            res.cookie("sso", "", { httpOnly: true, maxAge: 0, secure });

            try {
                verifyUrl.searchParams.set("sso", ssoid);
                verifyUrl.searchParams.set("api_key", apiKey);

                const response = await axios.get(verifyUrl.href);
                req.user = response.data;
            } catch (err) {
                if (err.response && err.response.status === 404) {
                    authenticateUrl.searchParams.set("origin", origin);
                    return res.axiosRedirect(authenticateUrl.href);
                } else {
                    throw err;
                }
            }
        } catch (error) {
            req.error = error;
            return errorHandler(req, res, next);
        }

        return next();
    };
};
