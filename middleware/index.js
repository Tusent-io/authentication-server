const mongoose = require("mongoose");
const cookieParser = require("cookie-parser")();

/**
 * @param {object} options
 * @param {boolean} [options.secure=true]
 * @param {string} options.databaseUri
 * @param {string} options.ssoHostname
 */
module.exports = function (options) {
    if (typeof options.secure === "undefined") {
        options.secure = true;
    }

    mongoose.connect(options.databaseUri, { useNewUrlParser: true, useUnifiedTopology: true });
    const Token = mongoose.model("Token", { id: String, user: Object, created: Date });

    const getOrigin = function (req) {
        let origin = `${req.protocol}://${req.get("host")}${req.path}?`;
        for (let [key, value] of Object.entries(req.query)) {
            if (key != "ssoid")
            origin += `${key}=${value}&`;
        }
        origin = origin.substr(0, origin.length - 1);

        return origin;
    }

    let local = {};

    /**
     * @param {object} req
     * @param {object} res
     * @param {function} next
     */
    local.authenticate = function (req, res, next) {
        let origin = getOrigin(req);
        let escapedOrigin = encodeURIComponent(origin);
        let authURL = `http${options.secure ? "s" : ""}://${options.ssoHostname}/authenticate?origin=${escapedOrigin}`;

        cookieParser(req, res, () => {
            let ssoID;

            if (req.cookies["sso_id"] == null) {
                if (req.query["ssoid"] == null) {
                    return res.redirect(authURL);
                } else {
                    ssoID = decodeURIComponent(req.query["ssoid"]);

                    res.cookie("sso_id", ssoID, { httpOnly: true, maxAge: 10000, secure: options.secure });
                    return res.redirect(origin);
                }
            } else {
                ssoID = req.cookies["sso_id"];
            }
    
            Token.findOneAndDelete({ id: ssoID }, (err, doc) => {
                res.cookie("sso_id", "", { httpOnly: true, maxAge: 0, secure: options.secure });

                if (err || doc == null) {
                    return res.redirect(authURL);
                }
    
                req.user = doc.user;
                next();
            });
        });
    }

    /**
     * @param {object} req
     * @param {object} res
     * @param {function} next
     */
    local.requireLogin = function (req, res, next) {
        if (req.user == null) {
            let origin = getOrigin(req);
            let escapedOrigin = encodeURIComponent(origin);
            let loginURL = `http${options.secure ? "s" : ""}://${options.ssoHostname}/?origin=${escapedOrigin}`;

            return res.redirect(loginURL);
        }

        next();
    }

    return local;
}