const crypto = require("crypto");

module.exports = {
    tokens: {},
    timeouts: {},
    use(id) {
        try {
            return this.tokens[id];
        } finally {
            clearTimeout(this.timeouts[id]);
            delete this.tokens[id];
            delete this.timeouts[id];
        }
    },
    register(token, options = { keylength: 72, lifetime: 10000 }) {
        const { keylength = 72, lifetime = 10000 } = options;

        const id = crypto.randomBytes(keylength).toString("base64"); // Generate cryptographically safe random ID
        this.tokens[id] = token;
        this.timeouts[id] = setTimeout(() => this.use(id), lifetime);

        return id;
    },
};
