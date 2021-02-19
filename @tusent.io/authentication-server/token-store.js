const crypto = require("crypto");

module.exports = {
    _tokens: new Map(),
    consume(id) {
        return this._tokens.get(id)?.consume();
    },
    create(value, options = { keylength: 72, lifetime: 10000 }) {
        const { keylength = 72, lifetime = 10000 } = options;
        const tokens = this._tokens;

        const id = crypto.randomBytes(keylength).toString("base64"); // Generate cryptographically safe random ID
        const timeout = setTimeout(() => this.consume(id), lifetime);

        tokens.set(id, {
            consume() {
                tokens.delete(id);
                clearTimeout(timeout);
                return value;
            },
        });

        return id;
    },
};
