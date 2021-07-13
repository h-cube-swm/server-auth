const express = require("express")
const path = require('path')
const passport = require('passport')
const axios = require('axios')
const KakaoStrategy = require('passport-kakao').Strategy
const jose = require('node-jose');
const fs = require('fs').promises
const { clientID, callbackURL } = require('./secrets')

// JWT public key path
const KEY_PATH = path.join(__dirname, 'keys.json');

// Create key store
let keyStore = jose.JWK.createKeyStore();

// Create jwt with given payload content
async function getJwt(content) {
    const [key] = keyStore.all({ use: 'sig' });
    const opt = { format: 'compact' };
    const payload = JSON.stringify({
        iss: 'zetin',
        exp: Math.floor((Date.now()) / 1000) + 24 * 3600,
        iat: Math.floor(Date.now() / 1000),
        sub: 'auth',
        ...content
    });
    return await jose.JWS.createSign(opt, key)
        .update(payload)
        .final();
}

const app = express()

// Service static files
app.use(express.static(path.join(__dirname, 'public')))

// Root page redirection
app.get('/', (req, res) => {
    res.redirect('/index.html')
})

// Get keys
app.get('/keys', (req, res) => {
    const keys = keyStore.all({ use: 'sig' });
    res.send(keys);
});

// Process OAuth
passport.use('kakao',
    new KakaoStrategy({ clientID, callbackURL }, (accessToken, refreshToken, profile, done) => {
        done(null, profile)
    })
)
app.get('/oauth/kakao/login', passport.authenticate('kakao'))
app.get('/oauth/kakao/callback', passport.authenticate('kakao', { session: false, }), (req, res) => {
    res.redirect('/');
});

// Process logout
app.get('/logout', (req, res) => {
    res.send("Logout is not implemented yet!")
});

// Restore keyStore if key.json exists
(async function main() {
    try {
        let keyFile = await fs.readFile(KEY_PATH, 'utf-8');
        let input = JSON.parse(keyFile);
        keyStore = await jose.JWK.asKeyStore(input);
    } catch (_) {
        await keyStore.generate('RSA', 1024, { alg: 'RS256', use: 'sig' });
        fs.writeFile(
            KEY_PATH,
            JSON.stringify(keyStore.toJSON(true)),
            'utf-8'
        );
    }

    app.listen(80, () => {
        console.log("Auth server started.");
    });
})();