const express = require("express");
const path = require('path');
const passport = require('passport');
const KakaoStrategy = require('passport-kakao').Strategy;
const jose = require('node-jose');
const fs = require('fs').promises;
const cookieParser = require('cookie-parser');
const { clientID, callbackURL, rootDomain } = require('./secrets');

// JWT public key path
const KEY_PATH = path.join(__dirname, 'keys.json');

// Create key store
let keyStore = jose.JWK.createKeyStore();

// Create jwt with given payload content
async function getJwt(content) {
    const [key] = keyStore.all({ use: 'sig' });
    const opt = { format: 'compact' };
    const payload = JSON.stringify({
        iss: 'hcube',
        exp: Math.floor((Date.now()) / 1000) + 24 * 3600,
        iat: Math.floor(Date.now() / 1000),
        sub: 'auth',
        ...content
    });
    return await jose.JWS.createSign(opt, key)
        .update(payload)
        .final();
}

const app = express();

// Service static files
app.use(express.static(path.join(__dirname, 'public')));
// Use cookie
app.use(cookieParser());

// Get keys
app.get('/keys', (req, res) => {
    const keys = keyStore.all({ use: 'sig' });
    res.send(keys);
});

// Process OAuth
passport.use('kakao',
    new KakaoStrategy({ clientID, callbackURL }, (accessToken, refreshToken, profile, done) => {
        done(null, profile);
    })
);
app.get('/oauth/kakao/login', passport.authenticate('kakao'));
app.get('/oauth/kakao/callback', passport.authenticate('kakao', { session: false, }), async (req, res) => {
    // Get user information and build JWT
    const { user } = req;
    const jwt = await getJwt({
        provider: 'kakao',
        id: user.id
    });

    // Convey jwt with cookie
    res.cookie('token', jwt, { domain: rootDomain, maxAge: 60 * 1000 });

    // Redirect to requested location
    const redirect = req.cookies.redirect;
    if (redirect && redirect.startsWith('/')) {
        res.redirect(`https://${rootDomain}${redirect}`);
    } else res.redirect('/');
});

async function main() {
    // Restore key store if key.json exists. Or generate key store.
    try {
        let keyFile = await fs.readFile(KEY_PATH, 'utf-8');
        let keyJSON = JSON.parse(keyFile);
        keyStore = await jose.JWK.asKeyStore(keyJSON);
    } catch (_) {
        await keyStore.generate('RSA', 1024, { alg: 'RS256', use: 'sig' });
        let keyJSON = keyStore.toJSON(true);
        let keyFile = JSON.stringify(keyJSON);
        await fs.writeFile(KEY_PATH, keyFile, 'utf-8');
    }

    app.listen(80, () => {
        console.log("Auth server started.");
    });
}

main();