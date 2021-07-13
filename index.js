const express = require("express")
const path = require('path')
const passport = require('passport')
const axios = require('axios')
const KakaoStrategy = require('passport-kakao').Strategy

const {
    clientID,
    callbackURL
} = require('./secrets')

passport.use('kakao',
    new KakaoStrategy({ clientID, callbackURL }, (accessToken, refreshToken, profile, done) => {
        console.log('Access', accessToken)
        console.log('Refresh', refreshToken)
        console.log('Profile', profile)
        done(null, profile)
    })
)

const app = express()

app.use(express.static(path.join(__dirname, 'public')))

app.get('/', (req, res) => {
    res.redirect('/index.html')
})

app.get('/oauth/kakao/login', passport.authenticate('kakao'))
app.get('/oauth/kakao/callback', passport.authenticate('kakao', { session: false, }), (req, res) => {
    res.redirect('/');
});

app.listen(80)