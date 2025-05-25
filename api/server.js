const express = require('express');
const crypto = require('crypto');
const app = express();

let tokens = {};

// Middleware to parse JSON bodies
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Generate tokens
app.get('/auth', (req, res) => {
    const clientId = req.query.client_id;
    const redirectUri = req.query.redirect_uri;
    const state = req.query.state;
    
    // Redirect to login page
    res.redirect(`/login?client_id=${clientId}&redirect_uri=${redirectUri}&state=${state}`);
});

// Login Page
app.get('/login', (req, res) => {
    res.send(`
        <form action="/token" method="post">
            <input type="hidden" name="client_id" value="${req.query.client_id}">
            <input type="hidden" name="redirect_uri" value="${req.query.redirect_uri}">
            <input type="hidden" name="state" value="${req.query.state}">
            <button type="submit">Authorize</button>
        </form>
    `);
});

// Token Exchange
app.post('/token', (req, res) => {
    const code = crypto.randomBytes(16).toString('hex');
    const token = crypto.randomBytes(16).toString('hex');
    tokens[code] = token;
    
    res.redirect(`${req.body.redirect_uri}?code=${code}&state=${req.body.state}`);
});

// Token Validation (Alexa calls this)
app.post('/token/validate', (req, res) => {
    const grantType = req.body.grant_type;
    const code = req.body.code;
    const clientId = req.body.client_id;
    const clientSecret = req.body.client_secret;
    
    if (grantType === 'authorization_code' && tokens[code]) {
        res.json({
            access_token: tokens[code],
            refresh_token: crypto.randomBytes(16).toString('hex'),
            expires_in: 3600
        });
    } else {
        res.status(400).json({ error: "Invalid request" });
    }
});

// Export the app as a serverless function
module.exports = app;
