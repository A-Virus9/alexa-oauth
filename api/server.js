/**
 * Bypassed OAuth2 Authorization Server for Alexa Account Linking (for testing only)
 * Always authorizes and issues a token regardless of input.
 */

const express = require('express');
const crypto = require('crypto');
const app = express();

const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || `http://localhost:${PORT}`;

// Dummy client map for structure (not enforced)
const CLIENTS = {
  'alexa-button-skill': 'secret'
};

let tokens = {}; // In-memory token store

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Authorization Endpoint - auto-redirect with dummy code
app.get('/auth', (req, res) => {
  const { client_id, redirect_uri, state } = req.query;

  if (!client_id || !redirect_uri) {
    return res.status(400).send("Missing required query parameters: client_id or redirect_uri");
  }

  // Generate dummy auth code
  const code = crypto.randomBytes(16).toString('hex');
  tokens[code] = {
    access_token: crypto.randomBytes(32).toString('hex'),
    client_id,
    expires_at: Date.now() + 3600 * 1000
  };

  const redirectUrl = new URL(redirect_uri);
  redirectUrl.searchParams.append('code', code);
  if (state) redirectUrl.searchParams.append('state', state);

  res.redirect(redirectUrl.toString());
});

// Login Page - Skipped entirely
app.get('/login', (req, res) => {
  res.send(`
    <html>
    <body>
      <h2>This OAuth server automatically authorizes.</h2>
      <p>No login needed. Please return to the Alexa app.</p>
    </body>
    </html>
  `);
});

// Token endpoint (Alexa exchanges code for access token)
app.post('/token/exchange', (req, res) => {
  const dummyAccessToken = crypto.randomBytes(32).toString('hex');
  const dummyRefreshToken = crypto.randomBytes(32).toString('hex');

  res.json({
    access_token: dummyAccessToken,
    refresh_token: dummyRefreshToken,
    token_type: "Bearer",
    expires_in: 3600
  });
});

// Optional POST-based token creation (skipped in Alexa flow)
app.post('/token', (req, res) => {
  const { client_id, redirect_uri, state } = req.body;

  if (!client_id || !redirect_uri) {
    return res.status(400).send("Missing client_id or redirect_uri");
  }

  const code = crypto.randomBytes(16).toString('hex');
  tokens[code] = {
    access_token: crypto.randomBytes(32).toString('hex'),
    client_id,
    expires_at: Date.now() + 3600 * 1000
  };

  const redirectUrl = new URL(redirect_uri);
  redirectUrl.searchParams.append('code', code);
  if (state) redirectUrl.searchParams.append('state', state);

  res.redirect(redirectUrl.toString());
});

// Health check endpoint
app.get('/', (req, res) => {
  res.send("Bypassed OAuth2 Server is running ✅");
});

// Start local server
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Bypassed OAuth2 server running at ${HOST}`);
  });
}

// Export for serverless platforms
module.exports = app;
