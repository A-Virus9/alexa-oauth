/**
 * OAuth2 Authorization Server for Alexa Account Linking
 * Implements Authorization Code flow with:
 * - /auth   : Start authorization, redirects to login
 * - /login  : Login form to authorize client
 * - /token  : Exchanges authorization code, redirects with code
 * - /token/exchange : Token endpoint, Alexa exchanges code for access token
 */

const express = require('express');
const crypto = require('crypto');
const app = express();

const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || `http://localhost:${PORT}`;

// Dummy client credentials (replace with your actual client info)
const CLIENTS = {
  'alexa-button-skill': 'secret'
};

let tokens = {}; // Store tokens by code

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Authorization Endpoint
app.get('/auth', (req, res) => {
  const { client_id, redirect_uri, state } = req.query;

  if (!client_id || !redirect_uri) {
    return res.status(400).send("Missing required query parameters: client_id or redirect_uri");
  }
  if (!CLIENTS[client_id]) {
    return res.status(400).send("Invalid client_id");
  }

  // Redirect user to login page with client info and state preserved
  const loginUrl = new URL('alexa-oauth.vercel.app' + '/login');
  loginUrl.searchParams.append('client_id', client_id);
  loginUrl.searchParams.append('redirect_uri', redirect_uri);
  if(state) loginUrl.searchParams.append('state', state);

  res.redirect(loginUrl.toString());
});

// Login Page - user authorizes the client
app.get('/login', (req, res) => {
  const { client_id, redirect_uri, state } = req.query;
  if (!client_id || !redirect_uri) {
    return res.status(400).send("Missing client_id or redirect_uri in login");
  }

  res.send(`
    <html>
    <body>
      <h2>Authorize Application</h2>
      <p>Client ID: ${client_id}</p>
      <form method="post" action="/token">
        <input type="hidden" name="client_id" value="${client_id}" />
        <input type="hidden" name="redirect_uri" value="${redirect_uri}" />
        <input type="hidden" name="state" value="${state || ''}" />
        <button type="submit">Authorize</button>
      </form>
    </body>
    </html>
  `);
});

// Token Endpoint - authorization code generation and redirection
app.post('/token', (req, res) => {
  const { client_id, redirect_uri, state } = req.body;

  if (!client_id || !redirect_uri) {
    return res.status(400).send("Missing client_id or redirect_uri in token request");
  }
  if (!CLIENTS[client_id]) {
    return res.status(400).send("Invalid client_id");
  }

  // Generate authorization code and a token associated with it
  const code = crypto.randomBytes(16).toString('hex');
  const token = crypto.randomBytes(32).toString('hex');
  tokens[code] = {
    access_token: token,
    client_id,
    expires_at: Date.now() + 3600 * 1000 // 1 hour expiry
  };

  // Redirect URI must be absolute and valid per OAuth2 spec
  let redirectUrl;
  try {
    redirectUrl = new URL(redirect_uri);
  } catch (err) {
    return res.status(400).send("Invalid redirect_uri");
  }

  redirectUrl.searchParams.append('code', code);
  if (state) redirectUrl.searchParams.append('state', state);

  res.redirect(redirectUrl.toString());
});

// Token Exchange Endpoint - Alexa calls this to get access token
app.post('/token/exchange', (req, res) => {
  const { grant_type, code, client_id, client_secret, redirect_uri } = req.body;

  if (grant_type !== 'authorization_code') {
    return res.status(400).json({ error: "unsupported_grant_type" });
  }
  if (!code || !client_id || !client_secret) {
    return res.status(400).json({ error: "invalid_request", error_description: "Missing required parameters" });
  }
  // Validate client credentials
  if (CLIENTS[client_id] !== client_secret) {
    return res.status(401).json({ error: "invalid_client" });
  }
  const tokenEntry = tokens[code];
  if (!tokenEntry) {
    return res.status(400).json({ error: "invalid_grant", error_description: "Invalid or expired authorization code" });
  }
  if (tokenEntry.client_id !== client_id) {
    return res.status(400).json({ error: "invalid_grant", error_description: "Authorization code does not belong to client" });
  }
  
  if(Date.now() > tokenEntry.expires_at){
    delete tokens[code];
    return res.status(400).json({ error: "invalid_grant", error_description: "Authorization code has expired" });
  }

  // Respond with the access token info per Alexa spec
  res.json({
    access_token: tokenEntry.access_token,
    refresh_token: crypto.randomBytes(32).toString('hex'), // You may implement refresh tokens properly if needed
    token_type: "Bearer",
    expires_in: 3600
  });

  // Optionally invalidate the code after use
  delete tokens[code];
});

// Basic health check endpoint
app.get('/', (req, res) => {
  res.send("OAuth2 Server is running");
});

// Start the server for local testing (not required for serverless deployments)
if(require.main === module){
  app.listen(PORT, () => {
    console.log(`OAuth2 server running at ${HOST}`);
  });
}

// Export app for serverless deployment platforms (e.g., Vercel)
module.exports = app;

