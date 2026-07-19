'use strict';
const express  = require('express');
const crypto   = require('crypto');
const router   = express.Router();
const prisma   = require('../config/prisma');
const config   = require('../config');
const logger   = require('../utils/logger');
const { requireAuth } = require('../middleware/auth');
const { authLimiter } = require('../middleware/rateLimit');
const authCtrl = require('../controllers/authController');

router.use(authLimiter);

// ─── helpers ──────────────────────────────────────────────────────────────────

function stateCookie(res, state) {
  res.cookie('_oauth_state', state, {
    httpOnly: true,
    secure:   config.isProd(),
    sameSite: 'lax',
    maxAge:   10 * 60 * 1000,
    path:     '/',
  });
}

function verifyState(req, res) {
  const state  = req.query.state;
  const stored = req.cookies._oauth_state;
  res.clearCookie('_oauth_state', { path: '/' });
  if (!state || !stored || state !== stored) {
    logger.warn('OAuth state mismatch', { got: state, stored });
    return false;
  }
  return true;
}

async function upsertUser(provider, providerId, email, name, avatar) {
  return prisma.user.upsert({
    where:  { provider_providerId: { provider, providerId: String(providerId) } },
    update: { name, avatar, lastLoginAt: new Date() },
    create: { email, name, avatar, provider, providerId: String(providerId), isEmailVerified: true, lastLoginAt: new Date() },
  });
}

async function finishLogin(user, res) {
  const tokens = authCtrl.issueTokens(user);
  try { await authCtrl.createSession(user, tokens, { ip: null, headers: {} }); } catch (_) {}
  authCtrl.setCookies(res, tokens);
  res.redirect(config.frontend.url + '/');
}

// ─── GOOGLE ───────────────────────────────────────────────────────────────────

router.get('/google', (req, res) => {
  if (!config.oauth.google.clientId) return res.redirect('/?error=provider_not_configured');
  const state = crypto.randomBytes(16).toString('hex');
  stateCookie(res, state);
  const url = 'https://accounts.google.com/o/oauth2/v2/auth?' + new URLSearchParams({
    client_id:     config.oauth.google.clientId,
    redirect_uri:  config.oauth.google.callbackUrl,
    response_type: 'code',
    scope:         'openid profile email',
    state,
    access_type:   'offline',
    prompt:        'select_account',
  });
  res.redirect(url);
});

router.get('/google/callback', async (req, res) => {
  if (req.query.error) return res.redirect('/?error=google_failed');
  if (!verifyState(req, res)) return res.redirect('/?error=google_failed');

  try {
    // Exchange code for access token
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method:  'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body:    new URLSearchParams({
        code:          req.query.code,
        client_id:     config.oauth.google.clientId,
        client_secret: config.oauth.google.clientSecret,
        redirect_uri:  config.oauth.google.callbackUrl,
        grant_type:    'authorization_code',
      }),
    });
    const tokenData = await tokenRes.json();
    if (tokenData.error) { logger.error('Google token error', tokenData); return res.redirect('/?error=google_failed'); }

    // Get profile
    const profileRes = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: 'Bearer ' + tokenData.access_token },
    });
    const profile = await profileRes.json();
    if (!profile.email) return res.redirect('/?error=google_failed');

    const user = await upsertUser('google', profile.id, profile.email, profile.name || null, profile.picture || null);
    await finishLogin(user, res);
  } catch (err) {
    logger.error('Google callback error', { error: err.message, stack: err.stack });
    res.redirect('/?error=server_error');
  }
});

// ─── GITHUB ───────────────────────────────────────────────────────────────────

router.get('/github', (req, res) => {
  if (!config.oauth.github.clientId) return res.redirect('/?error=provider_not_configured');
  const state = crypto.randomBytes(16).toString('hex');
  stateCookie(res, state);
  const url = 'https://github.com/login/oauth/authorize?' + new URLSearchParams({
    client_id:    config.oauth.github.clientId,
    redirect_uri: config.oauth.github.callbackUrl,
    scope:        'user:email',
    state,
  });
  res.redirect(url);
});

router.get('/github/callback', async (req, res) => {
  if (req.query.error) return res.redirect('/?error=github_failed');
  if (!verifyState(req, res)) return res.redirect('/?error=github_failed');

  try {
    const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
      method:  'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      body:    new URLSearchParams({
        client_id:     config.oauth.github.clientId,
        client_secret: config.oauth.github.clientSecret,
        code:          req.query.code,
        redirect_uri:  config.oauth.github.callbackUrl,
      }),
    });
    const tokenData = await tokenRes.json();
    if (tokenData.error) return res.redirect('/?error=github_failed');

    const profileRes = await fetch('https://api.github.com/user', {
      headers: { Authorization: 'Bearer ' + tokenData.access_token, 'User-Agent': 'NexGen-Finance' },
    });
    const profile = await profileRes.json();

    let email = profile.email;
    if (!email) {
      const emailsRes = await fetch('https://api.github.com/user/emails', {
        headers: { Authorization: 'Bearer ' + tokenData.access_token, 'User-Agent': 'NexGen-Finance' },
      });
      const emails = await emailsRes.json();
      const primary = emails.find(e => e.primary && e.verified);
      email = primary ? primary.email : (emails[0] && emails[0].email);
    }
    if (!email) return res.redirect('/?error=github_failed');

    const user = await upsertUser('github', profile.id, email, profile.name || profile.login || null, profile.avatar_url || null);
    await finishLogin(user, res);
  } catch (err) {
    logger.error('GitHub callback error', { error: err.message });
    res.redirect('/?error=server_error');
  }
});

// ─── MICROSOFT ────────────────────────────────────────────────────────────────

router.get('/microsoft', (req, res) => {
  if (!config.oauth.microsoft.clientId) return res.redirect('/?error=provider_not_configured');
  const state  = crypto.randomBytes(16).toString('hex');
  const tenant = config.oauth.microsoft.tenantId || 'common';
  stateCookie(res, state);
  const url = `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/authorize?` + new URLSearchParams({
    client_id:     config.oauth.microsoft.clientId,
    redirect_uri:  config.oauth.microsoft.callbackUrl,
    response_type: 'code',
    scope:         'openid profile email User.Read',
    state,
  });
  res.redirect(url);
});

router.get('/microsoft/callback', async (req, res) => {
  if (req.query.error) return res.redirect('/?error=microsoft_failed');
  if (!verifyState(req, res)) return res.redirect('/?error=microsoft_failed');

  try {
    const tenant = config.oauth.microsoft.tenantId || 'common';
    const tokenRes = await fetch(`https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body:    new URLSearchParams({
        client_id:     config.oauth.microsoft.clientId,
        client_secret: config.oauth.microsoft.clientSecret,
        code:          req.query.code,
        redirect_uri:  config.oauth.microsoft.callbackUrl,
        grant_type:    'authorization_code',
        scope:         'openid profile email User.Read',
      }),
    });
    const tokenData = await tokenRes.json();
    if (tokenData.error) return res.redirect('/?error=microsoft_failed');

    const profileRes = await fetch('https://graph.microsoft.com/v1.0/me', {
      headers: { Authorization: 'Bearer ' + tokenData.access_token },
    });
    const profile = await profileRes.json();
    const email   = profile.mail || profile.userPrincipalName;
    if (!email) return res.redirect('/?error=microsoft_failed');

    const user = await upsertUser('microsoft', profile.id, email, profile.displayName || null, null);
    await finishLogin(user, res);
  } catch (err) {
    logger.error('Microsoft callback error', { error: err.message });
    res.redirect('/?error=server_error');
  }
});

// ─── TOKEN MANAGEMENT ─────────────────────────────────────────────────────────

router.post('/refresh',    authCtrl.refreshToken);
router.post('/logout',     requireAuth, authCtrl.logout);
router.post('/logout/all', requireAuth, authCtrl.logoutAll);
router.get('/me',          requireAuth, authCtrl.me);

module.exports = router;
