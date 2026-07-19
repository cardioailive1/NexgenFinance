'use strict';
const express  = require('express');
const passport = require('passport');
const router   = express.Router();
const authCtrl = require('../controllers/authController');
const { requireAuth } = require('../middleware/auth');
const { authLimiter } = require('../middleware/rateLimit');
const config   = require('../config');

router.use(authLimiter);

// ── Google ────────────────────────────────────────────────────────────────────
if (config.oauth.google.clientId) {
  // Initiation: session:true stores OAuth state for CSRF verification
  router.get('/google',
    passport.authenticate('google', { scope: ['profile', 'email'], session: true })
  );
  // Callback: session:false — skip req.logIn/serializeUser, user is on req.user directly
  router.get('/google/callback',
    passport.authenticate('google', { session: false, failureRedirect: '/?error=google_failed' }),
    authCtrl.oauthCallback
  );
} else {
  router.get('/google',          (req, res) => res.redirect('/?error=provider_not_configured'));
  router.get('/google/callback', (req, res) => res.redirect('/?error=provider_not_configured'));
}

// ── GitHub ────────────────────────────────────────────────────────────────────
if (config.oauth.github.clientId) {
  router.get('/github',
    passport.authenticate('github', { scope: ['user:email'], session: true })
  );
  router.get('/github/callback',
    passport.authenticate('github', { session: false, failureRedirect: '/?error=github_failed' }),
    authCtrl.oauthCallback
  );
} else {
  router.get('/github',          (req, res) => res.redirect('/?error=provider_not_configured'));
  router.get('/github/callback', (req, res) => res.redirect('/?error=provider_not_configured'));
}

// ── Microsoft ─────────────────────────────────────────────────────────────────
if (config.oauth.microsoft.clientId) {
  router.get('/microsoft',
    passport.authenticate('microsoft', { session: true })
  );
  router.get('/microsoft/callback',
    passport.authenticate('microsoft', { session: false, failureRedirect: '/?error=microsoft_failed' }),
    authCtrl.oauthCallback
  );
} else {
  router.get('/microsoft',          (req, res) => res.redirect('/?error=provider_not_configured'));
  router.get('/microsoft/callback', (req, res) => res.redirect('/?error=provider_not_configured'));
}

// ── Token management ──────────────────────────────────────────────────────────
router.post('/refresh',    authCtrl.refreshToken);
router.post('/logout',     requireAuth, authCtrl.logout);
router.post('/logout/all', requireAuth, authCtrl.logoutAll);
router.get('/me',          requireAuth, authCtrl.me);

module.exports = router;
