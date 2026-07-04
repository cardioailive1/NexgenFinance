'use strict';
const express  = require('express');
const passport = require('passport');
const router   = express.Router();
const authCtrl = require('../controllers/authController');
const { requireAuth } = require('../middleware/auth');
const { authLimiter } = require('../middleware/rateLimit');

// Apply rate limit to all auth routes
router.use(authLimiter);

// ── OAuth2 initiation ─────────────────────────────────────────────────────────

router.get('/google',
  passport.authenticate('google', { scope: ['profile', 'email'], session: true })
);

router.get('/github',
  passport.authenticate('github', { scope: ['user:email'], session: true })
);

router.get('/microsoft',
  passport.authenticate('microsoft', { session: true })
);

// ── OAuth2 callbacks ──────────────────────────────────────────────────────────

router.get('/google/callback',
  passport.authenticate('google', { session: true, failureRedirect: '/auth?error=google_failed' }),
  authCtrl.oauthCallback
);

router.get('/github/callback',
  passport.authenticate('github', { session: true, failureRedirect: '/auth?error=github_failed' }),
  authCtrl.oauthCallback
);

router.get('/microsoft/callback',
  passport.authenticate('microsoft', { session: true, failureRedirect: '/auth?error=microsoft_failed' }),
  authCtrl.oauthCallback
);

// ── Token management ──────────────────────────────────────────────────────────

router.post('/refresh',  authCtrl.refreshToken);
router.post('/logout',   requireAuth, authCtrl.logout);
router.post('/logout/all', requireAuth, authCtrl.logoutAll);
router.get('/me',        requireAuth, authCtrl.me);

module.exports = router;
