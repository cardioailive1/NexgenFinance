'use strict';
const passport = require('passport');
const prisma   = require('./prisma');
const config   = require('./index');
const logger   = require('../utils/logger');
const auditService = require('../services/auditService');

function tryRequire(pkg) {
  try { return require(pkg); }
  catch (e) { logger.warn('OAuth package unavailable: ' + pkg); return null; }
}

async function handleOAuthUser(provider, profile, done, req) {
  try {
    const email = (
      (profile.emails && profile.emails[0] && profile.emails[0].value) ||
      (profile._json && (profile._json.email || profile._json.userPrincipalName)) ||
      null
    );
    if (!email) return done(null, false, { message: 'No email returned from OAuth provider.' });

    const user = await prisma.user.upsert({
      where:  { provider_providerId: { provider, providerId: String(profile.id) } },
      update: {
        name:        profile.displayName || null,
        avatar:      (profile.photos && profile.photos[0] && profile.photos[0].value) || null,
        lastLoginAt: new Date(),
        lastLoginIp: (req && req.ip) || null,
      },
      create: {
        email,
        name:            profile.displayName || null,
        avatar:          (profile.photos && profile.photos[0] && profile.photos[0].value) || null,
        provider,
        providerId:      String(profile.id),
        isEmailVerified: true,
        lastLoginAt:     new Date(),
        lastLoginIp:     (req && req.ip) || null,
      },
    });

    if (user.deletedAt) return done(null, false, { message: 'Account has been deleted.' });
    if (!user.isActive)  return done(null, false, { message: 'Account is disabled.' });

    await auditService.log({
      userId:    user.id,
      action:    'LOGIN',
      resource:  'oauth:' + provider,
      outcome:   'success',
      ipAddress: req && req.ip,
      userAgent: req && req.headers && req.headers['user-agent'],
      details:   { provider },
    });

    return done(null, user);
  } catch (err) {
    logger.error('OAuth user upsert failed', { provider, error: err.message });
    return done(err);
  }
}

function configurePassport() {
  // ── Google ────────────────────────────────────────────────────────────────
  var googlePkg = tryRequire('passport-google-oauth20');
  if (googlePkg && config.oauth.google.clientId) {
    try {
      passport.use(new googlePkg.Strategy(
        {
          clientID:          config.oauth.google.clientId,
          clientSecret:      config.oauth.google.clientSecret,
          callbackURL:       config.oauth.google.callbackUrl,
          passReqToCallback: true,
        },
        function(req, at, rt, profile, done) { return handleOAuthUser('google', profile, done, req); }
      ));
      logger.info('Passport: Google OAuth2 ready');
    } catch (e) { logger.warn('Google strategy init failed: ' + e.message); }
  }

  // ── GitHub ────────────────────────────────────────────────────────────────
  var githubPkg = tryRequire('passport-github2');
  if (githubPkg && config.oauth.github.clientId) {
    try {
      passport.use(new githubPkg.Strategy(
        {
          clientID:          config.oauth.github.clientId,
          clientSecret:      config.oauth.github.clientSecret,
          callbackURL:       config.oauth.github.callbackUrl,
          passReqToCallback: true,
          scope:             ['user:email'],
        },
        function(req, at, rt, profile, done) { return handleOAuthUser('github', profile, done, req); }
      ));
      logger.info('Passport: GitHub OAuth2 ready');
    } catch (e) { logger.warn('GitHub strategy init failed: ' + e.message); }
  }

  // ── Microsoft ─────────────────────────────────────────────────────────────
  var msPkg = tryRequire('passport-microsoft');
  if (msPkg && config.oauth.microsoft.clientId) {
    try {
      passport.use(new msPkg.Strategy(
        {
          clientID:          config.oauth.microsoft.clientId,
          clientSecret:      config.oauth.microsoft.clientSecret,
          callbackURL:       config.oauth.microsoft.callbackUrl,
          tenant:            config.oauth.microsoft.tenantId,
          passReqToCallback: true,
          scope:             ['user.read'],
        },
        function(req, at, rt, profile, done) { return handleOAuthUser('microsoft', profile, done, req); }
      ));
      logger.info('Passport: Microsoft OAuth2 ready');
    } catch (e) { logger.warn('Microsoft strategy init failed: ' + e.message); }
  }

  passport.serializeUser(function(user, done) { done(null, user.id); });
  passport.deserializeUser(async function(id, done) {
    try { done(null, await prisma.user.findUnique({ where: { id } })); }
    catch (err) { done(err); }
  });
}

module.exports = { configurePassport };
