'use strict';
const passport = require('passport');
const prisma    = require('./prisma');
const config    = require('./index');
const logger    = require('../utils/logger');
const auditService = require('../services/auditService');

// Lazy-require each strategy so a missing/broken package doesn't crash the server
function tryRequire(pkg) {
  try { return require(pkg); }
  catch (e) { logger.warn(`OAuth strategy package not available: ${pkg}`); return null; }
}

async function handleOAuthUser(provider, profile, done, req) {
  try {
    const email = (
      (profile.emails && profile.emails[0]?.value) ||
      profile._json?.email ||
      profile._json?.userPrincipalName ||
      null
    );
    if (!email) return done(null, false, { message: 'No email returned from OAuth provider.' });

    const user = await prisma.user.upsert({
      where:  { provider_providerId: { provider, providerId: String(profile.id) } },
      update: { name: profile.displayName || null, avatar: profile.photos?.[0]?.value || null, lastLoginAt: new Date(), lastLoginIp: req?.ip || null },
      create: { email, name: profile.displayName || null, avatar: profile.photos?.[0]?.value || null, provider, providerId: String(profile.id), isEmailVerified: true, lastLoginAt: new Date(), lastLoginIp: req?.ip || null },
    });

    if (user.deletedAt) return done(null, false, { message: 'Account has been deleted.' });
    if (!user.isActive)  return done(null, false, { message: 'Account is disabled.' });

    await auditService.log({ userId: user.id, action: 'LOGIN', resource: `oauth:${provider}`, outcome: 'success', ipAddress: req?.ip, userAgent: req?.headers?.['user-agent'], details: { provider } });
    return done(null, user);
  } catch (err) {
    logger.error('OAuth user upsert failed', { provider, error: err.message });
    return done(err);
  }
}

function configurePassport() {
  // ── Google ────────────────────────────────────────────────────────────────
  const GoogleStrategy = tryRequire('passport-google-oauth20')?.Strategy;
  if (GoogleStrategy && config.oauth.google.clientId) {
    try {
      passport.use(new GoogleStrategy(
        { clientID: config.oauth.google.clientId, clientSecret: config.oauth.google.clientSecret, callbackURL: config.oauth.google.callbackUrl, passReqToCallback: true },
        (req, at, rt, profile, done) => handleOAuthUser('google', profile, done, req)
      ));
      logger.info('Passport: Google OAuth2 ready');
    } catch (e) { logger.warn('Google strategy failed to init', { error: e.message }); }
  }

  // ── GitHub ────────────────────────────────────────────────────────────────
  const GitHubStrategy = tryRequire('passport-github2')?.Strategy;
  if (GitHubStrategy && config.oauth.github.clientId) {
    try {
      passport.use(new GitHubStrategy(
        { clientID: config.oauth.github.clientId, clientSecret: config.oauth.github.clientSecret, callbackURL: config.oauth.github.callbackUrl, passReqToCallback: true, scope: ['user:email'] },
        (req, at, rt, profile, done) => handleOAuthUser('github', profile, done, req)
      ));
      logger.info('Passport: GitHub OAuth2 ready');
    } catch (e) { logger.warn('GitHub strategy failed to init', { error: e.message }); }
  }

  // ── Microsoft ─────────────────────────────────────────────────────────────
  const MicrosoftStrategy = tryRequire('passport-microsoft')?.Strategy;
  if (MicrosoftStrategy && config.oauth.microsoft.clientId) {
    try {
      passport.use(new MicrosoftStrategy(
        { clientID: config.oauth.microsoft.clientId, clientSecret: config.oauth.microsoft.clientSecret, callbackURL: config.oauth.microsoft.callbackUrl, tenant: config.oauth.microsoft.tenantId, passReqToCallback: true, scope: ['user.read'] },
        (req, at, rt, profile, done) => handleOAuthUser('microsoft', profile, done, req)
      ));
      logger.info('Passport: Microsoft OAuth2 ready');
    } catch (e) { logger.warn('Microsoft strategy failed to init', { error: e.message }); }
  }

  passport.serializeUser((user, done) => done(null, user.id));
  passport.deserializeUser(async (id, done) => {
    try { done(null, await prisma.user.findUnique({ where: { id } })); }
    catch (err) { done(err); }
  });
}

module.exports = { configurePassport };


/**
 * Upsert OAuth user — creates on first login, updates on subsequent.
 */
async function handleOAuthUser(provider, profile, accessToken, done, req) {
  try {
    const email = (
      (profile.emails && profile.emails[0]?.value) ||
      profile._json?.email ||
      null
    );

    if (!email) {
      return done(null, false, { message: 'No email returned from OAuth provider.' });
    }

    const user = await prisma.user.upsert({
      where:  { provider_providerId: { provider, providerId: profile.id } },
      update: {
        name:       profile.displayName || profile.username || null,
        avatar:     profile.photos?.[0]?.value || null,
        lastLoginAt: new Date(),
        lastLoginIp: req?.ip || null,
      },
      create: {
        email,
        name:       profile.displayName || profile.username || null,
        avatar:     profile.photos?.[0]?.value || null,
        provider,
        providerId: profile.id,
        isEmailVerified: true, // OAuth providers pre-verify email
        lastLoginAt: new Date(),
        lastLoginIp: req?.ip || null,
      },
    });

    // Soft-deleted accounts cannot log in
    if (user.deletedAt) {
      return done(null, false, { message: 'Account has been deleted.' });
    }
    if (!user.isActive) {
      return done(null, false, { message: 'Account is disabled. Contact support.' });
    }

    await auditService.log({
      userId:    user.id,
      action:    'LOGIN',
      resource:  `oauth:${provider}`,
      outcome:   'success',
      ipAddress: req?.ip,
      userAgent: req?.headers?.['user-agent'],
      details:   { provider, providerId: profile.id },
    });

    return done(null, user);
  } catch (err) {
    logger.error('OAuth user upsert failed', { provider, error: err.message });
    return done(err);
  }
}

function configurePassport() {
  // ── Google ────────────────────────────────────────────────────────────────
  if (config.oauth.google.clientId) {
    passport.use(new GoogleStrategy(
      {
        clientID:     config.oauth.google.clientId,
        clientSecret: config.oauth.google.clientSecret,
        callbackURL:  config.oauth.google.callbackUrl,
        passReqToCallback: true,
        scope: ['profile', 'email'],
      },
      (req, accessToken, refreshToken, profile, done) =>
        handleOAuthUser('google', profile, accessToken, done, req)
    ));
    logger.info('Passport: Google OAuth2 strategy registered');
  }

  // ── GitHub ────────────────────────────────────────────────────────────────
  if (config.oauth.github.clientId) {
    passport.use(new GitHubStrategy(
      {
        clientID:     config.oauth.github.clientId,
        clientSecret: config.oauth.github.clientSecret,
        callbackURL:  config.oauth.github.callbackUrl,
        passReqToCallback: true,
        scope: ['user:email'],
      },
      (req, accessToken, refreshToken, profile, done) =>
        handleOAuthUser('github', profile, accessToken, done, req)
    ));
    logger.info('Passport: GitHub OAuth2 strategy registered');
  }

  // ── Microsoft ─────────────────────────────────────────────────────────────
  if (config.oauth.microsoft.clientId) {
    passport.use(new MicrosoftStrategy(
      {
        clientID:     config.oauth.microsoft.clientId,
        clientSecret: config.oauth.microsoft.clientSecret,
        callbackURL:  config.oauth.microsoft.callbackUrl,
        tenant:       config.oauth.microsoft.tenantId,
        passReqToCallback: true,
        scope: ['user.read'],
      },
      (req, accessToken, refreshToken, profile, done) =>
        handleOAuthUser('microsoft', profile, accessToken, done, req)
    ));
    logger.info('Passport: Microsoft OAuth2 strategy registered');
  }

  // Minimal serialization — we use stateless JWT, sessions just for OAuth handshake
  passport.serializeUser((user, done) => done(null, user.id));
  passport.deserializeUser(async (id, done) => {
    try {
      const user = await prisma.user.findUnique({ where: { id } });
      done(null, user);
    } catch (err) {
      done(err);
    }
  });
}

module.exports = { configurePassport };
