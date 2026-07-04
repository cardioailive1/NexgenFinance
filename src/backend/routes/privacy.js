'use strict';
const express      = require('express');
const router       = express.Router();
const privacyCtrl  = require('../controllers/privacyController');
const { requireAuth } = require('../middleware/auth');
const { privacyLimiter } = require('../middleware/rateLimit');

// Public metadata
router.get('/policy', privacyCtrl.policyMeta);

// Authenticated data rights
router.use(requireAuth);
router.use(privacyLimiter);

router.post('/consent', privacyCtrl.recordConsent);
router.post('/export',  privacyCtrl.requestExport);
router.post('/delete',  privacyCtrl.requestDeletion);

module.exports = router;
