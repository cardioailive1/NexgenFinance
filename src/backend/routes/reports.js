'use strict';
const express    = require('express');
const router     = express.Router();
const reportCtrl = require('../controllers/reportController');
const { requireAuth } = require('../middleware/auth');
const { reportLimiter } = require('../middleware/rateLimit');

router.use(requireAuth);

router.post('/generate', reportLimiter, reportCtrl.generateValidation, reportCtrl.generate);
router.get('/',          reportCtrl.list);
router.get('/:id',       reportCtrl.getOne);
router.delete('/:id',    reportCtrl.remove);

module.exports = router;
