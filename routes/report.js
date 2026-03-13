const express = require('express');
const router = express.Router();
const { generateForensicReport } = require('../forensics/reportGenerator');
const path = require('path');

router.get('/report/:sessionId?', async (req, res) => {
  try {
    const { sessionId } = req.params;

    const pdfPath = await generateForensicReport(sessionId || null);

    res.download(pdfPath, path.basename(pdfPath));
  } catch (err) {
    console.error('[PDF ERROR]', err);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;