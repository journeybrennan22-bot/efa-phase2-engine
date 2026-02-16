// ============================================
// EFA PHASE 2 — ENGINE
// Orchestrator, suppression, merged warning, telemetry
// ============================================
// ADDITIVE ONLY — plugs into existing processEmail() flow
// Called right before displayResults() in production
// ============================================

// ============================================
// MAIN ORCHESTRATOR
// ============================================
// This is the single entry point for Phase 2
// Takes email data + core warnings, returns modified warnings array
//
// Integration point in processEmail():
//   const phase2Result = runPhase2Engine(emailData, coreWarnings);
//   const finalWarnings = phase2Result.finalWarnings;
//   displayResults(finalWarnings);

function runPhase2Engine(emailData, coreWarnings) {
  const startTime = performance.now();

  // Bail if Phase 2 is disabled
  if (!PHASE2_CONFIG.enabled) {
    return {
      finalWarnings: coreWarnings,
      phase2Ran: false,
      matchedPatterns: [],
      suppressedWarnings: [],
      runtime: 0
    };
  }

  // ---- STEP 1: Collect all signals ----
  const signals = collectPhase2Signals(emailData, coreWarnings);

  // ---- STEP 2: Evaluate all five patterns ----
  const matchedPatterns = evaluateAllPatterns(signals, coreWarnings);

  // ---- STEP 3: If silent mode, return core warnings unchanged ----
  if (PHASE2_CONFIG.silentMode) {
    const runtime = performance.now() - startTime;

    // Log for silent mode review
    if (matchedPatterns.length > 0) {
      console.log('[EFA Phase 2 SILENT]', {
        patterns: matchedPatterns.map(p => p.patternId),
        runtime: runtime.toFixed(1) + 'ms'
      });
    }

    // Send telemetry even in silent mode
    if (PHASE2_CONFIG.telemetryEnabled && matchedPatterns.length > 0) {
      sendPhase2Telemetry(matchedPatterns, [], emailData);
    }

    return {
      finalWarnings: coreWarnings,
      phase2Ran: true,
      matchedPatterns: matchedPatterns,
      suppressedWarnings: [],
      runtime: performance.now() - startTime,
      silentMode: true
    };
  }

  // ---- STEP 4: Apply suppression ----
  const { filteredWarnings, suppressedWarnings } = applyPhase2Suppression(
    coreWarnings,
    matchedPatterns
  );

  // ---- STEP 5: Build merged Phase 2 warning (if any patterns matched) ----
  let finalWarnings = [...filteredWarnings];

  if (matchedPatterns.length > 0) {
    const mergedWarning = buildPhase2MergedWarning(matchedPatterns, suppressedWarnings);
    finalWarnings.push(mergedWarning);
  }

  // ---- STEP 6: Telemetry ----
  if (PHASE2_CONFIG.telemetryEnabled && matchedPatterns.length > 0) {
    sendPhase2Telemetry(matchedPatterns, suppressedWarnings, emailData);
  }

  const runtime = performance.now() - startTime;

  // Performance warning
  if (runtime > 200) {
    console.warn('[EFA Phase 2] Performance ceiling exceeded:', runtime.toFixed(1) + 'ms');
  }

  return {
    finalWarnings: finalWarnings,
    phase2Ran: true,
    matchedPatterns: matchedPatterns,
    suppressedWarnings: suppressedWarnings,
    runtime: runtime
  };
}

// ============================================
// SIGNAL COLLECTOR
// ============================================
// Runs all signal detection functions once and caches results
// Pattern evaluators read from this cache — no duplicate work

function collectPhase2Signals(emailData, coreWarnings) {
  const body = emailData.body || emailData.bodyText || '';
  const senderDomain = emailData.senderDomain || '';
  const attachments = emailData.attachments || [];

  // Extract URLs from body
  const urls = extractPhase2Urls(body);

  // Run all signal detections
  const signals = {
    // Language signals
    credentialLanguage: detectPhase2CredentialLanguage(body),
    unlockLanguage: detectPhase2UnlockLanguage(body),
    paymentChangeLanguage: detectPhase2PaymentChangeLanguage(body),
    secrecyLanguage: detectPhase2SecrecyLanguage(body),

    // URL signals
    urls: urls,
    suspiciousHostingLink: detectPhase2SuspiciousHostingLink(urls),
    legitPlatformLink: detectPhase2LegitPlatformLink(urls),
    senderLinkMismatch: detectPhase2SenderLinkMismatch(senderDomain, urls),

    // Attachment signals
    attachmentAnalysis: analyzePhase2Attachments(attachments),

    // Sender signals
    isUnknownSender: isPhase2UnknownSender(
      emailData.isKnownContact || false,
      senderDomain,
      emailData.trustedDomains || []
    ),

    // Trusted + known sender (for Pattern D guardrail)
    isTrustedKnownSender: (emailData.isKnownContact === true) &&
      (emailData.isTrustedDomain === true)
  };

  return signals;
}

// ============================================
// PATTERN EVALUATION RUNNER
// ============================================
// Runs all five patterns, returns array of matches
// Early exits per pattern when required signal is missing (performance)

function evaluateAllPatterns(signals, coreWarnings) {
  const matched = [];

  const patternA = evaluatePatternA(signals);
  if (patternA) matched.push(patternA);

  const patternB = evaluatePatternB(signals, coreWarnings);
  if (patternB) matched.push(patternB);

  const patternC = evaluatePatternC(signals, coreWarnings);
  if (patternC) matched.push(patternC);

  const patternD = evaluatePatternD(signals, coreWarnings);
  if (patternD) matched.push(patternD);

  const patternE = evaluatePatternE(signals, coreWarnings);
  if (patternE) matched.push(patternE);

  return matched;
}

// ============================================
// SUPPRESSION LOGIC
// ============================================
// Removes core warnings that are superseded by Phase 2 patterns
// Rule: suppression is ADDITIVE across all matched patterns
// If ANY matched pattern suppresses a core warning type, it's removed

function applyPhase2Suppression(coreWarnings, matchedPatterns) {
  if (matchedPatterns.length === 0) {
    return {
      filteredWarnings: coreWarnings,
      suppressedWarnings: []
    };
  }

  // Build combined suppression set from all matched patterns
  const suppressedTypes = new Set();
  for (const pattern of matchedPatterns) {
    const suppressList = SUPPRESSION_MAP[pattern.patternId];
    if (suppressList) {
      for (const type of suppressList) {
        suppressedTypes.add(type);
      }
    }
  }

  const filteredWarnings = [];
  const suppressedWarnings = [];

  for (const warning of coreWarnings) {
    const warningType = warning.type || warning.warningType;
    if (suppressedTypes.has(warningType)) {
      suppressedWarnings.push(warning);
    } else {
      filteredWarnings.push(warning);
    }
  }

  return { filteredWarnings, suppressedWarnings };
}

// ============================================
// MERGED WARNING BUILDER
// ============================================
// Creates a single consolidated Phase 2 warning from all matched patterns
// Includes suppressed signal details so user understands the full picture

function buildPhase2MergedWarning(matchedPatterns, suppressedWarnings) {
  // Find the highest confidence level among matched patterns
  const confidencePriority = { 'critical': 3, 'high': 2, 'medium': 1 };
  let highestConfidence = 'medium';
  for (const pattern of matchedPatterns) {
    if ((confidencePriority[pattern.confidence] || 0) >
        (confidencePriority[highestConfidence] || 0)) {
      highestConfidence = pattern.confidence;
    }
  }

  // Build the warning message
  let title;
  if (matchedPatterns.length === 1) {
    title = matchedPatterns[0].patternName;
  } else {
    title = 'Multiple Phishing Indicators Detected';
  }

  // Consolidate descriptions and recommendations
  const descriptions = matchedPatterns.map(p => p.description);
  const recommendations = matchedPatterns.map(p => p.recommendation);

  // Note which core warnings were absorbed
  let suppressionNote = '';
  if (suppressedWarnings.length > 0) {
    const absorbedTypes = suppressedWarnings.map(w => w.type || w.warningType);
    suppressionNote = 'This analysis incorporates and replaces ' +
      absorbedTypes.length + ' individual warning(s) with this combined assessment.';
  }

  // Map confidence to severity for the warning object
  const severityMap = {
    'critical': 'critical',
    'high': 'high',
    'medium': 'medium'
  };

  // Build warning object matching existing EFA warning structure
  // This should match whatever shape displayResults() expects
  return {
    type: 'phase2-phishing-pattern',
    warningType: 'phase2-phishing-pattern',
    severity: severityMap[highestConfidence] || 'high',
    title: title,
    message: descriptions.join(' '),
    recommendation: recommendations[0], // Most critical pattern's recommendation
    details: {
      patterns: matchedPatterns.map(p => ({
        id: p.patternId,
        name: p.patternName,
        confidence: p.confidence,
        description: p.description,
        recommendation: p.recommendation,
        signals: p.signals
      })),
      suppressedCoreWarnings: suppressedWarnings.map(w => ({
        type: w.type || w.warningType,
        message: w.message || ''
      })),
      suppressionNote: suppressionNote,
      patternCount: matchedPatterns.length
    },
    // Flag for UI to render Phase 2 style
    isPhase2: true,
    priority: PHASE2_WARNING_PRIORITY['phase2-phishing-pattern'] || 13
  };
}

// ============================================
// TELEMETRY
// ============================================
// Privacy-safe, opt-in only
// No email content stored — only pattern IDs, signal names, and matched values
// Designed for pattern tuning and false positive analysis

function sendPhase2Telemetry(matchedPatterns, suppressedWarnings, emailData) {
  if (!PHASE2_CONFIG.telemetryEnabled) return;

  const telemetryEvent = {
    timestamp: new Date().toISOString(),
    version: PHASE2_CONFIG.version,
    platform: emailData.platform || 'unknown', // 'gmail' or 'outlook'
    silentMode: PHASE2_CONFIG.silentMode,
    pattern_ids: matchedPatterns.map(p => p.patternId),
    pattern_confidences: matchedPatterns.map(p => p.confidence),
    suppressed_core_warnings: suppressedWarnings.map(w => w.type || w.warningType),
    signals: {},
    user_action: null  // populated later by UI interaction handler
  };

  // Extract matched values from each pattern's signals (no email content)
  for (const pattern of matchedPatterns) {
    if (pattern.signals) {
      for (const [signalName, signalData] of Object.entries(pattern.signals)) {
        if (signalData && signalData.matched) {
          telemetryEvent.signals[signalName] = {
            matched: signalData.matched
          };
        }
      }
    }
  }

  // In production, this sends to your telemetry endpoint
  // For now, just log it
  console.log('[EFA Phase 2 Telemetry]', JSON.stringify(telemetryEvent));

  // TODO: Replace with actual endpoint when ready
  // fetch('https://telemetry.emailfraudalert.com/v1/phase2', {
  //   method: 'POST',
  //   headers: { 'Content-Type': 'application/json' },
  //   body: JSON.stringify(telemetryEvent)
  // }).catch(err => console.warn('[EFA Phase 2] Telemetry send failed:', err));
}

// ============================================
// INTEGRATION HELPER
// ============================================
// Documents exactly where and how to wire Phase 2 into production
//
// In processEmail(), insert BEFORE displayResults():
//
//   // --- Phase 2 Phishing Pattern Engine ---
//   const emailDataForPhase2 = {
//     body: bodyText,              // already available
//     senderDomain: senderDomain,  // already available
//     attachments: attachments,    // already available
//     isKnownContact: isKnownContact,    // from existing contact check
//     isTrustedDomain: isTrustedDomain,  // from existing domain check
//     trustedDomains: TRUSTED_DOMAINS,   // existing constant
//     platform: 'outlook'          // or 'gmail'
//   };
//
//   const phase2Result = runPhase2Engine(emailDataForPhase2, warnings);
//   warnings = phase2Result.finalWarnings;
//   // --- End Phase 2 ---
//
//   displayResults(warnings);
