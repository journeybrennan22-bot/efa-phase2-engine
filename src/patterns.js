// ============================================
// EFA PHASE 2 — PATTERN EVALUATORS
// Five deterministic combinatorial patterns
// Each requires multiple signals to fire
// No single-signal warnings
// ============================================
// ADDITIVE ONLY — does not modify existing EFA functions
// ============================================

// ============================================
// PATTERN A — CREDENTIAL HARVESTING
// ============================================
// Fake login pages, password reset traps
// Requires: credential_language + links_present + sender_vs_link_domain_mismatch
// Suppresses: phishing-urgency

function evaluatePatternA(signals) {
  const { credentialLanguage, senderLinkMismatch, urls } = signals;

  // All three required
  if (!credentialLanguage) return null;
  if (!urls || urls.length === 0) return null;
  if (!senderLinkMismatch) return null;

  return {
    patternId: 'pattern_a_credential_harvesting',
    patternName: 'Credential Harvesting Attempt',
    confidence: 'high',
    signals: {
      credential_language: credentialLanguage,
      sender_link_mismatch: senderLinkMismatch,
      links_present: { count: urls.length }
    },
    description: 'This email asks for login credentials and contains links pointing to domains that don\'t match the sender. This is a common credential harvesting technique.',
    recommendation: 'Do NOT click any links in this email. If you need to verify your account, go directly to the website by typing the address in your browser.'
  };
}

// ============================================
// PATTERN B — BRAND IMPERSONATION + FREE HOSTING
// ============================================
// Fake brand emails linking to throwaway hosting
// Requires: brand_mismatch + suspicious_hosting_link + (credential_language OR urgency)
// Also fires with: brand_mismatch + legit_platform_link + 2 other signals
// Suppresses: brand-impersonation, phishing-urgency

function evaluatePatternB(signals, coreWarnings) {
  const { credentialLanguage, suspiciousHostingLink, legitPlatformLink } = signals;

  // Check if core EFA already flagged brand impersonation
  const hasBrandMismatch = coreWarnings.some(w =>
    w.type === 'brand-impersonation' || w.warningType === 'brand-impersonation'
  );

  if (!hasBrandMismatch) return null;

  // Path 1: Suspicious free hosting link (low threshold)
  if (suspiciousHostingLink) {
    // Need at least one more signal: credential language or urgency
    const hasUrgency = coreWarnings.some(w =>
      w.type === 'phishing-urgency' || w.warningType === 'phishing-urgency'
    );

    if (credentialLanguage || hasUrgency) {
      return {
        patternId: 'pattern_b_brand_free_hosting',
        patternName: 'Brand Impersonation with Suspicious Link',
        confidence: 'high',
        signals: {
          brand_mismatch: { fromCore: true },
          suspicious_hosting_link: suspiciousHostingLink,
          credential_language: credentialLanguage || null,
          urgency: hasUrgency || null
        },
        description: 'This email impersonates a known brand but links to a free hosting platform. Legitimate companies do not host login pages on free platforms.',
        recommendation: 'This is almost certainly a phishing attempt. Do not click any links. Report this email as phishing.'
      };
    }
  }

  // Path 2: Legit platform link (high threshold — needs 2+ other signals)
  if (legitPlatformLink) {
    let supportingSignalCount = 0;
    if (credentialLanguage) supportingSignalCount++;
    const hasUrgency = coreWarnings.some(w =>
      w.type === 'phishing-urgency' || w.warningType === 'phishing-urgency'
    );
    if (hasUrgency) supportingSignalCount++;
    if (signals.senderLinkMismatch) supportingSignalCount++;
    if (signals.unlockLanguage) supportingSignalCount++;

    if (supportingSignalCount >= 2) {
      return {
        patternId: 'pattern_b_brand_free_hosting',
        patternName: 'Brand Impersonation with Suspicious Link',
        confidence: 'medium',
        signals: {
          brand_mismatch: { fromCore: true },
          legit_platform_link: legitPlatformLink,
          supporting_signal_count: supportingSignalCount
        },
        description: 'This email impersonates a known brand and links to a file-sharing platform with multiple other suspicious indicators. Verify directly with the sender before clicking any links.',
        recommendation: 'Contact the supposed sender through a known, trusted channel before interacting with this email.'
      };
    }
  }

  return null;
}

// ============================================
// PATTERN C — HTML ATTACHMENT TRAP
// ============================================
// Fake secure message portals delivered as .html attachment
// Requires: html_attachment + (credential_language OR unlock_language) + (domain_mismatch OR brand_mismatch)
// Suppresses: phishing-urgency, brand-impersonation

function evaluatePatternC(signals, coreWarnings) {
  const { attachmentAnalysis, credentialLanguage, unlockLanguage, senderLinkMismatch } = signals;

  // Must have HTML attachment
  if (!attachmentAnalysis || !attachmentAnalysis.hasHtml) return null;

  // Must have credential or unlock language
  if (!credentialLanguage && !unlockLanguage) return null;

  // Must have domain mismatch or brand mismatch
  const hasBrandMismatch = coreWarnings.some(w =>
    w.type === 'brand-impersonation' || w.warningType === 'brand-impersonation'
  );
  const hasDomainMismatch = senderLinkMismatch != null;

  if (!hasBrandMismatch && !hasDomainMismatch) return null;

  return {
    patternId: 'pattern_c_html_attachment_trap',
    patternName: 'HTML Attachment Phishing Trap',
    confidence: 'high',
    signals: {
      html_attachment: { files: attachmentAnalysis.htmlFiles },
      credential_language: credentialLanguage || null,
      unlock_language: unlockLanguage || null,
      brand_mismatch: hasBrandMismatch || null,
      domain_mismatch: hasDomainMismatch ? senderLinkMismatch : null
    },
    description: 'This email contains an HTML file attachment that likely opens a fake login page in your browser. HTML attachments are a common way to bypass email link scanning.',
    recommendation: 'Do NOT open the HTML attachment. Delete this email. If you expected a document from this sender, contact them directly through a known channel.'
  };
}

// ============================================
// PATTERN D — DANGEROUS ATTACHMENT DELIVERY
// ============================================
// Encrypted/protected files with unlock instructions
// Requires: (archive/macro/disk_image/executable attachment) + unlock_language +
//           one of (unknown_sender, urgency, brand_mismatch, credential_language, payment_language)
// Guardrail: if sender is trusted AND known, requires TWO supporting signals
// Suppresses: wire-fraud, phishing-urgency

function evaluatePatternD(signals, coreWarnings) {
  const { attachmentAnalysis, unlockLanguage, credentialLanguage, paymentChangeLanguage } = signals;

  // Must have dangerous attachment (non-HTML — Pattern C handles HTML)
  if (!attachmentAnalysis) return null;
  const hasDangerousNonHtml = attachmentAnalysis.hasArchive ||
    attachmentAnalysis.hasDiskImage ||
    attachmentAnalysis.hasExecutable ||
    attachmentAnalysis.hasMacroCapable;

  if (!hasDangerousNonHtml) return null;

  // Must have unlock language
  if (!unlockLanguage) return null;

  // Count supporting signals
  const supportingSignals = [];

  if (signals.isUnknownSender) {
    supportingSignals.push('unknown_sender');
  }

  const hasUrgency = coreWarnings.some(w =>
    w.type === 'phishing-urgency' || w.warningType === 'phishing-urgency'
  );
  if (hasUrgency) {
    supportingSignals.push('urgency');
  }

  const hasBrandMismatch = coreWarnings.some(w =>
    w.type === 'brand-impersonation' || w.warningType === 'brand-impersonation'
  );
  if (hasBrandMismatch) {
    supportingSignals.push('brand_mismatch');
  }

  if (credentialLanguage) {
    supportingSignals.push('credential_language');
  }

  if (paymentChangeLanguage) {
    supportingSignals.push('payment_language');
  }

  // Guardrail: trusted known sender requires 2+ supporting signals
  const requiredCount = (signals.isTrustedKnownSender) ? 2 : 1;

  if (supportingSignals.length < requiredCount) return null;

  // Determine which attachment types triggered
  const attachTypes = [];
  if (attachmentAnalysis.hasArchive) attachTypes.push('archive');
  if (attachmentAnalysis.hasDiskImage) attachTypes.push('disk_image');
  if (attachmentAnalysis.hasExecutable) attachTypes.push('executable');
  if (attachmentAnalysis.hasMacroCapable) attachTypes.push('macro_capable');

  return {
    patternId: 'pattern_d_dangerous_attachment',
    patternName: 'Suspicious Protected Attachment',
    confidence: (attachmentAnalysis.hasExecutable || attachmentAnalysis.hasDiskImage) ? 'critical' : 'high',
    signals: {
      dangerous_attachment: {
        types: attachTypes,
        files: attachmentAnalysis.dangerousFiles.filter(f => {
          const ext = '.' + f.split('.').pop();
          return !DANGEROUS_ATTACHMENT_EXTENSIONS.html.includes(ext);
        })
      },
      unlock_language: unlockLanguage,
      supporting_signals: supportingSignals,
      trusted_sender_guardrail: signals.isTrustedKnownSender || false
    },
    description: 'This email contains a password-protected or encrypted attachment with unlock instructions in the body. Attackers use encryption to prevent email scanners from detecting malware inside attachments.',
    recommendation: 'Do NOT open the attachment or use the provided password. If you were expecting a file from this sender, confirm through a separate communication channel before opening.'
  };
}

// ============================================
// PATTERN E — PAYMENT REDIRECT / BEC
// ============================================
// Wire change scams, business email compromise
// Requires: payment_change_language + wire_keywords +
//           (reply-to mismatch OR on-behalf-of) +
//           (urgency OR secrecy)
// Suppresses: replyto-mismatch, on-behalf-of, wire-fraud, phishing-urgency

function evaluatePatternE(signals, coreWarnings) {
  const { paymentChangeLanguage, secrecyLanguage } = signals;

  // Must have payment change language (which already requires banking tokens)
  if (!paymentChangeLanguage) return null;

  // Must have reply-to mismatch OR on-behalf-of from core
  const hasReplyToMismatch = coreWarnings.some(w =>
    w.type === 'replyto-mismatch' || w.warningType === 'replyto-mismatch'
  );
  const hasOnBehalfOf = coreWarnings.some(w =>
    w.type === 'on-behalf-of' || w.warningType === 'on-behalf-of'
  );

  if (!hasReplyToMismatch && !hasOnBehalfOf) return null;

  // Must have urgency OR secrecy
  const hasUrgency = coreWarnings.some(w =>
    w.type === 'phishing-urgency' || w.warningType === 'phishing-urgency'
  );

  if (!hasUrgency && !secrecyLanguage) return null;

  return {
    patternId: 'pattern_e_payment_redirect',
    patternName: 'Payment Redirect / Business Email Compromise',
    confidence: 'critical',
    signals: {
      payment_change_language: paymentChangeLanguage,
      reply_to_mismatch: hasReplyToMismatch || null,
      on_behalf_of: hasOnBehalfOf || null,
      urgency: hasUrgency || null,
      secrecy_language: secrecyLanguage || null
    },
    description: 'This email requests a change to payment or wire instructions while using a spoofed sender identity and pressure tactics. This is a textbook Business Email Compromise (BEC) attack.',
    recommendation: 'STOP. Do NOT process any payment changes from this email. Call the supposed sender at a KNOWN phone number (not one from this email) to verify. This type of scam costs businesses billions annually.'
  };
}
