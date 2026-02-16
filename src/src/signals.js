// ============================================
// EFA PHASE 2 — SIGNAL DETECTION FUNCTIONS
// Each function detects one atomic signal
// Returns match data object or null
// ============================================
// ADDITIVE ONLY — does not modify existing EFA functions
// These reuse existing EFA functions where available
// ============================================

// ============================================
// CREDENTIAL LANGUAGE DETECTION
// ============================================

function detectPhase2CredentialLanguage(content) {
  if (!content) return null;
  const lowerContent = content.toLowerCase();

  // Check exclusions first — if any exclusion phrase is present,
  // require stronger evidence (more matching credential phrases)
  let hasExclusion = false;
  for (const exclusion of CREDENTIAL_EXCLUSION_PHRASES) {
    if (lowerContent.includes(exclusion)) {
      hasExclusion = true;
      break;
    }
  }

  const matched = [];
  for (const phrase of CREDENTIAL_REQUEST_PHRASES) {
    if (lowerContent.includes(phrase)) {
      matched.push(phrase);
    }
  }

  if (matched.length === 0) return null;

  // If exclusion phrases present, require 2+ credential matches to reduce false positives
  if (hasExclusion && matched.length < 2) return null;

  return {
    signal: 'credential_language',
    matched: matched,
    count: matched.length
  };
}

// ============================================
// UNLOCK / ATTACHMENT INSTRUCTION LANGUAGE
// ============================================

function detectPhase2UnlockLanguage(content) {
  if (!content) return null;
  const lowerContent = content.toLowerCase();

  const matched = [];
  for (const phrase of UNLOCK_LANGUAGE_PHRASES) {
    if (lowerContent.includes(phrase)) {
      matched.push(phrase);
    }
  }

  if (matched.length === 0) return null;

  return {
    signal: 'unlock_language',
    matched: matched,
    count: matched.length
  };
}

// ============================================
// PAYMENT CHANGE LANGUAGE
// ============================================
// Requires both a change phrase AND a banking token

function detectPhase2PaymentChangeLanguage(content) {
  if (!content) return null;
  const lowerContent = content.toLowerCase();

  const matchedPhrases = [];
  for (const phrase of PAYMENT_CHANGE_PHRASES) {
    if (lowerContent.includes(phrase)) {
      matchedPhrases.push(phrase);
    }
  }

  if (matchedPhrases.length === 0) return null;

  // Must also contain at least one banking token
  const matchedTokens = [];
  for (const token of BANKING_TOKENS) {
    if (lowerContent.includes(token)) {
      matchedTokens.push(token);
    }
  }

  if (matchedTokens.length === 0) return null;

  return {
    signal: 'payment_change_language',
    matchedPhrases: matchedPhrases,
    matchedTokens: matchedTokens
  };
}

// ============================================
// SECRECY LANGUAGE
// ============================================

function detectPhase2SecrecyLanguage(content) {
  if (!content) return null;
  const lowerContent = content.toLowerCase();

  const matched = [];
  for (const phrase of SECRECY_PHRASES) {
    if (lowerContent.includes(phrase)) {
      matched.push(phrase);
    }
  }

  if (matched.length === 0) return null;

  return {
    signal: 'secrecy_language',
    matched: matched
  };
}

// ============================================
// URL EXTRACTION FROM BODY TEXT
// ============================================

function extractPhase2Urls(bodyText) {
  if (!bodyText) return [];
  if (bodyText.length > PHASE2_CONFIG.maxBodyLengthForUrlScan) return [];

  const matches = bodyText.match(PHASE2_URL_REGEX);
  if (!matches) return [];

  const results = [];
  const seenHosts = new Set();

  for (let i = 0; i < Math.min(matches.length, PHASE2_CONFIG.maxUrlsToExtract); i++) {
    try {
      const url = matches[i].replace(/[.,;:!?)>\]]+$/, ''); // strip trailing punctuation
      const urlObj = new URL(url);
      const host = urlObj.hostname.toLowerCase();

      // Deduplicate by hostname
      if (!seenHosts.has(host)) {
        seenHosts.add(host);
        results.push({
          url: url,
          host: host,
          domain: getRegistrableDomainFromHost(host)
        });
      }
    } catch (e) {
      // malformed URL, skip
    }
  }

  return results;
}

// Simple domain extraction helper
// Gets registrable domain from hostname (e.g., "mail.google.com" -> "google.com")
// Falls back to host if can't determine
function getRegistrableDomainFromHost(host) {
  // If existing getRegistrableDomainName() is available, use it
  // Otherwise use this simple fallback
  if (typeof getRegistrableDomainName === 'function') {
    return getRegistrableDomainName(host);
  }
  const parts = host.split('.');
  if (parts.length <= 2) return host;
  // Handle common two-part TLDs
  const twoPartTlds = ['co.uk', 'com.au', 'co.nz', 'co.za', 'com.br', 'co.jp', 'co.kr', 'com.mx', 'co.in'];
  const lastTwo = parts.slice(-2).join('.');
  if (twoPartTlds.includes(lastTwo)) {
    return parts.slice(-3).join('.');
  }
  return parts.slice(-2).join('.');
}

// ============================================
// SUSPICIOUS FREE HOSTING LINK DETECTION
// ============================================

function detectPhase2SuspiciousHostingLink(urls) {
  if (!urls || urls.length === 0) return null;

  const matched = [];
  for (const urlInfo of urls) {
    for (const domain of SUSPICIOUS_FREE_HOSTING_DOMAINS) {
      if (urlInfo.host === domain || urlInfo.host.endsWith('.' + domain)) {
        matched.push({ url: urlInfo.url, hostingDomain: domain });
        break;
      }
    }
  }

  if (matched.length === 0) return null;

  return {
    signal: 'suspicious_hosting_link',
    matched: matched
  };
}

// ============================================
// COMMON LEGIT PLATFORM LINK DETECTION
// ============================================
// Only counts when 2+ other high-confidence signals are true

function detectPhase2LegitPlatformLink(urls) {
  if (!urls || urls.length === 0) return null;

  const matched = [];
  for (const urlInfo of urls) {
    for (const domain of COMMON_LEGIT_PLATFORMS) {
      if (urlInfo.host === domain || urlInfo.host.endsWith('.' + domain)) {
        matched.push({ url: urlInfo.url, platform: domain });
        break;
      }
    }
  }

  if (matched.length === 0) return null;

  return {
    signal: 'legit_platform_link',
    matched: matched
  };
}

// ============================================
// SENDER VS LINK DOMAIN MISMATCH
// ============================================
// Checks if any link points to a domain different from the sender's domain

function detectPhase2SenderLinkMismatch(senderDomain, urls) {
  if (!senderDomain || !urls || urls.length === 0) return null;

  const senderDomainLower = senderDomain.toLowerCase();
  const mismatched = [];

  for (const urlInfo of urls) {
    const linkDomain = urlInfo.domain;
    if (!linkDomain) continue;

    // Skip if link domain matches sender domain
    if (linkDomain === senderDomainLower) continue;
    if (linkDomain.endsWith('.' + senderDomainLower)) continue;
    if (senderDomainLower.endsWith('.' + linkDomain)) continue;

    // Skip common infrastructure domains that aren't suspicious on their own
    const infraDomains = ['google.com', 'gstatic.com', 'googleapis.com', 'microsoft.com',
      'office.com', 'outlook.com', 'live.com', 'cloudflare.com', 'akamai.net',
      'amazonaws.com', 'azurewebsites.net', 'doubleclick.net', 'googlesyndication.com',
      'googleadservices.com', 'facebook.com', 'fbcdn.net', 'twitter.com', 'linkedin.com'];

    let isInfra = false;
    for (const infra of infraDomains) {
      if (linkDomain === infra || linkDomain.endsWith('.' + infra)) {
        isInfra = true;
        break;
      }
    }
    if (isInfra) continue;

    mismatched.push({
      sender: senderDomainLower,
      linkDomain: linkDomain,
      url: urlInfo.url
    });
  }

  if (mismatched.length === 0) return null;

  return {
    signal: 'sender_link_mismatch',
    matched: mismatched
  };
}

// ============================================
// ATTACHMENT ANALYSIS
// ============================================
// Checks attachment filenames for dangerous types
// For Outlook: reads from Office.context.mailbox.item.attachments
// For Chrome: reads from emailData.attachments if available

function analyzePhase2Attachments(attachments) {
  if (!attachments || attachments.length === 0) return null;

  const results = {
    hasAttachments: true,
    hasDangerousType: false,
    hasHtml: false,
    hasArchive: false,
    hasDiskImage: false,
    hasExecutable: false,
    hasMacroCapable: false,
    dangerousFiles: [],
    htmlFiles: [],
    allFiles: []
  };

  for (const attachment of attachments) {
    const name = (attachment.name || attachment.fileName || '').toLowerCase();
    results.allFiles.push(name);

    const ext = '.' + name.split('.').pop();

    if (DANGEROUS_ATTACHMENT_EXTENSIONS.html.includes(ext)) {
      results.hasHtml = true;
      results.hasDangerousType = true;
      results.htmlFiles.push(name);
      results.dangerousFiles.push(name);
    }
    if (DANGEROUS_ATTACHMENT_EXTENSIONS.archive.includes(ext)) {
      results.hasArchive = true;
      results.hasDangerousType = true;
      results.dangerousFiles.push(name);
    }
    if (DANGEROUS_ATTACHMENT_EXTENSIONS.disk_image.includes(ext)) {
      results.hasDiskImage = true;
      results.hasDangerousType = true;
      results.dangerousFiles.push(name);
    }
    if (DANGEROUS_ATTACHMENT_EXTENSIONS.executable.includes(ext)) {
      results.hasExecutable = true;
      results.hasDangerousType = true;
      results.dangerousFiles.push(name);
    }
    if (DANGEROUS_ATTACHMENT_EXTENSIONS.macro_capable.includes(ext)) {
      results.hasMacroCapable = true;
      results.hasDangerousType = true;
      results.dangerousFiles.push(name);
    }

    // Check for double extensions (e.g., invoice.pdf.exe)
    const parts = name.split('.');
    if (parts.length >= 3) {
      const lastExt = '.' + parts[parts.length - 1];
      if (DANGEROUS_ATTACHMENT_EXTENSIONS.executable.includes(lastExt)) {
        results.hasExecutable = true;
        results.hasDangerousType = true;
        if (!results.dangerousFiles.includes(name)) {
          results.dangerousFiles.push(name);
        }
      }
    }
  }

  return results;
}

// ============================================
// UNKNOWN SENDER CHECK
// ============================================
// True if sender is not in contacts and not in trusted domains

function isPhase2UnknownSender(isKnownContact, senderDomain, trustedDomains) {
  if (isKnownContact) return false;

  // Check if sender is from a trusted domain
  if (senderDomain && trustedDomains) {
    // Reuse existing isTrustedDomain if available
    if (typeof isTrustedDomain === 'function') {
      if (isTrustedDomain(senderDomain)) return false;
    } else {
      // Fallback: check against provided list
      const lowerDomain = senderDomain.toLowerCase();
      for (const trusted of trustedDomains) {
        if (lowerDomain === trusted.toLowerCase()) return false;
      }
    }
  }

  return true;
}
