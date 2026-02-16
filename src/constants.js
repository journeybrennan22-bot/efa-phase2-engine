// ============================================
// EFA PHASE 2 — CONSTANTS
// Signal keywords, domain lists, configuration
// ============================================
// ADDITIVE ONLY — does not modify existing EFA constants
// These blocks get inserted below existing constants in production files
// ============================================

// ============================================
// CONFIGURATION
// ============================================

const PHASE2_CONFIG = {
  enabled: true,
  silentMode: true,           // true = compute but don't show warnings or suppress core warnings
  telemetryEnabled: false,    // opt-in only
  maxUrlsToExtract: 20,       // performance guardrail
  maxBodyLengthForUrlScan: 50000,  // skip URL extraction if body exceeds this
  version: '1.0.0'
};

// ============================================
// CREDENTIAL REQUEST LANGUAGE
// ============================================
// Strict list — only authentication/login related phrases
// Explicit exclusions: "please review", "review document", "review and sign"

const CREDENTIAL_REQUEST_PHRASES = [
  'verify your account',
  'confirm your identity',
  'confirm your account',
  'confirm your email',
  'verify your email',
  'update your credentials',
  're-authenticate',
  'login required',
  'sign in to continue',
  'sign in now',
  'log in to continue',
  'reset your password',
  'password expired',
  'password reset',
  'validate your account',
  'authentication required',
  'security verification',
  'unusual sign-in',
  'unusual activity',
  'suspicious activity',
  'unauthorized access',
  'account will be locked',
  'account suspended',
  'account disabled',
  'enter your password',
  'security code',
  'one-time code',
  'one-time password',
  'two-factor',
  '2fa',
  'verify your identity'
];

// Phrases that should NOT be treated as credential language
const CREDENTIAL_EXCLUSION_PHRASES = [
  'please review',
  'review document',
  'review and sign',
  'review the document',
  'review attached',
  'review the attached',
  'for your review',
  'ready for review'
];

// ============================================
// UNLOCK / ATTACHMENT INSTRUCTION LANGUAGE
// ============================================

const UNLOCK_LANGUAGE_PHRASES = [
  'password attached',
  'unlock code',
  'use this code',
  'open with password',
  'encrypted attachment',
  'secure document enclosed',
  'password is',
  'passcode is',
  'access code',
  'the password to open',
  'use the password',
  'protected document',
  'secure attachment',
  'open the attachment',
  'download the attachment',
  'password below',
  'password above',
  'enclosed password'
];

// ============================================
// PAYMENT CHANGE / WIRE REDIRECT LANGUAGE
// ============================================

const PAYMENT_CHANGE_PHRASES = [
  'updated bank',
  'new bank',
  'changed bank',
  'new account details',
  'updated account details',
  'updated payment details',
  'new payment info',
  'update your records',
  'revised wire instructions',
  'new wiring instructions',
  'please use the new account',
  'send to this account instead',
  'new routing number',
  'updated routing number',
  'payment details have changed',
  'wire to the following',
  'remit to',
  'send funds to'
];

// Payment change must co-occur with at least one banking token
const BANKING_TOKENS = [
  'routing number',
  'account number',
  'aba',
  'swift',
  'iban',
  'beneficiary',
  'bank account',
  'wire transfer',
  'wire instructions',
  'bank details'
];

// ============================================
// SECRECY TACTICS (used in Pattern E)
// ============================================

const SECRECY_PHRASES = [
  'keep this confidential',
  'between us',
  'do not tell',
  'dont tell',
  "don't tell",
  'handle personally',
  'urgent and confidential',
  'keep this quiet',
  'off the record',
  'private matter',
  'do not share',
  'do not discuss'
];

// ============================================
// SUSPICIOUS FREE HOSTING DOMAINS
// ============================================
// Platforms with almost no legitimate reason to appear
// in professional transactional email

const SUSPICIOUS_FREE_HOSTING_DOMAINS = [
  'netlify.app',
  'vercel.app',
  'github.io',
  'pages.dev',
  'firebaseapp.com',
  'web.app',
  'workers.dev',
  'glitch.me',
  'replit.app',
  'repl.co',
  'herokuapp.com',
  'bitbucket.io',
  'surge.sh',
  'ngrok-free.app',
  'ngrok.io',
  'webhook.site',
  'pipedream.net',
  'kesug.com',
  'wuaze.com',
  'rf.gd',
  'my-board.org',
  'blogspot.com',
  'weebly.com',
  '000webhostapp.com',
  'infinityfreeapp.com'
];

// ============================================
// COMMON LEGITIMATE PLATFORMS
// ============================================
// Frequently abused but also extremely common in business
// Only counts as a signal when 2+ other high-confidence signals are true

const COMMON_LEGIT_PLATFORMS = [
  'drive.google.com',
  'docs.google.com',
  'storage.googleapis.com',
  'googleusercontent.com',
  'sharepoint.com',
  'onedrive.live.com',
  '1drv.ms',
  'dropbox.com',
  'dropboxusercontent.com',
  'box.com',
  'app.box.com'
];

// ============================================
// DANGEROUS ATTACHMENT EXTENSIONS
// ============================================

const DANGEROUS_ATTACHMENT_EXTENSIONS = {
  archive: ['.zip', '.rar', '.7z', '.tar', '.gz'],
  disk_image: ['.iso', '.img', '.dmg'],
  executable: ['.exe', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.hta', '.msi', '.com', '.pif'],
  macro_capable: ['.xlsm', '.docm', '.pptm', '.xlam', '.dotm'],
  html: ['.html', '.htm', '.mhtml', '.svg']
};

// Flat list of all dangerous extensions for quick lookup
const ALL_DANGEROUS_EXTENSIONS = Object.values(DANGEROUS_ATTACHMENT_EXTENSIONS).flat();

// ============================================
// URL EXTRACTION
// ============================================

const PHASE2_URL_REGEX = /https?:\/\/[^\s<>"')\]]+/gi;

// ============================================
// SUPPRESSION MAPPING
// ============================================
// Maps each Phase 2 pattern to the EFA core warning types it replaces
// Rule: suppression is ADDITIVE across matched patterns
// If ANY matched pattern suppresses a core type, it's suppressed

const SUPPRESSION_MAP = {
  pattern_a_credential_harvesting: [
    'phishing-urgency'
  ],
  pattern_b_brand_free_hosting: [
    'brand-impersonation',
    'phishing-urgency'
  ],
  pattern_c_html_attachment_trap: [
    'phishing-urgency',
    'brand-impersonation'
  ],
  pattern_d_dangerous_attachment: [
    'wire-fraud',
    'phishing-urgency'
  ],
  pattern_e_payment_redirect: [
    'replyto-mismatch',
    'on-behalf-of',
    'wire-fraud',
    'phishing-urgency'
  ]
};

// ============================================
// WARNING PRIORITY
// ============================================
// Phase 2 merged warning slots into existing priority order
// Add this value to the existing WARNING_PRIORITY object

const PHASE2_WARNING_PRIORITY = {
  'phase2-phishing-pattern': 13  // above wire-fraud keywords, below existing sender warnings
};
