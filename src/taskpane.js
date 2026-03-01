// Email Fraud Detector - Outlook Web Add-in

// ============================================
// CONFIGURATION
// ============================================
const CONFIG = {
    clientId: '622f0452-d622-45d1-aab3-3a2026389dd3',
    redirectUri: 'https://journeybrennan22-bot.github.io/outlook-fraud-detector/src/taskpane.html',
    scopes: ['User.Read', 'Contacts.Read', 'Mail.ReadBasic'],
    trustedDomains: []
};

// ============================================
// DOMAIN REPUTATION BACKEND
// ============================================
const REPUTATION_API = 'https://efa-reputation.journeybrennan22-1f8.workers.dev';
const REPUTATION_TIMEOUT_MS = 5000;

async function checkDomainReputation(domain) {
    if (!domain) return null;
    try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), REPUTATION_TIMEOUT_MS);
        const resp = await fetch(
            `${REPUTATION_API}/lookup?domain=${encodeURIComponent(domain)}`,
            { signal: controller.signal }
        );
        clearTimeout(timeout);
        if (!resp.ok) return null;
        const data = await resp.json();
        if (data.status === 'malicious' || data.status === 'suspicious') {
            return data;
        }
        return null;
    } catch (e) {
        console.log('EFA reputation check skipped:', e.message);
        return null;
    }
}

// ============================================
// KNOWN EMAIL SERVICE PROVIDER (ESP) DOMAINS
// These platforms send on behalf of businesses,
// so reply-to mismatches are expected/legitimate.
// ============================================
const KNOWN_ESP_DOMAINS = [
    // Constant Contact
    'ccsend.com',
    // Mailchimp / Intuit
    'mailchimp.com', 'mandrillapp.com', 'mail.mailchimp.com', 'rsgsv.net', 'list-manage.com', 'mailchimpapp.net',
    // SendGrid (Twilio)
    'sendgrid.net', 'em.sendgrid.net',
    // Amazon SES
    'amazonses.com', 'us-east-1.amazonses.com', 'us-west-2.amazonses.com', 'eu-west-1.amazonses.com',
    // Mailgun
    'mailgun.org', 'mailgun.net',
    // Campaign Monitor
    'createsend.com', 'cmail19.com', 'cmail20.com',
    // HubSpot
    'hubspot.com', 'hubspotemail.net', 'hs-email.com',
    // Salesforce Marketing Cloud / Pardot
    'exacttarget.com', 'salesforce.com', 'pardot.com',
    // Klaviyo
    'klaviyo.com', 'klaviyomail.com',
    // ActiveCampaign
    'acsend.com', 'activehosted.com', 'emsend2.com',
    // ConvertKit
    'convertkit.com', 'ck.page',
    // Brevo (formerly Sendinblue)
    'sendinblue.com', 'brevo.com',
    // Postmark
    'postmarkapp.com',
    // SparkPost / MessageBird
    'sparkpostmail.com', 'messagebird.com',
    // GetResponse
    'getresponse.com', 'gr8.com',
    // AWeber
    'aweber.com',
    // Drip
    'drip.com',
    // Zoho Campaigns
    'zohocampaigns.com', 'zoho.com',
    // Marketo (Adobe)
    'mktomail.com', 'marketo.com',
    // MailerLite
    'mailerlite.com',
    // Benchmark Email
    'benchmarkemail.com', 'bmetrack.com',
    // iContact
    'icontact.com', 'icptrack.com',
    // Emma
    'e2ma.net', 'myemma.com',
    // Vertical Response
    'verticalresponse.com',
    // Keap / Infusionsoft
    'infusionmail.com', 'keap-link.com',
    // Qualtrics (survey platform)
    'qemailserver.com',
    // GovDelivery (Granicus) - Official government email platform
    // Verified-access only: requires confirmed government agency status to send.
    // NOT a self-service ESP. Do NOT extend this pattern to commercial ESPs.
    'govdelivery.com'
];

// v4.3.0: Email infrastructure providers whose Sender header is set by their own servers.
// These providers use the Sender header for calendar invites and notifications sent
// on behalf of their users. Unlike ESPs, no third party can trigger sends through these.
// Viktor: "I can't forge a Sender header from these without sending through their infrastructure."
// This list is ONLY used for on-behalf-of suppression, NOT for trust decisions.
// Criteria: Provider owns the infrastructure. No self-service API sending.
const CALENDAR_INFRASTRUCTURE_DOMAINS = [
    // Global
    'google.com', 'microsoft.com', 'outlook.com', 'apple.com', 'yahoo.com',
    // Japan
    'yahoo.co.jp',
    // Russia / CIS
    'yandex.ru', 'yandex.com', 'mail.ru',
    // India / Global
    'zoho.com',
    // Switzerland / Global
    'protonmail.com', 'proton.me',
    // Germany / Global
    'gmx.net', 'gmx.com', 'web.de',
    // South Korea
    'naver.com', 'daum.net',
    // China
    '163.com', '126.com', 'qq.com'
];

// ============================================
// v5.1.0: FREEMAIL PROVIDERS
// Used to detect ESP phishing (free reply-to from ESP sender)
// and provider routing suppression.
// ============================================
const FREEMAIL_SET = new Set([
    'gmail.com', 'googlemail.com',
    'outlook.com', 'hotmail.com', 'live.com', 'msn.com',
    'yahoo.com', 'ymail.com', 'rocketmail.com',
    'icloud.com', 'me.com', 'mac.com',
    'aol.com',
    'proton.me', 'protonmail.com',
    'gmx.com', 'gmx.net'
]);

// v5.1.0: KNOWN PROVIDER MAP
// Maps webmail sender domains to their known relay/routing domains.
// Used by detectViaRouting to suppress false positives on legitimate
// provider infrastructure (e.g., iCloud routing through me.com).
// Viktor: "If Apple's actual mail servers are compromised, the entire internet has bigger problems."
const KNOWN_PROVIDER_MAP = {
    'icloud.com': ['icloud.com', 'me.com', 'mac.com', 'apple.com'],
    'me.com': ['icloud.com', 'me.com', 'mac.com', 'apple.com'],
    'mac.com': ['icloud.com', 'me.com', 'mac.com', 'apple.com'],
    'gmail.com': ['gmail.com', 'google.com', 'googlemail.com', 'goog.com'],
    'googlemail.com': ['gmail.com', 'google.com', 'googlemail.com', 'goog.com'],
    'outlook.com': ['outlook.com', 'hotmail.com', 'live.com', 'microsoft.com', 'office365.com', 'protection.outlook.com', 'onmicrosoft.com'],
    'hotmail.com': ['outlook.com', 'hotmail.com', 'live.com', 'microsoft.com', 'office365.com', 'protection.outlook.com', 'onmicrosoft.com'],
    'live.com': ['outlook.com', 'hotmail.com', 'live.com', 'microsoft.com', 'office365.com', 'protection.outlook.com', 'onmicrosoft.com'],
    'yahoo.com': ['yahoo.com', 'ymail.com', 'rocketmail.com', 'yahoodns.net'],
    'ymail.com': ['yahoo.com', 'ymail.com', 'rocketmail.com', 'yahoodns.net'],
    'aol.com': ['aol.com', 'aim.com'],
    'proton.me': ['proton.me', 'protonmail.com', 'protonmail.ch'],
    'protonmail.com': ['proton.me', 'protonmail.com', 'protonmail.ch']
};

// v5.1.0: ESP SENDER DOMAINS (expanded from COP's curated list)
// These are domains ESPs use in From headers when sending on behalf of businesses.
// Used for Reply-To mismatch gating: if From is an ESP, apply downgrade rules.
// DKIM alignment check happens separately.
const ESP_SENDER_DOMAINS = new Set([
    'sendgrid.net', 'sendgrid.com',
    'mailchimp.com', 'cmail20.com', 'rsgsv.net', 'mandrillapp.com', 'mailchimpapp.net',
    'brevo.com', 'brevosend.com', 'sendinblue.com',
    'sparkpostmail.com',
    'hubspotemail.net', 'hs-email.com',
    'sfmc-email.com', 'exacttarget.com', 'marketingcloudapis.com',
    'marketo.net', 'mktoweb.com', 'mktomail.com',
    'zcsend.net', 'zohocampaigns.com',
    'acems1.com', 'activehosted.com', 'emsend2.com',
    'campaignmonitor.com', 'createsend.com',
    'klclick.com', 'klaviyo-mail.com', 'klaviyomail.com',
    'pardot.com',
    'mailgun.org', 'mailgun.net',
    'constantcontact.com', 'ccsend.com',
    'amazonses.com', 'ses.amazonaws.com',
    'postmarkapp.com',
    'messagebird.com',
    'getresponse.com', 'gr8.com',
    'aweber.com',
    'drip.com',
    'mailerlite.com',
    'benchmarkemail.com', 'bmetrack.com',
    'icontact.com', 'icptrack.com',
    'e2ma.net', 'myemma.com',
    'verticalresponse.com',
    'infusionmail.com', 'keap-link.com',
    'convertkit.com', 'ck.page',
    'govdelivery.com',
    // v5.1.0: Additional ESPs per COP adversarial review
    'mailjet.com',
    'elasticemail.com',
    'sendpulse.com', 'sendpulse.net',
    'mlsend.com',
    'mailersend.net', 'mailersend.com',
    'omnisend.com', 'omnsmail.com',
    'emsend1.com',
    'dripemail2.com', 'getdrip.com',
    'convertkit-mail.com',
    'cleverreach.com', 'crsend.com',
    'getresponse-mail.com', 'gr-cdn.com',
    'campaigner.com', 'cmail2.com',
    'moosend.com',
    'customeriomail.com',
    'iterable.com',
    'braze.com',
    'eloqua.com', 'elqm.net',
    'emarsys.net', 'emarsys.com',
    'cheetahmail.com',
    'acoustic.co', 'wcsend.com',
    'pepipost.com',
    'mailpoet.com', 'mp-email.net',
    // v5.2.0: Additional ESPs (Qualtrics survey platform)
    'qemailserver.com'
]);

// v5.1.0: HIGH RISK TLDs (boost-only, never sole trigger)
// Used in domain risk scoring. These have consistently high abuse rates.
const HIGH_RISK_TLDS = new Set([
    '.top', '.xyz', '.work', '.click', '.zip', '.mov',
    '.gq', '.ml', '.cf', '.ru',
    '.tk', '.ga', '.pw', '.cc', '.ws',
    '.buzz', '.icu', '.rest', '.country',
    '.sbs', '.mom', '.fit'
]);

// v5.1.0: Role suffixes that force brand/org evaluation even when proximity would skip.
// Viktor: "Orange Billing" or "Chase Security" should never dodge evaluation.
// COP: If display name is Brand + one of these suffixes, always evaluate.
const ORG_ROLE_SUFFIXES = new Set([
    'billing', 'support', 'security', 'alerts', 'accounts', 'payments',
    'collections', 'invoices', 'customer', 'service', 'services', 'team',
    'desk', 'notice', 'upgrades', 'verification', 'helpdesk'
]);

// v5.1.0: Common English words that are also protected brand names.
// These require exact or near-exact display name matches in org impersonation,
// preventing "The Orange County Register" from matching Orange SA
// while still catching "Orange" or "Orange Billing."
const PROTECTED_COMMON_WORD_BRANDS = new Set([
    'orange', 'delta', 'chase', 'liberty', 'frontier', 'mercury',
    'express', 'metro', 'summit', 'globe', 'ally', 'discover',
    'nationwide', 'progressive', 'prudential', 'guardian'
]);

// v5.2.0: Org-family domain map for Reply-To mismatch suppression.
// Some organizations legitimately use different domains for From and Reply-To
// (e.g., GameChanger sends from gamechanger.io, replies go to gc.com).
// If both sender and reply-to domains are in the same family, suppress mismatch.
// Viktor: Only helps when BOTH sides are in the known family; lookalikes on unrelated domains still fire.
const ORG_FAMILY_MAP = [
    new Set(['gamechanger.io', 'gc.com', 'dickssportinggoods.com', 'dicks.com', 'dcsg.com']),
];

// v5.2.0: International sender safe domains.
// Known legitimate brands using ccTLD domains that would otherwise trigger
// the International Sender warning. Narrow scope: only specific domains.
const INTL_SAFE_DOMAINS = new Set([
    'gamechanger.io',
]);

// ============================================
// COUNTRY CODE TLD LOOKUP
// Maps country-code TLDs to country names
// ============================================
const COUNTRY_CODE_TLDS = {
    // Compound TLDs (check these first - more specific)
    '.com.ar': 'Argentina', '.com.au': 'Australia', '.com.br': 'Brazil',
    '.com.cn': 'China', '.com.co': 'Colombia', '.com.mx': 'Mexico',
    '.com.ng': 'Nigeria', '.com.pk': 'Pakistan', '.com.ph': 'Philippines',
    '.com.tr': 'Turkey', '.com.ua': 'Ukraine', '.com.ve': 'Venezuela',
    '.com.vn': 'Vietnam', '.co.uk': 'United Kingdom', '.co.za': 'South Africa',
    '.co.in': 'India', '.co.jp': 'Japan', '.co.kr': 'South Korea',
    '.co.nz': 'New Zealand', '.net.br': 'Brazil', '.net.co': 'Colombia',
    '.org.br': 'Brazil', '.org.co': 'Colombia', '.org.uk': 'United Kingdom',
    '.co.uk.com': 'United Kingdom', '.us.com': 'United States', '.co.us': 'United States',
    
    // Single ccTLDs
    '.ar': 'Argentina', '.au': 'Australia', '.at': 'Austria',
    '.be': 'Belgium', '.br': 'Brazil', '.ca': 'Canada',
    '.ch': 'Switzerland', '.cl': 'Chile', '.cn': 'China',
    '.co': 'Colombia', '.cz': 'Czech Republic', '.de': 'Germany',
    '.dk': 'Denmark', '.es': 'Spain', '.fi': 'Finland',
    '.fr': 'France', '.gr': 'Greece', '.hk': 'Hong Kong',
    '.hu': 'Hungary', '.id': 'Indonesia', '.ie': 'Ireland',
    '.il': 'Israel', '.in': 'India', '.it': 'Italy',
    '.jp': 'Japan', '.kr': 'South Korea', '.mx': 'Mexico',
    '.my': 'Malaysia', '.nl': 'Netherlands', '.no': 'Norway',
    '.nz': 'New Zealand', '.pe': 'Peru', '.ph': 'Philippines',
    '.pk': 'Pakistan', '.pl': 'Poland', '.pt': 'Portugal',
    '.ro': 'Romania', '.ru': 'Russia', '.sa': 'Saudi Arabia',
    '.se': 'Sweden', '.sg': 'Singapore', '.th': 'Thailand',
    '.tr': 'Turkey', '.tw': 'Taiwan', '.ua': 'Ukraine',
    '.uk': 'United Kingdom', '.us': 'United States', '.ve': 'Venezuela', '.vn': 'Vietnam',
    '.za': 'South Africa', '.ng': 'Nigeria', '.ke': 'Kenya',
    '.eg': 'Egypt', '.ae': 'United Arab Emirates',
    '.io': 'British Indian Ocean Territory', '.ai': 'Anguilla',
    
    // Suspicious/commonly abused TLDs
    '.tk': 'Tokelau', '.ml': 'Mali', '.ga': 'Gabon',
    '.cf': 'Central African Republic', '.gq': 'Equatorial Guinea',
    '.cm': 'Cameroon', '.cc': 'Cocos Islands', '.ws': 'Samoa',
    '.pw': 'Palau', '.top': 'Generic (often abused)', '.xyz': 'Generic (often abused)',
    '.buzz': 'Generic (often abused)', '.icu': 'Generic (often abused)',
    '.biz': 'Generic (often abused)', '.info': 'Generic (often abused)',
    '.shop': 'Generic (often abused)', '.club': 'Generic (often abused)'
};

// TLDs to flag as international senders (subset that warrants warning)
const INTERNATIONAL_TLDS = [
    // Compound country TLDs
    '.com.co', '.com.br', '.com.mx', '.com.ar', '.com.au', '.com.ng',
    '.com.pk', '.com.ph', '.com.ua', '.com.ve', '.com.vn', '.com.tr',
    '.net.co', '.net.br', '.org.co',
    // Commonly abused TLDs
    '.cm', '.cc', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw',
    // ALL country code TLDs trigger international sender warning
    '.ae', '.ar', '.at', '.au', '.be', '.br', '.ca', '.ch', '.cl', '.cn',
    '.co', '.cz', '.de', '.dk', '.eg', '.es', '.fi', '.fr', '.gr',
    '.hk', '.hu', '.id', '.ie', '.il', '.in', '.it', '.jp',
    '.ke', '.kr', '.mx', '.my', '.ng', '.nl', '.no', '.nz',
    '.pe', '.ph', '.pk', '.pl', '.pt', '.ro', '.ru',
    '.sa', '.se', '.sg', '.th', '.tr', '.tw', '.ua', '.uk', '.us',
    '.ve', '.vn', '.za', '.io', '.ai'
];

// Country code TLDs that are widely used for generic/commercial purposes
const GENERIC_USE_CCTLDS = {
    '.co': 'This sender uses a .co domain (Colombia\'s country code). <strong>While some legitimate businesses use .co</strong>, scammers also exploit it to create convincing lookalike domains. If you don\'t recognize this sender, verify before clicking any links.',
    '.io': 'This sender uses a .io domain (British Indian Ocean Territory\'s country code). <strong>While some legitimate tech companies use .io</strong>, scammers also exploit it to create convincing lookalike domains. If you don\'t recognize this sender, verify before clicking any links.',
    '.ai': 'This sender uses a .ai domain (Anguilla\'s country code). <strong>While some legitimate AI and tech companies use .ai</strong>, scammers also exploit it to create convincing lookalike domains. If you don\'t recognize this sender, verify before clicking any links.'
};

// Fake country-lookalike TLDs (commercial services mimicking real TLDs)
const FAKE_COUNTRY_CODES = ['ae', 'ar', 'at', 'au', 'be', 'br', 'ca', 'ch', 'cl', 'cn', 'co', 'cz', 'de', 'dk', 'eg', 'es', 'eu', 'fi', 'fr', 'gr', 'hk', 'hu', 'id', 'ie', 'il', 'in', 'it', 'jp', 'ke', 'kr', 'mx', 'my', 'ng', 'nl', 'no', 'nz', 'pe', 'ph', 'pk', 'pl', 'pt', 'ro', 'ru', 'sa', 'se', 'sg', 'th', 'tr', 'tw', 'ua', 'uk', 'us', 've', 'vn', 'za'];
const FAKE_GTLDS = ['.com', '.net', '.org', '.info', '.biz'];
const FAKE_COUNTRY_TLDS = FAKE_COUNTRY_CODES.flatMap(cc => FAKE_GTLDS.map(gtld => '.' + cc + gtld));
FAKE_COUNTRY_TLDS.push('.co.uk.com');
FAKE_COUNTRY_TLDS.push('.co.us');

// Suspicious words commonly used in fake domains
const SUSPICIOUS_DOMAIN_WORDS = [
    'secure', 'security', 'verify', 'verification', 'login', 'signin', 'signon',
    'alert', 'alerts', 'support', 'helpdesk', 'service', 'services',
    'account', 'accounts', 'update', 'confirm', 'confirmation',
    'billing', 'payment', 'invoice', 'refund', 'claim',
    'unlock', 'suspended', 'locked', 'validate',
    'official', 'authentic', 'legit', 'real', 'genuine',
    'dept', 'department', 'center', 'centre',
    'online', 'web', 'portal', 'access', 'customer'
];

// Suspicious display name patterns (suggest impersonation)
const SUSPICIOUS_DISPLAY_PATTERNS = [
    'security', 'fraud', 'alert', 'support', 'helpdesk', 'help desk',
    'customer service', 'account team', 'billing', 'verification',
    'department', 'official', 'admin', 'administrator',
    'no-reply', 'noreply', 'do not reply', 'automated',
    'urgent', 'important', 'action required', 'immediate'
];

// ============================================
// NEW v3.5.0: PHISHING URGENCY KEYWORDS
// ============================================
const PHISHING_URGENCY_KEYWORDS = [
    'account locked', 'account suspended', 'account disabled',
    'account will be', 'account has been',
    'access suspended', 'access revoked', 'access denied',
    'will be deleted', 'scheduled for deletion', 'permanently removed',
    'permanently deleted', 'files will be lost', 'data will be erased',
    'photos will be deleted', 'videos will be deleted',
    'storage limit', 'storage full', 'critical limit',
    'quota exceeded', 'mailbox full', 'inbox full',
    'final notice', 'final warning', 'last chance',
    'immediate action', 'act immediately',
    'expires today', 'expires soon',
    'within 24 hours', 'within 48 hours',
    'verify your account', 'confirm your identity',
    'verify your email', 'verify your information',
    'update your payment', 'payment failed', 'payment declined',
    'billing problem', 'billing issue',
    'subscription expired', 'renew your subscription',
    'membership expired', 'unable to renew',
    'we\'ve blocked', 'has been blocked', 'temporarily blocked'
];

// ============================================
// BRAND IMPERSONATION DETECTION (CONTENT-BASED)
// ============================================
const BRAND_CONTENT_DETECTION = {
    'docusign': {
        keywords: ['docusign'],
        legitimateDomains: ['docusign.com', 'docusign.net']
    },
    'microsoft': {
        keywords: ['microsoft 365', 'microsoft-365', 'office 365', 'office-365', 'sharepoint', 'onedrive', 'microsoft account', 'microsoft teams'],
        legitimateDomains: ['microsoft.com', 'office.com', 'sharepoint.com', 'onedrive.com', 'live.com', 'outlook.com', 'office365.com', 'teams.mail.microsoft']
    },
    'google': {
        keywords: ['google drive', 'google docs', 'google account', 'google workspace'],
        legitimateDomains: ['google.com', 'gmail.com', 'googlemail.com']
    },
    'amazon': {
        keywords: ['amazon prime', 'amazon account', 'amazon order', 'amazon.com order'],
        legitimateDomains: ['amazon.com', 'amazon.co.uk', 'amazon.ca', 'amazonses.com']
    },
    'paypal': {
        keywords: ['paypal'],
        legitimateDomains: ['paypal.com']
    },
    'netflix': {
        keywords: ['netflix'],
        legitimateDomains: ['netflix.com']
    },
    'adobe sign': {
        keywords: ['adobe sign', 'adobesign'],
        legitimateDomains: ['adobe.com', 'adobesign.com', 'echosign.com']
    },
    'dropbox': {
        keywords: ['dropbox', 'dropbox sign', 'hellosign'],
        legitimateDomains: ['dropbox.com', 'hellosign.com', 'dropboxmail.com']
    },
    'apple': {
        keywords: ['apple id', 'icloud account', 'apple account'],
        legitimateDomains: ['apple.com', 'icloud.com']
    },
    'facebook': {
        keywords: ['facebook account', 'meta account', 'facebook security'],
        legitimateDomains: ['facebook.com', 'meta.com', 'facebookmail.com', 'fb.com', 'metamail.com']
    },
    'linkedin': {
        keywords: ['linkedin account', 'linkedin invitation', 'linkedin message'],
        legitimateDomains: ['linkedin.com']
    },
    'yahoo': {
        keywords: ['yahoo account', 'yahoo mail', 'yahoo security'],
        legitimateDomains: ['yahoo.com', 'yahoomail.com']
    },
    'mcafee': {
        keywords: ['mcafee'],
        legitimateDomains: ['mcafee.com']
    },
    'coinbase': {
        keywords: ['coinbase'],
        legitimateDomains: ['coinbase.com']
    },
    'dhl': {
        keywords: ['dhl express', 'dhl shipment', 'dhl delivery', 'dhl package'],
        legitimateDomains: ['dhl.com', 'dhl.de']
    },
    'fedex': {
        keywords: ['fedex', 'federal express'],
        legitimateDomains: ['fedex.com']
    },
    'ups': {
        keywords: ['ups package', 'ups delivery', 'ups shipment', 'united parcel'],
        legitimateDomains: ['ups.com']
    },
    'usps': {
        keywords: ['usps', 'postal service', 'usps delivery', 'usps package'],
        legitimateDomains: ['usps.com']
    },
    'zelle': {
        keywords: ['zelle'],
        legitimateDomains: ['zellepay.com', 'zelle.com']
    },
    'venmo': {
        keywords: ['venmo'],
        legitimateDomains: ['venmo.com']
    },
    'cashapp': {
        keywords: ['cash app', 'cashapp'],
        legitimateDomains: ['cash.app', 'square.com', 'squareup.com']
    },
    'quickbooks': {
        keywords: ['quickbooks', 'intuit'],
        legitimateDomains: ['intuit.com', 'quickbooks.com']
    },
    'zoom': {
        keywords: ['zoom meeting', 'zoom invitation', 'zoom account'],
        legitimateDomains: ['zoom.us', 'zoom.com']
    },
    'walmart': {
        keywords: ['walmart', 'wal-mart'],
        legitimateDomains: ['walmart.com']
    },
    'target': {
        keywords: ['target order', 'target account', 'target registry', 'target circle'],
        legitimateDomains: ['target.com']
    },
    'costco': {
        keywords: ['costco', 'costco wholesale'],
        legitimateDomains: ['costco.com']
    },
    'best buy': {
        keywords: ['best buy', 'bestbuy', 'geek squad'],
        legitimateDomains: ['bestbuy.com']
    },
    'home depot': {
        keywords: ['home depot'],
        legitimateDomains: ['homedepot.com']
    },
    'lowes': {
        keywords: ['lowe\'s', 'lowes'],
        legitimateDomains: ['lowes.com']
    },
    'ebay': {
        keywords: ['ebay'],
        legitimateDomains: ['ebay.com']
    },
    'dmv': {
        keywords: ['department of motor vehicles', 'dmv service desk', 'dmv appointment', 'dmv registration'],
        legitimateDomains: ['.gov']
    },
    'irs': {
        keywords: ['internal revenue service', 'irs refund', 'irs audit', 'irs notice'],
        legitimateDomains: ['irs.gov']
    },
    'social security': {
        keywords: ['social security administration', 'social security number', 'ssa benefit', 'social security statement'],
        legitimateDomains: ['ssa.gov']
    },
    'att': {
        keywords: ['at&t', 'att account', 'att wireless'],
        legitimateDomains: ['att.com', 'att.net', 'att-mail.com']
    },
    'verizon': {
        keywords: ['verizon', 'verizon wireless', 'verizon fios'],
        legitimateDomains: ['verizon.com', 'verizonwireless.com']
    },
    'tmobile': {
        keywords: ['t-mobile', 'tmobile'],
        legitimateDomains: ['t-mobile.com']
    },
    'xfinity': {
        keywords: ['xfinity', 'comcast'],
        legitimateDomains: ['xfinity.com', 'comcast.com', 'comcast.net']
    },
    'spectrum': {
        keywords: ['spectrum internet', 'spectrum account', 'spectrum mobile'],
        legitimateDomains: ['spectrum.com', 'spectrum.net', 'charter.com']
    },
    'frontier': {
        keywords: ['frontier internet', 'frontier account', 'frontier bill'],
        legitimateDomains: ['frontier.com']
    },
    'whatsapp': {
        keywords: ['whatsapp'],
        legitimateDomains: ['whatsapp.com']
    },
    'instagram': {
        keywords: ['instagram account', 'instagram security'],
        legitimateDomains: ['instagram.com', 'mail.instagram.com', 'facebookmail.com', 'metamail.com']
    },
    'tiktok': {
        keywords: ['tiktok account', 'tiktok security'],
        legitimateDomains: ['tiktok.com']
    },
    'twitter': {
        keywords: ['twitter account', 'x account'],
        legitimateDomains: ['twitter.com', 'x.com']
    },
    'snapchat': {
        keywords: ['snapchat account', 'snapchat security'],
        legitimateDomains: ['snapchat.com']
    },
    'steam': {
        keywords: ['steam account', 'steam guard', 'steam wallet'],
        legitimateDomains: ['steampowered.com', 'store.steampowered.com', 'steamcommunity.com']
    },
    'roblox': {
        keywords: ['roblox account', 'roblox security', 'robux'],
        legitimateDomains: ['roblox.com']
    },
    'playstation': {
        keywords: ['playstation account', 'psn account', 'playstation network'],
        legitimateDomains: ['playstation.com', 'sony.com', 'sonyentertainmentnetwork.com']
    },
    'xbox': {
        keywords: ['xbox account', 'xbox live', 'xbox game pass'],
        legitimateDomains: ['xbox.com', 'microsoft.com']
    },
    'epic games': {
        keywords: ['epic games', 'fortnite account', 'epic account'],
        legitimateDomains: ['epicgames.com', 'unrealengine.com']
    },
    'spotify': {
        keywords: ['spotify.com', 'open.spotify.com', 'account.spotify.com', 'spotify premium', 'spotify subscription', 'spotify support', 'spotify login', 'spotify app', 'spotify account', 'spotify receipt', 'spotify plan', 'reset your spotify password'],
        legitimateDomains: ['spotify.com', 'spotifymail.com']
    },
    'disney plus': {
        keywords: ['disney+', 'disney plus', 'disneyplus'],
        legitimateDomains: ['disneyplus.com', 'disney.com', 'go.com', 'd23.com', 'disneyonline.com']
    },
    'hulu': {
        keywords: ['hulu account', 'hulu subscription'],
        legitimateDomains: ['hulu.com']
    },
    'max': {
        keywords: ['hbo max', 'max account', 'max subscription'],
        legitimateDomains: ['max.com', 'hbomax.com']
    },
    'roku': {
        keywords: ['roku account', 'roku device'],
        legitimateDomains: ['roku.com']
    },
    'youtube': {
        keywords: ['youtube account', 'youtube premium', 'youtube tv'],
        legitimateDomains: ['youtube.com', 'google.com']
    },
    'paramount': {
        keywords: ['paramount+', 'paramount plus'],
        legitimateDomains: ['paramountplus.com', 'paramount.com']
    },
    'visa': {
        keywords: ['visa card', 'visa account', 'visa security'],
        legitimateDomains: ['visa.com']
    },
    'mastercard': {
        keywords: ['mastercard', 'master card'],
        legitimateDomains: ['mastercard.com']
    },
    'stripe': {
        keywords: ['stripe payment', 'stripe account'],
        legitimateDomains: ['stripe.com']
    },
    'robinhood': {
        keywords: ['robinhood account', 'robinhood security'],
        legitimateDomains: ['robinhood.com']
    },
    'fidelity': {
        keywords: ['fidelity investments', 'fidelity account', 'fidelity 401k'],
        legitimateDomains: ['fidelity.com', 'fidelityinvestments.com']
    },
    'schwab': {
        keywords: ['charles schwab', 'schwab account'],
        legitimateDomains: ['schwab.com']
    },
    'vanguard': {
        keywords: ['vanguard account', 'vanguard investments'],
        legitimateDomains: ['vanguard.com']
    },
    'morgan stanley': {
        keywords: ['morgan stanley'],
        legitimateDomains: ['morganstanley.com']
    },
    'wise': {
        keywords: ['wise transfer', 'transferwise'],
        legitimateDomains: ['wise.com']
    },
    'affirm': {
        keywords: ['affirm payment', 'affirm account'],
        legitimateDomains: ['affirm.com']
    },
    'klarna': {
        keywords: ['klarna payment', 'klarna account'],
        legitimateDomains: ['klarna.com']
    },
    'state farm': {
        keywords: ['state farm'],
        legitimateDomains: ['statefarm.com']
    },
    'geico': {
        keywords: ['geico'],
        legitimateDomains: ['geico.com']
    },
    'progressive': {
        keywords: ['progressive insurance', 'progressive auto'],
        legitimateDomains: ['progressive.com']
    },
    'allstate': {
        keywords: ['allstate'],
        legitimateDomains: ['allstate.com']
    },
    'liberty mutual': {
        keywords: ['liberty mutual'],
        legitimateDomains: ['libertymutual.com']
    },
    'farmers insurance': {
        keywords: ['farmers insurance'],
        legitimateDomains: ['farmers.com']
    },
    'nationwide': {
        keywords: ['nationwide insurance', 'nationwide account'],
        legitimateDomains: ['nationwide.com']
    },
    'travelers': {
        keywords: ['travelers insurance'],
        legitimateDomains: ['travelers.com']
    },
    'the hartford': {
        keywords: ['the hartford'],
        legitimateDomains: ['thehartford.com']
    },
    'american family': {
        keywords: ['american family insurance', 'amfam'],
        legitimateDomains: ['amfam.com']
    },
    'erie insurance': {
        keywords: ['erie insurance'],
        legitimateDomains: ['erieinsurance.com']
    },
    'unitedhealthcare': {
        keywords: ['unitedhealthcare', 'united healthcare', 'uhc'],
        legitimateDomains: ['uhc.com', 'unitedhealthcare.com', 'myuhc.com', 'optum.com']
    },
    'blue cross': {
        keywords: ['blue cross', 'blue shield', 'bcbs', 'bluecross'],
        legitimateDomains: ['bcbs.com', 'anthem.com', 'bluecrossma.com']
    },
    'cigna': {
        keywords: ['cigna'],
        legitimateDomains: ['cigna.com', 'mycigna.com']
    },
    'humana': {
        keywords: ['humana'],
        legitimateDomains: ['humana.com']
    },
    'kaiser': {
        keywords: ['kaiser permanente'],
        legitimateDomains: ['kaiserpermanente.org', 'kp.org']
    },
    'aetna': {
        keywords: ['aetna'],
        legitimateDomains: ['aetna.com']
    },
    'metlife': {
        keywords: ['metlife'],
        legitimateDomains: ['metlife.com']
    },
    'prudential': {
        keywords: ['prudential financial', 'prudential insurance'],
        legitimateDomains: ['prudential.com']
    },
    'new york life': {
        keywords: ['new york life'],
        legitimateDomains: ['newyorklife.com']
    },
    'northwestern mutual': {
        keywords: ['northwestern mutual'],
        legitimateDomains: ['northwesternmutual.com']
    },
    'aflac': {
        keywords: ['aflac'],
        legitimateDomains: ['aflac.com']
    },
    'aaa': {
        keywords: ['aaa membership', 'aaa roadside', 'aaa insurance'],
        legitimateDomains: ['aaa.com', 'ace.aaa.com', 'calif.aaa.com']
    },
    'booking.com': {
        keywords: ['booking.com', 'booking confirmation'],
        legitimateDomains: ['booking.com']
    },
    'airbnb': {
        keywords: ['airbnb'],
        legitimateDomains: ['airbnb.com', 'airbnbmail.com', 'airbnbaction.com', 'airbnblove.com']
    },
    'expedia': {
        keywords: ['expedia'],
        legitimateDomains: ['expedia.com']
    },
    'southwest airlines': {
        keywords: ['southwest airlines', 'southwest rapid rewards'],
        legitimateDomains: ['southwest.com', 'southwestairlines.com']
    },
    'united airlines': {
        keywords: ['united airlines', 'united mileageplus'],
        legitimateDomains: ['united.com']
    },
    'delta airlines': {
        keywords: ['delta air lines', 'delta skymiles'],
        legitimateDomains: ['delta.com']
    },
    'american airlines': {
        keywords: ['american airlines', 'aadvantage'],
        legitimateDomains: ['aa.com', 'americanairlines.com']
    },
    'norton': {
        keywords: ['norton', 'nortonlifelock', 'norton 360'],
        legitimateDomains: ['norton.com', 'nortonlifelock.com', 'gen.digital']
    },
    'avast': {
        keywords: ['avast'],
        legitimateDomains: ['avast.com']
    },
    'binance': {
        keywords: ['binance'],
        legitimateDomains: ['binance.com']
    },
    'kraken': {
        keywords: ['kraken exchange', 'kraken account'],
        legitimateDomains: ['kraken.com']
    },
    'crypto.com': {
        keywords: ['crypto.com'],
        legitimateDomains: ['crypto.com']
    },
    'salesforce': {
        keywords: ['salesforce', 'salesforce account', 'salesforce login'],
        legitimateDomains: ['salesforce.com', 'force.com', 'salesforce.org']
    },
    'slack': {
        keywords: ['slack workspace', 'slack account', 'slack notification'],
        legitimateDomains: ['slack.com', 'slack-edge.com']
    },
    'hubspot': {
        keywords: ['hubspot', 'hubspot account', 'hubspot crm'],
        legitimateDomains: ['hubspot.com', 'hs-analytics.net', 'hubspotemail.net']
    },
    'monday.com': {
        keywords: ['monday.com', 'monday board', 'monday workspace'],
        legitimateDomains: ['monday.com']
    },
    'asana': {
        keywords: ['asana', 'asana task', 'asana project'],
        legitimateDomains: ['asana.com']
    },
    'trello': {
        keywords: ['trello', 'trello board', 'trello card'],
        legitimateDomains: ['trello.com']
    },
    'notion': {
        keywords: ['notion workspace', 'notion account'],
        legitimateDomains: ['notion.so', 'notion.com']
    },
    'adobe': {
        keywords: ['adobe', 'acrobat', 'adobe send', 'adobe files', 'adobe document', 'adobe account', 'adobe subscription', 'adobe creative cloud', 'adobe pdf'],
        legitimateDomains: ['adobe.com', 'adobesign.com', 'echosign.com', 'acrobat.com', 'documentcloud.adobe.com']
    },
    'afterpay': {
        keywords: ['afterpay', 'after pay'],
        legitimateDomains: ['afterpay.com']
    },
    'sofi': {
        keywords: ['sofi', 'sofi account', 'sofi loan', 'sofi money'],
        legitimateDomains: ['sofi.com', 'sofi.org']
    },
    'synchrony': {
        keywords: ['synchrony', 'synchrony bank', 'synchrony financial'],
        legitimateDomains: ['synchrony.com', 'synchronybank.com', 'mysynchrony.com']
    },
    'chime': {
        keywords: ['chime', 'chime account', 'chime bank'],
        legitimateDomains: ['chime.com']
    },
    'pge': {
        keywords: ['pg&e', 'pge', 'pacific gas', 'pacific gas and electric'],
        legitimateDomains: ['pge.com']
    },
    'sce': {
        keywords: ['southern california edison', 'sce bill', 'sce account', 'sce energy', 'sce power', 'edison account'],
        legitimateDomains: ['sce.com']
    },
    'con edison': {
        keywords: ['con edison', 'coned', 'con ed'],
        legitimateDomains: ['coned.com', 'conedison.com']
    },
    'duke energy': {
        keywords: ['duke energy'],
        legitimateDomains: ['duke-energy.com']
    },
    'national grid': {
        keywords: ['national grid'],
        legitimateDomains: ['nationalgrid.com', 'nationalgridus.com']
    },
    'fpl': {
        keywords: ['florida power', 'fpl', 'florida power & light'],
        legitimateDomains: ['fpl.com', 'nexteraenergy.com']
    },
    'sdge': {
        keywords: ['san diego gas', 'sdge', 'sdg&e'],
        legitimateDomains: ['sdge.com']
    },
    'dominion energy': {
        keywords: ['dominion energy', 'dominion power'],
        legitimateDomains: ['dominionenergy.com']
    },
    'doordash': {
        keywords: ['doordash', 'door dash'],
        legitimateDomains: ['doordash.com']
    },
    'uber eats': {
        keywords: ['uber eats', 'ubereats'],
        legitimateDomains: ['uber.com', 'ubereats.com']
    },
    'grubhub': {
        keywords: ['grubhub', 'grub hub'],
        legitimateDomains: ['grubhub.com']
    },
    'instacart': {
        keywords: ['instacart'],
        legitimateDomains: ['instacart.com']
    },
    'uber': {
        keywords: ['uber account', 'uber ride', 'uber trip'],
        legitimateDomains: ['uber.com']
    },
    'lyft': {
        keywords: ['lyft', 'lyft ride', 'lyft account'],
        legitimateDomains: ['lyft.com', 'lyftmail.com']    },
    'etsy': {
        keywords: ['etsy', 'etsy shop', 'etsy order'],
        legitimateDomains: ['etsy.com']
    },
    'wayfair': {
        keywords: ['wayfair', 'wayfair order'],
        legitimateDomains: ['wayfair.com']
    },
    'ikea': {
        keywords: ['ikea', 'ikea order'],
        legitimateDomains: ['ikea.com']
    },
    'samsclub': {
        keywords: ['sam\'s club', 'sams club', 'samsclub'],
        legitimateDomains: ['samsclub.com']
    },
    'macys': {
        keywords: ['macy\'s', 'macys'],
        legitimateDomains: ['macys.com']
    },
    'kohls': {
        keywords: ['kohl\'s', 'kohls'],
        legitimateDomains: ['kohls.com']
    },
    'jcpenney': {
        keywords: ['jcpenney', 'jc penney', 'penney\'s'],
        legitimateDomains: ['jcpenney.com']
    },

    // ============================================
    // GLOBAL BRANDS (missing from phishing reports)
    // ============================================
    'telegram': {
        keywords: ['telegram account', 'telegram security', 'telegram verification'],
        legitimateDomains: ['telegram.org', 'telegram.me']
    },
    'sharefile': {
        keywords: ['sharefile', 'citrix sharefile'],
        legitimateDomains: ['sharefile.com', 'citrix.com', 'cloud.com']
    },
    'wetransfer': {
        keywords: ['wetransfer', 'we transfer'],
        legitimateDomains: ['wetransfer.com']
    },

    // ============================================
    // JAPAN
    // ============================================
    'kddi': {
        keywords: ['kddi', 'au account', 'au wallet', 'au pay'],
        legitimateDomains: ['kddi.com', 'au.com']
    },
    'jr east': {
        keywords: ['jr east', 'eki-net', 'suica'],
        legitimateDomains: ['jreast.co.jp', 'eki-net.com']
    },
    'aeon': {
        keywords: ['aeon card', 'aeon account', 'aeon pay', 'waon'],
        legitimateDomains: ['aeon.co.jp', 'aeoncredit.co.jp', 'aeon.com']
    },
    'jcb': {
        keywords: ['jcb card', 'jcb account', 'jcb payment'],
        legitimateDomains: ['jcb.co.jp', 'jcb.com']
    },
    'mufg': {
        keywords: ['mufg', 'mitsubishi ufj'],
        legitimateDomains: ['mufg.jp', 'bk.mufg.jp']
    },
    'smbc': {
        keywords: ['smbc', 'sumitomo mitsui', 'smbc card'],
        legitimateDomains: ['smbc.co.jp', 'smbc-card.com']
    },
    'mizuho': {
        keywords: ['mizuho bank', 'mizuho account'],
        legitimateDomains: ['mizuhobank.co.jp', 'mizuho-fg.co.jp']
    },
    'rakuten': {
        keywords: ['rakuten account', 'rakuten card', 'rakuten pay'],
        legitimateDomains: ['rakuten.co.jp', 'rakuten.com', 'rakuten-card.co.jp']
    },
    'mercari': {
        keywords: ['mercari account', 'mercari order'],
        legitimateDomains: ['mercari.com', 'mercari.jp']
    },
    'japan post': {
        keywords: ['japan post', 'yu-pack'],
        legitimateDomains: ['japanpost.jp', 'post.japanpost.jp']
    },
    'yamato': {
        keywords: ['yamato transport', 'kuroneko yamato', 'ta-q-bin'],
        legitimateDomains: ['kuronekoyamato.co.jp', 'yamato-hd.co.jp']
    },
    'sagawa': {
        keywords: ['sagawa express'],
        legitimateDomains: ['sagawa-exp.co.jp']
    },
    'line': {
        keywords: ['line account', 'line security', 'line pay'],
        legitimateDomains: ['line.me', 'linecorp.com']
    },
    'ntt docomo': {
        keywords: ['ntt docomo', 'docomo account', 'd account', 'd point'],
        legitimateDomains: ['docomo.ne.jp', 'nttdocomo.co.jp']
    },
    'softbank jp': {
        keywords: ['softbank account', 'softbank mobile', 'my softbank'],
        legitimateDomains: ['softbank.jp', 'mb.softbank.jp']
    },

    // ============================================
    // UNITED KINGDOM
    // ============================================
    'hsbc': {
        keywords: ['hsbc account', 'hsbc security', 'hsbc online'],
        legitimateDomains: ['hsbc.co.uk', 'hsbc.com', 'us.hsbc.com']
    },
    'barclays': {
        keywords: ['barclays account', 'barclays security', 'barclays bank'],
        legitimateDomains: ['barclays.co.uk', 'barclays.com']
    },
    'lloyds': {
        keywords: ['lloyds bank', 'lloyds account', 'lloyds security'],
        legitimateDomains: ['lloydsbank.co.uk', 'lloydsbank.com']
    },
    'natwest': {
        keywords: ['natwest account', 'natwest security', 'natwest bank'],
        legitimateDomains: ['natwest.com']
    },
    'santander': {
        keywords: ['santander account', 'santander security', 'santander bank'],
        legitimateDomains: ['santander.co.uk', 'santander.com']
    },
    'monzo': {
        keywords: ['monzo account', 'monzo security'],
        legitimateDomains: ['monzo.com']
    },
    'revolut': {
        keywords: ['revolut account', 'revolut security', 'revolut payment'],
        legitimateDomains: ['revolut.com']
    },
    'hmrc': {
        keywords: ['hmrc', 'hm revenue', 'self assessment'],
        legitimateDomains: ['gov.uk']
    },
    'nhs': {
        keywords: ['nhs appointment', 'nhs account', 'nhs login'],
        legitimateDomains: ['nhs.uk']
    },
    'dvla': {
        keywords: ['dvla', 'vehicle tax', 'driving licence'],
        legitimateDomains: ['gov.uk']
    },
    'bt': {
        keywords: ['bt broadband', 'bt account', 'bt bill'],
        legitimateDomains: ['bt.com']
    },
    'vodafone': {
        keywords: ['vodafone account', 'vodafone security', 'vodafone bill'],
        legitimateDomains: ['vodafone.co.uk', 'vodafone.com']
    },
    'o2': {
        keywords: ['o2 account', 'o2 security', 'o2 bill'],
        legitimateDomains: ['o2.co.uk']
    },
    'sky uk': {
        keywords: ['sky account', 'sky bill', 'sky broadband'],
        legitimateDomains: ['sky.com', 'sky.uk']
    },
    'royal mail': {
        keywords: ['royal mail', 'royal mail delivery', 'royal mail parcel'],
        legitimateDomains: ['royalmail.com']
    },
    'evri': {
        keywords: ['evri delivery', 'evri parcel', 'hermes delivery'],
        legitimateDomains: ['evri.com', 'myhermes.co.uk']
    },

    // ============================================
    // AUSTRALIA
    // ============================================
    'commonwealth bank': {
        keywords: ['commonwealth bank', 'commbank', 'netbank'],
        legitimateDomains: ['commbank.com.au', 'cba.com.au']
    },
    'westpac': {
        keywords: ['westpac account', 'westpac security'],
        legitimateDomains: ['westpac.com.au']
    },
    'anz bank': {
        keywords: ['anz bank', 'anz account', 'anz security'],
        legitimateDomains: ['anz.com.au', 'anz.com']
    },
    'nab': {
        keywords: ['nab account', 'national australia bank', 'nab security'],
        legitimateDomains: ['nab.com.au']
    },
    'ato': {
        keywords: ['australian taxation', 'ato refund', 'mygov', 'ato account'],
        legitimateDomains: ['ato.gov.au', 'my.gov.au']
    },
    'services australia': {
        keywords: ['centrelink', 'medicare australia', 'services australia'],
        legitimateDomains: ['servicesaustralia.gov.au', 'humanservices.gov.au']
    },
    'telstra': {
        keywords: ['telstra account', 'telstra bill', 'telstra security'],
        legitimateDomains: ['telstra.com.au', 'telstra.com']
    },
    'optus': {
        keywords: ['optus account', 'optus bill', 'optus security'],
        legitimateDomains: ['optus.com.au']
    },
    'australia post': {
        keywords: ['australia post', 'auspost delivery'],
        legitimateDomains: ['auspost.com.au']
    },

    // ============================================
    // INDIA
    // ============================================
    'sbi': {
        keywords: ['sbi account', 'state bank of india', 'sbi security', 'yono sbi'],
        legitimateDomains: ['sbi.co.in', 'onlinesbi.com']
    },
    'hdfc bank': {
        keywords: ['hdfc bank', 'hdfc account', 'hdfc security', 'hdfc netbanking'],
        legitimateDomains: ['hdfcbank.com']
    },
    'icici bank': {
        keywords: ['icici bank', 'icici account', 'icici security'],
        legitimateDomains: ['icicibank.com']
    },
    'paytm': {
        keywords: ['paytm account', 'paytm wallet', 'paytm payment'],
        legitimateDomains: ['paytm.com']
    },
    'phonepe': {
        keywords: ['phonepe account', 'phonepe payment'],
        legitimateDomains: ['phonepe.com']
    },
    'india post': {
        keywords: ['india post', 'india post delivery', 'speed post'],
        legitimateDomains: ['indiapost.gov.in']
    },
    'aadhaar': {
        keywords: ['aadhaar', 'uidai', 'aadhaar update', 'aadhaar verification'],
        legitimateDomains: ['uidai.gov.in']
    },
    'airtel india': {
        keywords: ['airtel account', 'airtel bill', 'airtel recharge'],
        legitimateDomains: ['airtel.in']
    },
    'jio': {
        keywords: ['jio account', 'jio recharge', 'reliance jio'],
        legitimateDomains: ['jio.com']
    },

    // ============================================
    // CANADA
    // ============================================
    'rbc': {
        keywords: ['rbc account', 'royal bank', 'rbc security'],
        legitimateDomains: ['rbc.com', 'rbcroyalbank.com']
    },
    'td canada': {
        keywords: ['td canada trust', 'td account', 'td security'],
        legitimateDomains: ['td.com', 'tdcanadatrust.com']
    },
    'scotiabank': {
        keywords: ['scotiabank account', 'scotiabank security'],
        legitimateDomains: ['scotiabank.com']
    },
    'bmo': {
        keywords: ['bmo account', 'bank of montreal', 'bmo security'],
        legitimateDomains: ['bmo.com']
    },
    'cibc': {
        keywords: ['cibc account', 'cibc security'],
        legitimateDomains: ['cibc.com']
    },
    'canada post': {
        keywords: ['canada post', 'canada post delivery', 'canada post parcel'],
        legitimateDomains: ['canadapost.ca', 'canadapost-postescanada.ca']
    },
    'cra': {
        keywords: ['canada revenue', 'cra refund', 'cra account', 'cra notice'],
        legitimateDomains: ['canada.ca', 'gc.ca']
    },
    'interac': {
        keywords: ['interac e-transfer', 'interac etransfer'],
        legitimateDomains: ['interac.ca']
    },

    // ============================================
    // EUROPE
    // ============================================
    'deutsche bank': {
        keywords: ['deutsche bank account'],
        legitimateDomains: ['deutsche-bank.de', 'db.com']
    },
    'bnp paribas': {
        keywords: ['bnp paribas', 'bnp account'],
        legitimateDomains: ['bnpparibas.com', 'bnpparibas.fr']
    },
    'ing bank': {
        keywords: ['ing bank', 'ing account', 'ing security'],
        legitimateDomains: ['ing.com', 'ing.nl', 'ing.de']
    },
    'rabobank': {
        keywords: ['rabobank account'],
        legitimateDomains: ['rabobank.nl', 'rabobank.com']
    },
    'credit agricole': {
        keywords: ['credit agricole'],
        legitimateDomains: ['credit-agricole.fr', 'ca-group.com']
    },
    'postnl': {
        keywords: ['postnl', 'postnl delivery', 'postnl parcel'],
        legitimateDomains: ['postnl.nl', 'postnl.com']
    },
    'deutsche post': {
        keywords: ['deutsche post', 'dhl paket'],
        legitimateDomains: ['deutschepost.de', 'dhl.de']
    },
    'la poste': {
        keywords: ['la poste', 'colissimo'],
        legitimateDomains: ['laposte.fr', 'laposte.net']
    },
    'correos': {
        keywords: ['correos delivery'],
        legitimateDomains: ['correos.es']
    },
    'poste italiane': {
        keywords: ['poste italiane'],
        legitimateDomains: ['poste.it', 'posteitaliane.it']
    },
    'orange': {
        keywords: ['orange mobile', 'orange account', 'orange bill'],
        legitimateDomains: ['orange.fr', 'orange.com']
    },
    'deutsche telekom': {
        keywords: ['deutsche telekom', 'telekom account', 'telekom bill'],
        legitimateDomains: ['telekom.de', 'telekom.com']
    },
    'swisscom': {
        keywords: ['swisscom account', 'swisscom bill'],
        legitimateDomains: ['swisscom.ch', 'swisscom.com']
    },
    'klarna eu': {
        keywords: ['klarna payment', 'klarna account', 'klarna invoice'],
        legitimateDomains: ['klarna.com']
    },

    // ============================================
    // SOUTH KOREA
    // ============================================
    'kakaobank': {
        keywords: ['kakaobank', 'kakao bank', 'kakao account'],
        legitimateDomains: ['kakaobank.com', 'kakaocorp.com']
    },
    'naver': {
        keywords: ['naver account', 'naver security', 'naver pay'],
        legitimateDomains: ['naver.com']
    },
    'coupang': {
        keywords: ['coupang order', 'coupang delivery'],
        legitimateDomains: ['coupang.com']
    },

    // ============================================
    // BRAZIL / LATIN AMERICA
    // ============================================
    'mercado libre': {
        keywords: ['mercado libre', 'mercadolibre', 'mercado pago'],
        legitimateDomains: ['mercadolibre.com', 'mercadopago.com', 'mercadolivre.com.br']
    },
    'nubank': {
        keywords: ['nubank account', 'nu account'],
        legitimateDomains: ['nubank.com.br']
    },
    'banco do brasil': {
        keywords: ['banco do brasil'],
        legitimateDomains: ['bb.com.br']
    },
    'itau': {
        keywords: ['itau account', 'itau bank'],
        legitimateDomains: ['itau.com.br']
    },
    'bradesco': {
        keywords: ['bradesco account'],
        legitimateDomains: ['bradesco.com.br']
    },
    'correios': {
        keywords: ['correios delivery', 'correios rastreamento'],
        legitimateDomains: ['correios.com.br']
    },

    // ============================================
    // SOUTHEAST ASIA
    // ============================================
    'grab': {
        keywords: ['grab account', 'grabpay', 'grab ride'],
        legitimateDomains: ['grab.com']
    },
    'shopee': {
        keywords: ['shopee order', 'shopee delivery', 'shopee account'],
        legitimateDomains: ['shopee.com', 'shopee.sg', 'shopee.co.id']
    },
    'lazada': {
        keywords: ['lazada order', 'lazada delivery', 'lazada account'],
        legitimateDomains: ['lazada.com', 'lazada.sg', 'lazada.co.id']
    },
    'gcash': {
        keywords: ['gcash account', 'gcash payment'],
        legitimateDomains: ['gcash.com']
    },
    // Hotels & Hospitality
    'marriott': { keywords: ['marriott', 'marriott bonvoy', 'marriott rewards'], legitimateDomains: ['marriott.com', 'marriottbonvoy.com', 'ritzcarlton.com', 'starwoodhotels.com'] },
    'hilton': { keywords: ['hilton hotel', 'hilton resort', 'hilton reservation', 'hilton honors', 'hilton garden'], legitimateDomains: ['hilton.com', 'hiltonhonors.com', 'hiltongrandvacations.com', 'hamptoninn.com'] },
    'ihg': { keywords: ['ihg', 'intercontinental', 'holiday inn', 'ihg rewards'], legitimateDomains: ['ihg.com', 'holidayinn.com', 'intercontinental.com', 'crowneplaza.com'] },
    'wyndham': { keywords: ['wyndham', 'wyndham rewards'], legitimateDomains: ['wyndham.com', 'wyndhamhotels.com', 'daysinn.com', 'super8.com', 'ramada.com'] },
    'best western': { keywords: ['best western', 'best western rewards'], legitimateDomains: ['bestwestern.com', 'bwhotels.com'] },
    'mgm resorts': { keywords: ['mgm resorts', 'mgm rewards', 'mgm grand'], legitimateDomains: ['mgmresorts.com', 'mgmgrand.com', 'bellagio.com', 'mandalaybay.com'] },
    'caesars': { keywords: ['caesars', 'caesars rewards', 'caesars palace'], legitimateDomains: ['caesars.com', 'caesarsrewards.com', 'harrahs.com'] },
    'accor': { keywords: ['accor', 'novotel', 'sofitel', 'ibis hotels'], legitimateDomains: ['accor.com', 'all.accor.com', 'novotel.com', 'sofitel.com'] },
    // Restaurants & Fast Food
    'mcdonalds': { keywords: ['mcdonalds', "mcdonald's"], legitimateDomains: ['mcdonalds.com', 'mcd.com'] },
    'starbucks': { keywords: ['starbucks', 'starbucks rewards'], legitimateDomains: ['starbucks.com'] },
    'chick-fil-a': { keywords: ['chick-fil-a', 'chick fil a', 'chickfila'], legitimateDomains: ['chick-fil-a.com', 'cfahome.com'] },
    'chipotle': { keywords: ['chipotle', 'chipotle rewards'], legitimateDomains: ['chipotle.com'] },
    'subway': { keywords: ['subway rewards'], legitimateDomains: ['subway.com'] },
    'dominos': { keywords: ['dominos', "domino's pizza"], legitimateDomains: ['dominos.com'] },
    'pizza hut': { keywords: ['pizza hut'], legitimateDomains: ['pizzahut.com'] },
    'taco bell': { keywords: ['taco bell'], legitimateDomains: ['tacobell.com'] },
    'wendys': { keywords: ['wendys', "wendy's"], legitimateDomains: ['wendys.com'] },
    'burger king': { keywords: ['burger king'], legitimateDomains: ['bk.com', 'burgerking.com'] },
    'dunkin': { keywords: ['dunkin', 'dunkin donuts'], legitimateDomains: ['dunkindonuts.com', 'dunkin.com'] },
    'panera': { keywords: ['panera', 'panera bread'], legitimateDomains: ['panerabread.com', 'panera.com'] },
    'popeyes': { keywords: ['popeyes'], legitimateDomains: ['popeyes.com'] },
    // Pharmacy & Healthcare
    'cvs': { keywords: ['cvs pharmacy', 'cvs health', 'cvs caremark'], legitimateDomains: ['cvs.com', 'cvshealth.com', 'cvscaremark.com'] },
    'walgreens': { keywords: ['walgreens', 'walgreens pharmacy'], legitimateDomains: ['walgreens.com'] },
    'rite aid': { keywords: ['rite aid'], legitimateDomains: ['riteaid.com'] },
    'labcorp': { keywords: ['labcorp', 'laboratory corporation'], legitimateDomains: ['labcorp.com'] },
    'quest diagnostics': { keywords: ['quest diagnostics'], legitimateDomains: ['questdiagnostics.com'] },
    // Grocery & Supermarkets
    'kroger': { keywords: ['kroger', 'kroger rewards'], legitimateDomains: ['kroger.com'] },
    'publix': { keywords: ['publix'], legitimateDomains: ['publix.com'] },
    'safeway': { keywords: ['safeway'], legitimateDomains: ['safeway.com', 'albertsons.com'] },
    'aldi': { keywords: ['aldi finds', 'aldi store'], legitimateDomains: ['aldi.us', 'aldi.com', 'aldi.co.uk'] },
    'trader joes': { keywords: ['trader joes', "trader joe's"], legitimateDomains: ['traderjoes.com'] },
    'whole foods': { keywords: ['whole foods', 'whole foods market'], legitimateDomains: ['wholefoodsmarket.com', 'wholefoods.com'] },
    // Entertainment & Tickets
    'ticketmaster': { keywords: ['ticketmaster'], legitimateDomains: ['ticketmaster.com', 'livenation.com', 'ticketmaster.co.uk'] },
    'stubhub': { keywords: ['stubhub'], legitimateDomains: ['stubhub.com'] },
    'gamestop': { keywords: ['gamestop'], legitimateDomains: ['gamestop.com'] },
    'amc theatres': { keywords: ['amc theatres', 'amc theaters', 'amc stubs'], legitimateDomains: ['amctheatres.com'] },
    // Beauty & Personal Care
    'sephora': { keywords: ['sephora', 'sephora beauty'], legitimateDomains: ['sephora.com'] },
    'ulta': { keywords: ['ulta beauty'], legitimateDomains: ['ulta.com', 'ultabeauty.com'] },
    'bath and body works': { keywords: ['bath and body works', 'bath & body works'], legitimateDomains: ['bathandbodyworks.com'] },
    // Airlines (additional)
    'british airways': { keywords: ['british airways'], legitimateDomains: ['britishairways.com', 'ba.com'] },
    'air canada': { keywords: ['air canada', 'aeroplan'], legitimateDomains: ['aircanada.com', 'aeroplan.com'] },
    'qatar airways': { keywords: ['qatar airways'], legitimateDomains: ['qatarairways.com'] },
    'singapore airlines': { keywords: ['singapore airlines', 'krisflyer'], legitimateDomains: ['singaporeair.com'] },
    'etihad': { keywords: ['etihad airways'], legitimateDomains: ['etihad.com'] },
    'cathay pacific': { keywords: ['cathay pacific'], legitimateDomains: ['cathaypacific.com'] },
    'air france': { keywords: ['air france'], legitimateDomains: ['airfrance.com'] },
    'klm': { keywords: ['klm royal dutch'], legitimateDomains: ['klm.com'] },
    // Travel & Booking (additional)
    'priceline': { keywords: ['priceline'], legitimateDomains: ['priceline.com'] },
    'agoda': { keywords: ['agoda booking'], legitimateDomains: ['agoda.com'] },
    'trivago': { keywords: ['trivago hotel'], legitimateDomains: ['trivago.com'] },
    // Real Estate brokerages: DO NOT add here. Body-only detection generates constant
    // false positives because agents mention competitor brands in every email thread.
    // These brands belong in IMPERSONATION_TARGETS only (display-name impersonation).
    // Tech/SaaS (additional)
    'servicenow': { keywords: ['servicenow'], legitimateDomains: ['servicenow.com'] },
    'workday': { keywords: ['workday'], legitimateDomains: ['workday.com', 'myworkday.com'] },
    // Telecom (additional)
    'frontier communications': { keywords: ['frontier communications', 'frontier fiber'], legitimateDomains: ['frontier.com', 'frontiernet.net'] },
    // ADDITIONAL GLOBAL
    'glovo': { keywords: ['glovo'], legitimateDomains: ['glovoapp.com'] },
    'wolt': { keywords: ['wolt'], legitimateDomains: ['wolt.com'] },
    'allegro': { keywords: ['allegro'], legitimateDomains: ['allegro.pl'] },
    'ozon': { keywords: ['ozon'], legitimateDomains: ['ozon.ru'] },
    'wildberries': { keywords: ['wildberries'], legitimateDomains: ['wildberries.ru'] },
    'yandex market': { keywords: ['yandex'], legitimateDomains: ['yandex.com', 'yandex.ru'] },
    'jumia': { keywords: ['jumia'], legitimateDomains: ['jumia.com'] },
    'mercado pago': { keywords: ['mercado pago'], legitimateDomains: ['mercadopago.com'] },
    'rappi': { keywords: ['rappi'], legitimateDomains: ['rappi.com'] },
    'norwegian air': { keywords: ['norwegian air'], legitimateDomains: ['norwegian.com'] },
    'finnair': { keywords: ['finnair'], legitimateDomains: ['finnair.com'] },
    'sas airlines': { keywords: ['sas', 'scandinavian airlines'], legitimateDomains: ['sas.se', 'flysas.com'] },
    'turkish airlines': { keywords: ['turkish airlines'], legitimateDomains: ['turkishairlines.com'] },
    'swiss air': { keywords: ['swiss air', 'swiss international'], legitimateDomains: ['swiss.com'] },
    'lufthansa': { keywords: ['lufthansa'], legitimateDomains: ['lufthansa.com'] },
    'garuda indonesia': { keywords: ['garuda indonesia'], legitimateDomains: ['garuda-indonesia.com'] },
    'thai airways': { keywords: ['thai airways'], legitimateDomains: ['thaiairways.com'] },
    'korean air': { keywords: ['korean air'], legitimateDomains: ['koreanair.com'] },
    'asiana airlines': { keywords: ['asiana airlines'], legitimateDomains: ['flyasiana.com'] },
    'eva air': { keywords: ['eva air'], legitimateDomains: ['evaair.com'] },
    'jetblue': { keywords: ['jetblue'], legitimateDomains: ['jetblue.com'] },
    'spirit airlines': { keywords: ['spirit airlines'], legitimateDomains: ['spirit.com'] },
    'frontier airlines': { keywords: ['frontier airlines'], legitimateDomains: ['flyfrontier.com'] },
    'alaska airlines': { keywords: ['alaska airlines'], legitimateDomains: ['alaskaair.com'] },
    'hawaiian airlines': { keywords: ['hawaiian airlines'], legitimateDomains: ['hawaiianairlines.com'] },
    'air new zealand': { keywords: ['air new zealand'], legitimateDomains: ['airnewzealand.com', 'airnewzealand.co.nz'] },
    'malaysia airlines': { keywords: ['malaysia airlines'], legitimateDomains: ['malaysiaairlines.com'] },
    'philippine airlines': { keywords: ['philippine airlines'], legitimateDomains: ['philippineairlines.com'] },
    'cebu pacific': { keywords: ['cebu pacific'], legitimateDomains: ['cebupacificair.com'] },
    'scoot': { keywords: ['scoot airlines'], legitimateDomains: ['flyscoot.com'] },
    'airasia': { keywords: ['airasia'], legitimateDomains: ['airasia.com'] },
    'china airlines': { keywords: ['china airlines'], legitimateDomains: ['china-airlines.com'] },
    'south african airways': { keywords: ['south african airways'], legitimateDomains: ['flysaa.com'] },
    'kenya airways': { keywords: ['kenya airways'], legitimateDomains: ['kenya-airways.com'] },
    'ethiopian airlines': { keywords: ['ethiopian airlines'], legitimateDomains: ['ethiopianairlines.com'] },
    'egypt air': { keywords: ['egyptair'], legitimateDomains: ['egyptair.com'] },
    'royal jordanian': { keywords: ['royal jordanian'], legitimateDomains: ['rj.com'] },
    'saudia airlines': { keywords: ['saudia', 'saudi arabian airlines'], legitimateDomains: ['saudia.com'] },
    // AUSTRALIA ASX
    'woolworths au': { keywords: ['woolworths'], legitimateDomains: ['woolworths.com.au'] },
    'coles': { keywords: ['coles'], legitimateDomains: ['coles.com.au'] },
    'jb hi fi': { keywords: ['jb hi-fi', 'jb hifi'], legitimateDomains: ['jbhifi.com.au'] },
    'harvey norman': { keywords: ['harvey norman'], legitimateDomains: ['harveynorman.com.au', 'harveynorman.com'] },
    'bunnings': { keywords: ['bunnings'], legitimateDomains: ['bunnings.com.au'] },
    'kmart au': { keywords: ['kmart'], legitimateDomains: ['kmart.com.au'] },
    'qantas': { keywords: ['qantas'], legitimateDomains: ['qantas.com', 'qantas.com.au'] },
    'virgin australia': { keywords: ['virgin australia'], legitimateDomains: ['virginaustralia.com'] },
    'seek': { keywords: ['seek jobs'], legitimateDomains: ['seek.com.au'] },
    'rea group': { keywords: ['realestate.com.au'], legitimateDomains: ['realestate.com.au', 'rea-group.com'] },
    'commbank': { keywords: ['commbank'], legitimateDomains: ['commbank.com.au'] },
    'ampol': { keywords: ['ampol'], legitimateDomains: ['ampol.com.au'] },
    'chemist warehouse': { keywords: ['chemist warehouse'], legitimateDomains: ['chemistwarehouse.com.au'] },
    'dan murphys': { keywords: ['dan murphy\'s', 'dan murphys'], legitimateDomains: ['danmurphys.com.au'] },
    'officeworks': { keywords: ['officeworks'], legitimateDomains: ['officeworks.com.au'] },
    'big w': { keywords: ['big w'], legitimateDomains: ['bigw.com.au'] },
    'myer': { keywords: ['myer'], legitimateDomains: ['myer.com.au'] },
    'david jones': { keywords: ['david jones'], legitimateDomains: ['davidjones.com'] },
    'anz': { keywords: ['anz'], legitimateDomains: ['anz.com.au', 'anz.com'] },
    // BRAZIL B3
    'magazine luiza': { keywords: ['magazine luiza', 'magalu'], legitimateDomains: ['magazineluiza.com.br'] },
    'americanas': { keywords: ['americanas'], legitimateDomains: ['americanas.com.br'] },
    'ifood': { keywords: ['ifood'], legitimateDomains: ['ifood.com.br'] },
    'totvs': { keywords: ['totvs'], legitimateDomains: ['totvs.com'] },
    'petrobras': { keywords: ['petrobras'], legitimateDomains: ['petrobras.com.br'] },
    'localiza': { keywords: ['localiza'], legitimateDomains: ['localiza.com'] },
    'azul airlines': { keywords: ['azul airlines', 'azul'], legitimateDomains: ['voeazul.com.br'] },
    'gol airlines': { keywords: ['gol airlines', 'gol'], legitimateDomains: ['voegol.com.br'] },
    'latam airlines': { keywords: ['latam airlines', 'latam'], legitimateDomains: ['latam.com'] },
    // CANADA TSX
    'tim hortons': { keywords: ['tim hortons'], legitimateDomains: ['timhortons.ca', 'timhortons.com'] },
    'canadian tire': { keywords: ['canadian tire'], legitimateDomains: ['canadiantire.ca'] },
    'loblaws': { keywords: ['loblaws', 'loblaw'], legitimateDomains: ['loblaws.ca'] },
    'shoppers drug mart': { keywords: ['shoppers drug mart'], legitimateDomains: ['shoppersdrugmart.ca'] },
    'metro inc': { keywords: ['metro groceries'], legitimateDomains: ['metro.ca'] },
    'rogers': { keywords: ['rogers'], legitimateDomains: ['rogers.com'] },
    'bell canada': { keywords: ['bell canada', 'bell mobility'], legitimateDomains: ['bell.ca'] },
    'telus': { keywords: ['telus'], legitimateDomains: ['telus.com'] },
    'manulife': { keywords: ['manulife'], legitimateDomains: ['manulife.com', 'manulife.ca'] },
    'sun life': { keywords: ['sun life'], legitimateDomains: ['sunlife.com', 'sunlife.ca'] },
    'westjet': { keywords: ['westjet'], legitimateDomains: ['westjet.com'] },
    'roots': { keywords: ['roots canada'], legitimateDomains: ['roots.com'] },
    'hudson bay': { keywords: ['hudson\'s bay', 'hudsons bay', 'the bay'], legitimateDomains: ['thebay.com'] },
    // CHINA CONSUMER
    'alibaba': { keywords: ['alibaba', 'aliexpress', 'taobao', 'tmall'], legitimateDomains: ['alibaba.com', 'aliexpress.com'] },
    'tencent': { keywords: ['tencent', 'wechat'], legitimateDomains: ['tencent.com', 'wechat.com'] },
    'jd.com': { keywords: ['jd.com'], legitimateDomains: ['jd.com'] },
    'pinduoduo': { keywords: ['pinduoduo'], legitimateDomains: ['pinduoduo.com'] },
    'baidu': { keywords: ['baidu'], legitimateDomains: ['baidu.com'] },
    'xiaomi': { keywords: ['xiaomi'], legitimateDomains: ['xiaomi.com', 'mi.com'] },
    'huawei': { keywords: ['huawei'], legitimateDomains: ['huawei.com', 'consumer.huawei.com'] },
    'oppo': { keywords: ['oppo'], legitimateDomains: ['oppo.com'] },
    'vivo': { keywords: ['vivo mobile'], legitimateDomains: ['vivo.com'] },
    'bilibili': { keywords: ['bilibili'], legitimateDomains: ['bilibili.com'] },
    'didi': { keywords: ['didi'], legitimateDomains: ['didiglobal.com'] },
    'meituan': { keywords: ['meituan'], legitimateDomains: ['meituan.com'] },
    'trip.com': { keywords: ['trip.com', 'ctrip'], legitimateDomains: ['trip.com', 'ctrip.com'] },
    'china southern airlines': { keywords: ['china southern'], legitimateDomains: ['csair.com'] },
    'china eastern airlines': { keywords: ['china eastern'], legitimateDomains: ['ceair.com'] },
    'air china': { keywords: ['air china'], legitimateDomains: ['airchina.com'] },
    // FRANCE CAC40
    'lvmh': { keywords: ['lvmh', 'louis vuitton', 'dior', 'sephora', 'tiffany'], legitimateDomains: ['lvmh.com', 'louisvuitton.com', 'dior.com', 'tiffany.com'] },
    'kering': { keywords: ['kering', 'gucci', 'balenciaga', 'yves saint laurent'], legitimateDomains: ['kering.com', 'gucci.com'] },
    'hermes': { keywords: ['hermès', 'hermes'], legitimateDomains: ['hermes.com'] },
    'loreal': { keywords: ['l\'oreal', 'loreal', 'l\'oréal'], legitimateDomains: ['loreal.com'] },
    'carrefour': { keywords: ['carrefour'], legitimateDomains: ['carrefour.com', 'carrefour.fr'] },
    'danone': { keywords: ['danone'], legitimateDomains: ['danone.com'] },
    'renault': { keywords: ['renault'], legitimateDomains: ['renault.com', 'renault.fr'] },
    'societe generale': { keywords: ['societe generale', 'société générale'], legitimateDomains: ['societegenerale.com', 'societegenerale.fr'] },
    'total energies': { keywords: ['totalenergies'], legitimateDomains: ['totalenergies.com'] },
    'axa': { keywords: ['axa'], legitimateDomains: ['axa.com', 'axa.fr'] },
    'decathlon': { keywords: ['decathlon'], legitimateDomains: ['decathlon.com', 'decathlon.fr'] },
    'bouygues telecom': { keywords: ['bouygues telecom', 'bouygues'], legitimateDomains: ['bouyguestelecom.fr'] },
    'free mobile': { keywords: ['free mobile'], legitimateDomains: ['free.fr'] },
    'sfr': { keywords: ['sfr'], legitimateDomains: ['sfr.fr'] },
    // GERMANY DAX
    'adidas': { keywords: ['adidas'], legitimateDomains: ['adidas.com', 'adidas.de'] },
    'siemens': { keywords: ['siemens'], legitimateDomains: ['siemens.com'] },
    'allianz': { keywords: ['allianz'], legitimateDomains: ['allianz.com', 'allianz.de'] },
    'zalando': { keywords: ['zalando'], legitimateDomains: ['zalando.com', 'zalando.de'] },
    'delivery hero': { keywords: ['delivery hero'], legitimateDomains: ['deliveryhero.com'] },
    'puma': { keywords: ['puma'], legitimateDomains: ['puma.com'] },
    'otto': { keywords: ['otto'], legitimateDomains: ['otto.de'] },
    'mediamarkt': { keywords: ['mediamarkt', 'media markt', 'saturn'], legitimateDomains: ['mediamarkt.de', 'saturn.de'] },
    // HONG KONG HKEX
    'aia': { keywords: ['aia insurance', 'aia'], legitimateDomains: ['aia.com'] },
    'mtr': { keywords: ['mtr corporation'], legitimateDomains: ['mtr.com.hk'] },
    'hang seng bank': { keywords: ['hang seng bank'], legitimateDomains: ['hangseng.com'] },
    'hk broadband': { keywords: ['hong kong broadband', 'hkbn'], legitimateDomains: ['hkbn.net'] },
    'clp holdings': { keywords: ['clp'], legitimateDomains: ['clp.com.hk'] },
    'hkt': { keywords: ['hkt', 'pccw'], legitimateDomains: ['hkt.com', 'pccw.com'] },
    // INDIA BSE NSE
    'tata motors': { keywords: ['tata motors'], legitimateDomains: ['tatamotors.com'] },
    'mahindra': { keywords: ['mahindra'], legitimateDomains: ['mahindra.com'] },
    'infosys': { keywords: ['infosys'], legitimateDomains: ['infosys.com'] },
    'tcs': { keywords: ['tata consultancy', 'tcs'], legitimateDomains: ['tcs.com'] },
    'zomato': { keywords: ['zomato'], legitimateDomains: ['zomato.com'] },
    'swiggy': { keywords: ['swiggy'], legitimateDomains: ['swiggy.com'] },
    'flipkart': { keywords: ['flipkart'], legitimateDomains: ['flipkart.com'] },
    'reliance': { keywords: ['reliance', 'reliance retail', 'reliance jio'], legitimateDomains: ['reliability.com', 'ril.com'] },
    'bajaj finserv': { keywords: ['bajaj finserv', 'bajaj finance'], legitimateDomains: ['bajajfinserv.in'] },
    'kotak': { keywords: ['kotak mahindra', 'kotak bank'], legitimateDomains: ['kotak.com'] },
    'axis bank': { keywords: ['axis bank'], legitimateDomains: ['axisbank.com'] },
    'myntra': { keywords: ['myntra'], legitimateDomains: ['myntra.com'] },
    'nykaa': { keywords: ['nykaa'], legitimateDomains: ['nykaa.com'] },
    'ola': { keywords: ['ola cabs', 'ola'], legitimateDomains: ['olacabs.com'] },
    'indigo airlines': { keywords: ['indigo', 'indigo airlines'], legitimateDomains: ['goindigo.in'] },
    'air india': { keywords: ['air india'], legitimateDomains: ['airindia.com'] },
    'irctc': { keywords: ['irctc'], legitimateDomains: ['irctc.co.in'] },
    // ITALY BORSA
    'ferrari': { keywords: ['ferrari'], legitimateDomains: ['ferrari.com'] },
    'enel': { keywords: ['enel'], legitimateDomains: ['enel.com', 'enel.it'] },
    'eni': { keywords: ['eni'], legitimateDomains: ['eni.com'] },
    'intesa sanpaolo': { keywords: ['intesa sanpaolo'], legitimateDomains: ['intesasanpaolo.com'] },
    'unicredit': { keywords: ['unicredit'], legitimateDomains: ['unicredit.it', 'unicredit.eu'] },
    'wind tre': { keywords: ['wind tre', 'windtre'], legitimateDomains: ['windtre.it'] },
    // JAPAN NIKKEI
    'sony': { keywords: ['sony', 'playstation'], legitimateDomains: ['sony.com', 'playstation.com'] },
    'nintendo': { keywords: ['nintendo'], legitimateDomains: ['nintendo.com', 'nintendo.co.jp'] },
    'panasonic': { keywords: ['panasonic'], legitimateDomains: ['panasonic.com', 'panasonic.jp'] },
    'hitachi': { keywords: ['hitachi'], legitimateDomains: ['hitachi.com'] },
    'toshiba': { keywords: ['toshiba'], legitimateDomains: ['toshiba.com', 'toshiba.co.jp'] },
    'sharp': { keywords: ['sharp'], legitimateDomains: ['sharp.com', 'sharp.co.jp'] },
    'canon': { keywords: ['canon'], legitimateDomains: ['canon.com', 'canon.co.jp'] },
    'nikon': { keywords: ['nikon'], legitimateDomains: ['nikon.com'] },
    'uniqlo': { keywords: ['uniqlo', 'fast retailing'], legitimateDomains: ['uniqlo.com'] },
    'muji': { keywords: ['muji'], legitimateDomains: ['muji.com', 'muji.net'] },
    'japan airlines': { keywords: ['japan airlines', 'jal'], legitimateDomains: ['jal.com', 'jal.co.jp'] },
    'ana': { keywords: ['all nippon airways', 'ana airlines'], legitimateDomains: ['ana.co.jp'] },
    'seven eleven jp': { keywords: ['7-eleven', 'seven eleven'], legitimateDomains: ['7-eleven.com', 'sej.co.jp'] },
    'lawson': { keywords: ['lawson'], legitimateDomains: ['lawson.co.jp'] },
    'familymart': { keywords: ['familymart', 'family mart'], legitimateDomains: ['family.co.jp'] },
    'daiso': { keywords: ['daiso'], legitimateDomains: ['daisoglobal.com', 'daiso-sangyo.co.jp'] },
    // MEXICO BMV
    'america movil': { keywords: ['america movil', 'telcel'], legitimateDomains: ['americamovil.com', 'telcel.com'] },
    'liverpool': { keywords: ['liverpool mexico'], legitimateDomains: ['liverpool.com.mx'] },
    'elektra': { keywords: ['elektra'], legitimateDomains: ['elektra.com.mx'] },
    'volaris': { keywords: ['volaris'], legitimateDomains: ['volaris.com'] },
    'aeromexico': { keywords: ['aeromexico'], legitimateDomains: ['aeromexico.com'] },
    // MIDDLE EAST
    'stc saudi': { keywords: ['stc', 'saudi telecom'], legitimateDomains: ['stc.com.sa'] },
    'al rajhi bank': { keywords: ['al rajhi', 'alrajhi'], legitimateDomains: ['alrajhibank.com.sa'] },
    'emirates airline': { keywords: ['emirates'], legitimateDomains: ['emirates.com'] },
    'etisalat': { keywords: ['etisalat'], legitimateDomains: ['etisalat.ae'] },
    'du telecom': { keywords: ['du telecom'], legitimateDomains: ['du.ae'] },
    'qatar national bank': { keywords: ['qnb'], legitimateDomains: ['qnb.com'] },
    'jarir': { keywords: ['jarir'], legitimateDomains: ['jarir.com'] },
    'noon': { keywords: ['noon'], legitimateDomains: ['noon.com'] },
    'careem': { keywords: ['careem'], legitimateDomains: ['careem.com'] },
    // NETHERLANDS EURONEXT
    'philips': { keywords: ['philips'], legitimateDomains: ['philips.com'] },
    'shell': { keywords: ['shell'], legitimateDomains: ['shell.com'] },
    'heineken': { keywords: ['heineken'], legitimateDomains: ['heineken.com'] },
    'kpn': { keywords: ['kpn'], legitimateDomains: ['kpn.com'] },
    'bol.com': { keywords: ['bol.com'], legitimateDomains: ['bol.com'] },
    'coolblue': { keywords: ['coolblue'], legitimateDomains: ['coolblue.nl', 'coolblue.be'] },
    // SINGAPORE SGX
    'dbs bank': { keywords: ['dbs bank', 'dbs'], legitimateDomains: ['dbs.com', 'dbs.com.sg'] },
    'ocbc bank': { keywords: ['ocbc'], legitimateDomains: ['ocbc.com'] },
    'uob bank': { keywords: ['uob'], legitimateDomains: ['uob.com.sg'] },
    'singtel': { keywords: ['singtel'], legitimateDomains: ['singtel.com'] },
    'starhub': { keywords: ['starhub'], legitimateDomains: ['starhub.com'] },
    'foodpanda': { keywords: ['foodpanda'], legitimateDomains: ['foodpanda.com'] },
    // SOUTHEAST ASIA
    'tokopedia': { keywords: ['tokopedia'], legitimateDomains: ['tokopedia.com'] },
    'gojek': { keywords: ['gojek'], legitimateDomains: ['gojek.com'] },
    'bca bank': { keywords: ['bca', 'bank central asia'], legitimateDomains: ['bca.co.id'] },
    'mandiri bank': { keywords: ['mandiri'], legitimateDomains: ['bankmandiri.co.id'] },
    'telkomsel': { keywords: ['telkomsel'], legitimateDomains: ['telkomsel.com'] },
    'ais thailand': { keywords: ['ais'], legitimateDomains: ['ais.th'] },
    'true corp': { keywords: ['true corp', 'truemove'], legitimateDomains: ['true.th'] },
    'dtac': { keywords: ['dtac'], legitimateDomains: ['dtac.co.th'] },
    'globe telecom': { keywords: ['globe telecom'], legitimateDomains: ['globe.com.ph'] },
    'smart communications': { keywords: ['smart communications'], legitimateDomains: ['smart.com.ph'] },
    'maybank': { keywords: ['maybank'], legitimateDomains: ['maybank.com', 'maybank2u.com.my'] },
    'cimb bank': { keywords: ['cimb'], legitimateDomains: ['cimb.com'] },
    'petronas': { keywords: ['petronas'], legitimateDomains: ['petronas.com'] },
    // SOUTH AFRICA JSE
    'shoprite': { keywords: ['shoprite', 'checkers'], legitimateDomains: ['shoprite.co.za'] },
    'woolworths sa': { keywords: ['woolworths'], legitimateDomains: ['woolworths.co.za'] },
    'pick n pay': { keywords: ['pick n pay'], legitimateDomains: ['pnp.co.za'] },
    'capitec bank': { keywords: ['capitec'], legitimateDomains: ['capitecbank.co.za'] },
    'fnb': { keywords: ['fnb', 'first national bank'], legitimateDomains: ['fnb.co.za'] },
    'nedbank': { keywords: ['nedbank'], legitimateDomains: ['nedbank.co.za'] },
    'discovery sa': { keywords: ['discovery health'], legitimateDomains: ['discovery.co.za'] },
    'mtn': { keywords: ['mtn'], legitimateDomains: ['mtn.com', 'mtn.co.za'] },
    'vodacom': { keywords: ['vodacom'], legitimateDomains: ['vodacom.co.za'] },
    'takealot': { keywords: ['takealot'], legitimateDomains: ['takealot.com'] },
    'standard bank': { keywords: ['standard bank'], legitimateDomains: ['standardbank.co.za'] },
    'absa bank': { keywords: ['absa'], legitimateDomains: ['absa.co.za'] },
    // SOUTH KOREA KRX
    'samsung': { keywords: ['samsung'], legitimateDomains: ['samsung.com'] },
    'lg': { keywords: ['lg electronics', 'lg'], legitimateDomains: ['lg.com'] },
    'sk telecom': { keywords: ['sk telecom', 'skt'], legitimateDomains: ['sktelecom.com', 'tworld.co.kr'] },
    'kt corp': { keywords: ['kt corp', 'kt telecom'], legitimateDomains: ['kt.com'] },
    'kakao': { keywords: ['kakao', 'kakaotalk'], legitimateDomains: ['kakao.com', 'kakaocorp.com'] },
    'lotte': { keywords: ['lotte'], legitimateDomains: ['lotte.co.kr', 'lotteshopping.com'] },
    'shinsegae': { keywords: ['shinsegae', 'emart'], legitimateDomains: ['shinsegae.com', 'emart.com'] },
    'gmarket': { keywords: ['gmarket'], legitimateDomains: ['gmarket.co.kr'] },
    '11st': { keywords: ['11st', '11street'], legitimateDomains: ['11st.co.kr'] },
    // SPAIN BME
    'zara': { keywords: ['zara', 'inditex'], legitimateDomains: ['zara.com', 'inditex.com'] },
    'bbva': { keywords: ['bbva'], legitimateDomains: ['bbva.com', 'bbva.es'] },
    'telefonica': { keywords: ['telefonica', 'movistar'], legitimateDomains: ['telefonica.com', 'movistar.com', 'movistar.es'] },
    'el corte ingles': { keywords: ['el corte inglés', 'el corte ingles'], legitimateDomains: ['elcorteingles.es'] },
    'iberia': { keywords: ['iberia airlines', 'iberia'], legitimateDomains: ['iberia.com'] },
    'caixabank': { keywords: ['caixabank'], legitimateDomains: ['caixabank.com', 'caixabank.es'] },
    // SWEDEN
    'hm': { keywords: ['h&m'], legitimateDomains: ['hm.com'] },
    'ericsson': { keywords: ['ericsson'], legitimateDomains: ['ericsson.com'] },
    'telia': { keywords: ['telia'], legitimateDomains: ['telia.com', 'telia.se'] },
    // SWITZERLAND
    'nestle': { keywords: ['nestlé', 'nestle', 'nespresso', 'nescafe', 'readyrefresh'], legitimateDomains: ['nestle.com', 'nespresso.com', 'nescafe.com', 'readyrefresh.com'] },
    'ubs': { keywords: ['ubs'], legitimateDomains: ['ubs.com'] },
    'zurich insurance': { keywords: ['zurich insurance', 'zurich'], legitimateDomains: ['zurich.com'] },
    'swiss post': { keywords: ['swiss post'], legitimateDomains: ['post.ch'] },
    'swisslife': { keywords: ['swiss life'], legitimateDomains: ['swisslife.com'] },
    // UK FTSE
    'tesco': { keywords: ['tesco', 'tesco clubcard'], legitimateDomains: ['tesco.com', 'tesco.co.uk'] },
    'sainsburys': { keywords: ['sainsbury\'s', 'sainsburys'], legitimateDomains: ['sainsburys.co.uk'] },
    'marks and spencer': { keywords: ['marks & spencer', 'marks and spencer', 'm&s'], legitimateDomains: ['marksandspencer.com'] },
    'next': { keywords: ['next.co.uk', 'next direct', 'next delivery', 'next order', 'next account', 'next returns', 'next tracking', 'next unlimited', 'nextdirect'], legitimateDomains: ['next.co.uk'] },
    'jd sports': { keywords: ['jd sports'], legitimateDomains: ['jdsports.co.uk', 'jdsports.com'] },
    'primark': { keywords: ['primark'], legitimateDomains: ['primark.com'] },
    'boots': { keywords: ['boots pharmacy', 'boots'], legitimateDomains: ['boots.com'] },
    'greggs': { keywords: ['greggs'], legitimateDomains: ['greggs.co.uk'] },
    'premier inn': { keywords: ['premier inn', 'whitbread'], legitimateDomains: ['premierinn.com'] },
    'easyjet': { keywords: ['easyjet'], legitimateDomains: ['easyjet.com'] },
    'ryanair': { keywords: ['ryanair'], legitimateDomains: ['ryanair.com'] },
    'british gas': { keywords: ['british gas', 'centrica'], legitimateDomains: ['britishgas.co.uk'] },
    'sse': { keywords: ['sse energy'], legitimateDomains: ['sse.co.uk'] },
    'just eat': { keywords: ['just eat'], legitimateDomains: ['just-eat.co.uk', 'just-eat.com'] },
    'ocado': { keywords: ['ocado'], legitimateDomains: ['ocado.com'] },
    'asos': { keywords: ['asos'], legitimateDomains: ['asos.com'] },
    'boohoo': { keywords: ['boohoo'], legitimateDomains: ['boohoo.com'] },
    'rightmove': { keywords: ['rightmove'], legitimateDomains: ['rightmove.co.uk'] },
    'auto trader uk': { keywords: ['auto trader'], legitimateDomains: ['autotrader.co.uk'] },
    'deliveroo': { keywords: ['deliveroo'], legitimateDomains: ['deliveroo.co.uk', 'deliveroo.com'] },
    'morrisons': { keywords: ['morrisons'], legitimateDomains: ['morrisons.com'] },
    'currys': { keywords: ['currys'], legitimateDomains: ['currys.co.uk'] },
    'argos': { keywords: ['argos'], legitimateDomains: ['argos.co.uk'] },
    'john lewis': { keywords: ['john lewis'], legitimateDomains: ['johnlewis.com'] },
    'waitrose': { keywords: ['waitrose'], legitimateDomains: ['waitrose.com'] },
    'screwfix': { keywords: ['screwfix'], legitimateDomains: ['screwfix.com'] },
    'halfords': { keywords: ['halfords'], legitimateDomains: ['halfords.com'] },
    'sky': { keywords: ['sky tv'], legitimateDomains: ['sky.com'] },
    'three mobile': { keywords: ['three mobile', 'three uk'], legitimateDomains: ['three.co.uk'] },
    'ee': { keywords: ['ee mobile'], legitimateDomains: ['ee.co.uk'] },
    'virgin media': { keywords: ['virgin media'], legitimateDomains: ['virginmedia.com'] },
    'virgin atlantic': { keywords: ['virgin atlantic'], legitimateDomains: ['virginatlantic.com'] },
    'wh smith': { keywords: ['wh smith', 'whsmith'], legitimateDomains: ['whsmith.co.uk'] },
    'pret a manger': { keywords: ['pret a manger', 'pret'], legitimateDomains: ['pret.co.uk', 'pret.com'] },
    'nandos': { keywords: ['nando\'s', 'nandos'], legitimateDomains: ['nandos.co.uk', 'nandos.com'] },
    'asda': { keywords: ['asda'], legitimateDomains: ['asda.com'] },
    'iceland': { keywords: ['iceland foods'], legitimateDomains: ['iceland.co.uk'] },
    'lidl': { keywords: ['lidl'], legitimateDomains: ['lidl.co.uk', 'lidl.com', 'lidl.de'] },
    'superdry': { keywords: ['superdry'], legitimateDomains: ['superdry.com'] },
    'river island': { keywords: ['river island'], legitimateDomains: ['riverisland.com'] },
    'topshop': { keywords: ['topshop'], legitimateDomains: ['topshop.com'] },
    'sportsdirect': { keywords: ['sports direct'], legitimateDomains: ['sportsdirect.com'] },
    'the body shop': { keywords: ['the body shop'], legitimateDomains: ['thebodyshop.com'] },
    // US AUTO
    'tesla': { keywords: ['tesla'], legitimateDomains: ['tesla.com'] },
    'ford': { keywords: ['ford motor', 'ford'], legitimateDomains: ['ford.com'] },
    'gm': { keywords: ['general motors', 'chevrolet', 'chevy', 'buick', 'cadillac', 'gmc'], legitimateDomains: ['gm.com', 'chevrolet.com', 'buick.com', 'cadillac.com', 'gmc.com'] },
    'toyota': { keywords: ['toyota', 'lexus'], legitimateDomains: ['toyota.com', 'lexus.com'] },
    'honda': { keywords: ['honda', 'acura'], legitimateDomains: ['honda.com', 'acura.com'] },
    'hyundai': { keywords: ['hyundai'], legitimateDomains: ['hyundai.com', 'hyundaiusa.com'] },
    'kia': { keywords: ['kia'], legitimateDomains: ['kia.com'] },
    'nissan': { keywords: ['nissan', 'infiniti'], legitimateDomains: ['nissanusa.com', 'infiniti.com', 'nissan.com'] },
    'subaru': { keywords: ['subaru'], legitimateDomains: ['subaru.com'] },
    'mazda': { keywords: ['mazda'], legitimateDomains: ['mazda.com', 'mazdausa.com'] },
    'bmw': { keywords: ['bmw'], legitimateDomains: ['bmw.com', 'bmwusa.com'] },
    'mercedes benz': { keywords: ['mercedes-benz', 'mercedes benz'], legitimateDomains: ['mercedes-benz.com', 'mbusa.com'] },
    'volkswagen': { keywords: ['volkswagen', 'vw'], legitimateDomains: ['volkswagen.com', 'vw.com'] },
    'audi': { keywords: ['audi'], legitimateDomains: ['audi.com', 'audiusa.com'] },
    'volvo': { keywords: ['volvo'], legitimateDomains: ['volvo.com', 'volvocars.com'] },
    'rivian': { keywords: ['rivian'], legitimateDomains: ['rivian.com'] },
    'lucid motors': { keywords: ['lucid motors', 'lucid'], legitimateDomains: ['lucidmotors.com'] },
    'stellantis': { keywords: ['stellantis', 'chrysler', 'ram truck', 'ram 1500', 'ram 2500', 'ram 3500', 'ram pickup', 'dodge charger', 'dodge challenger', 'dodge durango', 'jeep wrangler', 'jeep cherokee', 'jeep grand cherokee', 'jeep gladiator'], legitimateDomains: ['stellantis.com', 'jeep.com', 'chrysler.com', 'dodge.com', 'ramtrucks.com'] },
    // US FINANCIAL
    'goldman sachs': { keywords: ['goldman sachs'], legitimateDomains: ['goldmansachs.com', 'gs.com'] },
    'merrill lynch': { keywords: ['merrill lynch', 'merrill'], legitimateDomains: ['ml.com', 'merrilledge.com'] },
    'edward jones': { keywords: ['edward jones'], legitimateDomains: ['edwardjones.com'] },
    'raymond james': { keywords: ['raymond james'], legitimateDomains: ['raymondjames.com'] },
    'etrade': { keywords: ['e*trade', 'etrade'], legitimateDomains: ['etrade.com'] },
    'td ameritrade': { keywords: ['td ameritrade'], legitimateDomains: ['tdameritrade.com'] },
    'lendingclub': { keywords: ['lendingclub', 'lending club'], legitimateDomains: ['lendingclub.com'] },
    'rocket mortgage': { keywords: ['rocket mortgage', 'quicken loans', 'rocket companies'], legitimateDomains: ['rocketmortgage.com', 'quickenloans.com', 'rocketcompanies.com'] },
    'credit karma': { keywords: ['credit karma'], legitimateDomains: ['creditkarma.com'] },
    'nerdwallet': { keywords: ['nerdwallet'], legitimateDomains: ['nerdwallet.com'] },
    'marcus by goldman': { keywords: ['marcus by goldman', 'marcus savings'], legitimateDomains: ['marcus.com'] },
    'wealthfront': { keywords: ['wealthfront'], legitimateDomains: ['wealthfront.com'] },
    'betterment': { keywords: ['betterment'], legitimateDomains: ['betterment.com'] },
    'lemonade insurance': { keywords: ['lemonade'], legitimateDomains: ['lemonade.com'] },
    'root insurance': { keywords: ['root insurance'], legitimateDomains: ['joinroot.com'] },
    'oscar health': { keywords: ['oscar health'], legitimateDomains: ['hioscar.com'] },
    'discover financial': { keywords: ['discover card', 'discover financial', 'discover bank', 'discover secure message'], legitimateDomains: ['discover.com'] },
    // US FOOD BEVERAGE
    'coca cola': { keywords: ['coca-cola', 'coca cola', 'coke'], legitimateDomains: ['coca-cola.com', 'cocacola.com'] },
    'pepsi': { keywords: ['pepsi', 'pepsico'], legitimateDomains: ['pepsi.com', 'pepsico.com'] },
    'kfc': { keywords: ['kfc', 'kentucky fried chicken'], legitimateDomains: ['kfc.com'] },
    'olive garden': { keywords: ['olive garden', 'darden'], legitimateDomains: ['olivegarden.com', 'darden.com'] },
    'longhorn steakhouse': { keywords: ['longhorn steakhouse'], legitimateDomains: ['longhornsteakhouse.com'] },
    'red lobster': { keywords: ['red lobster'], legitimateDomains: ['redlobster.com'] },
    'applebees': { keywords: ['applebee\'s', 'applebees'], legitimateDomains: ['applebees.com'] },
    'ihop': { keywords: ['ihop'], legitimateDomains: ['ihop.com'] },
    'dennys': { keywords: ['denny\'s', 'dennys'], legitimateDomains: ['dennys.com'] },
    'jack in the box': { keywords: ['jack in the box'], legitimateDomains: ['jackinthebox.com'] },
    'sonic drive in': { keywords: ['sonic drive-in', 'sonic drive in'], legitimateDomains: ['sonicdrivein.com'] },
    'papa johns': { keywords: ['papa john\'s', 'papa johns'], legitimateDomains: ['papajohns.com'] },
    'little caesars': { keywords: ['little caesars', 'little caesar\'s'], legitimateDomains: ['littlecaesars.com'] },
    'wingstop': { keywords: ['wingstop'], legitimateDomains: ['wingstop.com'] },
    'shake shack': { keywords: ['shake shack'], legitimateDomains: ['shakeshack.com'] },
    'cracker barrel': { keywords: ['cracker barrel'], legitimateDomains: ['crackerbarrel.com'] },
    'dutch bros': { keywords: ['dutch bros'], legitimateDomains: ['dutchbros.com'] },
    'arbys': { keywords: ['arby\'s', 'arbys'], legitimateDomains: ['arbys.com'] },
    'buffalo wild wings': { keywords: ['buffalo wild wings'], legitimateDomains: ['buffalowildwings.com'] },
    'red robin': { keywords: ['red robin'], legitimateDomains: ['redrobin.com'] },
    'outback steakhouse': { keywords: ['outback steakhouse'], legitimateDomains: ['outback.com'] },
    'noodles and company': { keywords: ['noodles & company'], legitimateDomains: ['noodles.com'] },
    'five guys': { keywords: ['five guys'], legitimateDomains: ['fiveguys.com'] },
    'jersey mikes': { keywords: ['jersey mike\'s', 'jersey mikes'], legitimateDomains: ['jerseymikes.com'] },
    'jimmy johns': { keywords: ['jimmy john\'s', 'jimmy johns'], legitimateDomains: ['jimmyjohns.com'] },
    'panda express': { keywords: ['panda express'], legitimateDomains: ['pandaexpress.com'] },
    'hellofresh': { keywords: ['hellofresh', 'hello fresh'], legitimateDomains: ['hellofresh.com'] },
    'blue apron': { keywords: ['blue apron'], legitimateDomains: ['blueapron.com'] },
    // US HEALTH SERVICES
    'teladoc': { keywords: ['teladoc'], legitimateDomains: ['teladoc.com', 'teladochealth.com'] },
    'goodrx': { keywords: ['goodrx'], legitimateDomains: ['goodrx.com'] },
    'hims and hers': { keywords: ['hims', 'hers', 'hims & hers'], legitimateDomains: ['forhims.com', 'forhers.com'] },
    'zocdoc': { keywords: ['zocdoc'], legitimateDomains: ['zocdoc.com'] },
    'one medical': { keywords: ['one medical'], legitimateDomains: ['onemedical.com'] },
    'anthem': { keywords: ['anthem', 'elevance health'], legitimateDomains: ['anthem.com', 'elevancehealth.com'] },
    'centene': { keywords: ['centene', 'ambetter'], legitimateDomains: ['centene.com', 'ambetterhealth.com'] },
    'molina healthcare': { keywords: ['molina healthcare'], legitimateDomains: ['molinahealthcare.com'] },
    'wellcare': { keywords: ['wellcare'], legitimateDomains: ['wellcare.com'] },
    // US MEDIA ENTERTAINMENT
    'disney': { keywords: ['disney', 'walt disney', 'disneyland', 'disney world'], legitimateDomains: ['disney.com', 'disneyplus.com', 'go.com', 'disneyland.disney.go.com', 'disneyworld.disney.go.com', 'd23.com', 'thewaltdisneycompany.com', 'disneyonline.com'] },
    'hbo': { keywords: ['hbo', 'hbo max'], legitimateDomains: ['hbo.com', 'hbomax.com', 'max.com'] },
    'warner bros': { keywords: ['warner bros', 'warner brothers'], legitimateDomains: ['warnerbros.com', 'wbd.com'] },
    'peacock': { keywords: ['peacock tv', 'peacock streaming'], legitimateDomains: ['peacocktv.com'] },
    'paramount plus': { keywords: ['paramount+', 'paramount plus'], legitimateDomains: ['paramountplus.com', 'paramount.com'] },
    'espn': { keywords: ['espn'], legitimateDomains: ['espn.com'] },
    'twitch': { keywords: ['twitch'], legitimateDomains: ['twitch.tv'] },
    'audible': { keywords: ['audible'], legitimateDomains: ['audible.com'] },
    'kindle': { keywords: ['kindle unlimited'], legitimateDomains: ['amazon.com', 'kindle.com'] },
    'sirius xm': { keywords: ['siriusxm', 'sirius xm'], legitimateDomains: ['siriusxm.com'] },
    'discovery plus': { keywords: ['discovery+', 'discovery plus'], legitimateDomains: ['discoveryplus.com'] },
    'peloton': { keywords: ['peloton'], legitimateDomains: ['onepeloton.com'] },
    'planet fitness': { keywords: ['planet fitness'], legitimateDomains: ['planetfitness.com'] },
    '24 hour fitness': { keywords: ['24 hour fitness'], legitimateDomains: ['24hourfitness.com'] },
    // US RETAIL
    'gap': { keywords: ['gap', 'old navy', 'banana republic', 'athleta'], legitimateDomains: ['gap.com', 'oldnavy.com', 'bananarepublic.com', 'athleta.com'] },
    'lululemon': { keywords: ['lululemon'], legitimateDomains: ['lululemon.com'] },
    'under armour': { keywords: ['under armour', 'under armor'], legitimateDomains: ['underarmour.com'] },
    'tj maxx': { keywords: ['tj maxx', 'tjmaxx', 'marshalls', 'homegoods', 'tjx'], legitimateDomains: ['tjmaxx.com', 'tjx.com', 'marshalls.com', 'homegoods.com'] },
    'ross': { keywords: ['ross stores', 'ross dress for less'], legitimateDomains: ['rossstores.com'] },
    'burlington': { keywords: ['burlington'], legitimateDomains: ['burlington.com'] },
    'dollar general': { keywords: ['dollar general'], legitimateDomains: ['dollargeneral.com'] },
    'dollar tree': { keywords: ['dollar tree', 'family dollar'], legitimateDomains: ['dollartree.com', 'familydollar.com'] },
    'five below': { keywords: ['five below'], legitimateDomains: ['fivebelow.com'] },
    'dicks sporting goods': { keywords: ['dicks sporting goods', 'dick\'s sporting'], legitimateDomains: ['dickssportinggoods.com', 'dcsg.com', 'notifications.dcsg.com'] },
    'foot locker': { keywords: ['foot locker', 'footlocker'], legitimateDomains: ['footlocker.com'] },
    'victorias secret': { keywords: ['victoria\'s secret', 'victorias secret'], legitimateDomains: ['victoriassecret.com'] },
    'nordstrom': { keywords: ['nordstrom', 'nordstrom rack'], legitimateDomains: ['nordstrom.com', 'nordstromrack.com'] },
    'petco': { keywords: ['petco'], legitimateDomains: ['petco.com'] },
    'chewy': { keywords: ['chewy'], legitimateDomains: ['chewy.com'] },
    'williams sonoma': { keywords: ['williams sonoma', 'williams-sonoma', 'pottery barn', 'west elm'], legitimateDomains: ['williams-sonoma.com', 'potterybarn.com', 'westelm.com'] },
    'restoration hardware': { keywords: ['restoration hardware', 'rh'], legitimateDomains: ['rh.com', 'restorationhardware.com'] },
    'crate and barrel': { keywords: ['crate and barrel', 'crate & barrel', 'cb2'], legitimateDomains: ['crateandbarrel.com', 'cb2.com'] },
    'autozone': { keywords: ['autozone'], legitimateDomains: ['autozone.com'] },
    'oreilly auto': { keywords: ['o\'reilly auto', 'oreilly auto'], legitimateDomains: ['oreillyauto.com'] },
    'advance auto parts': { keywords: ['advance auto parts'], legitimateDomains: ['advanceautoparts.com'] },
    'tractor supply': { keywords: ['tractor supply'], legitimateDomains: ['tractorsupply.com'] },
    'carmax': { keywords: ['carmax'], legitimateDomains: ['carmax.com'] },
    'carvana': { keywords: ['carvana'], legitimateDomains: ['carvana.com'] },
    'bed bath': { keywords: ['bed bath'], legitimateDomains: ['bedbathandbeyond.com'] },
    'pier 1': { keywords: ['pier 1', 'pier one'], legitimateDomains: ['pier1.com'] },
    'office depot': { keywords: ['office depot', 'officemax'], legitimateDomains: ['officedepot.com'] },
    'staples': { keywords: ['staples'], legitimateDomains: ['staples.com'] },
    'big lots': { keywords: ['big lots'], legitimateDomains: ['biglots.com'] },
    'michaels': { keywords: ['michaels'], legitimateDomains: ['michaels.com'] },
    'hobby lobby': { keywords: ['hobby lobby'], legitimateDomains: ['hobbylobby.com'] },
    'ace hardware': { keywords: ['ace hardware'], legitimateDomains: ['acehardware.com'] },
    'menards': { keywords: ['menards'], legitimateDomains: ['menards.com'] },
    'overstock': { keywords: ['overstock'], legitimateDomains: ['overstock.com'] },
    'zappos': { keywords: ['zappos'], legitimateDomains: ['zappos.com'] },
    'wish': { keywords: ['wish'], legitimateDomains: ['wish.com'] },
    'temu': { keywords: ['temu'], legitimateDomains: ['temu.com'] },
    'shein': { keywords: ['shein'], legitimateDomains: ['shein.com', 'us.shein.com'] },
    'poshmark': { keywords: ['poshmark'], legitimateDomains: ['poshmark.com'] },
    // US SUBSCRIPTIONS
    'grammarly': { keywords: ['grammarly'], legitimateDomains: ['grammarly.com'] },
    'coursera': { keywords: ['coursera'], legitimateDomains: ['coursera.org'] },
    'udemy': { keywords: ['udemy'], legitimateDomains: ['udemy.com'] },
    'linkedin learning': { keywords: ['linkedin learning'], legitimateDomains: ['linkedin.com', 'learning.linkedin.com'] },
    'duolingo': { keywords: ['duolingo'], legitimateDomains: ['duolingo.com'] },
    'masterclass': { keywords: ['masterclass'], legitimateDomains: ['masterclass.com'] },
    'calm': { keywords: ['calm app'], legitimateDomains: ['calm.com'] },
    'headspace': { keywords: ['headspace'], legitimateDomains: ['headspace.com'] },
    'weight watchers': { keywords: ['weight watchers', 'weightwatchers', 'ww'], legitimateDomains: ['weightwatchers.com', 'ww.com'] },
    // US TECH ADDITIONAL
    'cloudflare': { keywords: ['cloudflare'], legitimateDomains: ['cloudflare.com'] },
    'twilio': { keywords: ['twilio'], legitimateDomains: ['twilio.com'] },
    'zendesk': { keywords: ['zendesk'], legitimateDomains: ['zendesk.com'] },
    'mailchimp': { keywords: ['mailchimp'], legitimateDomains: ['mailchimp.com'] },
    'squarespace': { keywords: ['squarespace'], legitimateDomains: ['squarespace.com'] },
    'shopify': { keywords: ['shopify'], legitimateDomains: ['shopify.com', 'myshopify.com'] },
    'wix': { keywords: ['wix'], legitimateDomains: ['wix.com'] },
    'godaddy': { keywords: ['godaddy'], legitimateDomains: ['godaddy.com'] },
    'github': { keywords: ['github'], legitimateDomains: ['github.com'] },
    'atlassian': { keywords: ['atlassian', 'jira', 'confluence'], legitimateDomains: ['atlassian.com', 'atlassian.net'] },
    'canva': { keywords: ['canva'], legitimateDomains: ['canva.com'] },
    'figma': { keywords: ['figma'], legitimateDomains: ['figma.com'] },
    'openai': { keywords: ['openai', 'chatgpt'], legitimateDomains: ['openai.com', 'chatgpt.com'] },
    'oracle': { keywords: ['oracle'], legitimateDomains: ['oracle.com'] },
    'sap': { keywords: ['sap'], legitimateDomains: ['sap.com'] },
    'intuit': { keywords: ['intuit'], legitimateDomains: ['intuit.com'] },
    'square': { keywords: ['square'], legitimateDomains: ['squareup.com', 'square.com'] },
    'toast': { keywords: ['toast pos', 'toast inc'], legitimateDomains: ['toasttab.com'] },
    // US TRAVEL
    'tripadvisor': { keywords: ['tripadvisor', 'trip advisor'], legitimateDomains: ['tripadvisor.com'] },
    'hotels.com': { keywords: ['hotels.com'], legitimateDomains: ['hotels.com'] },
    'vrbo': { keywords: ['vrbo'], legitimateDomains: ['vrbo.com'] },
    'hopper': { keywords: ['hopper'], legitimateDomains: ['hopper.com'] },
    'kayak': { keywords: ['kayak'], legitimateDomains: ['kayak.com'] },
    'travelocity': { keywords: ['travelocity'], legitimateDomains: ['travelocity.com'] },
    'orbitz': { keywords: ['orbitz'], legitimateDomains: ['orbitz.com'] },
    // ============================================
    // CLOUDFLARE TOP 50 GAP FILL
    // ============================================
    'caixa': {
        keywords: ['caixa economica', 'caixa federal', 'caixa conta', 'caixa poupanca'],
        legitimateDomains: ['caixa.gov.br', 'caixa.com.br']
    },
    'bank millennium': {
        keywords: ['bank millennium', 'millennium bank', 'millenet'],
        legitimateDomains: ['bankmillennium.pl', 'millenniumbm.pl']
    },
    'inpost': {
        keywords: ['inpost', 'paczkomat', 'inpost paczka'],
        legitimateDomains: ['inpost.pl', 'inpost.eu', 'inpost.co.uk']
    },
    'dpd': {
        keywords: ['dpd parcel', 'dpd delivery', 'dpd package', 'dpd shipment'],
        legitimateDomains: ['dpd.com', 'dpd.de', 'dpd.co.uk', 'dpd.fr', 'dpd.com.pl']
    },
    'lexisnexis': {
        keywords: ['lexisnexis', 'lexis nexis', 'lexis advance'],
        legitimateDomains: ['lexisnexis.com', 'lexis.com']
    },
    'nicos': {
        keywords: ['nicos card', 'nicos credit', 'mitsubishi ufj nicos'],
        legitimateDomains: ['nicos.co.jp', 'cr.mufg.jp']
    },
    'banco de la nación argentina': {
        keywords: ['banco de la nación argentina'],
        legitimateDomains: ['bna.com.ar']
    },
    'afip': {
        keywords: ['afip'],
        legitimateDomains: ['afip.gob.ar']
    },
    'university of buenos aires': {
        keywords: ['university of buenos aires', 'uba'],
        legitimateDomains: ['uba.ar']
    },
    'bank australia': {
        keywords: ['bank australia'],
        legitimateDomains: ['bankaust.com.au']
    },
    'ing australia': {
        keywords: ['ing australia'],
        legitimateDomains: ['ing.com.au']
    },
    'macquarie bank': {
        keywords: ['macquarie bank'],
        legitimateDomains: ['macquarie.com.au']
    },
    'australian federal police': {
        keywords: ['australian federal police'],
        legitimateDomains: ['afp.gov.au']
    },
    'department of home affairs': {
        keywords: ['department of home affairs'],
        legitimateDomains: ['homeaffairs.gov.au']
    },
    'australian national university': {
        keywords: ['australian national university', 'anu'],
        legitimateDomains: ['anu.edu.au']
    },
    'monash university': {
        keywords: ['monash university'],
        legitimateDomains: ['monash.edu']
    },
    'university of melbourne': {
        keywords: ['university of melbourne'],
        legitimateDomains: ['unimelb.edu.au']
    },
    'university of new south wales': {
        keywords: ['university of new south wales', 'unsw'],
        legitimateDomains: ['unsw.edu.au']
    },
    'university of queensland': {
        keywords: ['university of queensland'],
        legitimateDomains: ['uq.edu.au']
    },
    'university of sydney': {
        keywords: ['university of sydney'],
        legitimateDomains: ['sydney.edu.au']
    },
    'agl': {
        keywords: ['agl'],
        legitimateDomains: ['agl.com.au']
    },
    'energyaustralia': {
        keywords: ['energyaustralia'],
        legitimateDomains: ['energyaustralia.com.au']
    },
    'origin energy': {
        keywords: ['origin energy'],
        legitimateDomains: ['originenergy.com.au']
    },
    'erste bank': {
        keywords: ['erste bank'],
        legitimateDomains: ['erstebank.at']
    },
    'raiffeisen bank international': {
        keywords: ['raiffeisen bank international'],
        legitimateDomains: ['rbinternational.com']
    },
    'unicredit bank austria': {
        keywords: ['unicredit bank austria'],
        legitimateDomains: ['bankaustria.at']
    },
    'finanzonline': {
        keywords: ['finanzonline'],
        legitimateDomains: ['finanzonline.bmf.gv.at']
    },
    'oesterreich.gv.at': {
        keywords: ['oesterreich.gv.at'],
        legitimateDomains: ['oesterreich.gv.at']
    },
    'a1 telekom austria': {
        keywords: ['a1 telekom austria'],
        legitimateDomains: ['a1.net']
    },
    'tu wien': {
        keywords: ['tu wien'],
        legitimateDomains: ['tuwien.at']
    },
    'university of vienna': {
        keywords: ['university of vienna'],
        legitimateDomains: ['univie.ac.at']
    },
    'bnp paribas fortis': {
        keywords: ['bnp paribas fortis'],
        legitimateDomains: ['bnpparibasfortis.be']
    },
    'belfius': {
        keywords: ['belfius'],
        legitimateDomains: ['belfius.be']
    },
    'ing belgium': {
        keywords: ['ing belgium'],
        legitimateDomains: ['ing.be']
    },
    'kbc': {
        keywords: ['kbc'],
        legitimateDomains: ['kbc.com']
    },
    'belgian federal police': {
        keywords: ['belgian federal police'],
        legitimateDomains: ['police.be']
    },
    'fps finance': {
        keywords: ['fps finance', 'spf finances'],
        legitimateDomains: ['finance.belgium.be']
    },
    'orange belgium': {
        keywords: ['orange belgium'],
        legitimateDomains: ['orange.be']
    },
    'proximus': {
        keywords: ['proximus'],
        legitimateDomains: ['proximus.be']
    },
    'telenet': {
        keywords: ['telenet'],
        legitimateDomains: ['telenet.be']
    },
    'ghent university': {
        keywords: ['ghent university'],
        legitimateDomains: ['ugent.be']
    },
    'ku leuven': {
        keywords: ['ku leuven'],
        legitimateDomains: ['kuleuven.be']
    },
    'caixa econômica federal': {
        keywords: ['caixa econômica federal'],
        legitimateDomains: ['caixa.gov.br']
    },
    'santander brasil': {
        keywords: ['santander brasil'],
        legitimateDomains: ['santander.com.br']
    },
    'detran': {
        keywords: ['detran'],
        legitimateDomains: ['gov.br']
    },
    'detran-sp': {
        keywords: ['detran-sp'],
        legitimateDomains: ['detran.sp.gov.br']
    },
    'inss': {
        keywords: ['inss'],
        legitimateDomains: ['inss.gov.br']
    },
    'polícia federal': {
        keywords: ['polícia federal'],
        legitimateDomains: ['pf.gov.br']
    },
    'receita federal do brasil': {
        keywords: ['receita federal do brasil'],
        legitimateDomains: ['rfb.gov.br']
    },
    'gov.br': {
        keywords: ['gov.br'],
        legitimateDomains: ['gov.br']
    },
    'university of sao paulo': {
        keywords: ['university of sao paulo', 'usp'],
        legitimateDomains: ['usp.br']
    },
    'eletrobras': {
        keywords: ['eletrobras'],
        legitimateDomains: ['eletrobras.com']
    },
    'enel brasil': {
        keywords: ['enel brasil'],
        legitimateDomains: ['enel.com.br']
    },
    'itaipu binacional': {
        keywords: ['itaipu binacional'],
        legitimateDomains: ['itaipu.gov.br']
    },
    'sabesp': {
        keywords: ['sabesp'],
        legitimateDomains: ['sabesp.com.br']
    },
    'eq bank': {
        keywords: ['eq bank'],
        legitimateDomains: ['eqbank.ca']
    },
    'national bank of canada': {
        keywords: ['national bank of canada'],
        legitimateDomains: ['nbc.ca']
    },
    'tangerine': {
        keywords: ['tangerine'],
        legitimateDomains: ['tangerine.ca']
    },
    'atb financial': {
        keywords: ['atb financial'],
        legitimateDomains: ['atb.com']
    },
    'affinity credit union': {
        keywords: ['affinity credit union'],
        legitimateDomains: ['affinitycu.ca']
    },
    'coast capital savings': {
        keywords: ['coast capital savings'],
        legitimateDomains: ['coastcapitalsavings.com']
    },
    'desjardins': {
        keywords: ['desjardins'],
        legitimateDomains: ['desjardins.com']
    },
    'first west credit union': {
        keywords: ['first west credit union'],
        legitimateDomains: ['firstwestcu.ca']
    },
    'meridian credit union': {
        keywords: ['meridian credit union'],
        legitimateDomains: ['meridiancu.ca']
    },
    'servus credit union': {
        keywords: ['servus credit union'],
        legitimateDomains: ['servus.ca']
    },
    'vancity': {
        keywords: ['vancity'],
        legitimateDomains: ['vancity.com']
    },
    'canada revenue agency': {
        keywords: ['canada revenue agency', 'cra'],
        legitimateDomains: ['cra-arc.gc.ca']
    },
    'revenu québec': {
        keywords: ['revenu québec'],
        legitimateDomains: ['revenuquebec.ca']
    },
    'serviceontario': {
        keywords: ['serviceontario'],
        legitimateDomains: ['ontario.ca']
    },
    'bell': {
        keywords: ['bell'],
        legitimateDomains: ['bell.ca']
    },
    'mcgill university': {
        keywords: ['mcgill university'],
        legitimateDomains: ['mcgill.ca']
    },
    'university of alberta': {
        keywords: ['university of alberta'],
        legitimateDomains: ['ualberta.ca']
    },
    'university of british columbia': {
        keywords: ['university of british columbia'],
        legitimateDomains: ['ubc.ca']
    },
    'university of toronto': {
        keywords: ['university of toronto'],
        legitimateDomains: ['utoronto.ca']
    },
    'university of waterloo': {
        keywords: ['university of waterloo'],
        legitimateDomains: ['uwaterloo.ca']
    },
    'bc hydro': {
        keywords: ['bc hydro'],
        legitimateDomains: ['bchydro.com']
    },
    'enbridge gas': {
        keywords: ['enbridge gas'],
        legitimateDomains: ['enbridgegas.com']
    },
    'hydro-québec': {
        keywords: ['hydro-québec'],
        legitimateDomains: ['hydroquebec.com']
    },
    'ontario power generation': {
        keywords: ['ontario power generation'],
        legitimateDomains: ['opg.com']
    },
    'toronto hydro': {
        keywords: ['toronto hydro'],
        legitimateDomains: ['torontohydro.com']
    },
    'banco de chile': {
        keywords: ['banco de chile'],
        legitimateDomains: ['bancochile.cl']
    },
    'sii': {
        keywords: ['sii'],
        legitimateDomains: ['sii.cl']
    },
    'universidad de chile': {
        keywords: ['universidad de chile'],
        legitimateDomains: ['uchile.cl']
    },
    'agricultural bank of china': {
        keywords: ['agricultural bank of china', 'abc'],
        legitimateDomains: ['abchina.com']
    },
    'bank of china': {
        keywords: ['bank of china'],
        legitimateDomains: ['boc.cn']
    },
    'china construction bank': {
        keywords: ['china construction bank', 'ccb'],
        legitimateDomains: ['ccb.com']
    },
    'china merchants bank': {
        keywords: ['china merchants bank'],
        legitimateDomains: ['cmbchina.com']
    },
    'industrial and commercial bank of china': {
        keywords: ['industrial and commercial bank of china', 'icbc'],
        legitimateDomains: ['icbc.com.cn']
    },
    'webank': {
        keywords: ['webank'],
        legitimateDomains: ['webank.com']
    },
    'ministry of public security': {
        keywords: ['ministry of public security'],
        legitimateDomains: ['mps.gov.cn']
    },
    'national immigration administration': {
        keywords: ['national immigration administration'],
        legitimateDomains: ['nia.gov.cn']
    },
    'state taxation administration': {
        keywords: ['state taxation administration'],
        legitimateDomains: ['chinatax.gov.cn']
    },
    'fudan university': {
        keywords: ['fudan university'],
        legitimateDomains: ['fudan.edu.cn']
    },
    'hong kong university of science and technology': {
        keywords: ['hong kong university of science and technology', 'hkust'],
        legitimateDomains: ['hkust.edu.hk']
    },
    'peking university': {
        keywords: ['peking university'],
        legitimateDomains: ['pku.edu.cn']
    },
    'shanghai jiao tong university': {
        keywords: ['shanghai jiao tong university'],
        legitimateDomains: ['sjtu.edu.cn']
    },
    'tsinghua university': {
        keywords: ['tsinghua university'],
        legitimateDomains: ['tsinghua.edu.cn']
    },
    'university of hong kong': {
        keywords: ['university of hong kong'],
        legitimateDomains: ['hku.hk']
    },
    'china southern power grid': {
        keywords: ['china southern power grid'],
        legitimateDomains: ['csg.cn']
    },
    'state grid corporation of china': {
        keywords: ['state grid corporation of china'],
        legitimateDomains: ['sgcc.com.cn']
    },
    'banco de la república': {
        keywords: ['banco de la república', 'colombia'],
        legitimateDomains: ['banrep.gov.co']
    },
    'dian': {
        keywords: ['dian'],
        legitimateDomains: ['dian.gov.co']
    },
    'national university of colombia': {
        keywords: ['national university of colombia'],
        legitimateDomains: ['unal.edu.co']
    },
    'česká spořitelna': {
        keywords: ['česká spořitelna'],
        legitimateDomains: ['csas.cz']
    },
    'finanční správa': {
        keywords: ['finanční správa'],
        legitimateDomains: ['financnisprava.cz']
    },
    'danske bank': {
        keywords: ['danske bank'],
        legitimateDomains: ['danskebank.com']
    },
    'nykredit': {
        keywords: ['nykredit'],
        legitimateDomains: ['nykredit.dk']
    },
    'postnord denmark': {
        keywords: ['postnord denmark'],
        legitimateDomains: ['postnord.dk']
    },
    'borger.dk': {
        keywords: ['borger.dk'],
        legitimateDomains: ['borger.dk']
    },
    'danish police': {
        keywords: ['danish police'],
        legitimateDomains: ['politi.dk']
    },
    'skat': {
        keywords: ['skat'],
        legitimateDomains: ['skat.dk']
    },
    'technical university of denmark': {
        keywords: ['technical university of denmark', 'dtu'],
        legitimateDomains: ['dtu.dk']
    },
    'university of copenhagen': {
        keywords: ['university of copenhagen'],
        legitimateDomains: ['ku.dk']
    },
    'national bank of egypt': {
        keywords: ['national bank of egypt'],
        legitimateDomains: ['nbe.com.eg']
    },
    'egyptian national post organization': {
        keywords: ['egyptian national post organization'],
        legitimateDomains: ['egyptpost.org']
    },
    'egypt passport/immigration': {
        keywords: ['egypt passport/immigration', 'moi portal'],
        legitimateDomains: ['moi.gov.eg']
    },
    'egyptian tax authority': {
        keywords: ['egyptian tax authority'],
        legitimateDomains: ['eta.gov.eg']
    },
    'aalto university': {
        keywords: ['aalto university'],
        legitimateDomains: ['aalto.fi']
    },
    'university of helsinki': {
        keywords: ['university of helsinki'],
        legitimateDomains: ['helsinki.fi']
    },
    'boursorama banque': {
        keywords: ['boursorama banque'],
        legitimateDomains: ['boursorama.com']
    },
    'crédit agricole': {
        keywords: ['crédit agricole'],
        legitimateDomains: ['credit-agricole.com']
    },
    'crédit lyonnais': {
        keywords: ['crédit lyonnais', 'lcl'],
        legitimateDomains: ['lcl.fr']
    },
    'crédit mutuel': {
        keywords: ['crédit mutuel'],
        legitimateDomains: ['creditmutuel.fr']
    },
    'groupe bpce': {
        keywords: ['groupe bpce'],
        legitimateDomains: ['bpce.fr']
    },
    'la banque postale': {
        keywords: ['la banque postale'],
        legitimateDomains: ['labanquepostale.fr']
    },
    'chronopost': {
        keywords: ['chronopost'],
        legitimateDomains: ['chronopost.fr']
    },
    'ants': {
        keywords: ['ants'],
        legitimateDomains: ['ants.gouv.fr']
    },
    'assurance maladie': {
        keywords: ['assurance maladie'],
        legitimateDomains: ['ameli.fr']
    },
    'caf': {
        keywords: ['caf', 'caisse d\'allocations familiales'],
        legitimateDomains: ['caf.fr']
    },
    'french national police': {
        keywords: ['french national police'],
        legitimateDomains: ['police-nationale.interieur.gouv.fr']
    },
    'service-public.fr': {
        keywords: ['service-public.fr'],
        legitimateDomains: ['service-public.fr']
    },
    'impots.gouv.fr': {
        keywords: ['impots.gouv.fr'],
        legitimateDomains: ['impots.gouv.fr']
    },
    'bredin prat': {
        keywords: ['bredin prat'],
        legitimateDomains: ['bredinprat.com']
    },
    'gide loyrette nouel': {
        keywords: ['gide loyrette nouel'],
        legitimateDomains: ['gide.com']
    },
    'free': {
        keywords: ['free mobile', 'freebox', 'free fibre', 'free fiber', 'mon compte free', 'facture free', 'assistance free', 'iliad free', 'freebox os', 'iliad'],
        legitimateDomains: ['free.fr']
    },
    'sorbonne université': {
        keywords: ['sorbonne université'],
        legitimateDomains: ['sorbonne-universite.fr']
    },
    'université psl': {
        keywords: ['université psl'],
        legitimateDomains: ['psl.eu']
    },
    'école polytechnique': {
        keywords: ['école polytechnique'],
        legitimateDomains: ['polytechnique.edu']
    },
    'edf': {
        keywords: ['edf'],
        legitimateDomains: ['edf.fr']
    },
    'engie': {
        keywords: ['engie'],
        legitimateDomains: ['engie.com']
    },
    'rte': {
        keywords: ['rte', 'france transmission'],
        legitimateDomains: ['rte-france.com']
    },
    'veolia': {
        keywords: ['veolia'],
        legitimateDomains: ['veolia.com']
    },
    'commerzbank': {
        keywords: ['commerzbank'],
        legitimateDomains: ['commerzbank.com']
    },
    'dz bank': {
        keywords: ['dz bank'],
        legitimateDomains: ['dzbank.com']
    },
    'kfw': {
        keywords: ['kfw'],
        legitimateDomains: ['kfw.de']
    },
    'n26': {
        keywords: ['n26'],
        legitimateDomains: ['n26.com']
    },
    'bvg': {
        keywords: ['bvg'],
        legitimateDomains: ['bvg.de']
    },
    'bundesportal': {
        keywords: ['bundesportal'],
        legitimateDomains: ['bund.de']
    },
    'bundeszentralamt für steuern': {
        keywords: ['bundeszentralamt für steuern', 'bzst'],
        legitimateDomains: ['bzst.de']
    },
    'deutsche rentenversicherung': {
        keywords: ['deutsche rentenversicherung'],
        legitimateDomains: ['deutsche-rentenversicherung.de']
    },
    'federal employment agency': {
        keywords: ['federal employment agency', 'bundesagentur für arbeit'],
        legitimateDomains: ['arbeitsagentur.de']
    },
    'federal police': {
        keywords: ['federal police', 'bundespolizei'],
        legitimateDomains: ['bundespolizei.de']
    },
    'kraftfahrt-bundesamt': {
        keywords: ['kraftfahrt-bundesamt', 'kba'],
        legitimateDomains: ['kba.de']
    },
    'zoll': {
        keywords: ['zoll', 'german customs'],
        legitimateDomains: ['zoll.de']
    },
    'gleiss lutz': {
        keywords: ['gleiss lutz'],
        legitimateDomains: ['gleisslutz.com']
    },
    'hengeler mueller': {
        keywords: ['hengeler mueller'],
        legitimateDomains: ['hengeler.com']
    },
    'noerr': {
        keywords: ['noerr'],
        legitimateDomains: ['noerr.com']
    },
    'vodafone germany': {
        keywords: ['vodafone germany'],
        legitimateDomains: ['vodafone.de']
    },
    'heidelberg university': {
        keywords: ['heidelberg university'],
        legitimateDomains: ['uni-heidelberg.de']
    },
    'lmu munich': {
        keywords: ['lmu munich'],
        legitimateDomains: ['lmu.de']
    },
    'rwth aachen university': {
        keywords: ['rwth aachen university'],
        legitimateDomains: ['rwth-aachen.de']
    },
    'technical university of munich': {
        keywords: ['technical university of munich', 'tum'],
        legitimateDomains: ['tum.de']
    },
    'e.on': {
        keywords: ['e.on'],
        legitimateDomains: ['eon.com']
    },
    'enbw': {
        keywords: ['enbw'],
        legitimateDomains: ['enbw.com']
    },
    'rwe': {
        keywords: ['rwe'],
        legitimateDomains: ['rwe.com']
    },
    'stadtwerke münchen': {
        keywords: ['stadtwerke münchen'],
        legitimateDomains: ['swm.de']
    },
    'vattenfall germany': {
        keywords: ['vattenfall germany'],
        legitimateDomains: ['vattenfall.de']
    },
    'bdo': {
        keywords: ['bdo'],
        legitimateDomains: ['bdo.com']
    },
    'bdo uk': {
        keywords: ['bdo uk'],
        legitimateDomains: ['bdo.co.uk']
    },
    'bdo usa': {
        keywords: ['bdo usa'],
        legitimateDomains: ['bdo.com']
    },
    'baker tilly': {
        keywords: ['baker tilly'],
        legitimateDomains: ['bakertilly.com']
    },
    'crowe': {
        keywords: ['crowe'],
        legitimateDomains: ['crowe.com']
    },
    'crowe uk': {
        keywords: ['crowe uk'],
        legitimateDomains: ['crowe.co.uk']
    },
    'deloitte': {
        keywords: ['deloitte'],
        legitimateDomains: ['deloitte.com']
    },
    'ey': {
        keywords: ['ey'],
        legitimateDomains: ['ey.com']
    },
    'grant thornton': {
        keywords: ['grant thornton'],
        legitimateDomains: ['grantthornton.global']
    },
    'grant thornton us': {
        keywords: ['grant thornton us'],
        legitimateDomains: ['grantthornton.com']
    },
    'hlb': {
        keywords: ['hlb'],
        legitimateDomains: ['hlb.global']
    },
    'kpmg': {
        keywords: ['kpmg'],
        legitimateDomains: ['kpmg.com']
    },
    'kreston global': {
        keywords: ['kreston global'],
        legitimateDomains: ['kreston.com']
    },
    'mazars': {
        keywords: ['mazars'],
        legitimateDomains: ['mazars.com']
    },
    'moore global': {
        keywords: ['moore global'],
        legitimateDomains: ['moore-global.com']
    },
    'nexia': {
        keywords: ['nexia'],
        legitimateDomains: ['nexia.com']
    },
    'pkf': {
        keywords: ['pkf'],
        legitimateDomains: ['pkf.com']
    },
    'primeglobal': {
        keywords: ['primeglobal'],
        legitimateDomains: ['primeglobal.net']
    },
    'pwc': {
        keywords: ['pwc'],
        legitimateDomains: ['pwc.com']
    },
    'rsm': {
        keywords: ['rsm'],
        legitimateDomains: ['rsm.global']
    },
    'rsm us': {
        keywords: ['rsm us'],
        legitimateDomains: ['rsmus.com']
    },
    'gls': {
        keywords: ['gls'],
        legitimateDomains: ['gls-group.com']
    },
    'alpha bank': {
        keywords: ['alpha bank'],
        legitimateDomains: ['alpha.gr']
    },
    'aade': {
        keywords: ['aade'],
        legitimateDomains: ['aade.gr']
    },
    'otp bank': {
        keywords: ['otp bank'],
        legitimateDomains: ['otpbank.hu']
    },
    'nav': {
        keywords: ['nav'],
        legitimateDomains: ['nav.gov.hu']
    },
    'indusind bank': {
        keywords: ['indusind bank'],
        legitimateDomains: ['indusind.com']
    },
    'kotak mahindra bank': {
        keywords: ['kotak mahindra bank'],
        legitimateDomains: ['kotak.com']
    },
    'digilocker': {
        keywords: ['digilocker'],
        legitimateDomains: ['digilocker.gov.in']
    },
    'epfo': {
        keywords: ['epfo'],
        legitimateDomains: ['epfindia.gov.in']
    },
    'gst portal': {
        keywords: ['gst portal'],
        legitimateDomains: ['gst.gov.in']
    },
    'income tax department': {
        keywords: ['income tax department'],
        legitimateDomains: ['incometax.gov.in']
    },
    'npci': {
        keywords: ['npci'],
        legitimateDomains: ['npci.org.in']
    },
    'passport seva': {
        keywords: ['passport seva'],
        legitimateDomains: ['passportindia.gov.in']
    },
    'iit bombay': {
        keywords: ['iit bombay'],
        legitimateDomains: ['iitb.ac.in']
    },
    'iit delhi': {
        keywords: ['iit delhi'],
        legitimateDomains: ['iitd.ac.in']
    },
    'iit madras': {
        keywords: ['iit madras'],
        legitimateDomains: ['iitm.ac.in']
    },
    'indian institute of science': {
        keywords: ['indian institute of science', 'iisc'],
        legitimateDomains: ['iisc.ac.in']
    },
    'indian institute of technology bombay': {
        keywords: ['indian institute of technology bombay'],
        legitimateDomains: ['iitb.ac.in']
    },
    'indian institute of technology delhi': {
        keywords: ['indian institute of technology delhi'],
        legitimateDomains: ['iitd.ac.in']
    },
    'indian institute of technology kanpur': {
        keywords: ['indian institute of technology kanpur'],
        legitimateDomains: ['iitk.ac.in']
    },
    'bni': {
        keywords: ['bni', 'bank negara indonesia'],
        legitimateDomains: ['bni.co.id']
    },
    'bri': {
        keywords: ['bri', 'bank rakyat indonesia'],
        legitimateDomains: ['bri.co.id']
    },
    'bank mandiri': {
        keywords: ['bank mandiri'],
        legitimateDomains: ['bankmandiri.co.id']
    },
    'jenius': {
        keywords: ['jenius', 'btpn'],
        legitimateDomains: ['jenius.com']
    },
    'pos indonesia': {
        keywords: ['pos indonesia'],
        legitimateDomains: ['posindonesia.co.id']
    },
    'directorate general of taxes': {
        keywords: ['directorate general of taxes', 'djp'],
        legitimateDomains: ['pajak.go.id']
    },
    'immigration': {
        keywords: ['immigration', 'direktorat jenderal imigrasi'],
        legitimateDomains: ['imigrasi.go.id']
    },
    'pln': {
        keywords: ['pln', 'perusahaan listrik negara'],
        legitimateDomains: ['pln.co.id']
    },
    'aib': {
        keywords: ['aib'],
        legitimateDomains: ['aib.ie']
    },
    'bank of ireland': {
        keywords: ['bank of ireland'],
        legitimateDomains: ['bankofireland.com']
    },
    'permanent tsb': {
        keywords: ['permanent tsb'],
        legitimateDomains: ['ptsb.ie']
    },
    'an garda síochána': {
        keywords: ['an garda síochána'],
        legitimateDomains: ['garda.ie']
    },
    'department of social protection': {
        keywords: ['department of social protection'],
        legitimateDomains: ['gov.ie']
    },
    'revenue': {
        keywords: ['revenue.ie', 'irish revenue', 'revenue commissioners', 'office of the revenue commissioners', 'ros.ie', 'revenue myaccount', 'revenue customer number', 'revenue.ie payments'],
        legitimateDomains: ['revenue.ie']
    },
    'trinity college dublin': {
        keywords: ['trinity college dublin'],
        legitimateDomains: ['tcd.ie']
    },
    'university college dublin': {
        keywords: ['university college dublin'],
        legitimateDomains: ['ucd.ie']
    },
    'bank hapoalim': {
        keywords: ['bank hapoalim'],
        legitimateDomains: ['bankhapoalim.co.il']
    },
    'bank leumi': {
        keywords: ['bank leumi'],
        legitimateDomains: ['leumi.co.il']
    },
    'israel discount bank': {
        keywords: ['israel discount bank'],
        legitimateDomains: ['discountbank.co.il']
    },
    'mizrahi-tefahot': {
        keywords: ['mizrahi-tefahot'],
        legitimateDomains: ['mizrahi-tefahot.co.il']
    },
    'israel tax authority': {
        keywords: ['israel tax authority'],
        legitimateDomains: ['taxes.gov.il']
    },
    'population and immigration authority': {
        keywords: ['population and immigration authority'],
        legitimateDomains: ['gov.il']
    },
    'bper banca': {
        keywords: ['bper banca'],
        legitimateDomains: ['bper.it']
    },
    'banco bpm': {
        keywords: ['banco bpm'],
        legitimateDomains: ['bancobpm.it']
    },
    'agenzia delle entrate': {
        keywords: ['agenzia delle entrate'],
        legitimateDomains: ['agenziaentrate.gov.it']
    },
    'inps': {
        keywords: ['inps', 'social security'],
        legitimateDomains: ['inps.it']
    },
    'ministero dell\'interno': {
        keywords: ['ministero dell\'interno'],
        legitimateDomains: ['interno.gov.it']
    },
    'ministero delle infrastrutture e dei trasporti': {
        keywords: ['ministero delle infrastrutture e dei trasporti'],
        legitimateDomains: ['mit.gov.it']
    },
    'polizia di stato': {
        keywords: ['polizia di stato'],
        legitimateDomains: ['poliziadistato.it']
    },
    'bonellierede': {
        keywords: ['bonellierede'],
        legitimateDomains: ['bonellierede.com']
    },
    'chiomenti': {
        keywords: ['chiomenti'],
        legitimateDomains: ['chiomenti.net']
    },
    'tim': {
        keywords: ['tim'],
        legitimateDomains: ['tim.it']
    },
    'vodafone italy': {
        keywords: ['vodafone italy'],
        legitimateDomains: ['vodafone.it']
    },
    'bocconi university': {
        keywords: ['bocconi university'],
        legitimateDomains: ['unibocconi.it']
    },
    'politecnico di milano': {
        keywords: ['politecnico di milano'],
        legitimateDomains: ['polimi.it']
    },
    'polytechnic university of turin': {
        keywords: ['polytechnic university of turin'],
        legitimateDomains: ['polito.it']
    },
    'sapienza university of rome': {
        keywords: ['sapienza university of rome'],
        legitimateDomains: ['uniroma1.it']
    },
    'university of bologna': {
        keywords: ['university of bologna'],
        legitimateDomains: ['unibo.it']
    },
    'university of milan': {
        keywords: ['university of milan'],
        legitimateDomains: ['unimi.it']
    },
    'a2a': {
        keywords: ['a2a'],
        legitimateDomains: ['a2a.eu']
    },
    'acea': {
        keywords: ['acea'],
        legitimateDomains: ['acea.it']
    },
    'snam': {
        keywords: ['snam'],
        legitimateDomains: ['snam.it']
    },
    'terna': {
        keywords: ['terna'],
        legitimateDomains: ['terna.it']
    },
    'japan post bank': {
        keywords: ['japan post bank'],
        legitimateDomains: ['jp-bank.japanpost.jp']
    },
    'rakuten bank': {
        keywords: ['rakuten bank'],
        legitimateDomains: ['rakuten-bank.co.jp']
    },
    'immigration services agency of japan': {
        keywords: ['immigration services agency of japan'],
        legitimateDomains: ['isa.go.jp']
    },
    'japan pension service': {
        keywords: ['japan pension service'],
        legitimateDomains: ['nenkin.go.jp']
    },
    'mynumber portal': {
        keywords: ['mynumber portal'],
        legitimateDomains: ['myna.go.jp']
    },
    'national tax agency': {
        keywords: ['national tax agency', 'nta'],
        legitimateDomains: ['nta.go.jp']
    },
    'kyoto university': {
        keywords: ['kyoto university'],
        legitimateDomains: ['kyoto-u.ac.jp']
    },
    'osaka university': {
        keywords: ['osaka university'],
        legitimateDomains: ['osaka-u.ac.jp']
    },
    'tohoku university': {
        keywords: ['tohoku university'],
        legitimateDomains: ['tohoku.ac.jp']
    },
    'university of tokyo': {
        keywords: ['university of tokyo'],
        legitimateDomains: ['u-tokyo.ac.jp']
    },
    'kansai electric power': {
        keywords: ['kansai electric power', 'kepco'],
        legitimateDomains: ['kepco.co.jp']
    },
    'osaka gas': {
        keywords: ['osaka gas'],
        legitimateDomains: ['osakagas.co.jp']
    },
    'tepco': {
        keywords: ['tepco'],
        legitimateDomains: ['tepco.co.jp']
    },
    'tokyo gas': {
        keywords: ['tokyo gas'],
        legitimateDomains: ['tokyo-gas.co.jp']
    },
    'equity bank kenya': {
        keywords: ['equity bank kenya'],
        legitimateDomains: ['equitybank.co.ke']
    },
    'kcb bank': {
        keywords: ['kcb bank'],
        legitimateDomains: ['kcbgroup.com']
    },
    'kenya post': {
        keywords: ['kenya post'],
        legitimateDomains: ['posta.co.ke']
    },
    'kenya revenue authority': {
        keywords: ['kenya revenue authority', 'kra'],
        legitimateDomains: ['kra.go.ke']
    },
    'ecitizen kenya': {
        keywords: ['ecitizen kenya'],
        legitimateDomains: ['ecitizen.go.ke']
    },
    'safaricom': {
        keywords: ['safaricom'],
        legitimateDomains: ['safaricom.co.ke']
    },
    'kenya power': {
        keywords: ['kenya power'],
        legitimateDomains: ['kplc.co.ke']
    },
    'hong leong bank': {
        keywords: ['hong leong bank'],
        legitimateDomains: ['hlb.com.my']
    },
    'public bank': {
        keywords: ['public bank'],
        legitimateDomains: ['publicbank.com.my']
    },
    'rhb bank': {
        keywords: ['rhb bank'],
        legitimateDomains: ['rhbgroup.com']
    },
    'pos malaysia': {
        keywords: ['pos malaysia'],
        legitimateDomains: ['pos.com.my']
    },
    'jabatan imigresen malaysia': {
        keywords: ['jabatan imigresen malaysia'],
        legitimateDomains: ['imi.gov.my']
    },
    'lhdn': {
        keywords: ['lhdn'],
        legitimateDomains: ['hasil.gov.my']
    },
    'bbva méxico': {
        keywords: ['bbva méxico'],
        legitimateDomains: ['bbva.mx']
    },
    'banco azteca': {
        keywords: ['banco azteca'],
        legitimateDomains: ['bancoazteca.com.mx']
    },
    'banorte': {
        keywords: ['banorte'],
        legitimateDomains: ['banorte.com']
    },
    'citibanamex': {
        keywords: ['citibanamex'],
        legitimateDomains: ['banamex.com']
    },
    'santander méxico': {
        keywords: ['santander méxico'],
        legitimateDomains: ['santander.com.mx']
    },
    'correos de méxico': {
        keywords: ['correos de méxico'],
        legitimateDomains: ['correosdemexico.gob.mx']
    },
    'imss': {
        keywords: ['imss'],
        legitimateDomains: ['imss.gob.mx']
    },
    'sat': {
        keywords: ['sat.gob', 'sat mexico', 'servicio de administracion tributaria', 'factura sat', 'buzon tributario', 'comprobante fiscal', 'cfdi'],
        legitimateDomains: ['sat.gob.mx']
    },
    'sep': {
        keywords: ['sep'],
        legitimateDomains: ['sep.gob.mx']
    },
    'secretaría de relaciones exteriores': {
        keywords: ['secretaría de relaciones exteriores', 'sre'],
        legitimateDomains: ['sre.gob.mx']
    },
    'national autonomous university of mexico': {
        keywords: ['national autonomous university of mexico', 'unam'],
        legitimateDomains: ['unam.mx']
    },
    'tecnológico de monterrey': {
        keywords: ['tecnológico de monterrey'],
        legitimateDomains: ['tec.mx']
    },
    'cfe': {
        keywords: ['cfe'],
        legitimateDomains: ['cfe.mx']
    },
    'conagua': {
        keywords: ['conagua'],
        legitimateDomains: ['conagua.gob.mx']
    },
    'abn amro': {
        keywords: ['abn amro'],
        legitimateDomains: ['abnamro.com']
    },
    'bunq': {
        keywords: ['bunq'],
        legitimateDomains: ['bunq.com']
    },
    'belastingdienst': {
        keywords: ['belastingdienst'],
        legitimateDomains: ['belastingdienst.nl']
    },
    'duo': {
        keywords: ['duo.nl', 'dienst uitvoering onderwijs', 'education executive agency', 'duo studiefinanciering', 'duo studielening', 'mijn duo'],
        legitimateDomains: ['duo.nl']
    },
    'digid': {
        keywords: ['digid'],
        legitimateDomains: ['digid.nl']
    },
    'ind': {
        keywords: ['ind'],
        legitimateDomains: ['ind.nl']
    },
    'politie': {
        keywords: ['politie', 'netherlands police'],
        legitimateDomains: ['politie.nl']
    },
    'buren': {
        keywords: ['buren', 'nl law firm'],
        legitimateDomains: ['burenlegal.com']
    },
    'vodafoneziggo': {
        keywords: ['vodafoneziggo'],
        legitimateDomains: ['vodafoneziggo.nl']
    },
    'delft university of technology': {
        keywords: ['delft university of technology', 'tu delft'],
        legitimateDomains: ['tudelft.nl']
    },
    'erasmus university rotterdam': {
        keywords: ['erasmus university rotterdam'],
        legitimateDomains: ['eur.nl']
    },
    'leiden university': {
        keywords: ['leiden university'],
        legitimateDomains: ['universiteitleiden.nl']
    },
    'university of amsterdam': {
        keywords: ['university of amsterdam'],
        legitimateDomains: ['uva.nl']
    },
    'wageningen university & research': {
        keywords: ['wageningen university & research'],
        legitimateDomains: ['wur.nl']
    },
    'eneco': {
        keywords: ['eneco'],
        legitimateDomains: ['eneco.com']
    },
    'vattenfall netherlands': {
        keywords: ['vattenfall netherlands'],
        legitimateDomains: ['vattenfall.nl']
    },
    'anz new zealand': {
        keywords: ['anz new zealand'],
        legitimateDomains: ['anz.co.nz']
    },
    'asb bank': {
        keywords: ['asb bank'],
        legitimateDomains: ['asb.co.nz']
    },
    'bnz': {
        keywords: ['bnz'],
        legitimateDomains: ['bnz.co.nz']
    },
    'kiwibank': {
        keywords: ['kiwibank'],
        legitimateDomains: ['kiwibank.co.nz']
    },
    'westpac nz': {
        keywords: ['westpac nz'],
        legitimateDomains: ['westpac.co.nz']
    },
    'nz post': {
        keywords: ['nz post'],
        legitimateDomains: ['nzpost.co.nz']
    },
    'immigration new zealand': {
        keywords: ['immigration new zealand'],
        legitimateDomains: ['immigration.govt.nz']
    },
    'inland revenue': {
        keywords: ['inland revenue', 'nz'],
        legitimateDomains: ['ird.govt.nz']
    },
    'university of auckland': {
        keywords: ['university of auckland'],
        legitimateDomains: ['auckland.ac.nz']
    },
    'university of otago': {
        keywords: ['university of otago'],
        legitimateDomains: ['otago.ac.nz']
    },
    'access bank': {
        keywords: ['access bank'],
        legitimateDomains: ['accessbankplc.com']
    },
    'firstbank nigeria': {
        keywords: ['firstbank nigeria'],
        legitimateDomains: ['firstbanknigeria.com']
    },
    'gtbank': {
        keywords: ['gtbank'],
        legitimateDomains: ['gtbank.com']
    },
    'zenith bank': {
        keywords: ['zenith bank'],
        legitimateDomains: ['zenithbank.com']
    },
    'firs': {
        keywords: ['firs'],
        legitimateDomains: ['firs.gov.ng']
    },
    'nigeria immigration service': {
        keywords: ['nigeria immigration service'],
        legitimateDomains: ['immigration.gov.ng']
    },
    'airtel africa': {
        keywords: ['airtel africa'],
        legitimateDomains: ['airtel.africa']
    },
    'glo': {
        keywords: ['glo', 'globacom'],
        legitimateDomains: ['gloworld.com']
    },
    'dnb bank': {
        keywords: ['dnb bank', 'dnb account', 'dnb id', 'dnb security'],
        legitimateDomains: ['dnb.no']
    },
    'posten norge': {
        keywords: ['posten norge'],
        legitimateDomains: ['posten.no']
    },
    'norwegian police': {
        keywords: ['norwegian police'],
        legitimateDomains: ['politiet.no']
    },
    'skatteetaten': {
        keywords: ['skatteetaten'],
        legitimateDomains: ['skatteetaten.no']
    },
    'university of oslo': {
        keywords: ['university of oslo'],
        legitimateDomains: ['uio.no']
    },
    'banco de crédito del perú': {
        keywords: ['banco de crédito del perú', 'bcp'],
        legitimateDomains: ['viabcp.com']
    },
    'sunat': {
        keywords: ['sunat'],
        legitimateDomains: ['sunat.gob.pe']
    },
    'national university of san marcos': {
        keywords: ['national university of san marcos'],
        legitimateDomains: ['unmsm.edu.pe']
    },
    'bdo unibank': {
        keywords: ['bdo unibank'],
        legitimateDomains: ['bdo.com.ph']
    },
    'bank of the philippine islands': {
        keywords: ['bank of the philippine islands', 'bpi'],
        legitimateDomains: ['bpi.com.ph']
    },
    'metrobank': {
        keywords: ['metrobank'],
        legitimateDomains: ['metrobank.com.ph']
    },
    'philippine postal corporation': {
        keywords: ['philippine postal corporation', 'phlpost'],
        legitimateDomains: ['phlpost.gov.ph']
    },
    'bi': {
        keywords: ['bureau of immigration'],
        legitimateDomains: ['immigration.gov.ph']
    },
    'bir': {
        keywords: ['bir'],
        legitimateDomains: ['bir.gov.ph']
    },
    'bank pekao': {
        keywords: ['bank pekao'],
        legitimateDomains: ['pekao.com.pl']
    },
    'pko bank polski': {
        keywords: ['pko bank polski'],
        legitimateDomains: ['pkobp.pl']
    },
    'santander bank polska': {
        keywords: ['santander bank polska'],
        legitimateDomains: ['santander.pl']
    },
    'mbank': {
        keywords: ['mbank'],
        legitimateDomains: ['mbank.pl']
    },
    'poczta polska': {
        keywords: ['poczta polska'],
        legitimateDomains: ['poczta-polska.pl']
    },
    'kas': {
        keywords: ['kas'],
        legitimateDomains: ['gov.pl']
    },
    'zus': {
        keywords: ['zus', 'social insurance institution'],
        legitimateDomains: ['zus.pl']
    },
    'caixa geral de depósitos': {
        keywords: ['caixa geral de depósitos', 'cgd'],
        legitimateDomains: ['cgd.pt']
    },
    'millennium bcp': {
        keywords: ['millennium bcp'],
        legitimateDomains: ['millenniumbcp.pt']
    },
    'novo banco': {
        keywords: ['novo banco'],
        legitimateDomains: ['novobanco.pt']
    },
    'ctt': {
        keywords: ['ctt', 'portugal post'],
        legitimateDomains: ['ctt.pt']
    },
    'autoridade tributária e aduaneira': {
        keywords: ['autoridade tributária e aduaneira'],
        legitimateDomains: ['portaldasfinancas.gov.pt']
    },
    'serviço de estrangeiros e fronteiras - legacy': {
        keywords: ['serviço de estrangeiros e fronteiras - legacy', 'sef'],
        legitimateDomains: ['sef.pt']
    },
    'banca transilvania': {
        keywords: ['banca transilvania'],
        legitimateDomains: ['bancatransilvania.ro']
    },
    'anaf': {
        keywords: ['anaf'],
        legitimateDomains: ['anaf.ro']
    },
    'riyad bank': {
        keywords: ['riyad bank'],
        legitimateDomains: ['riyadbank.com']
    },
    'saudi british bank': {
        keywords: ['saudi british bank', 'sabb'],
        legitimateDomains: ['sabb.com']
    },
    'saudi national bank': {
        keywords: ['saudi national bank', 'snb'],
        legitimateDomains: ['snb.com.sa']
    },
    'absher': {
        keywords: ['absher'],
        legitimateDomains: ['absher.sa']
    },
    'gosi': {
        keywords: ['gosi'],
        legitimateDomains: ['gosi.gov.sa']
    },
    'ministry of human resources and social development': {
        keywords: ['ministry of human resources and social development'],
        legitimateDomains: ['hrsd.gov.sa']
    },
    'ministry of interior': {
        keywords: ['ministry of interior'],
        legitimateDomains: ['moi.gov.sa']
    },
    'zatca': {
        keywords: ['zatca'],
        legitimateDomains: ['zatca.gov.sa']
    },
    'mobily': {
        keywords: ['mobily'],
        legitimateDomains: ['mobily.com.sa']
    },
    'zain saudi arabia': {
        keywords: ['zain saudi arabia'],
        legitimateDomains: ['sa.zain.com']
    },
    'stc': {
        keywords: ['stc'],
        legitimateDomains: ['stc.com.sa']
    },
    'saudi electricity company': {
        keywords: ['saudi electricity company'],
        legitimateDomains: ['se.com.sa']
    },
    'uob': {
        keywords: ['uob'],
        legitimateDomains: ['uobgroup.com']
    },
    'singpost': {
        keywords: ['singpost'],
        legitimateDomains: ['singpost.com']
    },
    'cpf board': {
        keywords: ['cpf board'],
        legitimateDomains: ['cpf.gov.sg']
    },
    'ica': {
        keywords: ['ica'],
        legitimateDomains: ['ica.gov.sg']
    },
    'iras': {
        keywords: ['iras'],
        legitimateDomains: ['iras.gov.sg']
    },
    'nanyang technological university': {
        keywords: ['nanyang technological university', 'ntu'],
        legitimateDomains: ['ntu.edu.sg']
    },
    'national university of singapore': {
        keywords: ['national university of singapore', 'nus'],
        legitimateDomains: ['nus.edu.sg']
    },
    'sars': {
        keywords: ['sars'],
        legitimateDomains: ['sars.gov.za']
    },
    'eskom': {
        keywords: ['eskom'],
        legitimateDomains: ['eskom.co.za']
    },
    'hana bank': {
        keywords: ['hana bank'],
        legitimateDomains: ['kebhana.com']
    },
    'kb kookmin bank': {
        keywords: ['kb kookmin bank'],
        legitimateDomains: ['kbstar.com']
    },
    'shinhan bank': {
        keywords: ['shinhan bank'],
        legitimateDomains: ['shinhan.com']
    },
    'woori bank': {
        keywords: ['woori bank'],
        legitimateDomains: ['wooribank.com']
    },
    'korea post': {
        keywords: ['korea post'],
        legitimateDomains: ['epost.go.kr']
    },
    'korea immigration service': {
        keywords: ['korea immigration service'],
        legitimateDomains: ['immigration.go.kr']
    },
    'korea national health insurance service': {
        keywords: ['korea national health insurance service', 'nhis'],
        legitimateDomains: ['nhis.or.kr']
    },
    'korean national police agency': {
        keywords: ['korean national police agency'],
        legitimateDomains: ['police.go.kr']
    },
    'national tax service': {
        keywords: ['national tax service', 'nts'],
        legitimateDomains: ['nts.go.kr']
    },
    'kaist': {
        keywords: ['kaist'],
        legitimateDomains: ['kaist.ac.kr']
    },
    'korea university': {
        keywords: ['korea university'],
        legitimateDomains: ['korea.edu']
    },
    'seoul national university': {
        keywords: ['seoul national university'],
        legitimateDomains: ['snu.ac.kr']
    },
    'yonsei university': {
        keywords: ['yonsei university'],
        legitimateDomains: ['yonsei.ac.kr']
    },
    'kogas': {
        keywords: ['kogas', 'korea gas corporation'],
        legitimateDomains: ['kogas.or.kr']
    },
    'bankinter': {
        keywords: ['bankinter'],
        legitimateDomains: ['bankinter.com']
    },
    'mrw': {
        keywords: ['mrw'],
        legitimateDomains: ['mrw.es']
    },
    'seur': {
        keywords: ['seur'],
        legitimateDomains: ['seur.com']
    },
    'agencia tributaria': {
        keywords: ['agencia tributaria', 'aeat'],
        legitimateDomains: ['agenciatributaria.es']
    },
    'dgt': {
        keywords: ['dgt'],
        legitimateDomains: ['dgt.es']
    },
    'policía nacional': {
        keywords: ['policía nacional'],
        legitimateDomains: ['policia.es']
    },
    'sepe': {
        keywords: ['sepe', 'public employment service'],
        legitimateDomains: ['sepe.es']
    },
    'seguridad social': {
        keywords: ['seguridad social', 'seg-social.es', 'tesorería general', 'import@ss', 'cl@ve', 'inss'],
        legitimateDomains: ['seg-social.es']
    },
    'garrigues': {
        keywords: ['garrigues'],
        legitimateDomains: ['garrigues.com']
    },
    'uría menéndez': {
        keywords: ['uría menéndez'],
        legitimateDomains: ['uria.com']
    },
    'orange spain': {
        keywords: ['orange spain'],
        legitimateDomains: ['orange.es']
    },
    'complutense university of madrid': {
        keywords: ['complutense university of madrid'],
        legitimateDomains: ['ucm.es']
    },
    'universidad autónoma de madrid': {
        keywords: ['universidad autónoma de madrid'],
        legitimateDomains: ['uam.es']
    },
    'university of barcelona': {
        keywords: ['university of barcelona'],
        legitimateDomains: ['ub.edu']
    },
    'aguas de barcelona': {
        keywords: ['aguas de barcelona', 'agbar'],
        legitimateDomains: ['aiguesdebarcelona.cat']
    },
    'endesa': {
        keywords: ['endesa'],
        legitimateDomains: ['endesa.com']
    },
    'iberdrola': {
        keywords: ['iberdrola'],
        legitimateDomains: ['iberdrola.com']
    },
    'iberdrola clientes': {
        keywords: ['iberdrola clientes', 'iberdrola españa', 'iberdrola.es'],
        legitimateDomains: ['iberdrola.es']
    },
    'naturgy': {
        keywords: ['naturgy'],
        legitimateDomains: ['naturgy.com']
    },
    'handelsbanken': {
        keywords: ['handelsbanken'],
        legitimateDomains: ['handelsbanken.com']
    },
    'nordea': {
        keywords: ['nordea', 'nordics'],
        legitimateDomains: ['nordea.com']
    },
    'seb': {
        keywords: ['seb'],
        legitimateDomains: ['sebgroup.com']
    },
    'svenska handelsbanken': {
        keywords: ['svenska handelsbanken'],
        legitimateDomains: ['handelsbanken.se']
    },
    'swedbank': {
        keywords: ['swedbank'],
        legitimateDomains: ['swedbank.com']
    },
    'postnord': {
        keywords: ['postnord'],
        legitimateDomains: ['postnord.se']
    },
    'försäkringskassan': {
        keywords: ['försäkringskassan', 'social insurance'],
        legitimateDomains: ['forsakringskassan.se']
    },
    'skatteverket': {
        keywords: ['skatteverket'],
        legitimateDomains: ['skatteverket.se']
    },
    'swedish police': {
        keywords: ['swedish police'],
        legitimateDomains: ['polisen.se']
    },
    'karolinska institutet': {
        keywords: ['karolinska institutet'],
        legitimateDomains: ['ki.se']
    },
    'lund university': {
        keywords: ['lund university'],
        legitimateDomains: ['lunduniversity.lu.se']
    },
    'uppsala university': {
        keywords: ['uppsala university'],
        legitimateDomains: ['uu.se']
    },
    'credit suisse': {
        keywords: ['credit suisse'],
        legitimateDomains: ['credit-suisse.com']
    },
    'postfinance': {
        keywords: ['postfinance'],
        legitimateDomains: ['postfinance.ch']
    },
    'raiffeisen switzerland': {
        keywords: ['raiffeisen switzerland'],
        legitimateDomains: ['raiffeisen.ch']
    },
    'zürcher kantonalbank': {
        keywords: ['zürcher kantonalbank', 'zkb'],
        legitimateDomains: ['zkb.ch']
    },
    'sem': {
        keywords: ['sem'],
        legitimateDomains: ['sem.admin.ch']
    },
    'swiss federal tax administration': {
        keywords: ['swiss federal tax administration', 'fta'],
        legitimateDomains: ['estv.admin.ch']
    },
    'salt': {
        keywords: ['salt'],
        legitimateDomains: ['salt.ch']
    },
    'epfl': {
        keywords: ['epfl'],
        legitimateDomains: ['epfl.ch']
    },
    'eth zurich': {
        keywords: ['eth zurich'],
        legitimateDomains: ['ethz.ch']
    },
    'university of basel': {
        keywords: ['university of basel'],
        legitimateDomains: ['unibas.ch']
    },
    'university of geneva': {
        keywords: ['university of geneva'],
        legitimateDomains: ['unige.ch']
    },
    'university of zurich': {
        keywords: ['university of zurich'],
        legitimateDomains: ['uzh.ch']
    },
    'axpo': {
        keywords: ['axpo'],
        legitimateDomains: ['axpo.com']
    },
    'national university of taiwan': {
        keywords: ['national university of taiwan'],
        legitimateDomains: ['ntu.edu.tw']
    },
    'bangkok bank': {
        keywords: ['bangkok bank'],
        legitimateDomains: ['bangkokbank.com']
    },
    'kasikornbank': {
        keywords: ['kasikornbank'],
        legitimateDomains: ['kasikornbank.com']
    },
    'krungsri': {
        keywords: ['krungsri', 'bank of ayudhya'],
        legitimateDomains: ['krungsri.com']
    },
    'krungthai bank': {
        keywords: ['krungthai bank'],
        legitimateDomains: ['ktb.co.th']
    },
    'siam commercial bank': {
        keywords: ['siam commercial bank', 'scb'],
        legitimateDomains: ['scb.co.th']
    },
    'thailand post': {
        keywords: ['thailand post'],
        legitimateDomains: ['thailandpost.co.th']
    },
    'immigration bureau': {
        keywords: ['immigration bureau', 'thailand'],
        legitimateDomains: ['immigration.go.th']
    },
    'revenue department': {
        keywords: ['revenue department', 'thailand'],
        legitimateDomains: ['rd.go.th']
    },
    'akbank': {
        keywords: ['akbank'],
        legitimateDomains: ['akbank.com']
    },
    'garanti bbva': {
        keywords: ['garanti bbva'],
        legitimateDomains: ['garantibbva.com.tr']
    },
    'yapı kredi': {
        keywords: ['yapı kredi'],
        legitimateDomains: ['yapikredi.com.tr']
    },
    'i̇şbank': {
        keywords: ['i̇şbank'],
        legitimateDomains: ['isbank.com.tr']
    },
    'ptt': {
        keywords: ['ptt'],
        legitimateDomains: ['ptt.gov.tr']
    },
    'revenue administration': {
        keywords: ['revenue administration', 'gi̇b'],
        legitimateDomains: ['gib.gov.tr']
    },
    'sgk': {
        keywords: ['sgk', 'social security institution'],
        legitimateDomains: ['sgk.gov.tr']
    },
    'e-devlet': {
        keywords: ['e-devlet'],
        legitimateDomains: ['turkiye.gov.tr']
    },
    'abu dhabi commercial bank': {
        keywords: ['abu dhabi commercial bank', 'adcb'],
        legitimateDomains: ['adcb.com']
    },
    'dubai islamic bank': {
        keywords: ['dubai islamic bank'],
        legitimateDomains: ['dib.ae']
    },
    'emirates nbd': {
        keywords: ['emirates nbd'],
        legitimateDomains: ['emiratesnbd.com']
    },
    'first abu dhabi bank': {
        keywords: ['first abu dhabi bank', 'fab'],
        legitimateDomains: ['bankfab.com']
    },
    'dubai police': {
        keywords: ['dubai police'],
        legitimateDomains: ['dubaipolice.gov.ae']
    },
    'federal tax authority': {
        keywords: ['federal tax authority', 'fta'],
        legitimateDomains: ['tax.gov.ae']
    },
    'icp': {
        keywords: ['icp'],
        legitimateDomains: ['icp.gov.ae']
    },
    'addc': {
        keywords: ['addc'],
        legitimateDomains: ['addc.ae']
    },
    'dewa': {
        keywords: ['dewa'],
        legitimateDomains: ['dewa.gov.ae']
    },
    'metro bank': {
        keywords: ['metro bank'],
        legitimateDomains: ['metrobankonline.co.uk']
    },
    'starling bank': {
        keywords: ['starling bank'],
        legitimateDomains: ['starlingbank.com']
    },
    'tsb bank': {
        keywords: ['tsb bank'],
        legitimateDomains: ['tsb.co.uk']
    },
    'virgin money uk': {
        keywords: ['virgin money uk'],
        legitimateDomains: ['virginmoneyukplc.com']
    },
    'bath building society': {
        keywords: ['bath building society'],
        legitimateDomains: ['bathbuildingsociety.co.uk']
    },
    'beverley building society': {
        keywords: ['beverley building society'],
        legitimateDomains: ['beverleybuildingsociety.co.uk']
    },
    'buckinghamshire building society': {
        keywords: ['buckinghamshire building society'],
        legitimateDomains: ['bucksbs.co.uk']
    },
    'cambridge building society': {
        keywords: ['cambridge building society'],
        legitimateDomains: ['cambridgebs.co.uk']
    },
    'coventry building society': {
        keywords: ['coventry building society'],
        legitimateDomains: ['coventrybuildingsociety.co.uk']
    },
    'hinckley & rugby building society': {
        keywords: ['hinckley & rugby building society'],
        legitimateDomains: ['hrbs.co.uk']
    },
    'leeds building society': {
        keywords: ['leeds building society'],
        legitimateDomains: ['leedsbuildingsociety.co.uk']
    },
    'loughborough building society': {
        keywords: ['loughborough building society'],
        legitimateDomains: ['theloughborough.co.uk']
    },
    'market harborough building society': {
        keywords: ['market harborough building society'],
        legitimateDomains: ['mhbs.co.uk']
    },
    'marsden building society': {
        keywords: ['marsden building society'],
        legitimateDomains: ['themarsden.co.uk']
    },
    'monmouthshire building society': {
        keywords: ['monmouthshire building society'],
        legitimateDomains: ['monbs.com']
    },
    'nationwide building society': {
        keywords: ['nationwide building society'],
        legitimateDomains: ['nationwide.co.uk']
    },
    'newcastle building society': {
        keywords: ['newcastle building society'],
        legitimateDomains: ['newcastle.co.uk']
    },
    'nottingham building society': {
        keywords: ['nottingham building society'],
        legitimateDomains: ['thenottingham.com']
    },
    'penrith building society': {
        keywords: ['penrith building society'],
        legitimateDomains: ['penrithbs.co.uk']
    },
    'principality building society': {
        keywords: ['principality building society'],
        legitimateDomains: ['principality.co.uk']
    },
    'saffron building society': {
        keywords: ['saffron building society'],
        legitimateDomains: ['saffronbs.co.uk']
    },
    'skipton building society': {
        keywords: ['skipton building society'],
        legitimateDomains: ['skipton.co.uk']
    },
    'yorkshire building society': {
        keywords: ['yorkshire building society'],
        legitimateDomains: ['ybs.co.uk']
    },
    'dpd uk': {
        keywords: ['dpd uk'],
        legitimateDomains: ['dpd.co.uk']
    },
    'yodel': {
        keywords: ['yodel'],
        legitimateDomains: ['yodel.co.uk']
    },
    'companies house': {
        keywords: ['companies house'],
        legitimateDomains: ['companieshouse.gov.uk']
    },
    'driver and vehicle licensing agency': {
        keywords: ['driver and vehicle licensing agency', 'dvla'],
        legitimateDomains: ['dvla.gov.uk']
    },
    'hm revenue & customs': {
        keywords: ['hm revenue & customs', 'hmrc'],
        legitimateDomains: ['hmrc.gov.uk']
    },
    'home office': {
        keywords: ['home office'],
        legitimateDomains: ['homeoffice.gov.uk']
    },
    'bupa': {
        keywords: ['bupa'],
        legitimateDomains: ['bupa.co.uk']
    },
    'nuffield health': {
        keywords: ['nuffield health'],
        legitimateDomains: ['nuffieldhealth.com']
    },
    'ramsay health care uk': {
        keywords: ['ramsay health care uk'],
        legitimateDomains: ['ramsayhealth.co.uk']
    },
    'spire healthcare': {
        keywords: ['spire healthcare'],
        legitimateDomains: ['spirehealthcare.com']
    },
    'allen & overy': {
        keywords: ['allen & overy'],
        legitimateDomains: ['allenovery.com']
    },
    'ashurst': {
        keywords: ['ashurst'],
        legitimateDomains: ['ashurst.com']
    },
    'bird & bird': {
        keywords: ['bird & bird'],
        legitimateDomains: ['twobirds.com']
    },
    'cms': {
        keywords: ['cms'],
        legitimateDomains: ['cms.law']
    },
    'clifford chance': {
        keywords: ['clifford chance'],
        legitimateDomains: ['cliffordchance.com']
    },
    'eversheds sutherland': {
        keywords: ['eversheds sutherland'],
        legitimateDomains: ['eversheds-sutherland.com']
    },
    'freshfields': {
        keywords: ['freshfields'],
        legitimateDomains: ['freshfields.com']
    },
    'herbert smith freehills': {
        keywords: ['herbert smith freehills'],
        legitimateDomains: ['hsf.com']
    },
    'hogan lovells': {
        keywords: ['hogan lovells'],
        legitimateDomains: ['hoganlovells.com']
    },
    'linklaters': {
        keywords: ['linklaters'],
        legitimateDomains: ['linklaters.com']
    },
    'macfarlanes': {
        keywords: ['macfarlanes'],
        legitimateDomains: ['macfarlanes.com']
    },
    'norton rose fulbright': {
        keywords: ['norton rose fulbright'],
        legitimateDomains: ['nortonrosefulbright.com']
    },
    'pinsent masons': {
        keywords: ['pinsent masons'],
        legitimateDomains: ['pinsentmasons.com']
    },
    'slaughter and may': {
        keywords: ['slaughter and may'],
        legitimateDomains: ['slaughterandmay.com']
    },
    'stephenson harwood': {
        keywords: ['stephenson harwood'],
        legitimateDomains: ['shlegal.com']
    },
    'taylor wessing': {
        keywords: ['taylor wessing'],
        legitimateDomains: ['taylorwessing.com']
    },
    'virgin media o2': {
        keywords: ['virgin media o2'],
        legitimateDomains: ['virginmediao2.co.uk']
    },
    'imperial college london': {
        keywords: ['imperial college london'],
        legitimateDomains: ['imperial.ac.uk']
    },
    'king\'s college london': {
        keywords: ['king\'s college london'],
        legitimateDomains: ['kcl.ac.uk']
    },
    'london school of economics and political science': {
        keywords: ['london school of economics and political science', 'lse'],
        legitimateDomains: ['lse.ac.uk']
    },
    'ucl': {
        keywords: ['ucl', 'university college london'],
        legitimateDomains: ['ucl.ac.uk']
    },
    'university of birmingham': {
        keywords: ['university of birmingham'],
        legitimateDomains: ['bham.ac.uk']
    },
    'university of bristol': {
        keywords: ['university of bristol'],
        legitimateDomains: ['bristol.ac.uk']
    },
    'university of cambridge': {
        keywords: ['university of cambridge'],
        legitimateDomains: ['cam.ac.uk']
    },
    'university of edinburgh': {
        keywords: ['university of edinburgh'],
        legitimateDomains: ['ed.ac.uk']
    },
    'university of glasgow': {
        keywords: ['university of glasgow'],
        legitimateDomains: ['gla.ac.uk']
    },
    'university of leeds': {
        keywords: ['university of leeds'],
        legitimateDomains: ['leeds.ac.uk']
    },
    'university of manchester': {
        keywords: ['university of manchester'],
        legitimateDomains: ['manchester.ac.uk']
    },
    'university of nottingham': {
        keywords: ['university of nottingham'],
        legitimateDomains: ['nottingham.ac.uk']
    },
    'university of oxford': {
        keywords: ['university of oxford'],
        legitimateDomains: ['ox.ac.uk']
    },
    'university of sheffield': {
        keywords: ['university of sheffield'],
        legitimateDomains: ['sheffield.ac.uk']
    },
    'university of southampton': {
        keywords: ['university of southampton'],
        legitimateDomains: ['southampton.ac.uk']
    },
    'university of warwick': {
        keywords: ['university of warwick'],
        legitimateDomains: ['warwick.ac.uk']
    },
    'e.on uk': {
        keywords: ['e.on uk'],
        legitimateDomains: ['eonenergy.com']
    },
    'edf energy': {
        keywords: ['edf energy'],
        legitimateDomains: ['edfenergy.com']
    },
    'octopus energy': {
        keywords: ['octopus energy'],
        legitimateDomains: ['octopus.energy']
    },
    'scottishpower': {
        keywords: ['scottishpower'],
        legitimateDomains: ['scottishpower.co.uk']
    },
    'severn trent': {
        keywords: ['severn trent'],
        legitimateDomains: ['stwater.co.uk']
    },
    'thames water': {
        keywords: ['thames water'],
        legitimateDomains: ['thameswater.co.uk']
    },
    'united utilities': {
        keywords: ['united utilities'],
        legitimateDomains: ['uuplc.co.uk']
    },
    'arvest bank': {
        keywords: ['arvest bank'],
        legitimateDomains: ['arvest.com']
    },
    'associated bank': {
        keywords: ['associated bank'],
        legitimateDomains: ['associatedbank.com']
    },
    'bok financial / bank of oklahoma': {
        keywords: ['bok financial / bank of oklahoma'],
        legitimateDomains: ['bokf.com']
    },
    'banc of california': {
        keywords: ['banc of california'],
        legitimateDomains: ['bancofcal.com']
    },
    'cadence bank': {
        keywords: ['cadence bank'],
        legitimateDomains: ['cadencebank.com']
    },
    'citizens bank': {
        keywords: ['citizens bank'],
        legitimateDomains: ['citizensbank.com']
    },
    'city national bank': {
        keywords: ['city national bank'],
        legitimateDomains: ['cnb.com']
    },
    'comerica bank': {
        keywords: ['comerica bank'],
        legitimateDomains: ['comerica.com']
    },
    'current': {
        keywords: ['current bank', 'current debit', 'current mobile banking', 'current card', 'current app'],
        legitimateDomains: ['current.com']
    },
    'first citizens bank': {
        keywords: ['first citizens bank'],
        legitimateDomains: ['firstcitizens.com']
    },
    'first hawaiian bank': {
        keywords: ['first hawaiian bank'],
        legitimateDomains: ['fhb.com']
    },
    'first interstate bank': {
        keywords: ['first interstate bank'],
        legitimateDomains: ['firstinterstatebank.com']
    },
    'frost bank': {
        keywords: ['frost bank'],
        legitimateDomains: ['frostbank.com']
    },
    'keybank': {
        keywords: ['keybank'],
        legitimateDomains: ['key.com']
    },
    'm&t bank': {
        keywords: ['m&t bank'],
        legitimateDomains: ['mtb.com']
    },
    'signature bank': {
        keywords: ['signature bank'],
        legitimateDomains: ['signatureny.com']
    },
    'silicon valley bank - legacy phishing': {
        keywords: ['silicon valley bank - legacy phishing', 'svb'],
        legitimateDomains: ['svb.com']
    },
    'synovus bank': {
        keywords: ['synovus bank'],
        legitimateDomains: ['synovus.com']
    },
    'valley bank': {
        keywords: ['valley bank'],
        legitimateDomains: ['valley.com']
    },
    'varo bank': {
        keywords: ['varo bank'],
        legitimateDomains: ['varomoney.com']
    },
    'webster bank': {
        keywords: ['webster bank'],
        legitimateDomains: ['websterbank.com']
    },
    'wintrust': {
        keywords: ['wintrust'],
        legitimateDomains: ['wintrust.com']
    },
    'zions bank': {
        keywords: ['zions bank'],
        legitimateDomains: ['zionsbank.com']
    },
    'alliant credit union': {
        keywords: ['alliant credit union'],
        legitimateDomains: ['alliantcreditunion.org']
    },
    'america first credit union': {
        keywords: ['america first credit union'],
        legitimateDomains: ['americafirst.com']
    },
    'america\'s credit union': {
        keywords: ['america\'s credit union'],
        legitimateDomains: ['americascu.org']
    },
    'arkansas federal credit union': {
        keywords: ['arkansas federal credit union'],
        legitimateDomains: ['afcu.org']
    },
    'becu': {
        keywords: ['becu'],
        legitimateDomains: ['becu.org']
    },
    'baxter credit union': {
        keywords: ['baxter credit union', 'bcu'],
        legitimateDomains: ['bcu.org']
    },
    'bellco credit union': {
        keywords: ['bellco credit union'],
        legitimateDomains: ['bellco.org']
    },
    'boulder valley credit union': {
        keywords: ['boulder valley credit union'],
        legitimateDomains: ['bvcu.org']
    },
    'connexus credit union': {
        keywords: ['connexus credit union'],
        legitimateDomains: ['connexuscu.org']
    },
    'desert financial credit union': {
        keywords: ['desert financial credit union'],
        legitimateDomains: ['desertfinancial.com']
    },
    'digital federal credit union': {
        keywords: ['digital federal credit union', 'dcu'],
        legitimateDomains: ['dcu.org']
    },
    'ent credit union': {
        keywords: ['ent credit union'],
        legitimateDomains: ['ent.com']
    },
    'first community credit union': {
        keywords: ['first community credit union'],
        legitimateDomains: ['firstcommunity.com']
    },
    'first tech federal credit union': {
        keywords: ['first tech federal credit union'],
        legitimateDomains: ['firsttechfed.com']
    },
    'gecu': {
        keywords: ['gecu'],
        legitimateDomains: ['gecu.com']
    },
    'georgia\'s own credit union': {
        keywords: ['georgia\'s own credit union'],
        legitimateDomains: ['georgiasown.org']
    },
    'golden 1 credit union': {
        keywords: ['golden 1 credit union'],
        legitimateDomains: ['golden1.com']
    },
    'harborstone credit union': {
        keywords: ['harborstone credit union'],
        legitimateDomains: ['harborstone.com']
    },
    'kinecta federal credit union': {
        keywords: ['kinecta federal credit union'],
        legitimateDomains: ['kinecta.org']
    },
    'langley federal credit union': {
        keywords: ['langley federal credit union'],
        legitimateDomains: ['langleyfcu.org']
    },
    'mountain america credit union': {
        keywords: ['mountain america credit union'],
        legitimateDomains: ['macu.com']
    },
    'navy army community credit union': {
        keywords: ['navy army community credit union'],
        legitimateDomains: ['navyarmyccu.com']
    },
    'nusenda credit union': {
        keywords: ['nusenda credit union'],
        legitimateDomains: ['nusenda.org']
    },
    'onpoint community credit union': {
        keywords: ['onpoint community credit union'],
        legitimateDomains: ['onpointcu.com']
    },
    'patelco credit union': {
        keywords: ['patelco credit union'],
        legitimateDomains: ['patelco.org']
    },
    'pentagon federal credit union': {
        keywords: ['pentagon federal credit union', 'penfed'],
        legitimateDomains: ['penfed.org']
    },
    'people\'s credit union': {
        keywords: ['people\'s credit union', 'ri'],
        legitimateDomains: ['peoplescu.com']
    },
    'rbfcu': {
        keywords: ['rbfcu'],
        legitimateDomains: ['rbfcu.org']
    },
    'redstone federal credit union': {
        keywords: ['redstone federal credit union'],
        legitimateDomains: ['redfcu.org']
    },
    'secu maryland': {
        keywords: ['secu maryland'],
        legitimateDomains: ['secu.com']
    },
    'schoolsfirst federal credit union': {
        keywords: ['schoolsfirst federal credit union'],
        legitimateDomains: ['schoolsfirstfcu.org']
    },
    'security service federal credit union': {
        keywords: ['security service federal credit union'],
        legitimateDomains: ['ssfcu.org']
    },
    'sound credit union': {
        keywords: ['sound credit union'],
        legitimateDomains: ['soundcu.com']
    },
    'space coast credit union': {
        keywords: ['space coast credit union'],
        legitimateDomains: ['sccu.com']
    },
    'spokane teachers credit union': {
        keywords: ['spokane teachers credit union', 'stcu'],
        legitimateDomains: ['stcu.org']
    },
    'state employees\' credit union': {
        keywords: ['state employees\' credit union', 'nc secu'],
        legitimateDomains: ['ncsecu.org']
    },
    'suncoast credit union': {
        keywords: ['suncoast credit union'],
        legitimateDomains: ['suncoastcreditunion.com']
    },
    'teachers federal credit union': {
        keywords: ['teachers federal credit union'],
        legitimateDomains: ['teachersfcu.org']
    },
    'tinker federal credit union': {
        keywords: ['tinker federal credit union'],
        legitimateDomains: ['tinkerfcu.org']
    },
    'travis credit union': {
        keywords: ['travis credit union'],
        legitimateDomains: ['traviscu.org']
    },
    'unfcu': {
        keywords: ['unfcu'],
        legitimateDomains: ['unfcu.org']
    },
    'unify financial credit union': {
        keywords: ['unify financial credit union'],
        legitimateDomains: ['unifyfcu.com']
    },
    'united federal credit union': {
        keywords: ['united federal credit union'],
        legitimateDomains: ['unitedfcu.com']
    },
    'vystar credit union': {
        keywords: ['vystar credit union'],
        legitimateDomains: ['vystarcu.org']
    },
    'wright-patt credit union': {
        keywords: ['wright-patt credit union'],
        legitimateDomains: ['wpcu.coop']
    },
    'adventhealth': {
        keywords: ['adventhealth'],
        legitimateDomains: ['adventhealth.com']
    },
    'ascension': {
        keywords: ['ascension'],
        legitimateDomains: ['ascension.org']
    },
    'banner health': {
        keywords: ['banner health'],
        legitimateDomains: ['bannerhealth.com']
    },
    'cleveland clinic': {
        keywords: ['cleveland clinic'],
        legitimateDomains: ['clevelandclinic.org']
    },
    'commonspirit health': {
        keywords: ['commonspirit health'],
        legitimateDomains: ['commonspirit.org']
    },
    'hca healthcare': {
        keywords: ['hca healthcare'],
        legitimateDomains: ['hcahealthcare.com']
    },
    'johns hopkins medicine': {
        keywords: ['johns hopkins medicine'],
        legitimateDomains: ['hopkinsmedicine.org']
    },
    'mass general brigham': {
        keywords: ['mass general brigham'],
        legitimateDomains: ['massgeneralbrigham.org']
    },
    'mayo clinic': {
        keywords: ['mayo clinic'],
        legitimateDomains: ['mayoclinic.org']
    },
    'nyu langone health': {
        keywords: ['nyu langone health'],
        legitimateDomains: ['nyulangone.org']
    },
    'providence': {
        keywords: ['providence'],
        legitimateDomains: ['providence.org']
    },
    'sutter health': {
        keywords: ['sutter health'],
        legitimateDomains: ['sutterhealth.org']
    },
    'trinity health': {
        keywords: ['trinity health'],
        legitimateDomains: ['trinity-health.org']
    },
    'upmc': {
        keywords: ['upmc'],
        legitimateDomains: ['upmc.com']
    },
    'akin': {
        keywords: ['akin'],
        legitimateDomains: ['akin.com']
    },
    'bclp': {
        keywords: ['bclp'],
        legitimateDomains: ['bclplaw.com']
    },
    'baker botts': {
        keywords: ['baker botts'],
        legitimateDomains: ['bakerbotts.com']
    },
    'baker mckenzie': {
        keywords: ['baker mckenzie'],
        legitimateDomains: ['bakermckenzie.com']
    },
    'cleary gottlieb': {
        keywords: ['cleary gottlieb'],
        legitimateDomains: ['cgsh.com']
    },
    'cooley': {
        keywords: ['cooley'],
        legitimateDomains: ['cooley.com']
    },
    'covington & burling': {
        keywords: ['covington & burling'],
        legitimateDomains: ['cov.com']
    },
    'dla piper': {
        keywords: ['dla piper'],
        legitimateDomains: ['dlapiper.com']
    },
    'debevoise & plimpton': {
        keywords: ['debevoise & plimpton'],
        legitimateDomains: ['debevoise.com']
    },
    'dentons': {
        keywords: ['dentons'],
        legitimateDomains: ['dentons.com']
    },
    'gibson, dunn & crutcher': {
        keywords: ['gibson, dunn & crutcher'],
        legitimateDomains: ['gibsondunn.com']
    },
    'goodwin': {
        keywords: ['goodwin'],
        legitimateDomains: ['goodwinlaw.com']
    },
    'greenberg traurig': {
        keywords: ['greenberg traurig'],
        legitimateDomains: ['gtlaw.com']
    },
    'holland & knight': {
        keywords: ['holland & knight'],
        legitimateDomains: ['hklaw.com']
    },
    'jones day': {
        keywords: ['jones day'],
        legitimateDomains: ['jonesday.com']
    },
    'king & spalding': {
        keywords: ['king & spalding'],
        legitimateDomains: ['kslaw.com']
    },
    'kirkland & ellis': {
        keywords: ['kirkland & ellis'],
        legitimateDomains: ['kirkland.com']
    },
    'latham & watkins': {
        keywords: ['latham & watkins'],
        legitimateDomains: ['lw.com']
    },
    'mayer brown': {
        keywords: ['mayer brown'],
        legitimateDomains: ['mayerbrown.com']
    },
    'milbank': {
        keywords: ['milbank'],
        legitimateDomains: ['milbank.com']
    },
    'morgan, lewis & bockius': {
        keywords: ['morgan, lewis & bockius'],
        legitimateDomains: ['morganlewis.com']
    },
    'o\'melveny & myers': {
        keywords: ['o\'melveny & myers'],
        legitimateDomains: ['omm.com']
    },
    'orrick': {
        keywords: ['orrick'],
        legitimateDomains: ['orrick.com']
    },
    'paul hastings': {
        keywords: ['paul hastings'],
        legitimateDomains: ['paulhastings.com']
    },
    'paul, weiss': {
        keywords: ['paul, weiss'],
        legitimateDomains: ['paulweiss.com']
    },
    'perkins coie': {
        keywords: ['perkins coie'],
        legitimateDomains: ['perkinscoie.com']
    },
    'quinn emanuel urquhart & sullivan': {
        keywords: ['quinn emanuel urquhart & sullivan'],
        legitimateDomains: ['quinnemanuel.com']
    },
    'reed smith': {
        keywords: ['reed smith'],
        legitimateDomains: ['reedsmith.com']
    },
    'ropes & gray': {
        keywords: ['ropes & gray'],
        legitimateDomains: ['ropesgray.com']
    },
    'shearman & sterling': {
        keywords: ['shearman & sterling'],
        legitimateDomains: ['shearman.com']
    },
    'sidley austin': {
        keywords: ['sidley austin'],
        legitimateDomains: ['sidley.com']
    },
    'simpson thacher & bartlett': {
        keywords: ['simpson thacher & bartlett'],
        legitimateDomains: ['stblaw.com']
    },
    'skadden, arps, slate, meagher & flom': {
        keywords: ['skadden, arps, slate, meagher & flom'],
        legitimateDomains: ['skadden.com']
    },
    'squire patton boggs': {
        keywords: ['squire patton boggs'],
        legitimateDomains: ['squirepattonboggs.com']
    },
    'sullivan & cromwell': {
        keywords: ['sullivan & cromwell'],
        legitimateDomains: ['sullcrom.com']
    },
    'weil, gotshal & manges': {
        keywords: ['weil, gotshal & manges'],
        legitimateDomains: ['weil.com']
    },
    'white & case': {
        keywords: ['white & case'],
        legitimateDomains: ['whitecase.com']
    },
    'wilmerhale': {
        keywords: ['wilmerhale'],
        legitimateDomains: ['wilmerhale.com']
    },
    'winston & strawn': {
        keywords: ['winston & strawn'],
        legitimateDomains: ['winston.com']
    },
    'amrock': {
        keywords: ['amrock'],
        legitimateDomains: ['amrock.com']
    },
    'fidelity national title': {
        keywords: ['fidelity national title'],
        legitimateDomains: ['fidelitynationaltitle.com']
    },
    'wfg national title': {
        keywords: ['wfg national title'],
        legitimateDomains: ['wfgtitle.com']
    },
    'california institute of technology': {
        keywords: ['california institute of technology', 'caltech'],
        legitimateDomains: ['caltech.edu']
    },
    'carnegie mellon university': {
        keywords: ['carnegie mellon university'],
        legitimateDomains: ['cmu.edu']
    },
    'columbia university': {
        keywords: ['columbia university'],
        legitimateDomains: ['columbia.edu']
    },
    'cornell university': {
        keywords: ['cornell university'],
        legitimateDomains: ['cornell.edu']
    },
    'duke university': {
        keywords: ['duke university'],
        legitimateDomains: ['duke.edu']
    },
    'georgia institute of technology': {
        keywords: ['georgia institute of technology'],
        legitimateDomains: ['gatech.edu']
    },
    'harvard university': {
        keywords: ['harvard university'],
        legitimateDomains: ['harvard.edu']
    },
    'johns hopkins university': {
        keywords: ['johns hopkins university'],
        legitimateDomains: ['jhu.edu']
    },
    'massachusetts institute of technology': {
        keywords: ['massachusetts institute of technology', 'mit'],
        legitimateDomains: ['mit.edu']
    },
    'new york university': {
        keywords: ['new york university', 'nyu'],
        legitimateDomains: ['nyu.edu']
    },
    'northwestern university': {
        keywords: ['northwestern university'],
        legitimateDomains: ['northwestern.edu']
    },
    'princeton university': {
        keywords: ['princeton university'],
        legitimateDomains: ['princeton.edu']
    },
    'stanford university': {
        keywords: ['stanford university'],
        legitimateDomains: ['stanford.edu']
    },
    'uc san diego': {
        keywords: ['uc san diego'],
        legitimateDomains: ['ucsd.edu']
    },
    'ucla': {
        keywords: ['ucla'],
        legitimateDomains: ['ucla.edu']
    },
    'university of california, berkeley': {
        keywords: ['university of california, berkeley'],
        legitimateDomains: ['berkeley.edu']
    },
    'university of chicago': {
        keywords: ['university of chicago'],
        legitimateDomains: ['uchicago.edu']
    },
    'university of michigan': {
        keywords: ['university of michigan'],
        legitimateDomains: ['umich.edu']
    },
    'university of pennsylvania': {
        keywords: ['university of pennsylvania'],
        legitimateDomains: ['upenn.edu']
    },
    'yale university': {
        keywords: ['yale university'],
        legitimateDomains: ['yale.edu']
    },
    'southern company': {
        keywords: ['southern company'],
        legitimateDomains: ['southerncompany.com']
    },
    'xcel energy': {
        keywords: ['xcel energy'],
        legitimateDomains: ['xcelenergy.com']
    },
    'bidv': {
        keywords: ['bidv'],
        legitimateDomains: ['bidv.com.vn']
    },
    'techcombank': {
        keywords: ['techcombank'],
        legitimateDomains: ['techcombank.com.vn']
    },
    'vpbank': {
        keywords: ['vpbank'],
        legitimateDomains: ['vpbank.com.vn']
    },
    'vietcombank': {
        keywords: ['vietcombank'],
        legitimateDomains: ['vietcombank.com.vn']
    },
    'vietinbank': {
        keywords: ['vietinbank'],
        legitimateDomains: ['vietinbank.vn']
    },
    'vietnam post': {
        keywords: ['vietnam post'],
        legitimateDomains: ['vnpost.vn']
    },
    'general department of taxation': {
        keywords: ['general department of taxation', 'vietnam'],
        legitimateDomains: ['gdt.gov.vn']
    },
    'vietnam immigration': {
        keywords: ['vietnam immigration'],
        legitimateDomains: ['immigration.gov.vn']
    }
};

// ============================================
// ORGANIZATION IMPERSONATION TARGETS
// ============================================
const IMPERSONATION_TARGETS = {
    "social security": ["ssa.gov"],
    "social security administration": ["ssa.gov"],
    "internal revenue service": ["irs.gov"],
    "irs": ["irs.gov"],
    "treasury department": ["treasury.gov"],
    "us treasury": ["treasury.gov"],
    "department of treasury": ["treasury.gov"],
    "medicare": ["medicare.gov", "cms.gov"],
    "medicaid": ["medicaid.gov", "cms.gov"],
    "federal bureau of investigation": ["fbi.gov"],
    "fbi": ["fbi.gov"],
    "veterans affairs": ["va.gov"],
    "department of veterans affairs": ["va.gov"],
    "va benefits": ["va.gov"],
    "federal trade commission": ["ftc.gov"],
    "ftc": ["ftc.gov"],
    "department of homeland security": ["dhs.gov"],
    "homeland security": ["dhs.gov"],
    "uscis": ["uscis.gov"],
    "us citizenship": ["uscis.gov"],
    "department of justice": ["justice.gov", "usdoj.gov"],
    "department of labor": ["dol.gov"],
    "small business administration": ["sba.gov"],
    "sba": ["sba.gov"],
    "federal housing administration": ["hud.gov"],
    "hud": ["hud.gov"],
    "student aid": ["studentaid.gov", "ed.gov"],
    "fafsa": ["studentaid.gov", "ed.gov"],
    "department of education": ["ed.gov"],
    "usps": ["usps.com"],
    "postal service": ["usps.com"],
    "us postal service": ["usps.com"],
    "united states postal": ["usps.com"],
    "ups": ["ups.com"],
    "united parcel service": ["ups.com"],
    "fedex": ["fedex.com"],
    "federal express": ["fedex.com"],
    "dhl": ["dhl.com"],
    "wells fargo": ["wellsfargo.com", "wf.com", "notify.wellsfargo.com"],
    "bank of america": ["bankofamerica.com", "bofa.com"],
    "chase bank": ["chase.com", "jpmorganchase.com"],
    "jpmorgan chase": ["chase.com", "jpmorganchase.com"],
    "jpmorgan": ["chase.com", "jpmorganchase.com"],
    "citibank": ["citi.com", "citibank.com"],
    "citigroup": ["citi.com", "citibank.com"],
    "us bank": ["usbank.com"],
    "u.s. bank": ["usbank.com"],
    "pnc bank": ["pnc.com"],
    "capital one": ["capitalone.com"],
    "td bank": ["td.com", "tdbank.com"],
    "truist": ["truist.com"],
    "regions bank": ["regions.com"],
    "fifth third bank": ["53.com"],
    "huntington bank": ["huntington.com"],
    "ally bank": ["ally.com"],
    "discover bank": ["discover.com"],
    "american express": ["americanexpress.com", "amex.com", "aexp.com"],
    "navy federal": ["navyfederal.org"],
    "navy federal credit union": ["navyfederal.org"],
    "usaa": ["usaa.com"],
    "microsoft support": ["microsoft.com"],
    "microsoft account": ["microsoft.com", "live.com"],
    "microsoft security": ["microsoft.com"],
    "apple support": ["apple.com"],
    "apple id": ["apple.com"],
    "apple security": ["apple.com"],
    "google support": ["google.com"],
    "google account": ["google.com"],
    "google security": ["google.com"],
    "amazon support": ["amazon.com"],
    "amazon account": ["amazon.com"],
    "amazon security": ["amazon.com"],
    "netflix support": ["netflix.com"],
    "netflix account": ["netflix.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "adobe sign": ["adobe.com", "adobesign.com"],
    "intuit": ["intuit.com"],
    "quickbooks": ["intuit.com", "quickbooks.com"],
    "turbotax": ["intuit.com", "turbotax.com"],
    "paypal": ["paypal.com"],
    "venmo": ["venmo.com"],
    "zelle": ["zellepay.com"],
    "cash app": ["cash.app", "square.com"],
    "cashapp": ["cash.app", "square.com"],
    "equifax": ["equifax.com"],
    "experian": ["experian.com"],
    "transunion": ["transunion.com"],
    "fidelity national title": ["fnf.com", "fntg.com"],
    "first american title": ["firstam.com"],
    "first american": ["firstam.com"],
    "chicago title": ["chicagotitle.com", "fnf.com"],
    "stewart title": ["stewart.com"],
    "old republic title": ["oldrepublictitle.com", "oldrepublic.com"],
    "walmart": ["walmart.com"],
    "walmart customer support": ["walmart.com"],
    "costco": ["costco.com"],
    "costco wholesale": ["costco.com"],
    "best buy": ["bestbuy.com"],
    "geek squad": ["bestbuy.com", "geeksquad.com"],
    "home depot": ["homedepot.com"],
    "lowes": ["lowes.com"],
    "ebay": ["ebay.com"],
    "dmv": [".gov"],
    "dmv service desk": [".gov"],
    "department of motor vehicles": [".gov"],
    "motor vehicles": [".gov"],
    "state tax board": [".gov"],
    "franchise tax board": [".gov"],
    "edd": [".gov"],
    "employment development": [".gov"],
    "unemployment insurance": [".gov"],
    "child support services": [".gov"],
    "department of revenue": [".gov"],
    "state attorney general": [".gov"],
    "attorney general": [".gov"],
    "at&t": ["att.com", "att.net", "att-mail.com"],
    "att": ["att.com", "att.net", "att-mail.com"],
    "att wireless": ["att.com"],
    "verizon": ["verizon.com", "verizonwireless.com"],
    "verizon wireless": ["verizon.com", "verizonwireless.com"],
    "t-mobile": ["t-mobile.com"],
    "tmobile": ["t-mobile.com"],
    "sprint": ["sprint.com", "t-mobile.com"],
    "xfinity": ["xfinity.com", "comcast.com"],
    "comcast": ["xfinity.com", "comcast.com", "comcast.net"],
    "spectrum": ["spectrum.com", "spectrum.net", "charter.com"],
    "cox communications": ["cox.com"],
    "cricket wireless": ["cricketwireless.com"],
    "metro by t-mobile": ["t-mobile.com", "metrobyt-mobile.com"],
    "boost mobile": ["boostmobile.com"],
    "whatsapp": ["whatsapp.com"],
    "whatsapp support": ["whatsapp.com"],
    "instagram": ["instagram.com", "mail.instagram.com", "facebookmail.com", "metamail.com"],
    "instagram support": ["instagram.com"],
    "tiktok": ["tiktok.com"],
    "tiktok support": ["tiktok.com"],
    "twitter": ["twitter.com", "x.com"],
    "twitter support": ["twitter.com", "x.com"],
    "snapchat": ["snapchat.com"],
    "snapchat support": ["snapchat.com"],
    "pinterest": ["pinterest.com"],
    "reddit": ["reddit.com", "redditmail.com"],
    "threads": ["threads.net", "instagram.com"],
    "steam support": ["steampowered.com"],
    "valve": ["valvesoftware.com", "steampowered.com"],
    "roblox": ["roblox.com"],
    "roblox support": ["roblox.com"],
    "playstation": ["playstation.com", "sony.com"],
    "playstation network": ["playstation.com", "sony.com"],
    "psn": ["playstation.com", "sony.com"],
    "xbox": ["xbox.com", "microsoft.com"],
    "xbox live": ["xbox.com", "microsoft.com"],
    "epic games": ["epicgames.com"],
    "fortnite": ["epicgames.com"],
    "nintendo": ["nintendo.com"],
    "nintendo account": ["nintendo.com"],
    "ea games": ["ea.com"],
    "electronic arts": ["ea.com"],
    "riot games": ["riotgames.com"],
    "blizzard": ["blizzard.com", "battle.net"],
    "battle.net": ["blizzard.com", "battle.net"],
    "spotify": ["spotify.com", "spotifymail.com"],
    "spotify support": ["spotify.com"],
    "disney+": ["disneyplus.com", "disney.com", "d23.com", "disneyonline.com"],
    "disney plus": ["disneyplus.com", "disney.com", "d23.com", "disneyonline.com"],
    "hulu": ["hulu.com"],
    "hulu support": ["hulu.com"],
    "hbo max": ["max.com", "hbomax.com"],
    "roku": ["roku.com"],
    "youtube": ["youtube.com", "google.com"],
    "youtube tv": ["youtube.com", "google.com"],
    "paramount+": ["paramountplus.com", "paramount.com"],
    "paramount plus": ["paramountplus.com", "paramount.com"],
    "peacock": ["peacocktv.com", "nbcuni.com"],
    "apple tv": ["apple.com"],
    "visa": ["visa.com"],
    "visa card": ["visa.com"],
    "mastercard": ["mastercard.com"],
    "master card": ["mastercard.com"],
    "stripe": ["stripe.com"],
    "robinhood": ["robinhood.com"],
    "fidelity": ["fidelity.com", "fidelityinvestments.com"],
    "fidelity investments": ["fidelity.com"],
    "charles schwab": ["schwab.com"],
    "schwab": ["schwab.com"],
    "vanguard": ["vanguard.com"],
    "e-trade": ["etrade.com"],
    "etrade": ["etrade.com"],
    "td ameritrade": ["tdameritrade.com", "schwab.com"],
    "morgan stanley": ["morganstanley.com"],
    "merrill lynch": ["ml.com", "merrilledge.com"],
    "goldman sachs": ["goldmansachs.com", "gs.com"],
    "transferwise": ["wise.com"],
    "klarna": ["klarna.com"],
    "state farm": ["statefarm.com"],
    "state farm insurance": ["statefarm.com"],
    "geico": ["geico.com"],
    "progressive insurance": ["progressive.com"],
    "allstate": ["allstate.com"],
    "allstate insurance": ["allstate.com"],
    "liberty mutual": ["libertymutual.com"],
    "farmers insurance": ["farmers.com"],
    "farmers": ["farmers.com"],
    "nationwide insurance": ["nationwide.com"],
    "travelers": ["travelers.com"],
    "travelers insurance": ["travelers.com"],
    "the hartford": ["thehartford.com"],
    "hartford insurance": ["thehartford.com"],
    "american family insurance": ["amfam.com"],
    "amfam": ["amfam.com"],
    "erie insurance": ["erieinsurance.com"],
    "shelter insurance": ["shelterinsurance.com"],
    "auto-owners insurance": ["auto-owners.com"],
    "unitedhealthcare": ["uhc.com", "unitedhealthcare.com", "myuhc.com", "optum.com"],
    "united healthcare": ["uhc.com", "unitedhealthcare.com", "myuhc.com"],
    "uhc": ["uhc.com", "unitedhealthcare.com"],
    "blue cross": ["bcbs.com", "anthem.com"],
    "blue shield": ["bcbs.com", "anthem.com"],
    "blue cross blue shield": ["bcbs.com"],
    "bcbs": ["bcbs.com"],
    "anthem": ["anthem.com", "elevancehealth.com"],
    "cigna": ["cigna.com", "mycigna.com"],
    "humana": ["humana.com"],
    "kaiser permanente": ["kaiserpermanente.org", "kp.org"],
    "kaiser": ["kaiserpermanente.org", "kp.org"],
    "aetna": ["aetna.com"],
    "molina healthcare": ["molinahealthcare.com"],
    "centene": ["centene.com"],
    "metlife": ["metlife.com"],
    "prudential financial": ["prudential.com"],
    "new york life": ["newyorklife.com"],
    "northwestern mutual": ["northwesternmutual.com"],
    "aflac": ["aflac.com"],
    "lincoln financial": ["lincolnfinancial.com", "lfg.com"],
    "principal financial": ["principal.com"],
    "guardian life": ["guardianlife.com"],
    "mass mutual": ["massmutual.com"],
    "massmutual": ["massmutual.com"],
    "transamerica": ["transamerica.com"],
    "mutual of omaha": ["mutualofomaha.com"],
    "aaa": ["aaa.com"],
    "aaa roadside": ["aaa.com"],
    "aaa insurance": ["aaa.com"],
    "booking.com": ["booking.com"],
    "airbnb": ["airbnb.com", "airbnbmail.com", "airbnbaction.com", "airbnblove.com"],
    "airbnb support": ["airbnb.com"],
    "expedia": ["expedia.com"],
    "vrbo": ["vrbo.com"],
    "hotels.com": ["hotels.com"],
    "tripadvisor": ["tripadvisor.com"],
    "southwest airlines": ["southwest.com"],
    "southwest": ["southwest.com"],
    "united airlines": ["united.com"],
    "delta air lines": ["delta.com"],
    "delta airlines": ["delta.com"],
    "american airlines": ["aa.com", "americanairlines.com"],
    "jetblue": ["jetblue.com"],
    "alaska airlines": ["alaskaair.com"],
    "frontier airlines": ["flyfrontier.com"],
    "spirit airlines": ["spirit.com"],
    "norton": ["norton.com", "nortonlifelock.com", "gen.digital"],
    "nortonlifelock": ["norton.com", "nortonlifelock.com"],
    "norton 360": ["norton.com"],
    "avast": ["avast.com"],
    "avg": ["avg.com"],
    "kaspersky": ["kaspersky.com"],
    "bitdefender": ["bitdefender.com"],
    "malwarebytes": ["malwarebytes.com"],
    "binance": ["binance.com"],
    "kraken": ["kraken.com"],
    "crypto.com": ["crypto.com"],
    "gemini": ["gemini.com"],
    "opensea": ["opensea.io"],
    "salesforce": ["salesforce.com", "force.com"],
    "salesforce support": ["salesforce.com"],
    "slack": ["slack.com"],
    "slack support": ["slack.com"],
    "hubspot": ["hubspot.com"],
    "monday.com": ["monday.com"],
    "monday": ["monday.com"],
    "asana": ["asana.com"],
    "trello": ["trello.com"],
    "notion": ["notion.so", "notion.com"],
    "adobe": ["adobe.com"],
    "adobe account": ["adobe.com"],
    "adobe support": ["adobe.com"],
    "adobe creative cloud": ["adobe.com"],
    "afterpay": ["afterpay.com"],
    "sofi": ["sofi.com"],
    "sofi bank": ["sofi.com"],
    "synchrony": ["synchrony.com", "synchronybank.com", "mysynchrony.com"],
    "synchrony bank": ["synchrony.com", "synchronybank.com"],
    "chime": ["chime.com"],
    "chime bank": ["chime.com"],
    "pg&e": ["pge.com"],
    "pge": ["pge.com"],
    "pacific gas and electric": ["pge.com"],
    "southern california edison": ["sce.com"],
    "con edison": ["coned.com", "conedison.com"],
    "coned": ["coned.com", "conedison.com"],
    "duke energy": ["duke-energy.com"],
    "national grid": ["nationalgrid.com", "nationalgridus.com"],
    "florida power": ["fpl.com"],
    "fpl": ["fpl.com"],
    "sdge": ["sdge.com"],
    "san diego gas": ["sdge.com"],
    "dominion energy": ["dominionenergy.com"],
    "doordash": ["doordash.com"],
    "doordash support": ["doordash.com"],
    "uber eats": ["uber.com", "ubereats.com"],
    "ubereats": ["uber.com", "ubereats.com"],
    "grubhub": ["grubhub.com"],
    "instacart": ["instacart.com"],
    "uber": ["uber.com"],
    "uber support": ["uber.com"],
    "lyft": ["lyft.com", "lyftmail.com"],
    "lyft support": ["lyft.com", "lyftmail.com"],
    "etsy": ["etsy.com"],
    "etsy support": ["etsy.com"],
    "wayfair": ["wayfair.com"],
    "ikea": ["ikea.com"],
    "sam's club": ["samsclub.com"],
    "sams club": ["samsclub.com"],
    "macy's": ["macys.com"],
    "macys": ["macys.com"],
    "kohl's": ["kohls.com"],
    "kohls": ["kohls.com"],
    "jcpenney": ["jcpenney.com"],
    "jc penney": ["jcpenney.com"],

    // Japan
    "kddi": ["kddi.com", "au.com"], "au": ["au.com", "kddi.com"],
    "jr east": ["jreast.co.jp"], "eki-net": ["jreast.co.jp", "eki-net.com"],
    "aeon": ["aeon.co.jp", "aeoncredit.co.jp"], "aeon card": ["aeon.co.jp", "aeoncredit.co.jp"],
    "jcb": ["jcb.co.jp", "jcb.com"], "jcb card": ["jcb.co.jp", "jcb.com"],
    "mufg": ["mufg.jp", "bk.mufg.jp"], "mitsubishi ufj": ["mufg.jp", "bk.mufg.jp"],
    "smbc": ["smbc.co.jp", "smbc-card.com"], "sumitomo mitsui": ["smbc.co.jp"],
    "mizuho bank": ["mizuhobank.co.jp", "mizuho-fg.co.jp"],
    "rakuten": ["rakuten.co.jp", "rakuten.com"], "rakuten card": ["rakuten.co.jp", "rakuten-card.co.jp"],
    "mercari": ["mercari.com", "mercari.jp"],
    "japan post": ["japanpost.jp", "post.japanpost.jp"],
    "yamato transport": ["kuronekoyamato.co.jp"], "kuroneko": ["kuronekoyamato.co.jp"],
    "sagawa express": ["sagawa-exp.co.jp"],
    "line account": ["line.me"],
    "docomo": ["docomo.ne.jp", "nttdocomo.co.jp"], "ntt docomo": ["docomo.ne.jp", "nttdocomo.co.jp"],
    "softbank": ["softbank.jp", "mb.softbank.jp"],

    // United Kingdom
    "hsbc": ["hsbc.co.uk", "hsbc.com"], "hsbc bank": ["hsbc.co.uk", "hsbc.com"],
    "barclays": ["barclays.co.uk", "barclays.com"], "barclays bank": ["barclays.co.uk"],
    "lloyds bank": ["lloydsbank.co.uk", "lloydsbank.com"], "lloyds": ["lloydsbank.co.uk"],
    "natwest": ["natwest.com"], "natwest bank": ["natwest.com"],
    "santander": ["santander.co.uk", "santander.com"],
    "monzo": ["monzo.com"], "monzo bank": ["monzo.com"],
    "revolut": ["revolut.com"],
    "hmrc": ["gov.uk"], "hm revenue": ["gov.uk"],
    "dvla": ["gov.uk"],
    "nhs": ["nhs.uk"],
    "royal mail": ["royalmail.com"],
    "evri": ["evri.com"], "hermes": ["evri.com", "myhermes.co.uk"],
    "bt": ["bt.com"], "bt broadband": ["bt.com"],
    "vodafone": ["vodafone.co.uk", "vodafone.com"],
    "o2": ["o2.co.uk"],
    "three mobile": ["three.co.uk"],

    // Australia
    "commonwealth bank": ["commbank.com.au", "cba.com.au"], "commbank": ["commbank.com.au"],
    "westpac": ["westpac.com.au"], "westpac bank": ["westpac.com.au"],
    "anz": ["anz.com.au", "anz.com"], "anz bank": ["anz.com.au"],
    "nab": ["nab.com.au"], "national australia bank": ["nab.com.au"],
    "australia post": ["auspost.com.au"], "auspost": ["auspost.com.au"],
    "ato": ["ato.gov.au"], "australian taxation": ["ato.gov.au"],
    "mygov": ["my.gov.au"],
    "centrelink": ["servicesaustralia.gov.au"],
    "telstra": ["telstra.com.au", "telstra.com"],
    "optus": ["optus.com.au"],

    // India
    "state bank of india": ["sbi.co.in", "onlinesbi.com"], "sbi": ["sbi.co.in", "onlinesbi.com"],
    "hdfc bank": ["hdfcbank.com"], "hdfc": ["hdfcbank.com"],
    "icici bank": ["icicibank.com"], "icici": ["icicibank.com"],
    "paytm": ["paytm.com"],
    "phonepe": ["phonepe.com"],
    "india post": ["indiapost.gov.in"],
    "aadhaar": ["uidai.gov.in"], "uidai": ["uidai.gov.in"],
    "airtel": ["airtel.in"],
    "jio": ["jio.com"], "reliance jio": ["jio.com"],

    // Canada
    "rbc": ["rbc.com", "rbcroyalbank.com"], "royal bank of canada": ["rbc.com"],
    "td canada trust": ["td.com", "tdcanadatrust.com"], "td bank": ["td.com"],
    "scotiabank": ["scotiabank.com"],
    "bmo": ["bmo.com"], "bank of montreal": ["bmo.com"],
    "cibc": ["cibc.com"],
    "canada post": ["canadapost.ca", "canadapost-postescanada.ca"],
    "canada revenue": ["canada.ca", "gc.ca"], "cra": ["canada.ca", "gc.ca"],
    "interac": ["interac.ca"], "interac e-transfer": ["interac.ca"],

    // Europe
    "deutsche bank": ["deutsche-bank.de", "db.com"],
    "bnp paribas": ["bnpparibas.com", "bnpparibas.fr"],
    "ing": ["ing.com", "ing.nl", "ing.de"], "ing bank": ["ing.com", "ing.nl"],
    "rabobank": ["rabobank.nl", "rabobank.com"],
    "credit agricole": ["credit-agricole.fr"],
    "postnl": ["postnl.nl", "postnl.com"],
    "deutsche post": ["deutschepost.de", "dhl.de"],
    "la poste": ["laposte.fr", "laposte.net"],
    "correos": ["correos.es"],
    "poste italiane": ["poste.it", "posteitaliane.it"],
    "deutsche telekom": ["telekom.de", "telekom.com"],
    "swisscom": ["swisscom.ch", "swisscom.com"],

    // South Korea
    "kakaobank": ["kakaobank.com", "kakaocorp.com"], "kakao bank": ["kakaobank.com"],
    "naver": ["naver.com"],
    "coupang": ["coupang.com"],

    // Brazil / Latin America
    "mercado libre": ["mercadolibre.com", "mercadopago.com"], "mercadolibre": ["mercadolibre.com"],
    "mercado pago": ["mercadopago.com", "mercadolibre.com"],
    "nubank": ["nubank.com.br"],
    "banco do brasil": ["bb.com.br"],
    "itau": ["itau.com.br"],
    "bradesco": ["bradesco.com.br"],
    "correios": ["correios.com.br"],

    // Southeast Asia
    "grab": ["grab.com"], "grabpay": ["grab.com"],
    "shopee": ["shopee.com", "shopee.sg", "shopee.co.id"],
    "lazada": ["lazada.com", "lazada.sg", "lazada.co.id"],
    "gcash": ["gcash.com"],
    // Hotels & Hospitality
    "marriott": ["marriott.com", "marriottbonvoy.com", "ritzcarlton.com"], "marriott bonvoy": ["marriott.com", "marriottbonvoy.com"],
    "hilton": ["hilton.com", "hiltonhonors.com", "hamptoninn.com"], "hilton honors": ["hilton.com", "hiltonhonors.com"],
    "holiday inn": ["ihg.com", "holidayinn.com"], "intercontinental": ["ihg.com", "intercontinental.com"],
    "wyndham": ["wyndham.com", "wyndhamhotels.com"], "best western": ["bestwestern.com"],
    "mgm resorts": ["mgmresorts.com", "mgmgrand.com"], "mgm grand": ["mgmresorts.com", "mgmgrand.com"],
    "caesars": ["caesars.com"], "caesars palace": ["caesars.com"],
    // Restaurants & Fast Food
    "mcdonalds": ["mcdonalds.com"], "mcdonald's": ["mcdonalds.com"],
    "starbucks": ["starbucks.com"], "chick-fil-a": ["chick-fil-a.com"],
    "chipotle": ["chipotle.com"], "domino's": ["dominos.com"], "dominos": ["dominos.com"],
    "pizza hut": ["pizzahut.com"], "taco bell": ["tacobell.com"],
    "wendy's": ["wendys.com"], "burger king": ["bk.com", "burgerking.com"],
    "dunkin": ["dunkin.com", "dunkindonuts.com"], "panera": ["panera.com", "panerabread.com"],
    "popeyes": ["popeyes.com"], "subway": ["subway.com"],
    // Pharmacy & Healthcare
    "cvs pharmacy": ["cvs.com"], "cvs health": ["cvs.com", "cvshealth.com"],
    "walgreens": ["walgreens.com"], "rite aid": ["riteaid.com"],
    "labcorp": ["labcorp.com"], "quest diagnostics": ["questdiagnostics.com"],
    // Grocery
    "kroger": ["kroger.com"], "publix": ["publix.com"], "safeway": ["safeway.com"],
    "aldi": ["aldi.us", "aldi.com"], "trader joe's": ["traderjoes.com"],
    "whole foods": ["wholefoodsmarket.com"],
    // Entertainment
    "ticketmaster": ["ticketmaster.com"], "stubhub": ["stubhub.com"],
    "gamestop": ["gamestop.com"], "amc theatres": ["amctheatres.com"],
    // Beauty
    "sephora": ["sephora.com"], "ulta": ["ulta.com", "ultabeauty.com"],
    "bath and body works": ["bathandbodyworks.com"], "bath & body works": ["bathandbodyworks.com"],
    // Airlines
    "british airways": ["britishairways.com", "ba.com"], "air canada": ["aircanada.com"],
    "qatar airways": ["qatarairways.com"], "singapore airlines": ["singaporeair.com"],
    "etihad": ["etihad.com"], "cathay pacific": ["cathaypacific.com"],
    "air france": ["airfrance.com"], "klm": ["klm.com"],
    // Travel
    "priceline": ["priceline.com"], "agoda": ["agoda.com"], "trivago": ["trivago.com"],
    // Real Estate brokerages: These belong in IMPERSONATION_TARGETS only.
    // Industry/vertical brands generate constant false positives in body-only
    // scanning (BRAND_CONTENT_DETECTION) because agents mention competitor brands
    // in every email thread. Display-name impersonation is the correct detection vector.
    "opendoor": ["opendoor.com"], "coldwell banker": ["coldwellbanker.com"],
    "keller williams": ["kw.com", "kellerwilliams.com"], "remax": ["remax.com"], "re/max": ["remax.com"],
    "century 21": ["century21.com"],
    // Tech
    "servicenow": ["servicenow.com"], "workday": ["workday.com"],
    // Telecom

    'glovo': ['glovoapp.com'],
    'wolt': ['wolt.com'],
    'allegro': ['allegro.pl'],
    'ozon': ['ozon.ru'],
    'wildberries': ['wildberries.ru'],
    'yandex': ['yandex.com', 'yandex.ru'],
    'jumia': ['jumia.com'],
    'mercado pago': ['mercadopago.com'],
    'rappi': ['rappi.com'],
    'norwegian air': ['norwegian.com'],
    'finnair': ['finnair.com'],
    'scandinavian airlines': ['sas.se', 'flysas.com'],
    'turkish airlines': ['turkishairlines.com'],
    'swiss air': ['swiss.com'],
    'swiss international': ['swiss.com'],
    'lufthansa': ['lufthansa.com'],
    'garuda indonesia': ['garuda-indonesia.com'],
    'thai airways': ['thaiairways.com'],
    'korean air': ['koreanair.com'],
    'asiana airlines': ['flyasiana.com'],
    'eva air': ['evaair.com'],
    'jetblue': ['jetblue.com'],
    'spirit airlines': ['spirit.com'],
    'frontier airlines': ['flyfrontier.com'],
    'alaska airlines': ['alaskaair.com'],
    'hawaiian airlines': ['hawaiianairlines.com'],
    'air new zealand': ['airnewzealand.com', 'airnewzealand.co.nz'],
    'malaysia airlines': ['malaysiaairlines.com'],
    'philippine airlines': ['philippineairlines.com'],
    'cebu pacific': ['cebupacificair.com'],
    'scoot airlines': ['flyscoot.com'],
    'airasia': ['airasia.com'],
    'china airlines': ['china-airlines.com'],
    'south african airways': ['flysaa.com'],
    'kenya airways': ['kenya-airways.com'],
    'ethiopian airlines': ['ethiopianairlines.com'],
    'egyptair': ['egyptair.com'],
    'royal jordanian': ['rj.com'],
    'saudia': ['saudia.com'],
    'saudi arabian airlines': ['saudia.com'],
    'woolworths': ['woolworths.com.au'],
    'coles': ['coles.com.au'],
    'jb hi-fi': ['jbhifi.com.au'],
    'jb hifi': ['jbhifi.com.au'],
    'harvey norman': ['harveynorman.com.au', 'harveynorman.com'],
    'bunnings': ['bunnings.com.au'],
    'kmart': ['kmart.com.au'],
    'qantas': ['qantas.com', 'qantas.com.au'],
    'virgin australia': ['virginaustralia.com'],
    'seek jobs': ['seek.com.au'],
    'realestate.com.au': ['realestate.com.au', 'rea-group.com'],
    'commbank': ['commbank.com.au'],
    'ampol': ['ampol.com.au'],
    'chemist warehouse': ['chemistwarehouse.com.au'],
    'dan murphy\'s': ['danmurphys.com.au'],
    'dan murphys': ['danmurphys.com.au'],
    'officeworks': ['officeworks.com.au'],
    'big w': ['bigw.com.au'],
    'myer': ['myer.com.au'],
    'david jones': ['davidjones.com'],
    'magazine luiza': ['magazineluiza.com.br'],
    'magalu': ['magazineluiza.com.br'],
    'americanas': ['americanas.com.br'],
    'ifood': ['ifood.com.br'],
    'totvs': ['totvs.com'],
    'petrobras': ['petrobras.com.br'],
    'localiza': ['localiza.com'],
    'azul airlines': ['voeazul.com.br'],
    'azul': ['voeazul.com.br'],
    'gol airlines': ['voegol.com.br'],
    'latam airlines': ['latam.com'],
    'latam': ['latam.com'],
    'tim hortons': ['timhortons.ca', 'timhortons.com'],
    'canadian tire': ['canadiantire.ca'],
    'loblaws': ['loblaws.ca'],
    'loblaw': ['loblaws.ca'],
    'shoppers drug mart': ['shoppersdrugmart.ca'],
    'metro groceries': ['metro.ca'],
    'rogers': ['rogers.com'],
    'bell canada': ['bell.ca'],
    'bell mobility': ['bell.ca'],
    'telus': ['telus.com'],
    'manulife': ['manulife.com', 'manulife.ca'],
    'sun life': ['sunlife.com', 'sunlife.ca'],
    'westjet': ['westjet.com'],
    'roots canada': ['roots.com'],
    'hudson\'s bay': ['thebay.com'],
    'hudsons bay': ['thebay.com'],
    'the bay': ['thebay.com'],
    'alibaba': ['alibaba.com', 'aliexpress.com'],
    'aliexpress': ['alibaba.com', 'aliexpress.com'],
    'taobao': ['alibaba.com', 'aliexpress.com'],
    'tmall': ['alibaba.com', 'aliexpress.com'],
    'tencent': ['tencent.com', 'wechat.com'],
    'wechat': ['tencent.com', 'wechat.com'],
    'jd.com': ['jd.com'],
    'pinduoduo': ['pinduoduo.com'],
    'baidu': ['baidu.com'],
    'xiaomi': ['xiaomi.com', 'mi.com'],
    'huawei': ['huawei.com', 'consumer.huawei.com'],
    'oppo': ['oppo.com'],
    'vivo mobile': ['vivo.com'],
    'bilibili': ['bilibili.com'],
    'meituan': ['meituan.com'],
    'trip.com': ['trip.com', 'ctrip.com'],
    'ctrip': ['trip.com', 'ctrip.com'],
    'china southern': ['csair.com'],
    'china eastern': ['ceair.com'],
    'air china': ['airchina.com'],
    'lvmh': ['lvmh.com', 'louisvuitton.com', 'dior.com', 'tiffany.com'],
    'louis vuitton': ['lvmh.com', 'louisvuitton.com', 'dior.com', 'tiffany.com'],
    'dior': ['lvmh.com', 'louisvuitton.com', 'dior.com', 'tiffany.com'],
    'sephora': ['lvmh.com', 'louisvuitton.com', 'dior.com', 'tiffany.com'],
    'tiffany': ['lvmh.com', 'louisvuitton.com', 'dior.com', 'tiffany.com'],
    'kering': ['kering.com', 'gucci.com'],
    'gucci': ['kering.com', 'gucci.com'],
    'balenciaga': ['kering.com', 'gucci.com'],
    'yves saint laurent': ['kering.com', 'gucci.com'],
    'hermès': ['hermes.com'],
    'hermes': ['hermes.com'],
    'l\'oreal': ['loreal.com'],
    'loreal': ['loreal.com'],
    'l\'oréal': ['loreal.com'],
    'carrefour': ['carrefour.com', 'carrefour.fr'],
    'danone': ['danone.com'],
    'renault': ['renault.com', 'renault.fr'],
    'societe generale': ['societegenerale.com', 'societegenerale.fr'],
    'société générale': ['societegenerale.com', 'societegenerale.fr'],
    'totalenergies': ['totalenergies.com'],
    'decathlon': ['decathlon.com', 'decathlon.fr'],
    'bouygues telecom': ['bouyguestelecom.fr'],
    'bouygues': ['bouyguestelecom.fr'],
    'free mobile': ['free.fr'],
    'adidas': ['adidas.com', 'adidas.de'],
    'siemens': ['siemens.com'],
    'allianz': ['allianz.com', 'allianz.de'],
    'zalando': ['zalando.com', 'zalando.de'],
    'delivery hero': ['deliveryhero.com'],
    'puma': ['puma.com'],
    'mediamarkt': ['mediamarkt.de', 'saturn.de'],
    'media markt': ['mediamarkt.de', 'saturn.de'],
    'saturn': ['mediamarkt.de', 'saturn.de'],
    'aia insurance': ['aia.com'],
    'mtr corporation': ['mtr.com.hk'],
    'hang seng bank': ['hangseng.com'],
    'hong kong broadband': ['hkbn.net'],
    'hkbn': ['hkbn.net'],
    'pccw': ['hkt.com', 'pccw.com'],
    'tata motors': ['tatamotors.com'],
    'mahindra': ['mahindra.com'],
    'infosys': ['infosys.com'],
    'tata consultancy': ['tcs.com'],
    'zomato': ['zomato.com'],
    'swiggy': ['swiggy.com'],
    'flipkart': ['flipkart.com'],
    'reliance': ['reliability.com', 'ril.com'],
    'reliance retail': ['reliability.com', 'ril.com'],
    'reliance jio': ['reliability.com', 'ril.com'],
    'bajaj finserv': ['bajajfinserv.in'],
    'bajaj finance': ['bajajfinserv.in'],
    'kotak mahindra': ['kotak.com'],
    'kotak bank': ['kotak.com'],
    'axis bank': ['axisbank.com'],
    'myntra': ['myntra.com'],
    'nykaa': ['nykaa.com'],
    'ola cabs': ['olacabs.com'],
    'indigo': ['goindigo.in'],
    'indigo airlines': ['goindigo.in'],
    'air india': ['airindia.com'],
    'irctc': ['irctc.co.in'],
    'ferrari': ['ferrari.com'],
    'enel': ['enel.com', 'enel.it'],
    'intesa sanpaolo': ['intesasanpaolo.com'],
    'unicredit': ['unicredit.it', 'unicredit.eu'],
    'wind tre': ['windtre.it'],
    'windtre': ['windtre.it'],
    'sony': ['sony.com', 'playstation.com'],
    'playstation': ['sony.com', 'playstation.com'],
    'nintendo': ['nintendo.com', 'nintendo.co.jp'],
    'panasonic': ['panasonic.com', 'panasonic.jp'],
    'hitachi': ['hitachi.com'],
    'toshiba': ['toshiba.com', 'toshiba.co.jp'],
    'sharp': ['sharp.com', 'sharp.co.jp'],
    'canon': ['canon.com', 'canon.co.jp'],
    'nikon': ['nikon.com'],
    'uniqlo': ['uniqlo.com'],
    'fast retailing': ['uniqlo.com'],
    'japan airlines': ['jal.com', 'jal.co.jp'],
    'all nippon airways': ['ana.co.jp'],
    'ana airlines': ['ana.co.jp'],
    '7-eleven': ['7-eleven.com', 'sej.co.jp'],
    'seven eleven': ['7-eleven.com', 'sej.co.jp'],
    'lawson': ['lawson.co.jp'],
    'familymart': ['family.co.jp'],
    'family mart': ['family.co.jp'],
    'daiso': ['daisoglobal.com', 'daiso-sangyo.co.jp'],
    'america movil': ['americamovil.com', 'telcel.com'],
    'telcel': ['americamovil.com', 'telcel.com'],
    'liverpool mexico': ['liverpool.com.mx'],
    'elektra': ['elektra.com.mx'],
    'volaris': ['volaris.com'],
    'aeromexico': ['aeromexico.com'],
    'saudi telecom': ['stc.com.sa'],
    'al rajhi': ['alrajhibank.com.sa'],
    'alrajhi': ['alrajhibank.com.sa'],
    'emirates': ['emirates.com'],
    'etisalat': ['etisalat.ae'],
    'du telecom': ['du.ae'],
    'jarir': ['jarir.com'],
    'noon': ['noon.com'],
    'careem': ['careem.com'],
    'philips': ['philips.com'],
    'heineken': ['heineken.com'],
    'bol.com': ['bol.com'],
    'coolblue': ['coolblue.nl', 'coolblue.be'],
    'dbs bank': ['dbs.com', 'dbs.com.sg'],
    'ocbc': ['ocbc.com'],
    'singtel': ['singtel.com'],
    'starhub': ['starhub.com'],
    'foodpanda': ['foodpanda.com'],
    'tokopedia': ['tokopedia.com'],
    'gojek': ['gojek.com'],
    'bank central asia': ['bca.co.id'],
    'mandiri': ['bankmandiri.co.id'],
    'telkomsel': ['telkomsel.com'],
    'true corp': ['true.th'],
    'truemove': ['true.th'],
    'dtac': ['dtac.co.th'],
    'globe telecom': ['globe.com.ph'],
    'smart communications': ['smart.com.ph'],
    'maybank': ['maybank.com', 'maybank2u.com.my'],
    'cimb': ['cimb.com'],
    'petronas': ['petronas.com'],
    'shoprite': ['shoprite.co.za'],
    'checkers': ['shoprite.co.za'],
    'woolworths': ['woolworths.co.za'],
    'pick n pay': ['pnp.co.za'],
    'capitec': ['capitecbank.co.za'],
    'first national bank': ['fnb.co.za'],
    'nedbank': ['nedbank.co.za'],
    'discovery health': ['discovery.co.za'],
    'vodacom': ['vodacom.co.za'],
    'takealot': ['takealot.com'],
    'standard bank': ['standardbank.co.za'],
    'absa': ['absa.co.za'],
    'samsung': ['samsung.com'],
    'lg electronics': ['lg.com'],
    'sk telecom': ['sktelecom.com', 'tworld.co.kr'],
    'kt corp': ['kt.com'],
    'kt telecom': ['kt.com'],
    'kakao': ['kakao.com', 'kakaocorp.com'],
    'kakaotalk': ['kakao.com', 'kakaocorp.com'],
    'lotte': ['lotte.co.kr', 'lotteshopping.com'],
    'shinsegae': ['shinsegae.com', 'emart.com'],
    'emart': ['shinsegae.com', 'emart.com'],
    'gmarket': ['gmarket.co.kr'],
    '11st': ['11st.co.kr'],
    '11street': ['11st.co.kr'],
    'zara': ['zara.com', 'inditex.com'],
    'inditex': ['zara.com', 'inditex.com'],
    'bbva': ['bbva.com', 'bbva.es'],
    'telefonica': ['telefonica.com', 'movistar.com', 'movistar.es'],
    'movistar': ['telefonica.com', 'movistar.com', 'movistar.es'],
    'el corte inglés': ['elcorteingles.es'],
    'el corte ingles': ['elcorteingles.es'],
    'iberia airlines': ['iberia.com'],
    'iberia': ['iberia.com'],
    'caixabank': ['caixabank.com', 'caixabank.es'],
    'ericsson': ['ericsson.com'],
    'telia': ['telia.com', 'telia.se'],
    'nestlé': ['nestle.com', 'nespresso.com', 'nescafe.com', 'readyrefresh.com'],
    'nestle': ['nestle.com', 'nespresso.com', 'nescafe.com', 'readyrefresh.com'],
    'nespresso': ['nestle.com', 'nespresso.com', 'nescafe.com', 'readyrefresh.com'],
    'nescafe': ['nestle.com', 'nespresso.com', 'nescafe.com', 'readyrefresh.com'],
    'readyrefresh': ['nestle.com', 'nespresso.com', 'nescafe.com', 'readyrefresh.com'],
    'zurich insurance': ['zurich.com'],
    'zurich': ['zurich.com'],
    'swiss post': ['post.ch'],
    'swiss life': ['swisslife.com'],
    'tesco': ['tesco.com', 'tesco.co.uk'],
    'tesco clubcard': ['tesco.com', 'tesco.co.uk'],
    'sainsbury\'s': ['sainsburys.co.uk'],
    'sainsburys': ['sainsburys.co.uk'],
    'marks & spencer': ['marksandspencer.com'],
    'marks and spencer': ['marksandspencer.com'],
    'jd sports': ['jdsports.co.uk', 'jdsports.com'],
    'primark': ['primark.com'],
    'boots pharmacy': ['boots.com'],
    'boots': ['boots.com'],
    'greggs': ['greggs.co.uk'],
    'premier inn': ['premierinn.com'],
    'whitbread': ['premierinn.com'],
    'easyjet': ['easyjet.com'],
    'ryanair': ['ryanair.com'],
    'british gas': ['britishgas.co.uk'],
    'centrica': ['britishgas.co.uk'],
    'sse energy': ['sse.co.uk'],
    'just eat': ['just-eat.co.uk', 'just-eat.com'],
    'ocado': ['ocado.com'],
    'asos': ['asos.com'],
    'boohoo': ['boohoo.com'],
    'rightmove': ['rightmove.co.uk'],
    'auto trader': ['autotrader.co.uk'],
    'deliveroo': ['deliveroo.co.uk', 'deliveroo.com'],
    'morrisons': ['morrisons.com'],
    'currys': ['currys.co.uk'],
    'argos': ['argos.co.uk'],
    'john lewis': ['johnlewis.com'],
    'waitrose': ['waitrose.com'],
    'screwfix': ['screwfix.com'],
    'halfords': ['halfords.com'],
    'sky tv': ['sky.com'],
    'three mobile': ['three.co.uk'],
    'three uk': ['three.co.uk'],
    'ee mobile': ['ee.co.uk'],
    'virgin media': ['virginmedia.com'],
    'virgin atlantic': ['virginatlantic.com'],
    'wh smith': ['whsmith.co.uk'],
    'whsmith': ['whsmith.co.uk'],
    'pret a manger': ['pret.co.uk', 'pret.com'],
    'pret': ['pret.co.uk', 'pret.com'],
    'nando\'s': ['nandos.co.uk', 'nandos.com'],
    'nandos': ['nandos.co.uk', 'nandos.com'],
    'asda': ['asda.com'],
    'iceland foods': ['iceland.co.uk'],
    'lidl': ['lidl.co.uk', 'lidl.com', 'lidl.de'],
    'superdry': ['superdry.com'],
    'river island': ['riverisland.com'],
    'topshop': ['topshop.com'],
    'sports direct': ['sportsdirect.com'],
    'the body shop': ['thebodyshop.com'],
    'tesla': ['tesla.com'],
    'ford motor': ['ford.com'],
    'general motors': ['gm.com', 'chevrolet.com', 'buick.com', 'cadillac.com', 'gmc.com'],
    'chevrolet': ['gm.com', 'chevrolet.com', 'buick.com', 'cadillac.com', 'gmc.com'],
    'chevy': ['gm.com', 'chevrolet.com', 'buick.com', 'cadillac.com', 'gmc.com'],
    'buick': ['gm.com', 'chevrolet.com', 'buick.com', 'cadillac.com', 'gmc.com'],
    'cadillac': ['gm.com', 'chevrolet.com', 'buick.com', 'cadillac.com', 'gmc.com'],
    'toyota': ['toyota.com', 'lexus.com'],
    'lexus': ['toyota.com', 'lexus.com'],
    'honda': ['honda.com', 'acura.com'],
    'acura': ['honda.com', 'acura.com'],
    'hyundai': ['hyundai.com', 'hyundaiusa.com'],
    'nissan': ['nissanusa.com', 'infiniti.com', 'nissan.com'],
    'infiniti': ['nissanusa.com', 'infiniti.com', 'nissan.com'],
    'subaru': ['subaru.com'],
    'mazda': ['mazda.com', 'mazdausa.com'],
    'mercedes-benz': ['mercedes-benz.com', 'mbusa.com'],
    'mercedes benz': ['mercedes-benz.com', 'mbusa.com'],
    'volkswagen': ['volkswagen.com', 'vw.com'],
    'audi': ['audi.com', 'audiusa.com'],
    'volvo': ['volvo.com', 'volvocars.com'],
    'rivian': ['rivian.com'],
    'lucid motors': ['lucidmotors.com'],
    'lucid': ['lucidmotors.com'],
    'stellantis': ['stellantis.com', 'jeep.com', 'chrysler.com', 'dodge.com', 'ramtrucks.com'],
    'jeep wrangler': ['jeep.com', 'stellantis.com'],
    'jeep cherokee': ['jeep.com', 'stellantis.com'],
    'jeep grand cherokee': ['jeep.com', 'stellantis.com'],
    'jeep gladiator': ['jeep.com', 'stellantis.com'],
    'chrysler': ['stellantis.com', 'jeep.com', 'chrysler.com', 'dodge.com', 'ramtrucks.com'],
    'dodge charger': ['dodge.com', 'stellantis.com'],
    'dodge challenger': ['dodge.com', 'stellantis.com'],
    'dodge durango': ['dodge.com', 'stellantis.com'],
    'ram truck': ['ramtrucks.com', 'stellantis.com'],
    'ram 1500': ['ramtrucks.com', 'stellantis.com'],
    'ram 2500': ['ramtrucks.com', 'stellantis.com'],
    'ram 3500': ['ramtrucks.com', 'stellantis.com'],
    'goldman sachs': ['goldmansachs.com', 'gs.com'],
    'merrill lynch': ['ml.com', 'merrilledge.com'],
    'merrill': ['ml.com', 'merrilledge.com'],
    'edward jones': ['edwardjones.com'],
    'raymond james': ['raymondjames.com'],
    'e*trade': ['etrade.com'],
    'etrade': ['etrade.com'],
    'td ameritrade': ['tdameritrade.com'],
    'lendingclub': ['lendingclub.com'],
    'lending club': ['lendingclub.com'],
    'rocket mortgage': ['rocketmortgage.com', 'quickenloans.com', 'rocketcompanies.com'],
    'quicken loans': ['rocketmortgage.com', 'quickenloans.com', 'rocketcompanies.com'],
    'rocket companies': ['rocketmortgage.com', 'quickenloans.com', 'rocketcompanies.com'],
    'credit karma': ['creditkarma.com'],
    'nerdwallet': ['nerdwallet.com'],
    'marcus by goldman': ['marcus.com'],
    'marcus savings': ['marcus.com'],
    'wealthfront': ['wealthfront.com'],
    'betterment': ['betterment.com'],
    'lemonade': ['lemonade.com'],
    'root insurance': ['joinroot.com'],
    'oscar health': ['hioscar.com'],
    'discover card': ['discover.com'],
    'discover financial': ['discover.com'],
    'discover bank': ['discover.com'],
    'discover secure message': ['discover.com'],
    'coca-cola': ['coca-cola.com', 'cocacola.com'],
    'coca cola': ['coca-cola.com', 'cocacola.com'],
    'pepsi': ['pepsi.com', 'pepsico.com'],
    'pepsico': ['pepsi.com', 'pepsico.com'],
    'kentucky fried chicken': ['kfc.com'],
    'olive garden': ['olivegarden.com', 'darden.com'],
    'darden': ['olivegarden.com', 'darden.com'],
    'longhorn steakhouse': ['longhornsteakhouse.com'],
    'red lobster': ['redlobster.com'],
    'applebee\'s': ['applebees.com'],
    'applebees': ['applebees.com'],
    'ihop': ['ihop.com'],
    'denny\'s': ['dennys.com'],
    'dennys': ['dennys.com'],
    'jack in the box': ['jackinthebox.com'],
    'sonic drive-in': ['sonicdrivein.com'],
    'sonic drive in': ['sonicdrivein.com'],
    'papa john\'s': ['papajohns.com'],
    'papa johns': ['papajohns.com'],
    'little caesars': ['littlecaesars.com'],
    'little caesar\'s': ['littlecaesars.com'],
    'wingstop': ['wingstop.com'],
    'shake shack': ['shakeshack.com'],
    'cracker barrel': ['crackerbarrel.com'],
    'dutch bros': ['dutchbros.com'],
    'arby\'s': ['arbys.com'],
    'arbys': ['arbys.com'],
    'buffalo wild wings': ['buffalowildwings.com'],
    'red robin': ['redrobin.com'],
    'outback steakhouse': ['outback.com'],
    'noodles & company': ['noodles.com'],
    'five guys': ['fiveguys.com'],
    'jersey mike\'s': ['jerseymikes.com'],
    'jersey mikes': ['jerseymikes.com'],
    'jimmy john\'s': ['jimmyjohns.com'],
    'jimmy johns': ['jimmyjohns.com'],
    'panda express': ['pandaexpress.com'],
    'hellofresh': ['hellofresh.com'],
    'hello fresh': ['hellofresh.com'],
    'blue apron': ['blueapron.com'],
    'teladoc': ['teladoc.com', 'teladochealth.com'],
    'goodrx': ['goodrx.com'],
    'hims': ['forhims.com', 'forhers.com'],
    'hers': ['forhims.com', 'forhers.com'],
    'hims & hers': ['forhims.com', 'forhers.com'],
    'zocdoc': ['zocdoc.com'],
    'one medical': ['onemedical.com'],
    'anthem': ['anthem.com', 'elevancehealth.com'],
    'elevance health': ['anthem.com', 'elevancehealth.com'],
    'centene': ['centene.com', 'ambetterhealth.com'],
    'ambetter': ['centene.com', 'ambetterhealth.com'],
    'molina healthcare': ['molinahealthcare.com'],
    'wellcare': ['wellcare.com'],
    'disney': ['disney.com', 'disneyplus.com', 'go.com', 'disneyland.disney.go.com', 'disneyworld.disney.go.com', 'd23.com', 'thewaltdisneycompany.com', 'disneyonline.com'],
    'walt disney': ['disney.com', 'disneyplus.com', 'go.com', 'disneyland.disney.go.com', 'disneyworld.disney.go.com', 'd23.com', 'thewaltdisneycompany.com', 'disneyonline.com'],
    'disneyland': ['disney.com', 'disneyplus.com', 'go.com', 'disneyland.disney.go.com', 'disneyworld.disney.go.com', 'd23.com', 'thewaltdisneycompany.com', 'disneyonline.com'],
    'disney world': ['disney.com', 'disneyplus.com', 'go.com', 'disneyland.disney.go.com', 'disneyworld.disney.go.com', 'd23.com', 'thewaltdisneycompany.com', 'disneyonline.com'],
    'hbo max': ['hbo.com', 'hbomax.com', 'max.com'],
    'warner bros': ['warnerbros.com', 'wbd.com'],
    'warner brothers': ['warnerbros.com', 'wbd.com'],
    'peacock tv': ['peacocktv.com'],
    'peacock streaming': ['peacocktv.com'],
    'paramount+': ['paramountplus.com', 'paramount.com'],
    'paramount plus': ['paramountplus.com', 'paramount.com'],
    'espn': ['espn.com'],
    'twitch': ['twitch.tv'],
    'audible': ['audible.com'],
    'kindle unlimited': ['amazon.com', 'kindle.com'],
    'siriusxm': ['siriusxm.com'],
    'sirius xm': ['siriusxm.com'],
    'discovery+': ['discoveryplus.com'],
    'discovery plus': ['discoveryplus.com'],
    'peloton': ['onepeloton.com'],
    'planet fitness': ['planetfitness.com'],
    '24 hour fitness': ['24hourfitness.com'],
    'old navy': ['gap.com', 'oldnavy.com', 'bananarepublic.com', 'athleta.com'],
    'banana republic': ['gap.com', 'oldnavy.com', 'bananarepublic.com', 'athleta.com'],
    'athleta': ['gap.com', 'oldnavy.com', 'bananarepublic.com', 'athleta.com'],
    'lululemon': ['lululemon.com'],
    'under armour': ['underarmour.com'],
    'under armor': ['underarmour.com'],
    'tj maxx': ['tjmaxx.com', 'tjx.com', 'marshalls.com', 'homegoods.com'],
    'tjmaxx': ['tjmaxx.com', 'tjx.com', 'marshalls.com', 'homegoods.com'],
    'marshalls': ['tjmaxx.com', 'tjx.com', 'marshalls.com', 'homegoods.com'],
    'homegoods': ['tjmaxx.com', 'tjx.com', 'marshalls.com', 'homegoods.com'],
    'ross stores': ['rossstores.com'],
    'ross dress for less': ['rossstores.com'],
    'burlington': ['burlington.com'],
    'dollar general': ['dollargeneral.com'],
    'dollar tree': ['dollartree.com', 'familydollar.com'],
    'family dollar': ['dollartree.com', 'familydollar.com'],
    'five below': ['fivebelow.com'],
    'dicks sporting goods': ['dickssportinggoods.com', 'dcsg.com', 'notifications.dcsg.com'],
    'dick\'s sporting': ['dickssportinggoods.com', 'dcsg.com', 'notifications.dcsg.com'],
    'foot locker': ['footlocker.com'],
    'footlocker': ['footlocker.com'],
    'victoria\'s secret': ['victoriassecret.com'],
    'victorias secret': ['victoriassecret.com'],
    'nordstrom': ['nordstrom.com', 'nordstromrack.com'],
    'nordstrom rack': ['nordstrom.com', 'nordstromrack.com'],
    'petco': ['petco.com'],
    'chewy': ['chewy.com'],
    'williams sonoma': ['williams-sonoma.com', 'potterybarn.com', 'westelm.com'],
    'williams-sonoma': ['williams-sonoma.com', 'potterybarn.com', 'westelm.com'],
    'pottery barn': ['williams-sonoma.com', 'potterybarn.com', 'westelm.com'],
    'west elm': ['williams-sonoma.com', 'potterybarn.com', 'westelm.com'],
    'restoration hardware': ['rh.com', 'restorationhardware.com'],
    'crate and barrel': ['crateandbarrel.com', 'cb2.com'],
    'crate & barrel': ['crateandbarrel.com', 'cb2.com'],
    'autozone': ['autozone.com'],
    'o\'reilly auto': ['oreillyauto.com'],
    'oreilly auto': ['oreillyauto.com'],
    'advance auto parts': ['advanceautoparts.com'],
    'tractor supply': ['tractorsupply.com'],
    'carmax': ['carmax.com'],
    'carvana': ['carvana.com'],
    'bed bath': ['bedbathandbeyond.com'],
    'pier 1': ['pier1.com'],
    'pier one': ['pier1.com'],
    'office depot': ['officedepot.com'],
    'officemax': ['officedepot.com'],
    'staples': ['staples.com'],
    'big lots': ['biglots.com'],
    'michaels': ['michaels.com'],
    'hobby lobby': ['hobbylobby.com'],
    'ace hardware': ['acehardware.com'],
    'menards': ['menards.com'],
    'overstock': ['overstock.com'],
    'zappos': ['zappos.com'],
    'wish': ['wish.com'],
    'temu': ['temu.com'],
    'shein': ['shein.com', 'us.shein.com'],
    'poshmark': ['poshmark.com'],
    'grammarly': ['grammarly.com'],
    'coursera': ['coursera.org'],
    'udemy': ['udemy.com'],
    'linkedin learning': ['linkedin.com', 'learning.linkedin.com'],
    'duolingo': ['duolingo.com'],
    'masterclass': ['masterclass.com'],
    'calm app': ['calm.com'],
    'headspace': ['headspace.com'],
    'weight watchers': ['weightwatchers.com', 'ww.com'],
    'weightwatchers': ['weightwatchers.com', 'ww.com'],
    'cloudflare': ['cloudflare.com'],
    'twilio': ['twilio.com'],
    'zendesk': ['zendesk.com'],
    'mailchimp': ['mailchimp.com'],
    'squarespace': ['squarespace.com'],
    'shopify': ['shopify.com', 'myshopify.com'],
    'godaddy': ['godaddy.com'],
    'github': ['github.com'],
    'atlassian': ['atlassian.com', 'atlassian.net'],
    'jira': ['atlassian.com', 'atlassian.net'],
    'confluence': ['atlassian.com', 'atlassian.net'],
    'canva': ['canva.com'],
    'figma': ['figma.com'],
    'openai': ['openai.com', 'chatgpt.com'],
    'chatgpt': ['openai.com', 'chatgpt.com'],
    'oracle': ['oracle.com'],
    'intuit': ['intuit.com'],
    'square': ['squareup.com', 'square.com'],
    'toast pos': ['toasttab.com'],
    'toast inc': ['toasttab.com'],
    'tripadvisor': ['tripadvisor.com'],
    'trip advisor': ['tripadvisor.com'],
    'hotels.com': ['hotels.com'],
    'vrbo': ['vrbo.com'],
    'hopper': ['hopper.com'],
    'kayak': ['kayak.com'],
    'travelocity': ['travelocity.com'],
    'orbitz': ['orbitz.com'],
    // Cloudflare Top 50 Gap Fill
    'caixa': ['caixa.gov.br', 'caixa.com.br'],
    'caixa economica': ['caixa.gov.br', 'caixa.com.br'],
    'caixa economica federal': ['caixa.gov.br', 'caixa.com.br'],
    'bank millennium': ['bankmillennium.pl'],
    'millennium bank': ['bankmillennium.pl'],
    'inpost': ['inpost.pl', 'inpost.eu', 'inpost.co.uk'],
    'dpd': ['dpd.com', 'dpd.de', 'dpd.co.uk', 'dpd.fr', 'dpd.com.pl'],
    'dpd delivery': ['dpd.com', 'dpd.de', 'dpd.co.uk'],
    'deutscher paketdienst': ['dpd.com', 'dpd.de'],
    'lexisnexis': ['lexisnexis.com', 'lexis.com'],
    'lexis nexis': ['lexisnexis.com', 'lexis.com'],
    'nicos': ['nicos.co.jp', 'cr.mufg.jp'],
    'nicos card': ['nicos.co.jp', 'cr.mufg.jp'],
    'mitsubishi ufj nicos': ['nicos.co.jp', 'cr.mufg.jp'],
    'national police agency': ['npa.go.jp'],
    'japan police': ['npa.go.jp'],
    'banco de la nación argentina': ['bna.com.ar'],
    'afip': ['afip.gob.ar'],
    'university of buenos aires': ['uba.ar'],
    'uba': ['uba.ar'],
    'bank australia': ['bankaust.com.au'],
    'ing australia': ['ing.com.au'],
    'macquarie bank': ['macquarie.com.au'],
    'australian federal police': ['afp.gov.au'],
    'department of home affairs': ['homeaffairs.gov.au'],
    'australian national university': ['anu.edu.au'],
    'anu': ['anu.edu.au'],
    'monash university': ['monash.edu'],
    'university of melbourne': ['unimelb.edu.au'],
    'university of new south wales': ['unsw.edu.au'],
    'unsw': ['unsw.edu.au'],
    'university of queensland': ['uq.edu.au'],
    'university of sydney': ['sydney.edu.au'],
    'agl': ['agl.com.au'],
    'energyaustralia': ['energyaustralia.com.au'],
    'origin energy': ['originenergy.com.au'],
    'erste bank': ['erstebank.at'],
    'raiffeisen bank international': ['rbinternational.com'],
    'unicredit bank austria': ['bankaustria.at'],
    'finanzonline': ['finanzonline.bmf.gv.at'],
    'oesterreich.gv.at': ['oesterreich.gv.at'],
    'a1 telekom austria': ['a1.net'],
    'tu wien': ['tuwien.at'],
    'university of vienna': ['univie.ac.at'],
    'bnp paribas fortis': ['bnpparibasfortis.be'],
    'belfius': ['belfius.be'],
    'ing belgium': ['ing.be'],
    'kbc': ['kbc.com'],
    'belgian federal police': ['police.be'],
    'fps finance': ['finance.belgium.be'],
    'spf finances': ['finance.belgium.be'],
    'orange belgium': ['orange.be'],
    'proximus': ['proximus.be'],
    'telenet': ['telenet.be'],
    'ghent university': ['ugent.be'],
    'ku leuven': ['kuleuven.be'],
    'caixa econômica federal': ['caixa.gov.br'],
    'santander brasil': ['santander.com.br'],
    'detran': ['gov.br'],
    'detran-sp': ['detran.sp.gov.br'],
    'inss': ['inss.gov.br'],
    'polícia federal': ['pf.gov.br'],
    'receita federal do brasil': ['rfb.gov.br'],
    'gov.br': ['gov.br'],
    'university of sao paulo': ['usp.br'],
    'usp': ['usp.br'],
    'eletrobras': ['eletrobras.com'],
    'enel brasil': ['enel.com.br'],
    'itaipu binacional': ['itaipu.gov.br'],
    'sabesp': ['sabesp.com.br'],
    'eq bank': ['eqbank.ca'],
    'national bank of canada': ['nbc.ca'],
    'tangerine': ['tangerine.ca'],
    'atb financial': ['atb.com'],
    'affinity credit union': ['affinitycu.ca'],
    'coast capital savings': ['coastcapitalsavings.com'],
    'desjardins': ['desjardins.com'],
    'first west credit union': ['firstwestcu.ca'],
    'meridian credit union': ['meridiancu.ca'],
    'servus credit union': ['servus.ca'],
    'vancity': ['vancity.com'],
    'canada revenue agency': ['cra-arc.gc.ca'],
    'revenu québec': ['revenuquebec.ca'],
    'serviceontario': ['ontario.ca'],
    'bell': ['bell.ca'],
    'mcgill university': ['mcgill.ca'],
    'university of alberta': ['ualberta.ca'],
    'university of british columbia': ['ubc.ca'],
    'university of toronto': ['utoronto.ca'],
    'university of waterloo': ['uwaterloo.ca'],
    'bc hydro': ['bchydro.com'],
    'enbridge gas': ['enbridgegas.com'],
    'hydro-québec': ['hydroquebec.com'],
    'ontario power generation': ['opg.com'],
    'toronto hydro': ['torontohydro.com'],
    'banco de chile': ['bancochile.cl'],
    'sii': ['sii.cl'],
    'universidad de chile': ['uchile.cl'],
    'agricultural bank of china': ['abchina.com'],
    'abc': ['abchina.com'],
    'bank of china': ['boc.cn'],
    'china construction bank': ['ccb.com'],
    'ccb': ['ccb.com'],
    'china merchants bank': ['cmbchina.com'],
    'industrial and commercial bank of china': ['icbc.com.cn'],
    'icbc': ['icbc.com.cn'],
    'webank': ['webank.com'],
    'ministry of public security': ['mps.gov.cn'],
    'national immigration administration': ['nia.gov.cn'],
    'state taxation administration': ['chinatax.gov.cn'],
    'fudan university': ['fudan.edu.cn'],
    'hong kong university of science and technology': ['hkust.edu.hk'],
    'hkust': ['hkust.edu.hk'],
    'peking university': ['pku.edu.cn'],
    'shanghai jiao tong university': ['sjtu.edu.cn'],
    'tsinghua university': ['tsinghua.edu.cn'],
    'university of hong kong': ['hku.hk'],
    'china southern power grid': ['csg.cn'],
    'state grid corporation of china': ['sgcc.com.cn'],
    'banco de la república': ['banrep.gov.co'],
    'colombia': ['banrep.gov.co'],
    'dian': ['dian.gov.co'],
    'national university of colombia': ['unal.edu.co'],
    'česká spořitelna': ['csas.cz'],
    'finanční správa': ['financnisprava.cz'],
    'danske bank': ['danskebank.com'],
    'nykredit': ['nykredit.dk'],
    'postnord denmark': ['postnord.dk'],
    'borger.dk': ['borger.dk'],
    'danish police': ['politi.dk'],
    'skat': ['skat.dk'],
    'tax agency': ['skat.dk'],
    'technical university of denmark': ['dtu.dk'],
    'dtu': ['dtu.dk'],
    'university of copenhagen': ['ku.dk'],
    'national bank of egypt': ['nbe.com.eg'],
    'egyptian national post organization': ['egyptpost.org'],
    'egypt passport/immigration': ['moi.gov.eg'],
    'moi portal': ['moi.gov.eg'],
    'egyptian tax authority': ['eta.gov.eg'],
    'aalto university': ['aalto.fi'],
    'university of helsinki': ['helsinki.fi'],
    'boursorama banque': ['boursorama.com'],
    'crédit agricole': ['credit-agricole.com'],
    'crédit lyonnais': ['lcl.fr'],
    'lcl': ['lcl.fr'],
    'crédit mutuel': ['creditmutuel.fr'],
    'groupe bpce': ['bpce.fr'],
    'la banque postale': ['labanquepostale.fr'],
    'chronopost': ['chronopost.fr'],
    'ants': ['ants.gouv.fr'],
    'assurance maladie': ['ameli.fr'],
    'caf': ['caf.fr'],
    'french national police': ['police-nationale.interieur.gouv.fr'],
    'service-public.fr': ['service-public.fr'],
    'impots.gouv.fr': ['impots.gouv.fr'],
    'bredin prat': ['bredinprat.com'],
    'gide loyrette nouel': ['gide.com'],
    'free': ['free.fr'],
    'iliad': ['free.fr'],
    'sorbonne université': ['sorbonne-universite.fr'],
    'université psl': ['psl.eu'],
    'école polytechnique': ['polytechnique.edu'],
    'edf': ['edf.fr'],
    'engie': ['engie.com'],
    'rte': ['rte-france.com'],
    'france transmission': ['rte-france.com'],
    'veolia': ['veolia.com'],
    'commerzbank': ['commerzbank.com'],
    'dz bank': ['dzbank.com'],
    'kfw': ['kfw.de'],
    'n26': ['n26.com'],
    'bvg': ['bvg.de'],
    'bundesportal': ['bund.de'],
    'bundeszentralamt für steuern': ['bzst.de'],
    'bzst': ['bzst.de'],
    'deutsche rentenversicherung': ['deutsche-rentenversicherung.de'],
    'federal employment agency': ['arbeitsagentur.de'],
    'federal police': ['bundespolizei.de'],
    'bundespolizei': ['bundespolizei.de'],
    'kraftfahrt-bundesamt': ['kba.de'],
    'kba': ['kba.de'],
    'zoll': ['zoll.de'],
    'german customs': ['zoll.de'],
    'gleiss lutz': ['gleisslutz.com'],
    'hengeler mueller': ['hengeler.com'],
    'noerr': ['noerr.com'],
    'vodafone germany': ['vodafone.de'],
    'heidelberg university': ['uni-heidelberg.de'],
    'lmu munich': ['lmu.de'],
    'rwth aachen university': ['rwth-aachen.de'],
    'technical university of munich': ['tum.de'],
    'tum': ['tum.de'],
    'e.on': ['eon.com'],
    'enbw': ['enbw.com'],
    'rwe': ['rwe.com'],
    'stadtwerke münchen': ['swm.de'],
    'vattenfall germany': ['vattenfall.de'],
    'bdo': ['bdo.com'],
    'bdo uk': ['bdo.co.uk'],
    'bdo usa': ['bdo.com'],
    'baker tilly': ['bakertilly.com'],
    'crowe': ['crowe.com'],
    'crowe uk': ['crowe.co.uk'],
    'deloitte': ['deloitte.com'],
    'ey': ['ey.com'],
    'grant thornton': ['grantthornton.global'],
    'grant thornton us': ['grantthornton.com'],
    'hlb': ['hlb.global'],
    'kpmg': ['kpmg.com'],
    'kreston global': ['kreston.com'],
    'mazars': ['mazars.com'],
    'moore global': ['moore-global.com'],
    'nexia': ['nexia.com'],
    'pkf': ['pkf.com'],
    'primeglobal': ['primeglobal.net'],
    'pwc': ['pwc.com'],
    'rsm': ['rsm.global'],
    'rsm us': ['rsmus.com'],
    'gls': ['gls-group.com'],
    'alpha bank': ['alpha.gr'],
    'aade': ['aade.gr'],
    'otp bank': ['otpbank.hu'],
    'nav': ['nav.gov.hu'],
    'indusind bank': ['indusind.com'],
    'kotak mahindra bank': ['kotak.com'],
    'digilocker': ['digilocker.gov.in'],
    'epfo': ['epfindia.gov.in'],
    'gst portal': ['gst.gov.in'],
    'income tax department': ['incometax.gov.in'],
    'npci': ['npci.org.in'],
    'passport seva': ['passportindia.gov.in'],
    'iit bombay': ['iitb.ac.in'],
    'iit delhi': ['iitd.ac.in'],
    'iit madras': ['iitm.ac.in'],
    'indian institute of science': ['iisc.ac.in'],
    'iisc': ['iisc.ac.in'],
    'indian institute of technology bombay': ['iitb.ac.in'],
    'indian institute of technology delhi': ['iitd.ac.in'],
    'indian institute of technology kanpur': ['iitk.ac.in'],
    'bni': ['bni.co.id'],
    'bri': ['bri.co.id'],
    'bank mandiri': ['bankmandiri.co.id'],
    'jenius': ['jenius.com'],
    'btpn': ['jenius.com'],
    'pos indonesia': ['posindonesia.co.id'],
    'directorate general of taxes': ['pajak.go.id'],
    'djp': ['pajak.go.id'],
    'immigration': ['imigrasi.go.id'],
    'pln': ['pln.co.id'],
    'aib': ['aib.ie'],
    'bank of ireland': ['bankofireland.com'],
    'permanent tsb': ['ptsb.ie'],
    'an garda síochána': ['garda.ie'],
    'department of social protection': ['gov.ie'],
    'irish revenue': ['revenue.ie'],
    'revenue commissioners': ['revenue.ie'],
    'revenue.ie': ['revenue.ie'],
    'trinity college dublin': ['tcd.ie'],
    'university college dublin': ['ucd.ie'],
    'bank hapoalim': ['bankhapoalim.co.il'],
    'bank leumi': ['leumi.co.il'],
    'israel discount bank': ['discountbank.co.il'],
    'mizrahi-tefahot': ['mizrahi-tefahot.co.il'],
    'israel tax authority': ['taxes.gov.il'],
    'population and immigration authority': ['gov.il'],
    'bper banca': ['bper.it'],
    'banco bpm': ['bancobpm.it'],
    'agenzia delle entrate': ['agenziaentrate.gov.it'],
    'inps': ['inps.it'],
    'ministero dell\'interno': ['interno.gov.it'],
    'ministero delle infrastrutture e dei trasporti': ['mit.gov.it'],
    'polizia di stato': ['poliziadistato.it'],
    'bonellierede': ['bonellierede.com'],
    'chiomenti': ['chiomenti.net'],
    'tim': ['tim.it'],
    'vodafone italy': ['vodafone.it'],
    'bocconi university': ['unibocconi.it'],
    'politecnico di milano': ['polimi.it'],
    'polytechnic university of turin': ['polito.it'],
    'sapienza university of rome': ['uniroma1.it'],
    'university of bologna': ['unibo.it'],
    'university of milan': ['unimi.it'],
    'a2a': ['a2a.eu'],
    'acea': ['acea.it'],
    'snam': ['snam.it'],
    'terna': ['terna.it'],
    'japan post bank': ['jp-bank.japanpost.jp'],
    'rakuten bank': ['rakuten-bank.co.jp'],
    'immigration services agency of japan': ['isa.go.jp'],
    'japan pension service': ['nenkin.go.jp'],
    'mynumber portal': ['myna.go.jp'],
    'national tax agency': ['nta.go.jp'],
    'nta': ['nta.go.jp'],
    'kyoto university': ['kyoto-u.ac.jp'],
    'osaka university': ['osaka-u.ac.jp'],
    'tohoku university': ['tohoku.ac.jp'],
    'university of tokyo': ['u-tokyo.ac.jp'],
    'kansai electric power': ['kepco.co.jp'],
    'kepco': ['kepco.co.jp'],
    'osaka gas': ['osakagas.co.jp'],
    'tepco': ['tepco.co.jp'],
    'tokyo gas': ['tokyo-gas.co.jp'],
    'equity bank kenya': ['equitybank.co.ke'],
    'kcb bank': ['kcbgroup.com'],
    'kenya post': ['posta.co.ke'],
    'kenya revenue authority': ['kra.go.ke'],
    'kra': ['kra.go.ke'],
    'ecitizen kenya': ['ecitizen.go.ke'],
    'safaricom': ['safaricom.co.ke'],
    'kenya power': ['kplc.co.ke'],
    'hong leong bank': ['hlb.com.my'],
    'public bank': ['publicbank.com.my'],
    'rhb bank': ['rhbgroup.com'],
    'pos malaysia': ['pos.com.my'],
    'jabatan imigresen malaysia': ['imi.gov.my'],
    'lhdn': ['hasil.gov.my'],
    'bbva méxico': ['bbva.mx'],
    'banco azteca': ['bancoazteca.com.mx'],
    'banorte': ['banorte.com'],
    'citibanamex': ['banamex.com'],
    'santander méxico': ['santander.com.mx'],
    'correos de méxico': ['correosdemexico.gob.mx'],
    'imss': ['imss.gob.mx'],
    'sat.gob': ['sat.gob.mx'],
    'sat mexico': ['sat.gob.mx'],
    'servicio de administracion tributaria': ['sat.gob.mx'],
    'factura sat': ['sat.gob.mx'],
    'sep': ['sep.gob.mx'],
    'secretaría de relaciones exteriores': ['sre.gob.mx'],
    'sre': ['sre.gob.mx'],
    'national autonomous university of mexico': ['unam.mx'],
    'unam': ['unam.mx'],
    'tecnológico de monterrey': ['tec.mx'],
    'cfe': ['cfe.mx'],
    'conagua': ['conagua.gob.mx'],
    'abn amro': ['abnamro.com'],
    'bunq': ['bunq.com'],
    'belastingdienst': ['belastingdienst.nl'],
    'duo.nl': ['duo.nl'],
    'dienst uitvoering onderwijs': ['duo.nl'],
    'digid': ['digid.nl'],
    'ind': ['ind.nl'],
    'politie': ['politie.nl'],
    'netherlands police': ['politie.nl'],
    'buren': ['burenlegal.com'],
    'vodafoneziggo': ['vodafoneziggo.nl'],
    'delft university of technology': ['tudelft.nl'],
    'tu delft': ['tudelft.nl'],
    'erasmus university rotterdam': ['eur.nl'],
    'leiden university': ['universiteitleiden.nl'],
    'university of amsterdam': ['uva.nl'],
    'wageningen university & research': ['wur.nl'],
    'eneco': ['eneco.com'],
    'vattenfall netherlands': ['vattenfall.nl'],
    'anz new zealand': ['anz.co.nz'],
    'asb bank': ['asb.co.nz'],
    'bnz': ['bnz.co.nz'],
    'kiwibank': ['kiwibank.co.nz'],
    'westpac nz': ['westpac.co.nz'],
    'nz post': ['nzpost.co.nz'],
    'immigration new zealand': ['immigration.govt.nz'],
    'inland revenue': ['ird.govt.nz'],
    'nz': ['ird.govt.nz'],
    'university of auckland': ['auckland.ac.nz'],
    'university of otago': ['otago.ac.nz'],
    'access bank': ['accessbankplc.com'],
    'firstbank nigeria': ['firstbanknigeria.com'],
    'gtbank': ['gtbank.com'],
    'zenith bank': ['zenithbank.com'],
    'firs': ['firs.gov.ng'],
    'nigeria immigration service': ['immigration.gov.ng'],
    'airtel africa': ['airtel.africa'],
    'glo': ['gloworld.com'],
    'globacom': ['gloworld.com'],
    'dnb bank': ['dnb.no'],
    'posten norge': ['posten.no'],
    'norwegian police': ['politiet.no'],
    'skatteetaten': ['skatteetaten.no'],
    'tax administration': ['skatteetaten.no'],
    'university of oslo': ['uio.no'],
    'banco de crédito del perú': ['viabcp.com'],
    'bcp': ['viabcp.com'],
    'sunat': ['sunat.gob.pe'],
    'national university of san marcos': ['unmsm.edu.pe'],
    'bdo unibank': ['bdo.com.ph'],
    'bank of the philippine islands': ['bpi.com.ph'],
    'bpi': ['bpi.com.ph'],
    'metrobank': ['metrobank.com.ph'],
    'philippine postal corporation': ['phlpost.gov.ph'],
    'phlpost': ['phlpost.gov.ph'],
    'bi': ['immigration.gov.ph'],
    'bir': ['bir.gov.ph'],
    'bank pekao': ['pekao.com.pl'],
    'pko bank polski': ['pkobp.pl'],
    'santander bank polska': ['santander.pl'],
    'mbank': ['mbank.pl'],
    'poczta polska': ['poczta-polska.pl'],
    'kas': ['gov.pl'],
    'zus': ['zus.pl'],
    'caixa geral de depósitos': ['cgd.pt'],
    'cgd': ['cgd.pt'],
    'millennium bcp': ['millenniumbcp.pt'],
    'novo banco': ['novobanco.pt'],
    'ctt': ['ctt.pt'],
    'portugal post': ['ctt.pt'],
    'autoridade tributária e aduaneira': ['portaldasfinancas.gov.pt'],
    'serviço de estrangeiros e fronteiras - legacy': ['sef.pt'],
    'sef': ['sef.pt'],
    'banca transilvania': ['bancatransilvania.ro'],
    'anaf': ['anaf.ro'],
    'riyad bank': ['riyadbank.com'],
    'saudi british bank': ['sabb.com'],
    'sabb': ['sabb.com'],
    'saudi national bank': ['snb.com.sa'],
    'snb': ['snb.com.sa'],
    'absher': ['absher.sa'],
    'gosi': ['gosi.gov.sa'],
    'ministry of human resources and social development': ['hrsd.gov.sa'],
    'ministry of interior': ['moi.gov.sa'],
    'zatca': ['zatca.gov.sa'],
    'mobily': ['mobily.com.sa'],
    'zain saudi arabia': ['sa.zain.com'],
    'stc': ['stc.com.sa'],
    'saudi electricity company': ['se.com.sa'],
    'uob': ['uobgroup.com'],
    'singpost': ['singpost.com'],
    'cpf board': ['cpf.gov.sg'],
    'ica': ['ica.gov.sg'],
    'iras': ['iras.gov.sg'],
    'nanyang technological university': ['ntu.edu.sg'],
    'ntu': ['ntu.edu.sg'],
    'national university of singapore': ['nus.edu.sg'],
    'nus': ['nus.edu.sg'],
    'sars': ['sars.gov.za'],
    'eskom': ['eskom.co.za'],
    'hana bank': ['kebhana.com'],
    'kb kookmin bank': ['kbstar.com'],
    'shinhan bank': ['shinhan.com'],
    'woori bank': ['wooribank.com'],
    'korea post': ['epost.go.kr'],
    'korea immigration service': ['immigration.go.kr'],
    'korea national health insurance service': ['nhis.or.kr'],
    'nhis': ['nhis.or.kr'],
    'korean national police agency': ['police.go.kr'],
    'national tax service': ['nts.go.kr'],
    'nts': ['nts.go.kr'],
    'kaist': ['kaist.ac.kr'],
    'korea university': ['korea.edu'],
    'seoul national university': ['snu.ac.kr'],
    'yonsei university': ['yonsei.ac.kr'],
    'kogas': ['kogas.or.kr'],
    'bankinter': ['bankinter.com'],
    'mrw': ['mrw.es'],
    'seur': ['seur.com'],
    'agencia tributaria': ['agenciatributaria.es'],
    'aeat': ['agenciatributaria.es'],
    'dgt': ['dgt.es'],
    'policía nacional': ['policia.es'],
    'sepe': ['sepe.es'],
    'seguridad social': ['seg-social.es'],
    'seg-social.es': ['seg-social.es'],
    'garrigues': ['garrigues.com'],
    'uría menéndez': ['uria.com'],
    'orange spain': ['orange.es'],
    'complutense university of madrid': ['ucm.es'],
    'universidad autónoma de madrid': ['uam.es'],
    'university of barcelona': ['ub.edu'],
    'aguas de barcelona': ['aiguesdebarcelona.cat'],
    'agbar': ['aiguesdebarcelona.cat'],
    'endesa': ['endesa.com'],
    'iberdrola': ['iberdrola.com'],
    'iberdrola clientes': ['iberdrola.es'],
    'naturgy': ['naturgy.com'],
    'handelsbanken': ['handelsbanken.com'],
    'nordea': ['nordea.com'],
    'nordics': ['nordea.com'],
    'seb': ['sebgroup.com'],
    'svenska handelsbanken': ['handelsbanken.se'],
    'swedbank': ['swedbank.com'],
    'postnord': ['postnord.se'],
    'försäkringskassan': ['forsakringskassan.se'],
    'social insurance': ['forsakringskassan.se'],
    'skatteverket': ['skatteverket.se'],
    'swedish police': ['polisen.se'],
    'karolinska institutet': ['ki.se'],
    'lund university': ['lunduniversity.lu.se'],
    'uppsala university': ['uu.se'],
    'credit suisse': ['credit-suisse.com'],
    'postfinance': ['postfinance.ch'],
    'raiffeisen switzerland': ['raiffeisen.ch'],
    'zürcher kantonalbank': ['zkb.ch'],
    'zkb': ['zkb.ch'],
    'sem': ['sem.admin.ch'],
    'swiss federal tax administration': ['estv.admin.ch'],
    'fta': ['estv.admin.ch'],
    'salt': ['salt.ch'],
    'epfl': ['epfl.ch'],
    'eth zurich': ['ethz.ch'],
    'university of basel': ['unibas.ch'],
    'university of geneva': ['unige.ch'],
    'university of zurich': ['uzh.ch'],
    'axpo': ['axpo.com'],
    'national university of taiwan': ['ntu.edu.tw'],
    'bangkok bank': ['bangkokbank.com'],
    'kasikornbank': ['kasikornbank.com'],
    'krungsri': ['krungsri.com'],
    'krungthai bank': ['ktb.co.th'],
    'siam commercial bank': ['scb.co.th'],
    'scb': ['scb.co.th'],
    'thailand post': ['thailandpost.co.th'],
    'immigration bureau': ['immigration.go.th'],
    'thailand': ['immigration.go.th'],
    'revenue department': ['rd.go.th'],
    'akbank': ['akbank.com'],
    'garanti bbva': ['garantibbva.com.tr'],
    'yapı kredi': ['yapikredi.com.tr'],
    'i̇şbank': ['isbank.com.tr'],
    'ptt': ['ptt.gov.tr'],
    'revenue administration': ['gib.gov.tr'],
    'sgk': ['sgk.gov.tr'],
    'e-devlet': ['turkiye.gov.tr'],
    'abu dhabi commercial bank': ['adcb.com'],
    'adcb': ['adcb.com'],
    'dubai islamic bank': ['dib.ae'],
    'emirates nbd': ['emiratesnbd.com'],
    'first abu dhabi bank': ['bankfab.com'],
    'fab': ['bankfab.com'],
    'dubai police': ['dubaipolice.gov.ae'],
    'federal tax authority': ['tax.gov.ae'],
    'icp': ['icp.gov.ae'],
    'addc': ['addc.ae'],
    'dewa': ['dewa.gov.ae'],
    'metro bank': ['metrobankonline.co.uk'],
    'starling bank': ['starlingbank.com'],
    'tsb bank': ['tsb.co.uk'],
    'virgin money uk': ['virginmoneyukplc.com'],
    'bath building society': ['bathbuildingsociety.co.uk'],
    'beverley building society': ['beverleybuildingsociety.co.uk'],
    'buckinghamshire building society': ['bucksbs.co.uk'],
    'cambridge building society': ['cambridgebs.co.uk'],
    'coventry building society': ['coventrybuildingsociety.co.uk'],
    'hinckley & rugby building society': ['hrbs.co.uk'],
    'leeds building society': ['leedsbuildingsociety.co.uk'],
    'loughborough building society': ['theloughborough.co.uk'],
    'market harborough building society': ['mhbs.co.uk'],
    'marsden building society': ['themarsden.co.uk'],
    'monmouthshire building society': ['monbs.com'],
    'nationwide building society': ['nationwide.co.uk'],
    'newcastle building society': ['newcastle.co.uk'],
    'nottingham building society': ['thenottingham.com'],
    'penrith building society': ['penrithbs.co.uk'],
    'principality building society': ['principality.co.uk'],
    'saffron building society': ['saffronbs.co.uk'],
    'skipton building society': ['skipton.co.uk'],
    'yorkshire building society': ['ybs.co.uk'],
    'dpd uk': ['dpd.co.uk'],
    'yodel': ['yodel.co.uk'],
    'companies house': ['companieshouse.gov.uk'],
    'driver and vehicle licensing agency': ['dvla.gov.uk'],
    'hm revenue & customs': ['hmrc.gov.uk'],
    'home office': ['homeoffice.gov.uk'],
    'bupa': ['bupa.co.uk'],
    'nuffield health': ['nuffieldhealth.com'],
    'ramsay health care uk': ['ramsayhealth.co.uk'],
    'spire healthcare': ['spirehealthcare.com'],
    'allen & overy': ['allenovery.com'],
    'ashurst': ['ashurst.com'],
    'bird & bird': ['twobirds.com'],
    'cms': ['cms.law'],
    'clifford chance': ['cliffordchance.com'],
    'eversheds sutherland': ['eversheds-sutherland.com'],
    'freshfields': ['freshfields.com'],
    'herbert smith freehills': ['hsf.com'],
    'hogan lovells': ['hoganlovells.com'],
    'linklaters': ['linklaters.com'],
    'macfarlanes': ['macfarlanes.com'],
    'norton rose fulbright': ['nortonrosefulbright.com'],
    'pinsent masons': ['pinsentmasons.com'],
    'slaughter and may': ['slaughterandmay.com'],
    'stephenson harwood': ['shlegal.com'],
    'taylor wessing': ['taylorwessing.com'],
    'virgin media o2': ['virginmediao2.co.uk'],
    'imperial college london': ['imperial.ac.uk'],
    'king\'s college london': ['kcl.ac.uk'],
    'london school of economics and political science': ['lse.ac.uk'],
    'lse': ['lse.ac.uk'],
    'ucl': ['ucl.ac.uk'],
    'university of birmingham': ['bham.ac.uk'],
    'university of bristol': ['bristol.ac.uk'],
    'university of cambridge': ['cam.ac.uk'],
    'university of edinburgh': ['ed.ac.uk'],
    'university of glasgow': ['gla.ac.uk'],
    'university of leeds': ['leeds.ac.uk'],
    'university of manchester': ['manchester.ac.uk'],
    'university of nottingham': ['nottingham.ac.uk'],
    'university of oxford': ['ox.ac.uk'],
    'university of sheffield': ['sheffield.ac.uk'],
    'university of southampton': ['southampton.ac.uk'],
    'university of warwick': ['warwick.ac.uk'],
    'e.on uk': ['eonenergy.com'],
    'edf energy': ['edfenergy.com'],
    'octopus energy': ['octopus.energy'],
    'scottishpower': ['scottishpower.co.uk'],
    'severn trent': ['stwater.co.uk'],
    'thames water': ['thameswater.co.uk'],
    'united utilities': ['uuplc.co.uk'],
    'arvest bank': ['arvest.com'],
    'associated bank': ['associatedbank.com'],
    'bok financial / bank of oklahoma': ['bokf.com'],
    'banc of california': ['bancofcal.com'],
    'cadence bank': ['cadencebank.com'],
    'citizens bank': ['citizensbank.com'],
    'city national bank': ['cnb.com'],
    'comerica bank': ['comerica.com'],
    'current bank': ['current.com'],
    'current debit': ['current.com'],
    'current mobile banking': ['current.com'],
    'first citizens bank': ['firstcitizens.com'],
    'first hawaiian bank': ['fhb.com'],
    'first interstate bank': ['firstinterstatebank.com'],
    'frost bank': ['frostbank.com'],
    'keybank': ['key.com'],
    'm&t bank': ['mtb.com'],
    'signature bank': ['signatureny.com'],
    'silicon valley bank - legacy phishing': ['svb.com'],
    'svb': ['svb.com'],
    'synovus bank': ['synovus.com'],
    'valley bank': ['valley.com'],
    'varo bank': ['varomoney.com'],
    'webster bank': ['websterbank.com'],
    'wintrust': ['wintrust.com'],
    'zions bank': ['zionsbank.com'],
    'alliant credit union': ['alliantcreditunion.org'],
    'america first credit union': ['americafirst.com'],
    'america\'s credit union': ['americascu.org'],
    'arkansas federal credit union': ['afcu.org'],
    'becu': ['becu.org'],
    'baxter credit union': ['bcu.org'],
    'bcu': ['bcu.org'],
    'bellco credit union': ['bellco.org'],
    'boulder valley credit union': ['bvcu.org'],
    'connexus credit union': ['connexuscu.org'],
    'desert financial credit union': ['desertfinancial.com'],
    'digital federal credit union': ['dcu.org'],
    'dcu': ['dcu.org'],
    'ent credit union': ['ent.com'],
    'first community credit union': ['firstcommunity.com'],
    'first tech federal credit union': ['firsttechfed.com'],
    'gecu': ['gecu.com'],
    'georgia\'s own credit union': ['georgiasown.org'],
    'golden 1 credit union': ['golden1.com'],
    'harborstone credit union': ['harborstone.com'],
    'kinecta federal credit union': ['kinecta.org'],
    'langley federal credit union': ['langleyfcu.org'],
    'mountain america credit union': ['macu.com'],
    'navy army community credit union': ['navyarmyccu.com'],
    'nusenda credit union': ['nusenda.org'],
    'onpoint community credit union': ['onpointcu.com'],
    'patelco credit union': ['patelco.org'],
    'pentagon federal credit union': ['penfed.org'],
    'penfed': ['penfed.org'],
    'people\'s credit union': ['peoplescu.com'],
    'ri': ['peoplescu.com'],
    'rbfcu': ['rbfcu.org'],
    'redstone federal credit union': ['redfcu.org'],
    'secu maryland': ['secu.com'],
    'schoolsfirst federal credit union': ['schoolsfirstfcu.org'],
    'security service federal credit union': ['ssfcu.org'],
    'sound credit union': ['soundcu.com'],
    'space coast credit union': ['sccu.com'],
    'spokane teachers credit union': ['stcu.org'],
    'stcu': ['stcu.org'],
    'state employees\' credit union': ['ncsecu.org'],
    'nc secu': ['ncsecu.org'],
    'suncoast credit union': ['suncoastcreditunion.com'],
    'teachers federal credit union': ['teachersfcu.org'],
    'tinker federal credit union': ['tinkerfcu.org'],
    'travis credit union': ['traviscu.org'],
    'unfcu': ['unfcu.org'],
    'unify financial credit union': ['unifyfcu.com'],
    'united federal credit union': ['unitedfcu.com'],
    'vystar credit union': ['vystarcu.org'],
    'wright-patt credit union': ['wpcu.coop'],
    'adventhealth': ['adventhealth.com'],
    'ascension': ['ascension.org'],
    'banner health': ['bannerhealth.com'],
    'cleveland clinic': ['clevelandclinic.org'],
    'commonspirit health': ['commonspirit.org'],
    'hca healthcare': ['hcahealthcare.com'],
    'johns hopkins medicine': ['hopkinsmedicine.org'],
    'mass general brigham': ['massgeneralbrigham.org'],
    'mayo clinic': ['mayoclinic.org'],
    'nyu langone health': ['nyulangone.org'],
    'providence': ['providence.org'],
    'sutter health': ['sutterhealth.org'],
    'trinity health': ['trinity-health.org'],
    'upmc': ['upmc.com'],
    'akin': ['akin.com'],
    'bclp': ['bclplaw.com'],
    'baker botts': ['bakerbotts.com'],
    'baker mckenzie': ['bakermckenzie.com'],
    'cleary gottlieb': ['cgsh.com'],
    'cooley': ['cooley.com'],
    'covington & burling': ['cov.com'],
    'dla piper': ['dlapiper.com'],
    'debevoise & plimpton': ['debevoise.com'],
    'dentons': ['dentons.com'],
    'gibson, dunn & crutcher': ['gibsondunn.com'],
    'goodwin': ['goodwinlaw.com'],
    'greenberg traurig': ['gtlaw.com'],
    'holland & knight': ['hklaw.com'],
    'jones day': ['jonesday.com'],
    'king & spalding': ['kslaw.com'],
    'kirkland & ellis': ['kirkland.com'],
    'latham & watkins': ['lw.com'],
    'mayer brown': ['mayerbrown.com'],
    'milbank': ['milbank.com'],
    'morgan, lewis & bockius': ['morganlewis.com'],
    'o\'melveny & myers': ['omm.com'],
    'orrick': ['orrick.com'],
    'paul hastings': ['paulhastings.com'],
    'paul, weiss': ['paulweiss.com'],
    'perkins coie': ['perkinscoie.com'],
    'quinn emanuel urquhart & sullivan': ['quinnemanuel.com'],
    'reed smith': ['reedsmith.com'],
    'ropes & gray': ['ropesgray.com'],
    'shearman & sterling': ['shearman.com'],
    'sidley austin': ['sidley.com'],
    'simpson thacher & bartlett': ['stblaw.com'],
    'skadden, arps, slate, meagher & flom': ['skadden.com'],
    'squire patton boggs': ['squirepattonboggs.com'],
    'sullivan & cromwell': ['sullcrom.com'],
    'weil, gotshal & manges': ['weil.com'],
    'white & case': ['whitecase.com'],
    'wilmerhale': ['wilmerhale.com'],
    'winston & strawn': ['winston.com'],
    'amrock': ['amrock.com'],
    'fidelity national title': ['fidelitynationaltitle.com'],
    'wfg national title': ['wfgtitle.com'],
    'california institute of technology': ['caltech.edu'],
    'caltech': ['caltech.edu'],
    'carnegie mellon university': ['cmu.edu'],
    'columbia university': ['columbia.edu'],
    'cornell university': ['cornell.edu'],
    'duke university': ['duke.edu'],
    'georgia institute of technology': ['gatech.edu'],
    'harvard university': ['harvard.edu'],
    'johns hopkins university': ['jhu.edu'],
    'massachusetts institute of technology': ['mit.edu'],
    'mit': ['mit.edu'],
    'new york university': ['nyu.edu'],
    'nyu': ['nyu.edu'],
    'northwestern university': ['northwestern.edu'],
    'princeton university': ['princeton.edu'],
    'stanford university': ['stanford.edu'],
    'uc san diego': ['ucsd.edu'],
    'ucla': ['ucla.edu'],
    'university of california, berkeley': ['berkeley.edu'],
    'university of chicago': ['uchicago.edu'],
    'university of michigan': ['umich.edu'],
    'university of pennsylvania': ['upenn.edu'],
    'yale university': ['yale.edu'],
    'southern company': ['southerncompany.com'],
    'xcel energy': ['xcelenergy.com'],
    'bidv': ['bidv.com.vn'],
    'techcombank': ['techcombank.com.vn'],
    'vpbank': ['vpbank.com.vn'],
    'vietcombank': ['vietcombank.com.vn'],
    'vietinbank': ['vietinbank.vn'],
    'vietnam post': ['vnpost.vn'],
    'general department of taxation': ['gdt.gov.vn'],
    'vietnam': ['gdt.gov.vn'],
    'vietnam immigration': ['immigration.gov.vn']

};

// ============================================
// KEYWORD CATEGORIES WITH EXPLANATIONS
// ============================================
const KEYWORD_CATEGORIES = {
    'Wire & Payment Methods': {
        keywords: [
            'wire transfer', 'wire instructions', 'wiring instructions',
            'wire information', 'wire details', 'updated wire',
            'new wire', 'wire account', 'wire funds',
            'ach transfer', 'direct deposit',
            'zelle', 'venmo', 'cryptocurrency', 'bitcoin',
            'send funds', 'transfer funds', 'remit funds',
            'wire to', 'remittance', 'wire payment',
            'western union', 'moneygram', 'money order',
            'gift card payment', 'pay with gift cards', 'send gift cards'
        ],
        explanation: 'Emails requesting money transfers are prime targets for fraud. Always verify payment requests by calling a known number before sending funds.'
    },
    'Banking Details': {
        keywords: [
            'bank account', 'account number', 'routing number',
            'aba number', 'swift code', 'iban',
            'bank statement', 'voided check', 'beneficiary'
        ],
        explanation: 'Requests for banking information via email are risky. Scammers use this data to redirect payments or steal funds.'
    },
    'Account Changes': {
        keywords: [
            'updated bank', 'new bank', 'changed bank',
            'updated payment', 'new payment info',
            'changed account', 'new account details',
            'payment update', 'revised instructions',
            'please update your records'
        ],
        explanation: 'Last-minute changes to payment details are the #1 sign of wire fraud. Always verify changes by phone before proceeding.'
    },
    'Real Estate & Legal': {
        keywords: [
            'closing funds', 'earnest money', 'escrow funds',
            'settlement funds', 'settlement payment',
            'retainer', 'trust account', 'iolta',
            'client funds', 'case settlement',
            'court filing fee', 'legal fee'
        ],
        explanation: 'Real estate and legal transactions are heavily targeted by scammers. Verify all payment instructions directly with your escrow officer or attorney.'
    },
    'Secrecy Tactics': {
        keywords: [
            'keep this confidential', 'keep this quiet',
            'dont mention this', 'dont tell anyone',
            'private matter',
            'off the record', 'handle personally'
        ],
        explanation: "Requests for secrecy are a major red flag. Legitimate transactions don't require you to bypass normal verification procedures."
    },
    'Sensitive Data Requests': {
        keywords: [
            'social security', 'ssn', 'tax id',
            'W-9', 'W9', 'ein number',
            'login credentials', 'password reset',
            'verify your account', 'verify immediately',
            'confirm your identity', 'verify your identity'
        ],
        explanation: 'Requests for sensitive personal information via email may be phishing attempts. Verify the request through a known phone number.'
    },
    'Authority Impersonation': {
        keywords: [
            'ceo request', 'cfo request', 'owner request',
            'boss asked', 'executive request', 'president asked'
        ],
        explanation: 'Scammers impersonate executives to pressure urgent payments. Verify any unusual requests directly with the person through a known channel.'
    },
    'Urgency Tactics': {
        keywords: [
            'act now', 'urgent action required', 'action required',
            'account suspended', 'account will be closed',
            'unusual activity', 'suspicious activity', 'unauthorized access',
            'action required within', 'expires today', 'last chance',
            'time is running out', 'final notice', 'respond within 24 hours',
            'failure to respond', 'immediate action required'
        ],
        explanation: 'False urgency is a common fraud tactic designed to prevent you from verifying details. Legitimate requests allow time to confirm.'
    },
    'Crypto & Wallet Scams': {
        keywords: [
            'connect wallet', 'connect your wallet',
            'claim airdrop', 'claim your airdrop',
            'verify eligibility', 'sign transaction',
            'sign all transactions', 'approve all transactions',
            'wallet verification', 'wallet verification required',
            'claim tokens', 'mint tokens',
            'token airdrop', 'verify your wallet'
        ],
        explanation: 'Crypto wallet scams use fake airdrop claims and verification prompts to steal your digital assets. Never connect your wallet or sign transactions from email links.'
    },
    'Inheritance & Lottery Scams': {
        keywords: [
            'inheritance', 'unclaimed inheritance', 'unclaimed funds',
            'next of kin', 'dormant account', 'claim your funds',
            'deceased estate', 'estate settlement', 'unclaimed property',
            'beneficiary notification', 'lottery winner',
            'congratulations you\'ve won', 'prize notification',
            'winning ticket', 'claim your prize', 'lucky winner',
            'you have won', 'you\'ve been selected', 'award notification'
        ],
        explanation: 'Inheritance claims and lottery notifications from unknown senders are almost always scams. Real inheritances come from known attorneys, and legitimate lotteries never notify winners by email.'
    },
    'Advance Fee Scams': {
        keywords: [
            'release fee', 'clearance fee', 'advance fee',
            'barrister', 'diplomatic courier', 'consignment box',
            'compensation fund', 'atm card shipment',
            'delivery charges required', 'customs charges', 'pay to release'
        ],
        explanation: 'Requests to pay upfront fees to release funds are a hallmark of advance fee fraud. No legitimate organization requires payment via email to release money owed to you.'
    }
};

// Build flat keyword list for detection
const WIRE_FRAUD_KEYWORDS = Object.values(KEYWORD_CATEGORIES).flatMap(cat => cat.keywords);

// v5.2.1: SW-01 — Feature flags for keyword detectors
// Flip to false to instantly disable either panel without removing code.
const ENABLE_DANGEROUS_KEYWORDS = true;
const ENABLE_PHISHING_WORDS = true;

// Helper function to get explanation for a keyword
function getKeywordExplanation(keyword) {
    const lowerKeyword = keyword.toLowerCase();
    for (const [category, data] of Object.entries(KEYWORD_CATEGORIES)) {
        if (data.keywords.some(k => k.toLowerCase() === lowerKeyword)) {
            return {
                category: category,
                explanation: data.explanation
            };
        }
    }
    return {
        category: 'Suspicious Content',
        explanation: 'This email contains terms that may indicate fraud. Verify any requests through a known phone number.'
    };
}

// Homoglyph characters (Cyrillic only)
// v4.3.1: Unicode normalization - strips zero-width characters and applies NFKC.
// Viktor: "Zero-width joiners in 'Fidelity' or Cyrillic 'а' for Latin 'a' are trivial attacks."
function stripUnicodeThreats(text) {
    if (!text) return '';
    // Strip zero-width characters: ZWSP, ZWNJ, ZWJ, soft hyphen, zero-width no-break space, word joiner
    let cleaned = text.replace(/[\u200B\u200C\u200D\u00AD\uFEFF\u2060\u200E\u200F]/g, '');
    // v4.3.2: Strip additional deceptive Unicode that bypasses brand keyword matching.
    // Viktor: "I insert an invisible separator inside 'Microsoft' and your keyword check
    // sees 'micro[invisible]soft' which doesn't match 'microsoft'. User sees the brand name
    // perfectly. Brand impersonation detection is blind."
    // Covers: exotic whitespace (en/em/thin/hair/figure/punctuation/math spaces, no-break space),
    // invisible math operators (separator, times, function apply, plus),
    // bidi controls (LRE, RLE, PDF, LRO, RLO, LRI, RLI, FSI, PDI),
    // and deceptive punctuation (middle dot, bullet) used as visual separators.
    // Does NOT strip standard ASCII punctuation (&, -, ', etc.) to preserve AT&T, T-Mobile, Lowe's.
    cleaned = cleaned.replace(/[\u00A0\u00B7\u2000-\u200A\u2022\u202A-\u202F\u205F\u2061-\u2064\u2066-\u2069]/g, '');
    // Apply NFKC normalization (converts visual confusables to canonical forms)
    if (typeof cleaned.normalize === 'function') {
        cleaned = cleaned.normalize('NFKC');
    }
    return cleaned;
}

// ============================================
// v5.2.0: BODY PREP LAYER — Detection Scope Rules
// Runs ONCE per message BEFORE any detection functions.
// Strips URL query strings/fragments from the scanning surface.
// Returns cleanText (visible text with URLs replaced by hostnames)
// and urlHosts (Set of unique hostnames for brand checks).
//
// Scope contract (COP + Claude agreed):
//   Brand impersonation: display name + From domain + cleanText + urlHosts
//   Dangerous keywords:  subject + cleanText ONLY (no URL content at all)
//   Other detectors:     unchanged (routing, reply-to, gibberish, etc.)
//
// Viktor: "I hide brand names in URL query params to trigger false positives
//   on legitimate emails. I also hide payment terms in tracking URLs."
//   → Stripping params kills both evasion vectors without losing real signal.
//   Real brand phishing always puts the brand in visible text, display name,
//   subject, or the URL hostname — never only in query params.
// ============================================
function prepareBodyForScanning(body) {
    if (!body) return { cleanText: '', urlHosts: new Set() };
    
    // Match URLs in plaintext (covers http/https, stops at whitespace or common delimiters)
    const urlRegex = /https?:\/\/[^\s<>"')\]},]+/gi;
    const urlHosts = new Set();
    
    const cleanText = body.replace(urlRegex, (fullUrl) => {
        try {
            // Strip trailing punctuation that got captured (period, comma, semicolon)
            let url = fullUrl.replace(/[.,;:!?)]+$/, '');
            
            // Parse the URL to extract hostname
            // Use URL constructor where available, fallback to regex
            let hostname = '';
            let firstPath = '';
            try {
                const parsed = new URL(url);
                hostname = parsed.hostname.toLowerCase();
                // Extract first path segment (e.g., /spotify/reset → "spotify")
                const pathParts = parsed.pathname.split('/').filter(p => p.length > 0);
                if (pathParts.length > 0) firstPath = pathParts[0].toLowerCase();
            } catch (e) {
                // Fallback: extract host via regex
                const hostMatch = url.match(/https?:\/\/([^/?#]+)/i);
                if (hostMatch) hostname = hostMatch[1].toLowerCase();
            }
            
            if (!hostname) return fullUrl; // Can't parse, leave as-is
            
            // Skip data: URIs, cid: references, tracking pixels
            if (hostname === '' || url.startsWith('data:') || url.startsWith('cid:')) {
                return ''; // Remove from scanning surface entirely
            }
            
            // Punycode decode if needed (xn-- prefixed domains)
            // Basic decode: browsers handle this natively via URL constructor above
            
            // Store hostname (and first path token if it looks like a brand slug)
            urlHosts.add(hostname);
            if (firstPath && firstPath.length > 2 && /^[a-z]/.test(firstPath)) {
                urlHosts.add(hostname + '/' + firstPath);
            }
            
            // Replace URL with hostname + first path token in the clean text
            // This preserves the brand-in-hostname signal while killing param noise
            // e.g., "https://phish.tld/spotify/reset?track=xyz" → "phish.tld/spotify"
            return hostname + (firstPath ? '/' + firstPath : '');
        } catch (e) {
            return fullUrl; // On any error, leave original
        }
    });
    
    return { cleanText, urlHosts };
}

// v4.3.3: Fuzzy phrase normalization for keyword evasion.
// Viktor: "I write 'acc ount susp-ended' or 'verif.y your identity' and your exact
// phrase matching sees garbage. User reads it perfectly. I bypass every keyword list."
// Solution: collapse internal separators (spaces, hyphens, dots, underscores) between
// lowercase letters. Run as secondary pass — exact match first, then collapsed.
function collapseForMatch(text) {
    if (!text) return '';
    return text.replace(/(?<=[a-z])[\s\-_.,;:]+(?=[a-z])/g, '');
}

function phraseMatchesContent(lowerContent, collapsedContent, phrase) {
    if (lowerContent.includes(phrase)) return true;
    const collapsedPhrase = phrase.replace(/\s+/g, '');
    return collapsedPhrase.length > 3 && collapsedContent.includes(collapsedPhrase);
}

const HOMOGLYPHS = {
    '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p', '\u0441': 'c', '\u0445': 'x',
    '\u0456': 'i', '\u0458': 'j', '\u0455': 's', '\u0501': 'd', '\u0261': 'g', '\u0578': 'n',
    '\u03bd': 'v', '\u0461': 'w', '\u0443': 'y', '\u04bb': 'h', '\u217c': 'l', '\uff4d': 'm',
    '\uff01': '!', '\uff20': '@'
};

// ============================================
// PHASE 2: PHISHING PATTERN ENGINE - CONSTANTS
// v4.2.0 - Silent mode (computes but does not display)
// ============================================

const PHASE2_CONFIG = {
    enabled: true,
    silentMode: true,
    telemetryEnabled: false,
    maxUrlsToExtract: 20,
    maxBodyLengthForUrlScan: 50000,
    version: '1.0.0'
};

const CREDENTIAL_REQUEST_PHRASES = [
    'verify your account', 'confirm your identity', 'confirm your account',
    'confirm your email', 'verify your email', 'update your credentials',
    're-authenticate', 'login required', 'sign in to continue', 'sign in now',
    'log in to continue', 'reset your password', 'password expired',
    'password reset', 'validate your account', 'authentication required',
    'security verification', 'unusual sign-in', 'unusual activity',
    'suspicious activity', 'unauthorized access', 'account will be locked',
    'account suspended', 'account disabled', 'enter your password',
    'security code', 'one-time code', 'one-time password',
    'two-factor', '2fa', 'verify your identity'
];

const CREDENTIAL_EXCLUSION_PHRASES = [
    'please review', 'review document', 'review and sign',
    'review the document', 'review attached', 'review the attached',
    'for your review', 'ready for review'
];

const UNLOCK_LANGUAGE_PHRASES = [
    'password attached', 'unlock code', 'use this code',
    'open with password', 'encrypted attachment', 'secure document enclosed',
    'password is', 'passcode is', 'access code',
    'the password to open', 'use the password', 'protected document',
    'secure attachment', 'open the attachment', 'download the attachment',
    'password below', 'password above', 'enclosed password'
];

const PAYMENT_CHANGE_PHRASES = [
    'updated bank', 'new bank', 'changed bank',
    'new account details', 'updated account details',
    'updated payment details', 'new payment info',
    'update your records', 'revised wire instructions',
    'new wiring instructions', 'please use the new account',
    'send to this account instead', 'new routing number',
    'updated routing number', 'payment details have changed',
    'wire to the following', 'remit to', 'send funds to'
];

const BANKING_TOKENS = [
    'routing number', 'account number', 'aba', 'swift', 'iban',
    'beneficiary', 'bank account', 'wire transfer',
    'wire instructions', 'bank details'
];

const SECRECY_PHRASES = [
    'keep this confidential', 'do not tell',
    'dont tell', "don't tell", 'handle personally',
    'urgent and confidential', 'keep this quiet',
    'off the record', 'private matter',
    'do not share', 'do not discuss'
];

const KNOWN_PLATFORM_DOMAINS = [
    // Project Management & Collaboration
    'upwork.com', 'github.com', 'linkedin.com', 'atlassian.net', 'atlassian.com', 'jira.com',
    'slack.com', 'asana.com', 'trello.com', 'notion.so', 'notion.com', 'makenotion.com',
    'figma.com', 'basecamp.com',
    'monday.com', 'clickup.com', 'smartsheet.com', 'teamwork.com', 'wrike.com',
    'airtable.com', 'todoist.com', 'linear.app', 'shortcut.com', 'height.app',
    // Website Builders & Forms
    'wix.com', 'wix-forms.com', 'wixforms.com', 'squarespace.com', 'typeform.com', 'jotform.com',
    'godaddy.com', 'webflow.com', 'wordpress.com', 'formstack.com',
    'surveymonkey.com', 'qualtrics.com', 'google.com', 'cognitoforms.com',
    // Developer Tools & DevOps
    'gitlab.com', 'bitbucket.org', 'stackoverflow.com', 'digitalocean.com',
    'cloudflare.com', 'sentry.io', 'datadog.com', 'pagerduty.com', 'newrelic.com',
    'launchdarkly.com', 'circleci.com', 'snyk.io', 'sonarcloud.io',
    // Communication & Video
    'zoom.us', 'zoom.com', 'webex.com', 'calendly.com', 'intercom.io',
    'drift.com', 'discord.com', 'discordapp.com', 'loom.com', 'ringcentral.com', 'goto.com',
    'dialpad.com', 'vonage.com', 'twilio.com',
    // CRM & Customer Support
    'salesforce.com', 'exacttarget.com', 'hubspot.com', 'hubspotemail.net',
    'pipedrive.com', 'zoho.com', 'freshworks.com',
    'freshdesk.com', 'zendesk.com', 'helpscout.com', 'front.com', 'gorgias.com',
    'copper.com', 'close.com', 'freshsales.io',
    // Invoicing, Billing & Payments
    'intuit.com', 'quickbooks.com', 'xero.com', 'freshbooks.com', 'stripe.com',
    'square.com', 'squareup.com',
    'paypal.com', 'paypal.co.uk', 'braintreepayments.com', 'chargebee.com', 'recurly.com',
    'paddle.com', 'bill.com', 'harvest.com', 'invoiceninja.com', 'wave.com',
    // Documents & E-Signature
    'docusign.com', 'docusign.net', 'hellosign.com', 'pandadoc.com', 'adobe.com',
    'dropbox.com', 'dropboxmail.com', 'box.com', 'sharepoint.com', 'onedrive.com',
    // HR & Recruiting
    'greenhouse.io', 'lever.co', 'bamboohr.com', 'gusto.com', 'rippling.com',
    'adp.com', 'workday.com', 'namely.com', 'justworks.com', 'deel.com',
    'paychex.com', 'paylocity.com', 'paycom.com', 'indeed.com', 'ziprecruiter.com',
    // Real Estate & Title/Escrow
    'closewise.com', 'snapdocs.com', 'dotloop.com', 'skyslope.com', 'qualia.com',
    'notarize.com', 'pavaso.com', 'docutech.com', 'softprocorp.com', 'ramquest.com',
    'resware.com', 'snapclose.com', 'atclose.com', 'settlor.com', 'certifid.com',
    'zillow.com', 'trulia.com', 'streeteasy.com', 'hotpads.com',
    'showingtime.com', 'followupboss.com',
    'realtor.com', 'redfin.com', 'compass.com', 'kw.com',
    'mls.com', 'mlsmatrix.com', 'flexmls.com', 'paragonmls.com', 'brightmls.com',
    'matrixmls.com', 'connectmls.com', 'stellarmls.com', 'ctmls.com',
    'corelogic.com', 'fnf.com', 'firstam.com', 'oldrepublictitle.com',
    'stewarttrustservices.com', 'stewart.com', 'fidelitynational.com',
    // Mortgage & Lending
    'encompass.com', 'elliemae.com', 'icemortgagetechnology.com', 'calyxsoftware.com',
    'bytesoftware.com', 'lendingpad.com', 'blend.com', 'mortgagecadence.com',
    'mortgage-email.com', 'topofmind.com', 'surefire.com', 'aboramedia.com',
    'mortgagecoach.com', 'totalexpert.com', 'homebot.ai', 'lodasoft.com',
    'bluesagetech.com', 'meridianlink.com', 'optimalblue.com', 'loanlogics.com',
    // Insurance
    'appliedsystems.com', 'hawksoft.com', 'vertafore.com', 'ezlynx.com',
    'agencybloc.com', 'bindhq.com', 'ams360.com', 'lemonade.com',
    'policygenius.com', 'goosehead.com', 'boldrisk.com',
    // Marketing & Analytics
    'canva.com', 'hootsuite.com', 'buffer.com', 'semrush.com', 'moz.com',
    'hotjar.com', 'mixpanel.com', 'amplitude.com', 'segment.com', 'optimizely.com',
    // Ecommerce
    'shopify.com', 'shopifyemail.com', 'myshopify.com', 'bigcommerce.com', 'etsy.com',
    'amazon.com', 'amazon.co.uk', 'amazon.ca', 'amazon.de', 'amazon.fr',
    'amazon.co.jp', 'amazon.com.au', 'amazonses.com', 'ebay.com',
    // Scheduling & Booking
    'acuityscheduling.com', 'schedulicity.com', 'mindbodyonline.com', 'vagaro.com',
    'booksy.com', 'setmore.com',
    // Events & Invitations
    'evite.com', 'eventbrite.com', 'meetup.com', 'paperlesspost.com', 'punchbowl.com',
    'rsvpify.com', 'partiful.com', 'splash.events', 'lu.ma',
    // Social Media
    'facebook.com', 'facebookmail.com', 'meta.com', 'instagram.com',
    'twitter.com', 'x.com',
    'pinterest.com', 'tiktok.com', 'reddit.com', 'redditmail.com',
    'nextdoor.com',
    'snapchat.com', 'whatsapp.com', 'telegram.org', 'threads.net',
    // Newsletter & Content Platforms
    'substack.com', 'beehiiv.com', 'medium.com', 'ghost.org', 'patreon.com',
    'gumroad.com', 'ko-fi.com',
    // Travel & Delivery
    'airbnb.com', 'airbnbmail.com', 'booking.com', 'expedia.com', 'uber.com', 'lyft.com',
    'lyftmail.com', 'doordash.com', 'grubhub.com', 'instacart.com',
    'vrbo.com', 'tripadvisor.com', 'kayak.com', 'hopper.com', 'turo.com',
    'southwest.com', 'delta.com', 'united.com', 'aa.com', 'jetblue.com',
    // Food & Restaurant
    'opentable.com', 'resy.com', 'yelp.com', 'toasttab.com', 'caviar.com',
    'ubereats.com', 'postmates.com', 'seamless.com',
    // Fitness & Wellness
    'peloton.com', 'classpass.com', 'myfitnesspal.com', 'strava.com',
    'fitbit.com',
    // Auto & Insurance Carriers
    'geico.com', 'progressive.com', 'statefarm.com', 'allstate.com', 'usaa.com',
    'libertymutual.com', 'nationwide.com', 'farmers.com', 'travelers.com',
    'carvana.com', 'carmax.com', 'tesla.com', 'carfax.com',
    // Home Services
    'thumbtack.com', 'angi.com', 'homeadvisor.com', 'taskrabbit.com',
    'rover.com', 'care.com', 'handy.com',
    // Banking & Financial Institutions
    'chase.com', 'jpmorgan.com', 'bankofamerica.com', 'bofa.com',
    'wellsfargo.com', 'wf.com', 'citi.com', 'citibank.com', 'citicards.com',
    'capitalone.com', 'ally.com', 'sofi.com', 'marcus.com', 'discover.com',
    'americanexpress.com', 'amex.com', 'aexp.com', 'usbank.com', 'pnc.com', 'tdbank.com',
    // Entertainment & Streaming
    'spotify.com', 'netflix.com', 'hulu.com', 'disneyplus.com',
    'youtube.com', 'twitch.tv', 'audible.com', 'kindle.com',
    // Retail & Shopping
    'target.com', 'costco.com', 'walmart.com', 'bestbuy.com', 'wayfair.com',
    'ikea.com', 'chewy.com', 'nordstrom.com', 'macys.com', 'homedepot.com',
    'lowes.com',
    // Parking & Tolls
    'parkmobile.com', 'spothero.com',
    // Notary & Signing Services
    'nationalnotary.org', 'notaryrotary.com', 'signingorder.com',
    // Wire & Payment Verification
    'earnnest.com', 'payjunction.com',
    // Cloud Fax
    'efax.com', 'hellofax.com',
    // Dating
    'tinder.com', 'bumble.com', 'hinge.co', 'match.com',
    // Cloud & Enterprise
    'amazonaws.com', 'microsoft.com', 'microsoft365.com', 'office.com', 'office365.com',
    'outlook.com', 'live.com', 'hotmail.com', 'apple.com', 'icloud.com',
    // Security & IT
    '1password.com', 'lastpass.com', 'okta.com', 'auth0.com',
    // Shipping
    'fedex.com', 'ups.com', 'shipstation.com', 'shippo.com',
    // Customer Feedback
    'trustpilot.com', 'g2.com', 'canny.io', 'productboard.com',
    // Education
    'coursera.org', 'udemy.com', 'teachable.com', 'thinkific.com',
    // Financial
    'plaid.com', 'robinhood.com', 'coinbase.com', 'venmo.com',
    'zellepay.com', 'zelle.com', 'cash.app',
    'wealthfront.com', 'betterment.com', 'fidelity.com', 'fidelityinvestments.com', 'schwab.com',
    'vanguard.com', 'creditkarma.com', 'experian.com', 'equifax.com', 'transunion.com',
    // Legal
    'clio.com', 'mycase.com', 'smokeball.com', 'lawpay.com', 'practicepanther.com',
    'rocketlawyer.com', 'legalzoom.com', 'docassemble.org',
    // Accounting & Tax
    'bench.co', 'pilot.com', 'taxact.com', 'hrblock.com', 'turbotax.com',
    'nerdwallet.com', 'expensify.com', 'brex.com', 'ramp.com', 'divvy.com',
    // Healthcare
    'zocdoc.com', 'athenahealth.com', 'practicefusion.com', 'simplepractice.com',
    'kareo.com', 'drchrono.com', 'healthgrades.com',
    // Telecom & Utilities
    'comcast.net', 'xfinity.com', 'att.com', 'verizon.com', 'tmobile.com',
    // Miscellaneous SaaS
    'zapier.com', 'ifttt.com', 'make.com',
    'lattice.com', 'culture-amp.com', '15five.com',
    'netlify.com', 'vercel.com', 'render.com',

    // ===== INTERNATIONAL =====

    // UK & Ireland - Banking
    'barclays.co.uk', 'barclays.com', 'hsbc.co.uk', 'hsbc.com', 'lloydsbank.com',
    'lloydsbankinggroup.com', 'natwest.com', 'rbs.co.uk', 'santander.co.uk', 'santander.com',
    'nationwide.co.uk', 'halifax.co.uk', 'bankofscotland.co.uk', 'firstdirect.com',
    'metrobankonline.co.uk', 'monzo.com', 'starlingbank.com', 'tsb.co.uk', 'virginmoney.com',
    'coop.co.uk',
    // UK - Telecom & Services
    'vodafone.co.uk', 'vodafone.com', 'o2.co.uk', 'three.co.uk', 'ee.co.uk', 'bt.com',
    'sky.com', 'talktalk.co.uk', 'virginmedia.com',
    // UK - Real Estate & Retail
    'rightmove.co.uk', 'zoopla.co.uk', 'onthemarket.com', 'purplebricks.co.uk',
    'gumtree.com', 'autotrader.co.uk', 'tesco.com', 'sainsburys.co.uk', 'asda.com',
    'marksandspencer.com', 'johnlewis.com', 'argos.co.uk', 'asos.com', 'boohoo.com',
    'ocado.com', 'deliveroo.com', 'justeat.co.uk',

    // Europe - Banking
    'deutschebank.de', 'deutschebank.com', 'commerzbank.de', 'commerzbank.com',
    'ing.com', 'ing.nl', 'rabobank.nl', 'rabobank.com',
    'bnpparibas.com', 'societegenerale.com', 'creditagricole.com',
    'unicredit.it', 'intesasanpaolo.com',
    'n26.com', 'klarna.com', 'afterpay.com', 'adyen.com',
    'swissquote.com', 'ubs.com', 'creditsuisse.com',
    'nordea.com', 'dnb.no', 'seb.se', 'handelsbanken.se',
    'bbva.com', 'bbva.es', 'caixabank.com', 'caixabank.es',
    'bankofireland.com', 'aib.ie', 'permanenttsb.ie',
    // Europe - Telecom
    'vodafone.de', 'orange.com', 'orange.fr', 't-mobile.nl',
    'telefonica.com', 'movistar.es', 'bouygues-telecom.fr',
    'swisscom.ch', 'proximus.be', 'kpn.com',
    // Europe - E-commerce & Travel
    'zalando.com', 'zalando.de', 'otto.de', 'allegro.pl', 'bol.com',
    'blablacar.com', 'flixbus.com', 'ryanair.com', 'easyjet.com',
    'lufthansa.com', 'airfrance.com', 'klm.com', 'britishairways.com',
    'iberia.com', 'vueling.com', 'trainline.com', 'sncf.com', 'eurostar.com',
    // Europe - Food Delivery
    'justeat.com', 'thuisbezorgd.nl', 'glovo.com', 'wolt.com', 'foodpanda.com',

    // India - Banking
    'sbi.co.in', 'hdfcbank.com', 'icicibank.com', 'axisbank.com',
    'kotakbank.com', 'kotakmahindra.com', 'yesbank.in',
    'pnbindia.in', 'bankofbaroda.in', 'canarabank.com',
    'idfcfirstbank.com', 'federalbank.co.in', 'indusind.com',
    // India - Fintech & E-commerce
    'paytm.com', 'phonepe.com', 'gpay.in',
    'flipkart.com', 'myntra.com', 'snapdeal.com', 'amazon.in',
    'meesho.com', 'nykaa.com', 'zomato.com', 'swiggy.com',
    'dunzo.com', 'bigbasket.com', 'olacabs.com',
    'makemytrip.com', 'goibibo.com', 'cleartrip.com',
    'policybazaar.com', 'zerodha.com', 'groww.in', 'cred.club',
    'jio.com', 'airtel.in', 'vi.com', 'bsnl.co.in',

    // Latin America - Banking & Fintech
    'nubank.com.br', 'nubank.com', 'mercadolibre.com', 'mercadopago.com',
    'bancodobrasil.com.br', 'bb.com.br', 'itau.com.br', 'bradesco.com.br',
    'banorte.com', 'bbva.mx', 'santander.com.mx',
    'bancodechile.cl', 'bancoestado.cl', 'bcp.com.pe', 'bancolombia.com',
    // Latin America - E-commerce & Services
    'rappi.com', 'ifood.com.br', '99app.com', 'cornershopapp.com',
    'falabella.com', 'liverpool.com.mx', 'americanas.com.br', 'magazineluiza.com.br',
    'latamairlines.com', 'avianca.com', 'volaris.com',

    // Australia & NZ - Banking
    'commbank.com.au', 'westpac.com.au', 'anz.com.au', 'nab.com.au',
    'macquarie.com.au', 'suncorp.com.au', 'bendigo.com.au',
    'ing.com.au', 'ubank.com.au', 'up.com.au',
    'anz.co.nz', 'asb.co.nz', 'bnz.co.nz', 'westpac.co.nz',
    // Australia & NZ - Services
    'telstra.com.au', 'optus.com.au', 'vodafone.com.au', 'spark.co.nz',
    'realestate.com.au', 'domain.com.au', 'carsales.com.au',
    'seek.com.au', 'seek.co.nz', 'flybuys.com.au',
    'qantas.com', 'airnewzealand.co.nz', 'afterpay.com.au', 'zip.co',

    // Japan
    'smbc.co.jp', 'mufg.jp', 'mizuhobank.co.jp',
    'rakuten.co.jp', 'rakuten.com', 'mercari.com', 'mercari.jp',
    'yahoo.co.jp', 'line.me', 'paypay.ne.jp', 'ana.co.jp', 'jal.co.jp',
    // South Korea
    'kbstar.com', 'shinhan.com', 'wooribank.com', 'hana.com',
    'kakaocorp.com', 'kakaopay.com', 'coupang.com',
    'naver.com', 'samsungcard.com', 'toss.im', 'koreanair.com', 'asiana.com',
    // China (diaspora)
    'alipay.com', 'wechat.com', 'jd.com', 'bankofchina.com', 'icbc.com.cn',

    // Southeast Asia
    'grab.com', 'gojek.com', 'shopee.com', 'lazada.com',
    'gcash.com', 'maya.ph', 'bdo.com.ph', 'bpi.com.ph',
    'dbs.com', 'dbs.com.sg', 'ocbc.com', 'uob.com',
    'maybank.com', 'cimb.com', 'rhbgroup.com',
    'bangkokbank.com', 'scb.co.th', 'kasikornbank.com',
    'airasia.com', 'cebuair.com', 'garuda-indonesia.com',

    // Middle East
    'emirates.com', 'etihad.com', 'flydubai.com', 'qatarairways.com', 'saudia.com',
    'emiratesnbd.com', 'adcb.com', 'mashreqbank.com',
    'alrajhibank.com', 'sab.com', 'stcpay.com.sa',
    'noon.com', 'namshi.com', 'careem.com', 'talabat.com',

    // Africa
    'safaricom.co.ke', 'mpesa.com', 'mtn.com', 'mtn.co.za',
    'fnb.co.za', 'standardbank.co.za', 'nedbank.co.za', 'absa.co.za',
    'capitecbank.co.za', 'discovery.co.za',
    'flutterwave.com', 'paystack.com', 'interswitch.com',
    'jumia.com', 'takealot.com',

    // Canada - Banking
    'rbc.com', 'td.com', 'scotiabank.com', 'bmo.com', 'cibc.com',
    'desjardins.com', 'tangerine.ca', 'simplii.com', 'eqbank.ca',
    'wealthsimple.com', 'questrade.com',
    // Canada - Services
    'shoppers.ca', 'canadapost.ca', 'bell.ca', 'rogers.com', 'telus.com',
    'aircanada.com', 'westjet.com',

    // Global Fintech & Crypto
    'wise.com', 'transferwise.com', 'revolut.com',
    'monese.com', 'remitly.com', 'worldremit.com',
    'binance.com', 'kraken.com', 'gemini.com', 'bitfinex.com',
    'blockchain.com', 'crypto.com', 'ledger.com',

    // ===== V4.3.0 SaaS PLATFORM EXPANSION (328 domains) =====

    // Transactional Email Services
    'mailjet.com', 'mailersend.com', 'smtp2go.com', 'socketlabs.com', 'elasticemail.com',
    'sendpulse.com', 'resend.com', 'mailtrap.io', 'sendlayer.com', 'customer.io',
    'courier.com', 'loops.so', 'sidemail.io', 'smtp.com', 'moosend.com',
    'sendy.co', 'mailpace.com', 'turbosmtp.com', 'pepipost.com', 'netcorecloud.com',
    // Global ESPs
    'sendinblue.co.uk', 'mailup.com', 'mailup.it', 'acumbamail.com', 'rapidmail.com',
    'cleverreach.com', 'newsletter2go.com', 'mailify.com', 'zohomail.com', 'freshmarketer.com',
    'mapp.com', 'emarsys.com', 'selligent.com', 'dotdigital.com', 'omnisend.com',

    // Real Estate Platforms - US
    'bombbomb.com', 'bbsv2.net', 'insiderealestate.com', 'kvcore.com', 'boomtownroi.com',
    'liondesk.com', 'wisageninc.com', 'topproducer.com', 'realgeeks.com', 'sierrainteractive.com',
    'agentlegend.com', 'verse.ai', 'propertybase.com', 'lofty.com', 'chime.house',
    'chimeinc.com', 'ixactcontact.com', 'cloze.com', 'contactually.com', 'moxiworks.com',
    'circlepix.com', 'homeactions.net',

    // Sports / Youth Organizations
    'bluesombrero.com', 'sportsconnect.com', 'stacksports.com', 'teamsnap.com',
    'sportsengine.com', 'leagueapps.com', 'jerseywatch.com', 'teampages.com',
    'playmetrics.com', 'activenetwork.com', 'active.com', 'demosphere.com',

    // Healthcare Patient Communication - US
    'phreesia.com', 'phreesia-mail.com', 'solutionreach.com', 'demandforce.com',
    'patientpop.com', 'tebra.com', 'weave.com', 'updox.com', 'rectanglehealth.com',
    'clearwaveinc.com', 'curogram.com', 'klara.com', 'luma-health.com', 'nexhealth.com',
    'doctible.com', 'srhealth.com', 'advancedmd.com', 'modmed.com', 'eclinicalworks.com',
    'getweave.com',
    // Dental - US
    'dentrix.com', 'opendentalsoft.com', 'revenuewell.com', 'lighthouse360.com',
    'yapi.com', 'patientconnect365.com',

    // Streaming / Entertainment
    'peacocktv.com', 'paramountplus.com', 'max.com', 'crunchyroll.com',
    'funimation.com', 'discoveryplus.com', 'espn.com', 'sling.com',

    // Restaurant / Hospitality
    'touchbistro.com', 'lightspeedhq.com', 'chownow.com', 'olo.com',
    'popmenu.com', 'bentobox.com', 'seven-rooms.com', 'wisely.com',
    'thefork.com', 'quandoo.com', 'tablecheck.com', 'covermanager.com',

    // Salon / Beauty / Wellness
    'fresha.com', 'glossgenius.com', 'boulevard.io', 'zenoti.com',
    'mangomint.com', 'salonbiz.com', 'meevo.com', 'phorest.com',
    'timely.com', 'treatwell.co.uk', 'shedul.com',

    // Veterinary / Pet
    'vetsource.com', 'petdesk.com', 'allydvm.com', 'weconnect.vet',

    // Auto Dealership
    'cdk.com', 'dealertrack.com', 'dealersocket.com', 'vinconnect.com',
    'autosoftdms.com', 'elead-crm.com', 'tekion.com',

    // Education - US
    'schoolmessenger.com', 'parentsquare.com', 'classdojo.com', 'remind.com',
    'finalsite.com', 'blackbaud.com', 'bloomz.net', 'smore.com', 'schoology.com',

    // Church / Nonprofit
    'planningcenteronline.com', 'pushpay.com', 'faithlife.com', 'breezechms.com',
    'tithe.ly', 'bloomerang.com', 'classy.org', 'neoncrm.com',

    // Property Management - US
    'appfolio.com', 'buildium.com', 'rentmanager.com', 'propertyware.com',
    'innago.com', 'tenantcloud.com',

    // Fitness / Gym
    'marianatek.com', 'clubready.com', 'perfectgym.com', 'gymmaster.com',
    'wodify.com', 'zen-planner.com', 'glofox.com', 'pike13.com',

    // HOA / Community
    'caliber.com', 'smartwebs.com', 'townsq.io', 'pilera.com',

    // Global Booking / Scheduling
    'simplybook.me', 'appointy.com',
    // Global Property Management / Vacation Rental
    'guesty.com', 'lodgify.com', 'hostaway.com', 'tokeet.com',

    // ===== UK =====
    // UK - Healthcare / Patient Engagement
    'drdoctor.co.uk', 'swiftqueue.com', 'bookinglab.co.uk', 'bookinglive.com',
    'herohealth.net', 'patchs.com', 'accurx.com', 'mjog.com',
    // UK - School / Parent Communication
    'parentmail.co.uk', 'arbor-education.com', 'bromcom.com', 'reachmoreparents.com',
    'schoolcomms.com', 'parentpay.com', 'schoolcloud.co.uk', 'classcharts.com',
    // UK - Real Estate (additions)
    'openrent.com', 'estate-agents.co.uk',

    // ===== EUROPE =====
    // Europe - Healthcare Booking
    'doctolib.fr', 'doctolib.de', 'doctolib.it', 'doctena.com', 'jameda.de',
    'miodottore.it', 'doctoralia.com', 'qare.fr', 'kry.se', 'doktor.se',
    // Europe - Real Estate Portals
    'seloger.com', 'leboncoin.fr', 'immobilienscout24.de', 'immowelt.de',
    'idealista.com', 'idealista.pt', 'funda.nl', 'hemnet.se',
    'finn.no', 'boliga.dk', 'daft.ie', 'myhome.ie',
    // Europe - Education
    'itslearning.com', 'untis.at', 'sdui.de',
    // Europe - General Business SaaS
    'jimdo.com', 'teamleader.eu', 'billomat.com', 'lexoffice.de', 'weclapp.com', 'fortnox.se',

    // ===== AUSTRALIA / NEW ZEALAND =====
    // AU/NZ - Healthcare
    'cliniko.com', 'hotdoc.com.au', 'healthengine.com.au', 'nookal.com', 'zanda.com',
    'gotohealth.com.au',
    // AU/NZ - Real Estate (additions)
    'allhomes.com.au', 'trademe.co.nz', 'realestate.co.nz', 'propertyguru.com.au',
    // AU/NZ - Education
    'compass.education', 'sentral.com.au', 'edval.education', 'schoolbox.com.au',
    // AU/NZ - Salon
    'nabooki.com', 'kitomba.com',

    // ===== JAPAN =====
    // Japan - Real Estate / Property
    'suumo.jp', 'homes.co.jp', 'athome.co.jp', 'chintai.net', 'ouchi.jp',
    'realestate.yahoo.co.jp',
    // Japan - Booking / Reservations
    'hotpepper.jp', 'tabelog.com', 'gurunavi.com', 'gnavi.co.jp', 'ikyu.com', 'yelp.co.jp',
    // Japan - Healthcare / Beauty
    'hotpepper-beauty.com', 'minimo.app', 'epark.jp', 'caloo.jp',

    // ===== SOUTH KOREA =====
    'zigbang.com', 'dabangapp.com', 'land.naver.com', 'realestate114.com', 'peterpanz.com',
    'baemin.com',

    // ===== INDIA =====
    // India - Healthcare
    'practo.com', '1mg.com', 'lybrate.com', 'medibuddy.in', 'netmeds.com',
    'apolloio.com', 'apollo247.com', 'pristyncare.com',
    // India - Real Estate
    'magicbricks.com', '99acres.com', 'housing.com', 'nobroker.in',
    'commonfloor.com', 'proptiger.com',
    // India - Education
    'byjus.com', 'vedantu.com', 'unacademy.com', 'extramarks.com',
    // India - Business SaaS
    'zoho.in', 'leadsquared.com', 'sell.do',

    // ===== BRAZIL =====
    // Brazil - Real Estate
    'vivareal.com.br', 'zapimoveis.com.br', 'imovelweb.com.br',
    'quintoandar.com.br', 'olx.com.br', 'wimoveis.com.br',
    // Brazil - Healthcare
    'doctoralia.com.br', 'conexasaude.com.br', 'iclinic.com.br', 'shosp.com.br',

    // ===== MIDDLE EAST =====
    // Middle East - Real Estate
    'bayut.com', 'propertyfinder.ae', 'dubizzle.com', 'aqar.fm',
    'zameen.com', 'opensooq.com', 'olx.com.eg', 'bproperty.com',
    // Middle East - Healthcare
    'vezeeta.com', 'altibbi.com', 'cura.healthcare', 'okadoc.com',

    // ===== SOUTHEAST ASIA =====
    'propertyguru.com.sg', 'propertyguru.com.my', 'ddproperty.com', '99.co',
    'rumah123.com', 'batdongsan.com.vn', 'lamudi.co.id', 'dotproperty.com.th',
    'chope.co', 'eatigo.com',

    // ===== CANADA =====
    'realtor.ca', 'zolo.ca', 'housesigma.com', 'condos.ca',
    'jane.app', 'clinicaid.ca', 'inputhealth.com',

    // ===== AFRICA =====
    'property24.com', 'privateproperty.co.za', 'jiji.com'
];

function getRootDomain(domain) {
    if (!domain) return domain;
    const d = domain.toLowerCase();
    const compoundTlds = ['.co.uk', '.co.za', '.co.in', '.co.jp', '.co.kr', '.co.nz',
                         '.com.ar', '.com.au', '.com.br', '.com.cn', '.com.co', '.com.mx',
                         '.com.ng', '.com.pk', '.com.ph', '.com.tr', '.com.ua', '.com.ve', '.com.vn',
                         '.net.br', '.net.co', '.org.br', '.org.co', '.org.uk'];
    for (const tld of compoundTlds) {
        if (d.endsWith(tld)) {
            const withoutTld = d.slice(0, -tld.length);
            const parts = withoutTld.split('.');
            return parts[parts.length - 1] + tld;
        }
    }
    const parts = d.split('.');
    if (parts.length >= 2) return parts[parts.length - 2] + '.' + parts[parts.length - 1];
    return d;
}

function isKnownPlatform(domain) {
    if (!domain) return false;
    const d = domain.toLowerCase();
    return KNOWN_PLATFORM_DOMAINS.some(p => d === p || d.endsWith('.' + p));
}

const SUSPICIOUS_FREE_HOSTING_DOMAINS = [
    'netlify.app', 'vercel.app', 'github.io', 'pages.dev',
    'firebaseapp.com', 'web.app', 'workers.dev', 'glitch.me',
    'replit.app', 'repl.co', 'herokuapp.com', 'bitbucket.io',
    'surge.sh', 'ngrok-free.app', 'ngrok.io', 'webhook.site',
    'pipedream.net', 'kesug.com', 'wuaze.com', 'rf.gd',
    'my-board.org', 'blogspot.com', 'weebly.com',
    '000webhostapp.com', 'infinityfreeapp.com'
];

const COMMON_LEGIT_PLATFORMS = [
    'drive.google.com', 'docs.google.com', 'storage.googleapis.com',
    'googleusercontent.com', 'sharepoint.com', 'onedrive.live.com',
    '1drv.ms', 'dropbox.com', 'dropboxusercontent.com',
    'box.com', 'app.box.com'
];

const DANGEROUS_ATTACHMENT_EXTENSIONS = {
    archive: ['.zip', '.rar', '.7z', '.tar', '.gz'],
    disk_image: ['.iso', '.img', '.dmg'],
    executable: ['.exe', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.hta', '.msi', '.com', '.pif'],
    macro_capable: ['.xlsm', '.docm', '.pptm', '.xlam', '.dotm'],
    html: ['.html', '.htm', '.mhtml', '.svg']
};

const PHASE2_URL_REGEX = /https?:\/\/[^\s<>"')\]]+/gi;

const SUPPRESSION_MAP = {
    pattern_a_credential_harvesting: ['phishing-urgency'],
    pattern_b_brand_free_hosting: ['brand-impersonation', 'phishing-urgency'],
    pattern_c_html_attachment_trap: ['phishing-urgency', 'brand-impersonation'],
    pattern_d_dangerous_attachment: ['wire-fraud', 'phishing-urgency'],
    pattern_e_payment_redirect: ['replyto-mismatch', 'on-behalf-of', 'wire-fraud', 'phishing-urgency']
};


// ============================================
// VALID TLD DETECTION (IANA Feb 2026 - 1,436 TLDs)
// ============================================
const VALID_TLDS = new Set(['aaa','aarp','abb','abbott','abbvie','abc','able','abogado','abudhabi','ac','academy','accenture','accountant','accountants','aco','actor','ad','ads','adult','ae','aeg','aero','aetna','af','afl','africa','ag','agakhan','agency','ai','aig','airbus','airforce','airtel','akdn','al','alibaba','alipay','allfinanz','allstate','ally','alsace','alstom','am','amazon','americanexpress','americanfamily','amex','amfam','amica','amsterdam','analytics','android','anquan','anz','ao','aol','apartments','app','apple','aq','aquarelle','ar','arab','aramco','archi','army','arpa','art','arte','as','asda','asia','associates','at','athleta','attorney','au','auction','audi','audible','audio','auspost','author','auto','autos','aw','aws','ax','axa','az','azure','ba','baby','baidu','banamex','band','bank','bar','barcelona','barclaycard','barclays','barefoot','bargains','baseball','basketball','bauhaus','bayern','bb','bbc','bbt','bbva','bcg','bcn','bd','be','beats','beauty','beer','berlin','best','bestbuy','bet','bf','bg','bh','bharti','bi','bible','bid','bike','bing','bingo','bio','biz','bj','black','blackfriday','blockbuster','blog','bloomberg','blue','bm','bms','bmw','bn','bnpparibas','bo','boats','boehringer','bofa','bom','bond','boo','book','booking','bosch','bostik','boston','bot','boutique','box','br','bradesco','bridgestone','broadway','broker','brother','brussels','bs','bt','build','builders','business','buy','buzz','bv','bw','by','bz','bzh','ca','cab','cafe','cal','call','calvinklein','cam','camera','camp','canon','capetown','capital','capitalone','car','caravan','cards','care','career','careers','cars','casa','case','cash','casino','cat','catering','catholic','cba','cbn','cbre','cc','cd','center','ceo','cern','cf','cfa','cfd','cg','ch','chanel','channel','charity','chase','chat','cheap','chintai','christmas','chrome','church','ci','cipriani','circle','cisco','citadel','citi','citic','city','ck','cl','claims','cleaning','click','clinic','clinique','clothing','cloud','club','clubmed','cm','cn','co','coach','codes','coffee','college','cologne','com','commbank','community','company','compare','computer','comsec','condos','construction','consulting','contact','contractors','cooking','cool','coop','corsica','country','coupon','coupons','courses','cpa','cr','credit','creditcard','creditunion','cricket','crown','crs','cruise','cruises','cu','cuisinella','cv','cw','cx','cy','cymru','cyou','cz','dad','dance','data','date','dating','datsun','day','dclk','dds','de','deal','dealer','deals','degree','delivery','dell','deloitte','delta','democrat','dental','dentist','desi','design','dev','dhl','diamonds','diet','digital','direct','directory','discount','discover','dish','diy','dj','dk','dm','dnp','do','docs','doctor','dog','domains','dot','download','drive','dtv','dubai','dupont','durban','dvag','dvr','dz','earth','eat','ec','eco','edeka','edu','education','ee','eg','email','emerck','energy','engineer','engineering','enterprises','epson','equipment','er','ericsson','erni','es','esq','estate','et','eu','eurovision','eus','events','exchange','expert','exposed','express','extraspace','fage','fail','fairwinds','faith','family','fan','fans','farm','farmers','fashion','fast','fedex','feedback','ferrari','ferrero','fi','fidelity','fido','film','final','finance','financial','fire','firestone','firmdale','fish','fishing','fit','fitness','fj','fk','flickr','flights','flir','florist','flowers','fly','fm','fo','foo','food','football','ford','forex','forsale','forum','foundation','fox','fr','free','fresenius','frl','frogans','frontier','ftr','fujitsu','fun','fund','furniture','futbol','fyi','ga','gal','gallery','gallo','gallup','game','games','gap','garden','gay','gb','gbiz','gd','gdn','ge','gea','gent','genting','george','gf','gg','ggee','gh','gi','gift','gifts','gives','giving','gl','glass','gle','global','globo','gm','gmail','gmbh','gmo','gmx','gn','godaddy','gold','goldpoint','golf','goodyear','goog','google','gop','got','gov','gp','gq','gr','grainger','graphics','gratis','green','gripe','grocery','group','gs','gt','gu','gucci','guge','guide','guitars','guru','gw','gy','hair','hamburg','hangout','haus','hbo','hdfc','hdfcbank','health','healthcare','help','helsinki','here','hermes','hiphop','hisamitsu','hitachi','hiv','hk','hkt','hm','hn','hockey','holdings','holiday','homedepot','homegoods','homes','homesense','honda','horse','hospital','host','hosting','hot','hotels','hotmail','house','how','hr','hsbc','ht','hu','hughes','hyatt','hyundai','ibm','icbc','ice','icu','id','ie','ieee','ifm','ikano','il','im','imamat','imdb','immo','immobilien','in','inc','industries','infiniti','info','ing','ink','institute','insurance','insure','int','international','intuit','investments','io','ipiranga','iq','ir','irish','is','ismaili','ist','istanbul','it','itau','itv','jaguar','java','jcb','je','jeep','jetzt','jewelry','jio','jll','jm','jmp','jnj','jo','jobs','joburg','jot','joy','jp','jpmorgan','jprs','juegos','juniper','kaufen','kddi','ke','kerryhotels','kerryproperties','kfh','kg','kh','ki','kia','kids','kim','kindle','kitchen','kiwi','km','kn','koeln','komatsu','kosher','kp','kpmg','kpn','kr','krd','kred','kuokgroup','kw','ky','kyoto','kz','la','lacaixa','lamborghini','lamer','land','landrover','lanxess','lasalle','lat','latino','latrobe','law','lawyer','lb','lc','lds','lease','leclerc','lefrak','legal','lego','lexus','lgbt','li','lidl','life','lifeinsurance','lifestyle','lighting','like','lilly','limited','limo','lincoln','link','live','living','lk','llc','llp','loan','loans','locker','locus','lol','london','lotte','lotto','love','lpl','lplfinancial','lr','ls','lt','ltd','ltda','lu','lundbeck','luxe','luxury','lv','ly','ma','madrid','maif','maison','makeup','man','management','mango','map','market','marketing','markets','marriott','marshalls','mattel','mba','mc','mckinsey','md','me','med','media','meet','melbourne','meme','memorial','men','menu','merckmsd','mg','mh','miami','microsoft','mil','mini','mint','mit','mitsubishi','mk','ml','mlb','mls','mm','mma','mn','mo','mobi','mobile','moda','moe','moi','mom','monash','money','monster','mormon','mortgage','moscow','moto','motorcycles','mov','movie','mp','mq','mr','ms','msd','mt','mtn','mtr','mu','museum','music','mv','mw','mx','my','mz','na','nab','nagoya','name','navy','nba','nc','ne','nec','net','netbank','netflix','network','neustar','new','news','next','nextdirect','nexus','nf','nfl','ng','ngo','nhk','ni','nico','nike','nikon','ninja','nissan','nissay','nl','no','nokia','norton','now','nowruz','nowtv','np','nr','nra','nrw','ntt','nu','nyc','nz','obi','observer','office','okinawa','olayan','olayangroup','ollo','om','omega','one','ong','onl','online','ooo','open','oracle','orange','org','organic','origins','osaka','otsuka','ott','ovh','pa','page','panasonic','paris','pars','partners','parts','party','pay','pccw','pe','pet','pf','pfizer','pg','ph','pharmacy','phd','philips','phone','photo','photography','photos','physio','pics','pictet','pictures','pid','pin','ping','pink','pioneer','pizza','pk','pl','place','play','playstation','plumbing','plus','pm','pn','pnc','pohl','poker','politie','porn','post','pr','praxi','press','prime','pro','prod','productions','prof','progressive','promo','properties','property','protection','pru','prudential','ps','pt','pub','pw','pwc','py','qa','qpon','quebec','quest','racing','radio','re','read','realestate','realtor','realty','recipes','red','redumbrella','rehab','reise','reisen','reit','reliance','ren','rent','rentals','repair','report','republican','rest','restaurant','review','reviews','rexroth','rich','richardli','ricoh','ril','rio','rip','ro','rocks','rodeo','rogers','room','rs','rsvp','ru','rugby','ruhr','run','rw','rwe','ryukyu','sa','saarland','safe','safety','sakura','sale','salon','samsclub','samsung','sandvik','sandvikcoromant','sanofi','sap','sarl','sas','save','saxo','sb','sbi','sbs','sc','scb','schaeffler','schmidt','scholarships','school','schule','schwarz','science','scot','sd','se','search','seat','secure','security','seek','select','sener','services','seven','sew','sex','sexy','sfr','sg','sh','shangrila','sharp','shell','shia','shiksha','shoes','shop','shopping','shouji','show','si','silk','sina','singles','site','sj','sk','ski','skin','sky','skype','sl','sling','sm','smart','smile','sn','sncf','so','soccer','social','softbank','software','sohu','solar','solutions','song','sony','soy','spa','space','sport','spot','sr','srl','ss','st','stada','staples','star','statebank','statefarm','stc','stcgroup','stockholm','storage','store','stream','studio','study','style','su','sucks','supplies','supply','support','surf','surgery','suzuki','sv','swatch','swiss','sx','sy','sydney','systems','sz','tab','taipei','talk','taobao','target','tatamotors','tatar','tattoo','tax','taxi','tc','tci','td','tdk','team','tech','technology','tel','temasek','tennis','teva','tf','tg','th','thd','theater','theatre','tiaa','tickets','tienda','tips','tires','tirol','tj','tjmaxx','tjx','tk','tkmaxx','tl','tm','tmall','tn','to','today','tokyo','tools','top','toray','toshiba','total','tours','town','toyota','toys','tr','trade','trading','training','travel','travelers','travelersinsurance','trust','trv','tt','tube','tui','tunes','tushu','tv','tvs','tw','tz','ua','ubank','ubs','ug','uk','unicom','university','uno','uol','ups','us','uy','uz','va','vacations','vana','vanguard','vc','ve','vegas','ventures','verisign','versicherung','vet','vg','vi','viajes','video','vig','viking','villas','vin','vip','virgin','visa','vision','viva','vivo','vlaanderen','vn','vodka','volvo','vote','voting','voto','voyage','vu','wales','walmart','walter','wang','wanggou','watch','watches','weather','weatherchannel','webcam','weber','website','wed','wedding','weibo','weir','wf','whoswho','wien','wiki','williamhill','win','windows','wine','winners','wme','woodside','work','works','world','wow','ws','wtc','wtf','xbox','xerox','xihuan','xin','xn--11b4c3d','xn--1ck2e1b','xn--1qqw23a','xn--2scrj9c','xn--30rr7y','xn--3bst00m','xn--3ds443g','xn--3e0b707e','xn--3hcrj9c','xn--3pxu8k','xn--42c2d9a','xn--45br5cyl','xn--45brj9c','xn--45q11c','xn--4dbrk0ce','xn--4gbrim','xn--54b7fta0cc','xn--55qw42g','xn--55qx5d','xn--5su34j936bgsg','xn--5tzm5g','xn--6frz82g','xn--6qq986b3xl','xn--80adxhks','xn--80ao21a','xn--80aqecdr1a','xn--80asehdb','xn--80aswg','xn--8y0a063a','xn--90a3ac','xn--90ae','xn--90ais','xn--9dbq2a','xn--9et52u','xn--9krt00a','xn--b4w605ferd','xn--bck1b9a5dre4c','xn--c1avg','xn--c2br7g','xn--cck2b3b','xn--cckwcxetd','xn--cg4bki','xn--clchc0ea0b2g2a9gcd','xn--czr694b','xn--czrs0t','xn--czru2d','xn--d1acj3b','xn--d1alf','xn--e1a4c','xn--eckvdtc9d','xn--efvy88h','xn--fct429k','xn--fhbei','xn--fiq228c5hs','xn--fiq64b','xn--fiqs8s','xn--fiqz9s','xn--fjq720a','xn--flw351e','xn--fpcrj9c3d','xn--fzc2c9e2c','xn--fzys8d69uvgm','xn--g2xx48c','xn--gckr3f0f','xn--gecrj9c','xn--gk3at1e','xn--h2breg3eve','xn--h2brj9c','xn--h2brj9c8c','xn--hxt814e','xn--i1b6b1a6a2e','xn--imr513n','xn--io0a7i','xn--j1aef','xn--j1amh','xn--j6w193g','xn--jlq480n2rg','xn--jvr189m','xn--kcrx77d1x4a','xn--kprw13d','xn--kpry57d','xn--kput3i','xn--l1acc','xn--lgbbat1ad8j','xn--mgb9awbf','xn--mgba3a3ejt','xn--mgba3a4f16a','xn--mgba7c0bbn0a','xn--mgbaam7a8h','xn--mgbab2bd','xn--mgbah1a3hjkrd','xn--mgbai9azgqp6j','xn--mgbayh7gpa','xn--mgbbh1a','xn--mgbbh1a71e','xn--mgbc0a9azcg','xn--mgbca7dzdo','xn--mgbcpq6gpa1a','xn--mgberp4a5d4ar','xn--mgbgu82a','xn--mgbi4ecexp','xn--mgbpl2fh','xn--mgbt3dhd','xn--mgbtx2b','xn--mgbx4cd0ab','xn--mix891f','xn--mk1bu44c','xn--mxtq1m','xn--ngbc5azd','xn--ngbe9e0a','xn--ngbrx','xn--node','xn--nqv7f','xn--nqv7fs00ema','xn--nyqy26a','xn--o3cw4h','xn--ogbpf8fl','xn--otu796d','xn--p1acf','xn--p1ai','xn--pgbs0dh','xn--pssy2u','xn--q7ce6a','xn--q9jyb4c','xn--qcka1pmc','xn--qxa6a','xn--qxam','xn--rhqv96g','xn--rovu88b','xn--rvc1e0am3e','xn--s9brj9c','xn--ses554g','xn--t60b56a','xn--tckwe','xn--tiq49xqyj','xn--unup4y','xn--vermgensberater-ctb','xn--vermgensberatung-pwb','xn--vhquv','xn--vuq861b','xn--w4r85el8fhu5dnra','xn--w4rs40l','xn--wgbh1c','xn--wgbl6a','xn--xhq521b','xn--xkc2al3hye2a','xn--xkc2dl3a5ee0h','xn--y9a3aq','xn--yfro4i67o','xn--ygbi2ammx','xn--zfr164b','xxx','xyz','yachts','yahoo','yamaxun','yandex','ye','yodobashi','yoga','yokohama','you','youtube','yt','yun','za','zappos','zara','zero','zip','zm','zone','zuerich','zw']);

function detectFakeTLD(domain) {
    if (!domain) return null;
    const parts = domain.toLowerCase().split('.');
    if (parts.length < 2) return null;
    const tld = parts[parts.length - 1];
    if (VALID_TLDS.has(tld)) return null;
    return { fakeTLD: '.' + tld, domain: domain };
}

// ============================================
// STATE
// ============================================
let msalInstance = null;
let knownContacts = new Set();
let currentUserEmail = null;
let currentItemId = null;
let isAutoScanEnabled = true;
let authInProgress = false;
let contactsFetched = false;

// ============================================
// USER-TRUSTED DOMAINS (Learned from Sent Items)
// ============================================
let userTrustedDomains = {};
const USER_TRUSTED_KEY = 'efa_trusted_domains';
const MAX_TRUSTED_DOMAINS = 500;
const FREE_EMAIL_PROVIDERS = [
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
    'icloud.com', 'mail.com', 'protonmail.com', 'proton.me', 'zoho.com',
    'yandex.com', 'yandex.ru', 'mail.ru', 'gmx.com', 'gmx.net', 'web.de',
    'yahoo.co.jp', 'naver.com', 'daum.net', '163.com', '126.com', 'qq.com',
    'live.com', 'msn.com', 'me.com', 'mac.com'
];

// ============================================
// USER-TRUSTED DOMAIN FUNCTIONS
// Learned automatically from user's Sent Items.
// Viktor gate: No domain enters this list if it's
// a lookalike of any known brand, org, or existing
// trusted domain. Viktor cannot poison this list
// without compromising the user's own mailbox.
// ============================================

function loadUserTrustedDomains() {
    try {
        const data = Office.context.roamingSettings.get(USER_TRUSTED_KEY);
        userTrustedDomains = data || {};
        console.log('Loaded ' + Object.keys(userTrustedDomains).length + ' user-trusted domains');
    } catch (e) {
        console.log('Could not load user-trusted domains:', e.message);
        userTrustedDomains = {};
    }
}

function saveUserTrustedDomains() {
    try {
        // v4.3.3: RoamingSettings has a 32KB cap (Microsoft docs).
        // Guard against silent truncation by checking size and pruning if needed.
        const MAX_ROAMING_BYTES = 28000; // 28KB, leaving 4KB headroom
        let serialized = JSON.stringify(userTrustedDomains);
        while (serialized.length > MAX_ROAMING_BYTES && Object.keys(userTrustedDomains).length > 0) {
            // Prune lowest-count domain
            let minKey = null, minCount = Infinity;
            for (const [k, v] of Object.entries(userTrustedDomains)) {
                if (v.c < minCount) { minCount = v.c; minKey = k; }
            }
            if (minKey) delete userTrustedDomains[minKey];
            serialized = JSON.stringify(userTrustedDomains);
        }
        Office.context.roamingSettings.set(USER_TRUSTED_KEY, userTrustedDomains);
        Office.context.roamingSettings.saveAsync((result) => {
            if (result.status !== Office.AsyncResultStatus.Succeeded) {
                console.log('Failed to save user-trusted domains');
            }
        });
    } catch (e) {
        console.log('Could not save user-trusted domains:', e.message);
    }
}

// VIKTOR GATE: The single chokepoint. Every domain must pass this
// before entering the trusted list. Checks against ALL known lists.
function isLookalikeOfKnownDomain(domain) {
    const d = domain.toLowerCase();
    
    // Check against existing user-trusted domains
    for (const trusted of Object.keys(userTrustedDomains)) {
        const distance = levenshteinDistance(d, trusted);
        if (distance > 0 && distance <= 2) return true;
    }
    
    // Check against hardcoded trusted domains (stock exchange companies, etc.)
    for (const trusted of CONFIG.trustedDomains) {
        const distance = levenshteinDistance(d, trusted);
        if (distance > 0 && distance <= 2) return true;
    }
    
    // Check against BRAND_CONTENT_DETECTION legitimate domains
    for (const brand of Object.values(BRAND_CONTENT_DETECTION)) {
        for (const legit of brand.legitimateDomains) {
            const distance = levenshteinDistance(d, legit);
            if (distance > 0 && distance <= 2) return true;
        }
    }
    
    // Check against IMPERSONATION_TARGETS domains
    for (const domains of Object.values(IMPERSONATION_TARGETS)) {
        for (const legit of domains) {
            const distance = levenshteinDistance(d, legit);
            if (distance > 0 && distance <= 2) return true;
        }
    }
    
    return false;
}

function addUserTrustedDomain(domain) {
    const d = domain.toLowerCase();
    
    // Skip free email providers (everyone uses them, no lookalike value)
    if (FREE_EMAIL_PROVIDERS.includes(d)) return;
    
    // Skip known ESPs (not real company domains)
    if (KNOWN_ESP_DOMAINS.includes(d)) return;
    
    // If already trusted, just update counter and timestamp
    // Track distinct days: only increment d when last seen was a different calendar day
    if (userTrustedDomains[d]) {
        userTrustedDomains[d].c++;
        const lastDay = new Date(userTrustedDomains[d].t).toDateString();
        const today = new Date().toDateString();
        if (lastDay !== today) {
            userTrustedDomains[d].d = (userTrustedDomains[d].d || 1) + 1;
        }
        userTrustedDomains[d].t = Date.now();
        return true;
    }
    
    // VIKTOR GATE: Reject if lookalike of any known domain
    if (isLookalikeOfKnownDomain(d)) {
        console.log('Gate rejected domain (lookalike): ' + d);
        return false;
    }
    
    // Evict least-contacted domain if at capacity
    const keys = Object.keys(userTrustedDomains);
    if (keys.length >= MAX_TRUSTED_DOMAINS) {
        let minKey = keys[0], minCount = userTrustedDomains[keys[0]].c;
        for (const k of keys) {
            if (userTrustedDomains[k].c < minCount) {
                minCount = userTrustedDomains[k].c;
                minKey = k;
            }
        }
        delete userTrustedDomains[minKey];
    }
    
    userTrustedDomains[d] = { c: 1, t: Date.now(), d: 1 };
    return true;
}

async function syncSentItemsDomains() {
    const token = await getAccessToken();
    if (!token) return;
    
    try {
        const response = await fetch(
            'https://graph.microsoft.com/v1.0/me/mailFolders/SentItems/messages?$select=toRecipients,ccRecipients&$top=50&$orderby=sentDateTime desc',
            { headers: { 'Authorization': 'Bearer ' + token } }
        );
        
        if (!response.ok) {
            console.log('Sent Items sync failed:', response.status);
            return;
        }
        
        const data = await response.json();
        let added = 0;
        
        for (const msg of data.value || []) {
            const recipients = [...(msg.toRecipients || []), ...(msg.ccRecipients || [])];
            for (const r of recipients) {
                const email = (r.emailAddress?.address || '').toLowerCase();
                const domain = email.split('@')[1];
                if (domain && addUserTrustedDomain(domain)) added++;
            }
        }
        
        if (added > 0) {
            saveUserTrustedDomains();
            console.log('Sent Items sync: processed domains, total trusted: ' + Object.keys(userTrustedDomains).length);
        }
    } catch (e) {
        console.log('Sent Items sync error:', e.message);
    }
}

// ============================================
// INITIALIZATION
// ============================================
Office.onReady(async (info) => {
    console.log('Email Fraud Detector v5.2.0 (Phase 2 Silent) script loaded, host:', info.host);
    if (info.host === Office.HostType.Outlook) {
        console.log('Email Fraud Detector v5.2.0 initializing for Outlook...');
        loadUserTrustedDomains();
        await initializeMsal();
        setupEventHandlers();
        analyzeCurrentEmail();
        setupAutoScan();
        console.log('Email Fraud Detector v5.2.0 ready');
    }
});

async function initializeMsal() {
    const msalConfig = {
        auth: {
            clientId: CONFIG.clientId,
            redirectUri: CONFIG.redirectUri,
            authority: 'https://login.microsoftonline.com/common'
        },
        cache: {
            cacheLocation: 'sessionStorage',
            storeAuthStateInCookie: false
        }
    };
    msalInstance = new msal.PublicClientApplication(msalConfig);
    
    try {
        await msalInstance.handleRedirectPromise();
        console.log('MSAL initialized, cleared any pending auth');
    } catch (e) {
        console.log('MSAL init note:', e.message);
    }
}

function setupEventHandlers() {
    document.getElementById('retry-btn').addEventListener('click', analyzeCurrentEmail);
}

function setupAutoScan() {
    if (Office.context.mailbox.addHandlerAsync) {
        Office.context.mailbox.addHandlerAsync(
            Office.EventType.ItemChanged,
            onItemChanged,
            (result) => {
                if (result.status === Office.AsyncResultStatus.Succeeded) {
                    console.log('Auto-scan enabled');
                }
            }
        );
    }
}

function onItemChanged() {
    // v5.2.1: Always reset panel immediately on navigation to prevent stale warnings
    resetPanelUI();
    if (isAutoScanEnabled) {
        analyzeCurrentEmail();
    }
}

function resetPanelUI() {
    const warningsList = document.getElementById('warnings-list');
    const warningsSection = document.getElementById('warnings-section');
    const warningsFooter = document.getElementById('warnings-footer');
    const safeMessage = document.getElementById('safe-message');
    const statusBadge = document.getElementById('status-badge');
    
    if (warningsList) warningsList.innerHTML = '';
    if (warningsSection) warningsSection.classList.add('hidden');
    if (warningsFooter) warningsFooter.classList.add('hidden');
    if (safeMessage) safeMessage.classList.add('hidden');
    if (statusBadge) {
        statusBadge.className = 'status-badge';
        const statusIcon = statusBadge.querySelector('.status-icon');
        const statusText = statusBadge.querySelector('.status-text');
        if (statusIcon) statusIcon.textContent = '';
        if (statusText) statusText.textContent = '';
    }
    document.body.classList.remove('status-critical', 'status-medium', 'status-info', 'status-safe');
    console.log('UI: resetPanelUI() called');
}

// ============================================
// AUTHENTICATION & DATA FETCHING
// ============================================
async function getAccessToken() {
    if (!msalInstance) return null;
    if (authInProgress) {
        console.log('Auth already in progress, skipping');
        return null;
    }
    
    const accounts = msalInstance.getAllAccounts();
    
    try {
        if (accounts.length > 0) {
            const response = await msalInstance.acquireTokenSilent({
                scopes: CONFIG.scopes,
                account: accounts[0]
            });
            return response.accessToken;
        } else {
            authInProgress = true;
            try {
                const response = await msalInstance.acquireTokenPopup({
                    scopes: CONFIG.scopes
                });
                authInProgress = false;
                return response.accessToken;
            } catch (popupError) {
                authInProgress = false;
                throw popupError;
            }
        }
    } catch (error) {
        console.log('Auth error:', error);
        authInProgress = false;
        
        if (error.errorCode === 'interaction_in_progress') {
            console.log('Clearing stuck auth state...');
            try {
                sessionStorage.clear();
                await msalInstance.handleRedirectPromise();
            } catch (e) {
                // Ignore cleanup errors
            }
        }
        return null;
    }
}

async function fetchContacts(token) {
    const contacts = [];
    
    try {
        let url = 'https://graph.microsoft.com/v1.0/me/contacts?$top=500&$select=emailAddresses';
        
        while (url) {
            const response = await fetch(url, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            
            if (!response.ok) break;
            
            const data = await response.json();
            
            if (data.value) {
                data.value.forEach(contact => {
                    if (contact.emailAddresses) {
                        contact.emailAddresses.forEach(email => {
                            if (email.address) {
                                contacts.push(email.address.toLowerCase());
                            }
                        });
                    }
                });
            }
            
            url = data['@odata.nextLink'] || null;
        }
        
        console.log('Fetched', contacts.length, 'contacts');
    } catch (error) {
        console.log('Contacts fetch error:', error);
    }
    
    return contacts;
}

async function fetchAllKnownContacts() {
    if (contactsFetched) return;
    
    const token = await getAccessToken();
    if (!token) {
        console.log('No token available, continuing without contacts');
        contactsFetched = true;
        return;
    }
    
    console.log('Fetching contacts...');
    
    const contacts = await fetchContacts(token);
    
    contacts.forEach(e => knownContacts.add(e));
    
    if (currentUserEmail) {
        knownContacts.add(currentUserEmail.toLowerCase());
    }
    
    console.log('Total known contacts:', knownContacts.size);
    contactsFetched = true;
}

// ============================================
// HELPER FUNCTIONS
// ============================================
// v4.3.1: User-learned domains require minimum 3 sends before earning trust.
// Viktor: "One tricked reply shouldn't buy me a free pass on all future emails."
const USER_TRUST_MIN_COUNT = 5;
const USER_TRUST_MIN_DAYS = 2;

function isTrustedDomain(domain) {
    const d = domain.toLowerCase();
    if (CONFIG.trustedDomains.includes(d)) return true;
    const entry = userTrustedDomains[d];
    // Require both minimum message count AND seen across multiple distinct days.
    // Viktor: "Getting 3 replies in one thread shouldn't make my domain trusted."
    return entry != null && entry.c >= USER_TRUST_MIN_COUNT && (entry.d || 1) >= USER_TRUST_MIN_DAYS;
}

function escapeRegex(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function formatEntityName(name) {
    const SPECIAL_CASE_NAMES = {
        'aaa': 'AAA', 'usps': 'USPS', 'irs': 'IRS', 'ups': 'UPS', 'dhl': 'DHL',
        'hsbc': 'HSBC', 'usaa': 'USAA', 'att': 'AT&T', 'hbo': 'HBO', 'bbb': 'BBB',
        'ssa': 'SSA', 'sce': 'SCE', 'irs': 'IRS', 'fbi': 'FBI', 'doj': 'DOJ',
        'dmv': 'DMV', 'edd': 'EDD', 'ftc': 'FTC'
    };
    const lower = name.toLowerCase();
    if (SPECIAL_CASE_NAMES[lower]) return SPECIAL_CASE_NAMES[lower];
    return name.split(' ').map(word => {
        const wLower = word.toLowerCase();
        if (SPECIAL_CASE_NAMES[wLower]) return SPECIAL_CASE_NAMES[wLower];
        return word.charAt(0).toUpperCase() + word.slice(1);
    }).join(' ');
}

function formatEmailForDisplay(email) {
    if (!email || !email.includes('@')) return escapeHtml(email);
    return escapeHtml(email).replace('@', '@<br>');
}

function levenshteinDistance(a, b) {
    if (a.length === 0) return b.length;
    if (b.length === 0) return a.length;
    
    const matrix = [];
    for (let i = 0; i <= b.length; i++) {
        matrix[i] = [i];
    }
    for (let j = 0; j <= a.length; j++) {
        matrix[0][j] = j;
    }
    for (let i = 1; i <= b.length; i++) {
        for (let j = 1; j <= a.length; j++) {
            if (b.charAt(i - 1) === a.charAt(j - 1)) {
                matrix[i][j] = matrix[i - 1][j - 1];
            } else {
                matrix[i][j] = Math.min(
                    matrix[i - 1][j - 1] + 1,
                    matrix[i][j - 1] + 1,
                    matrix[i - 1][j] + 1
                );
            }
        }
    }
    return matrix[b.length][a.length];
}

// ============================================
// DETECTION FUNCTIONS (Phase 1 - Existing)
// ============================================

function detectRecipientSpoofing(displayName, senderEmail) {
    if (!displayName || !currentUserEmail) return null;
    
    const displayLower = displayName.toLowerCase().trim();
    const recipientLower = currentUserEmail.toLowerCase();
    const recipientUsername = recipientLower.split('@')[0];
    
    const displayCleaned = displayLower.replace(/[\.\-_\s]/g, '');
    const recipientCleaned = recipientUsername.replace(/[\.\-_\s]/g, '');
    
    if (displayCleaned.length >= 4 && recipientCleaned.length >= 4) {
        if (displayCleaned.includes(recipientCleaned) || recipientCleaned.includes(displayCleaned)) {
            const senderLower = senderEmail.toLowerCase();
            if (!senderLower.includes(recipientUsername)) {
                return {
                    displayName: displayName,
                    recipientEmail: currentUserEmail
                };
            }
        }
    }
    
    return null;
}

// Recipient-domain impersonation: display name claims to be the recipient's own organization.
// Example: Display name "Purelogicescrow" from cosmetokyo.jp sent to info@purelogicescrow.com.
// The scammer is pretending to BE your company's email system.
// Critical severity - very high confidence, very low false positive risk.
function detectRecipientDomainImpersonation(displayName, senderDomain) {
    if (!displayName || !senderDomain || !currentUserEmail) return null;
    
    const recipientDomain = currentUserEmail.toLowerCase().split('@')[1];
    if (!recipientDomain) return null;
    
    // If sender IS the recipient's domain, this is internal mail - skip
    if (senderDomain.toLowerCase() === recipientDomain) return null;
    if (senderDomain.toLowerCase().endsWith('.' + recipientDomain)) return null;
    
    // Extract registrable name from recipient domain (e.g., "purelogicescrow" from purelogicescrow.com)
    const recipientName = getRegistrableDomainName(recipientDomain);
    if (!recipientName || recipientName.length < 5) return null; // Too short = too many false positives
    
    // Check if display name contains the recipient's domain name
    const displayLower = displayName.toLowerCase().replace(/[\.\-_\s]/g, '');
    
    if (displayLower.includes(recipientName)) {
        // Confirmed: display name impersonates the recipient's organization
        console.log('RECIPIENT DOMAIN IMPERSONATION - Display "' + displayName + '" contains "' + recipientName + '" but sent from ' + senderDomain);
        return {
            displayName: displayName,
            senderDomain: senderDomain,
            recipientDomain: recipientDomain,
            recipientOrgName: recipientName
        };
    }
    
    return null;
}

function detectPhishingUrgency(bodyText, subject) {
    if (!bodyText && !subject) return null;
    
    const textToCheck = ((subject || '') + ' ' + (bodyText || '')).toLowerCase();
    const collapsedText = collapseForMatch(textToCheck);
    const foundKeywords = [];
    
    for (const keyword of PHISHING_URGENCY_KEYWORDS) {
        if (phraseMatchesContent(textToCheck, collapsedText, keyword.toLowerCase())) {
            foundKeywords.push(keyword);
        }
    }
    
    if (foundKeywords.length >= 2) {
        return {
            keywords: foundKeywords.slice(0, 4)
        };
    }
    
    return null;
}

function detectGibberishDomain(email) {
    if (!email) return null;
    
    const parts = email.split('@');
    if (parts.length !== 2) return null;
    
    const domain = parts[1].toLowerCase();
    const domainParts = domain.split('.');
    if (domainParts.length < 2) return null;
    
    const mainPart = domainParts[0];
    
    let suspicionScore = 0;
    const reasons = [];
    
    if (mainPart.length > 3) {
        const digitCount = (mainPart.match(/\d/g) || []).length;
        const digitRatio = digitCount / mainPart.length;
        if (digitRatio > 0.5) {
            suspicionScore += 3;
            reasons.push('very high number ratio');
        } else if (digitRatio > 0.3) {
            suspicionScore += 2;
            reasons.push('high number ratio');
        }
    }
    
    if (domainParts.length >= 3) {
        let gibberishSubdomains = 0;
        const subdomains = domainParts.slice(0, -1);
        
        for (const sub of subdomains) {
            const hasDigits = /\d/.test(sub);
            const hasLetters = /[a-z]/i.test(sub);
            const isShortAndRandom = sub.length > 4 && hasDigits && hasLetters;
            const vowelCount = (sub.match(/[aeiou]/gi) || []).length;
            const isConsonantSoup = sub.length > 3 && hasLetters && vowelCount === 0;
            const containsNoWords = !/(mail|web|app|api|www|cdn|img|static|secure|login|account|cloud|storage)/i.test(sub);
            
            if ((isShortAndRandom || isConsonantSoup) && containsNoWords) {
                gibberishSubdomains++;
            }
        }
        
        if (gibberishSubdomains >= 2) {
            suspicionScore += 3;
            reasons.push('multiple random subdomains');
        }
    }
    
    const suspiciousTLDs = ['.us', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc', '.ws', '.top', '.xyz', '.buzz', '.cloud', '.online', '.site', '.website', '.store', '.live', '.icu', '.shop', '.club', '.info', '.biz', '.work', '.click', '.link', '.fun', '.space', '.vip', '.win', '.download', '.stream', '.review', '.bid', '.loan', '.date', '.trade', '.racing', '.party', '.cricket', '.science', '.gdn', '.rest', '.fit', '.mom', '.sbs'];
    const tld = '.' + domainParts[domainParts.length - 1];
    if (suspiciousTLDs.includes(tld) && suspicionScore > 0) {
        suspicionScore += 1;
        reasons.push('suspicious TLD (' + tld + ')');
    }
    
    if (mainPart.length > 3) {
        const vowelCount = (mainPart.match(/[aeiou]/gi) || []).length;
        if (vowelCount === 0) {
            suspicionScore += 3;
            reasons.push('no vowels in domain');
        }
    }
    
    if (mainPart.length >= 8) {
        const letterCount = (mainPart.match(/[a-z]/gi) || []).length;
        if (letterCount >= 6) {
            const vowelCount = (mainPart.match(/[aeiou]/gi) || []).length;
            const vowelRatio = vowelCount / letterCount;
            if (vowelRatio > 0 && vowelRatio < 0.22) {
                suspicionScore += 2;
                reasons.push('unpronounceable pattern');
            }
        }
    }
    
    if (mainPart.length > 20) {
        suspicionScore += 2;
        reasons.push('very long domain name');
    } else if (mainPart.length >= 15) {
        suspicionScore += 1;
        reasons.push('long domain name');
    }
    
    if (suspicionScore >= 3) {
        return {
            domain: domain,
            reasons: reasons
        };
    }
    
    return null;
}

// v4.2.10: Detect gibberish sender usernames
// "techsjdsydybbheesdsd" and "shsjgdgsdddds" are obviously not real people
function detectGibberishUsername(email) {
    if (!email) return null;
    
    const parts = email.split('@');
    if (parts.length !== 2) return null;
    
    const username = parts[0].toLowerCase();
    const domain = parts[1].toLowerCase();
    
    // v5.2.0: Token-based early allow for system/operational mailboxes.
    // Split username on separators and check individual tokens.
    // "nmls_notifications" → ["nmls", "notifications"] → "notifications" matches → skip.
    const usernameTokens = username.split(/[.\-_]+/).filter(t => t.length > 0);
    
    const systemTokens = new Set(['noreply', 'no', 'reply', 'donotreply', 'do', 'not',
        'postmaster', 'mailer', 'daemon', 'bounce',
        'admin', 'info', 'support', 'contact', 'help', 'sales', 'billing',
        'service', 'newsletter', 'notifications', 'notification',
        'alert', 'alerts', 'news', 'updates', 'feedback', 'enquiries',
        'hello', 'office', 'team', 'hr', 'helpdesk', 'mailer']);
    
    // If ANY token in the username is a system token, skip gibberish check
    if (usernameTokens.some(t => systemTokens.has(t))) return null;
    
    // v5.2.0: Brand-domain alignment check.
    // If a username token (≥3 chars) appears in the domain, it's brand-aligned.
    // e.g., "nmls" in both "nmls_notifications" and "nmlsnotifications.com" → skip
    const domainBase = domain.split('.')[0]; // "nmlsnotifications" from "nmlsnotifications.com"
    if (usernameTokens.some(t => t.length >= 3 && domainBase.includes(t))) return null;
    
    // Strip dots, hyphens, underscores for analysis
    const cleaned = username.replace(/[.\-_]/g, '');
    
    // v5.2.0: Require minimum length of 12 (was 10) to reduce over-firing
    if (cleaned.length < 12) return null;
    
    // v5.2.0: If username contains any recognizable word token (≥4 chars),
    // require higher suspicion threshold. Dictionary-like tokens suggest a real address.
    const hasDictionaryToken = usernameTokens.some(t => {
        if (t.length < 4) return false;
        const vowels = (t.match(/[aeiou]/gi) || []).length;
        return vowels / t.length >= 0.25; // Pronounceable = likely a real word
    });
    
    let suspicionScore = 0;
    const reasons = [];
    
    // Check 1: No vowels at all
    const letters = cleaned.replace(/[^a-z]/gi, '');
    const vowelCount = (letters.match(/[aeiou]/gi) || []).length;
    if (letters.length >= 8 && vowelCount === 0) {
        suspicionScore += 3;
        reasons.push('no vowels in username');
    }
    
    // Check 2: Low vowel ratio
    if (letters.length >= 10 && vowelCount > 0) {
        const vowelRatio = vowelCount / letters.length;
        if (vowelRatio < 0.20) {
            suspicionScore += 2;
            reasons.push('unpronounceable username');
        }
    }
    
    // Check 3: Long consecutive consonant cluster (5+)
    // Normal English maxes out at 3-4 consecutive consonants
    const consonantCluster = letters.match(/[^aeiou]{5,}/gi);
    if (consonantCluster) {
        suspicionScore += 2;
        reasons.push('consonant cluster (' + consonantCluster[0] + ')');
    }
    
    // Check 4: Repeated characters (3+ of same char in a row)
    if (/(.)\1{2,}/.test(cleaned)) {
        suspicionScore += 1;
        reasons.push('repeated characters');
    }
    
    // Check 5: Excessive length
    if (cleaned.length > 20) {
        suspicionScore += 2;
        reasons.push('very long username');
    } else if (cleaned.length >= 15) {
        suspicionScore += 1;
        reasons.push('long username');
    }
    
    // v5.2.0: Higher threshold when username contains recognizable words
    const threshold = hasDictionaryToken ? 5 : 3;
    if (suspicionScore >= threshold) {
        return {
            username: username,
            reasons: reasons
        };
    }
    
    return null;
}

function detectViaRouting(headers, senderDomain) {
    if (!headers) return null;
    
    // v5.1.0: Provider routing suppression
    // When sender is a major webmail provider, suppress routing warnings for hops
    // through that provider's known infrastructure. iCloud routes through me.com,
    // Gmail through google.com, Outlook through microsoft.com, etc.
    // Viktor: "If Apple's actual servers are compromised, the internet has bigger problems."
    // Only suppress when auth passes (checked separately by detectAuthFailure).
    const senderDomainLower = (senderDomain || '').toLowerCase();
    const providerDomains = KNOWN_PROVIDER_MAP[senderDomainLower];
    
    const receivedLines = headers.match(/Received:\s*from\s+[^\r\n]+/gi) || [];
    
    // If sender is a known webmail provider, check if ALL relay hops are within provider network
    if (providerDomains) {
        let hasOutsideHop = false;
        for (const line of receivedLines) {
            const domainMatch = line.match(/from\s+([a-zA-Z0-9][a-zA-Z0-9\.\-]*\.[a-zA-Z]{2,})/i);
            if (!domainMatch) continue;
            const relayDomain = domainMatch[1].toLowerCase();
            const relayParts = relayDomain.split('.');
            // Extract eTLD+1 of relay (simplified)
            const relayBase = relayParts.length >= 2 ? relayParts.slice(-2).join('.') : relayDomain;
            if (!providerDomains.some(pd => relayBase === pd || relayDomain.endsWith('.' + pd))) {
                // Check if it's a known legit service before flagging as outside
                const legitServices = ['google', 'gmail', 'microsoft', 'outlook', 'office365',
                                       'yahoo', 'aol', 'icloud', 'apple', 'protonmail',
                                       'ppops', 'ppe-hosted', 'pphosted', 'iphmx', 'barracudanetworks',
                                       'messagelabs', 'mimecast', 'fireeyecloud', 'trellix'];
                if (!legitServices.some(s => relayDomain.includes(s))) {
                    hasOutsideHop = true;
                    break;
                }
            }
        }
        if (!hasOutsideHop) return null; // All hops within provider network → safe
    }
    
    for (const line of receivedLines) {
        const domainMatch = line.match(/from\s+([a-zA-Z0-9][a-zA-Z0-9\.\-]*\.[a-zA-Z]{2,})/i);
        if (!domainMatch) continue;
        
        const relayDomain = domainMatch[1].toLowerCase();
        
        // v5.2.0: Unconditional AWS EC2 internal suppression.
        // .ec2.internal is AWS's private DNS, not publicly resolvable or registrable.
        // Only appears as internal SES/EC2 relay hops. Cannot be spoofed externally.
        if (relayDomain.endsWith('.ec2.internal') || relayDomain === 'ec2.internal') continue;
        
        // v5.2.0: Provider-domain skip for individual relay hops.
        // Even if other hops exist outside the provider network, don't flag
        // relay domains that ARE within the sender's known provider infrastructure.
        // e.g., icloud.com sender → mr85p00im-hyfv06011401.me.com is Apple infra, skip it.
        if (providerDomains) {
            const relayParts = relayDomain.split('.');
            const relayBase = relayParts.length >= 2 ? relayParts.slice(-2).join('.') : relayDomain;
            if (providerDomains.some(pd => relayBase === pd || relayDomain.endsWith('.' + pd))) continue;
        }
        
        // v4.3.0: Improved sender-brand matching - extract registrable domain, not first subdomain
        if (senderDomain) {
            const senderParts = senderDomain.split('.');
            const relayParts = relayDomain.split('.');
            const ccSLDs = ['co', 'com', 'org', 'net', 'ac', 'gov', 'edu'];
            let senderSLD;
            if (senderParts.length >= 3 && ccSLDs.includes(senderParts[senderParts.length - 2])) {
                senderSLD = senderParts[senderParts.length - 3];
            } else if (senderParts.length >= 2) {
                senderSLD = senderParts[senderParts.length - 2];
            }
            let relaySLD;
            if (relayParts.length >= 3 && ccSLDs.includes(relayParts[relayParts.length - 2])) {
                relaySLD = relayParts[relayParts.length - 3];
            } else if (relayParts.length >= 2) {
                relaySLD = relayParts[relayParts.length - 2];
            }
            // Forward check: sender SLD appears in relay domain (e.g., "pinterest" in "pinterestmail.com")
            if (senderSLD && senderSLD.length >= 4 && relayDomain.includes(senderSLD)) continue;
            // Reverse check: relay SLD appears in sender domain (e.g., "att" from att.com in "att-mail.com")
            if (relaySLD && relaySLD.length >= 3 && senderDomain.includes(relaySLD)) continue;
        }
        
        const legitServices = ['google', 'gmail', 'googlemail', 'microsoft', 'outlook', 'office365', 
                              'sendgrid', 'mailchimp', 'mandrillapp', 'amazonses', 'mailgun', 'postmark', 'sparkpost',
                              'mailjet', 'sendinblue', 'brevo', 'constantcontact', 'hubspot', 'salesforce', 'pardot',
                              'klaviyo', 'activecampaign', 'campaignmonitor', 'createsend', 'marketo', 'customer.io',
                              'convertkit', 'getresponse', 'aweber', 'omnisend', 'drip', 'govdelivery',
                              'zendesk', 'intercom', 'freshdesk', 'helpscout',
                              'zoho', 'yahoo', 'aol', 'icloud', 'apple', 'protonmail',
                              'ppops', 'ppe-hosted', 'pphosted', 'iphmx', 'barracudanetworks', 'messagelabs', 'mimecast',
                              'serverpod', 'emailsrvr', 'rackspace', 'fireeyecloud', 'trellix'];
        if (legitServices.some(s => relayDomain.includes(s))) continue;
        
        const domainParts = relayDomain.split('.');
        
        // v4.3.0: Check if relay's root domain (SLD) is a recognizable brand name
        // Server IDs as subdomains (mx0b-00191d01, p1-024085, outbound-216-24-61-192) are normal
        // for legitimate companies - only flag if the root domain ITSELF looks gibberish
        const relayCCSLDs = ['co', 'com', 'org', 'net', 'ac', 'gov', 'edu'];
        let relaySLDIndex;
        if (domainParts.length >= 3 && relayCCSLDs.includes(domainParts[domainParts.length - 2])) {
            relaySLDIndex = domainParts.length - 3;
        } else {
            relaySLDIndex = domainParts.length - 2;
        }
        if (relaySLDIndex >= 0) {
            const relaySLD = domainParts[relaySLDIndex];
            if (relaySLD.length >= 4) {
                const sldLetters = (relaySLD.match(/[a-z]/gi) || []).length;
                const sldDigits = (relaySLD.match(/\d/g) || []).length;
                const sldVowels = (relaySLD.match(/[aeiou]/gi) || []).length;
                // If root domain is all letters and pronounceable, it's a real brand
                if (sldLetters >= 4 && sldDigits === 0 && sldVowels / sldLetters >= 0.15) continue;
            }
        }
        const mainPart = domainParts[0];
        
        if (mainPart.length < 8) continue;
        
        let suspicionScore = 0;
        
        const digitCount = (mainPart.match(/\d/g) || []).length;
        const digitRatio = digitCount / mainPart.length;
        if (digitRatio > 0.3) suspicionScore += 2;
        
        const letterCount = (mainPart.match(/[a-z]/gi) || []).length;
        const vowelCount = (mainPart.match(/[aeiou]/gi) || []).length;
        if (letterCount > 0) {
            const vowelRatio = vowelCount / letterCount;
            if (vowelRatio === 0) suspicionScore += 3;
            else if (vowelRatio < 0.15) suspicionScore += 2;
        }
        
        if (mainPart.length > 15) suspicionScore += 1;
        if (mainPart.length > 20) suspicionScore += 1;
        
        if (domainParts.length >= 3) {
            const randomSubdomains = domainParts.slice(0, -1).filter(part => {
                const hasDigits = /\d/.test(part);
                const vowels = (part.match(/[aeiou]/gi) || []).length;
                return part.length > 6 && hasDigits && vowels <= 1;
            });
            if (randomSubdomains.length >= 2) suspicionScore += 2;
        }
        
        if (suspicionScore >= 3) {
            return {
                viaDomain: relayDomain,
                senderDomain: senderDomain
            };
        }
    }
    
    return null;
}

function detectAuthFailure(headers, senderDomain) {
    if (!headers) return null;
    
    if (senderDomain && CONFIG.trustedDomains.includes(senderDomain.toLowerCase())) return null;
    
    let score = 0;
    const failures = [];
    
    // v4.3.2: RFC 5322 compliant header extraction. Previous regex terminated on a hardcoded
    // list of header names and missed non-standard headers (ARC-Seal, X-Google-DKIM-Signature, etc).
    // Now: find Authentication-Results line, collect folded continuation lines (start with whitespace),
    // stop when a new header starts (line begins with non-whitespace + colon).
    // Viktor: "Different mail servers insert different headers. Brittle regex = inconsistent detection."
    let authText = '';
    const headerLines = headers.split('\n');
    let capturing = false;
    for (const line of headerLines) {
        if (/^Authentication-Results:/i.test(line)) {
            capturing = true;
            authText += line + '\n';
        } else if (capturing) {
            if (/^\s/.test(line)) {
                // RFC 5322 folded header continuation
                authText += line + '\n';
            } else {
                // New header started
                break;
            }
        }
    }
    authText = authText.toLowerCase();
    
    if (authText) {
        if (/dmarc\s*=\s*fail/i.test(authText)) {
            score += 2;
            failures.push('Sender identity not verified');
        }
        
        if (/dkim\s*=\s*none/i.test(authText)) {
            score += 1;
            failures.push('Email not digitally signed');
        } else if (/dkim\s*=\s*fail/i.test(authText)) {
            score += 2;
            failures.push('Digital signature failed');
        }
        
        if (/compauth\s*=\s*fail/i.test(authText)) {
            score += 2;
            failures.push('Security check failed');
        }
        
        if (/spf\s*=\s*fail\b/i.test(authText)) {
            score += 2;
            failures.push('Sender server not authorized');
        } else if (/spf\s*=\s*softfail/i.test(authText)) {
            score += 1;
            failures.push('Sender server not fully authorized');
        }
    }
    
    if (/CAT:SPOOF/i.test(headers)) {
        score += 3;
        if (!failures.includes('Flagged as spoofing')) {
            failures.push('Flagged as a fake sender');
        }
    }
    
    if (score >= 3 && failures.length > 0) {
        return {
            failures: failures,
            score: score,
            senderDomain: senderDomain
        };
    }
    
    return null;
}

function detectBrandImpersonation(subject, body, senderDomain, displayName) {
    console.log('BRAND CHECK CALLED - Domain:', senderDomain);
    
    // v4.3.1: Normalize Unicode before matching to defeat zero-width and confusable attacks
    const subjectLower = stripUnicodeThreats((subject || '')).toLowerCase();
    const bodyLower = stripUnicodeThreats((body || '')).toLowerCase();
    const displayNameLower = stripUnicodeThreats((displayName || '')).toLowerCase();
    
    for (const [brandName, config] of Object.entries(BRAND_CONTENT_DETECTION)) {
        // v4.3.0: Use word boundary matching to avoid substring false positives
        // e.g. "Sofia" should not trigger "Sofi" brand detection
        const keywordMatchesText = (text) => config.keywords.some(keyword => {
            const kw = keyword.toLowerCase();
            // For keywords with special chars like "at&t", use includes
            if (/[^a-z0-9\s]/.test(kw)) return text.includes(kw);
            // For normal keywords, use word boundary regex
            const re = new RegExp('\\b' + kw.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b', 'i');
            return re.test(text);
        });
        
        // Check each location separately: subject, display name, body
        const inSubject = keywordMatchesText(subjectLower);
        const inDisplayName = keywordMatchesText(displayNameLower);
        const inBody = keywordMatchesText(bodyLower);
        
        const mentionsBrand = inSubject || inDisplayName || inBody;
        
        if (mentionsBrand) {
            if (!senderDomain) {
                return {
                    brandName: formatEntityName(brandName),
                    senderDomain: '(invalid or hidden sender)',
                    legitimateDomains: config.legitimateDomains
                };
            }
            
            const domainLower = senderDomain.toLowerCase();
            const isLegitimate = config.legitimateDomains.some(legit => {
                if (legit.startsWith('.')) {
                    return domainLower.endsWith(legit);
                }
                return domainLower === legit || domainLower.endsWith(`.${legit}`);
            });
            
            if (!isLegitimate) {
                // v5.1.0: ESP suppression with COP exceptions
                const isESPDomain = KNOWN_ESP_DOMAINS.some(esp => domainLower === esp || domainLower.endsWith('.' + esp))
                    || ESP_SENDER_DOMAINS.has(domainLower)
                    || Array.from(ESP_SENDER_DOMAINS).some(esp => domainLower.endsWith('.' + esp));
                if (isESPDomain) {
                    // COP spec: Allow brand eval if protected brand token in display/subject,
                    // or if display name has brand + role suffix pattern
                    const brandLower = brandName.toLowerCase();
                    const isProtected = PROTECTED_COMMON_WORD_BRANDS.has(brandLower);
                    let forceEval = false;
                    
                    if (inSubject || inDisplayName) {
                        // Check for role suffix or protected brand exact/near-exact in display name
                        const dispWords = (displayName || '').toLowerCase().replace(/[^a-z0-9\s]/g, ' ')
                            .split(/\s+/).filter(w => w.length > 0);
                        // Role suffix: "Chase Security", "Orange Billing" from ESP
                        for (let i = 0; i < dispWords.length - 1; i++) {
                            if (dispWords[i] === brandLower && ORG_ROLE_SUFFIXES.has(dispWords[i + 1])) {
                                forceEval = true;
                                break;
                            }
                        }
                        // Protected brand exact/near-exact in display
                        if (isProtected && dispWords.length <= 2 && dispWords.includes(brandLower)) {
                            forceEval = true;
                        }
                    }
                    
                    if (!forceEval) {
                        console.log('BRAND CHECK SKIPPED [reason: esp-sender] -', brandName, 'from', senderDomain);
                        continue;
                    }
                    // else: force evaluation despite ESP — protected brand or role suffix detected
                }
                
                // TIER 1: Brand in subject or display name = email is claiming to BE this brand
                // Flag immediately (same as before)
                if (inSubject || inDisplayName) {
                    return {
                        brandName: formatEntityName(brandName),
                        senderDomain: senderDomain,
                        legitimateDomains: config.legitimateDomains
                    };
                }
                
                // TIER 2: Brand only in body = casual mention, require supporting signals
                // to avoid false positives on emails that just reference a brand
                
                // v4.3.0: If the sender is itself a recognized brand, skip body-only detection.
                // Legitimate companies mention other brands all the time (resellers, partnerships,
                // cross-promotions). GoDaddy mentioning Microsoft, Alaska Airlines mentioning Lyft, etc.
                let senderIsKnownBrand = false;
                // Check 1: Sender matches another brand in BRAND_CONTENT_DETECTION
                for (const [otherBrand, otherConfig] of Object.entries(BRAND_CONTENT_DETECTION)) {
                    if (otherBrand === brandName) continue; // Skip self
                    if (otherConfig.legitimateDomains.some(legit => {
                        if (legit.startsWith('.')) return domainLower.endsWith(legit);
                        return domainLower === legit || domainLower.endsWith('.' + legit);
                    })) {
                        senderIsKnownBrand = true;
                        break;
                    }
                }
                // Check 2: Sender matches an entity in IMPERSONATION_TARGETS
                if (!senderIsKnownBrand) {
                    for (const [, legDomains] of Object.entries(IMPERSONATION_TARGETS)) {
                        if (legDomains.some(legit => {
                            if (legit.startsWith('.')) return domainLower.endsWith(legit);
                            return domainLower === legit || domainLower.endsWith('.' + legit);
                        })) {
                            senderIsKnownBrand = true;
                            break;
                        }
                    }
                }
                // Check 3: Sender is a known platform domain
                if (!senderIsKnownBrand && typeof KNOWN_PLATFORM_DOMAINS !== 'undefined') {
                    const senderRootParts = domainLower.split('.');
                    // Extract root domain for platform check (e.g., "e.godaddy.com" -> "godaddy.com")
                    const senderRoot = senderRootParts.slice(-2).join('.');
                    const senderRootCC = senderRootParts.length >= 3 ? senderRootParts.slice(-3).join('.') : '';
                    if (KNOWN_PLATFORM_DOMAINS.includes(senderRoot) || 
                        (senderRootCC && KNOWN_PLATFORM_DOMAINS.includes(senderRootCC))) {
                        senderIsKnownBrand = true;
                    }
                }
                if (senderIsKnownBrand) {
                    // v4.3.1: Don't skip entirely - compromised vendor accounts are a real BEC vector.
                    // Viktor: "I compromise a legit vendor and send brand-themed phishing through their domain."
                    // Require BOTH urgency AND 3+ brand mentions for known senders.
                    const hasUrgency = PHISHING_URGENCY_KEYWORDS.some(phrase => 
                        (subjectLower + ' ' + bodyLower).includes(phrase.toLowerCase())
                    );
                    let brandMentionCount = 0;
                    let liveBrandMentions = 0;
                    const liveBodyForKnown = extractLiveBody(bodyLower);
                    const seenCtxKnown = new Set();
                    for (const keyword of config.keywords) {
                        const kw = keyword.toLowerCase();
                        let pos = 0;
                        while ((pos = bodyLower.indexOf(kw, pos)) !== -1) {
                            const ce = Math.min(bodyLower.length, pos + kw.length + 50);
                            const ctx = bodyLower.substring(pos, ce).replace(/\s+/g, ' ').trim();
                            if (!seenCtxKnown.has(ctx)) {
                                seenCtxKnown.add(ctx);
                                brandMentionCount++;
                                if (pos < liveBodyForKnown.length) liveBrandMentions++;
                            }
                            pos += kw.length;
                        }
                        if (brandMentionCount >= 3) break;
                    }
                    if (hasUrgency && brandMentionCount >= 3 && liveBrandMentions >= 1) {
                        console.log('BRAND CHECK TRIGGERED [reason: known-sender-strong-signals] -', brandName, 'from', senderDomain);
                        return {
                            brandName: formatEntityName(brandName),
                            senderDomain: senderDomain,
                            legitimateDomains: config.legitimateDomains
                        };
                    }
                    console.log('BRAND CHECK SKIPPED [reason: known-sender-weak-signals] -', brandName, 'from', senderDomain);
                    continue;
                }
                
                const hasSupport = _brandBodyHasSupportingSignals(config, bodyLower, subjectLower, domainLower, body || '');
                if (hasSupport) {
                    console.log('BRAND CHECK TRIGGERED [reason: body-only: ' + hasSupport + '] -', brandName, 'from', senderDomain);
                    return {
                        brandName: formatEntityName(brandName),
                        senderDomain: senderDomain,
                        legitimateDomains: config.legitimateDomains
                    };
                }
                
                console.log('BRAND CHECK SKIPPED [reason: body-only-no-supporting-signals] -', brandName, 'from', senderDomain);
            }
        }
    }
    
    return null;
}

// v5.2.0 SIG-01: Extract the "live body" — the author's new content, excluding quoted replies.
// Used to prevent repeated signature blocks in thread history from inflating brand mention counts.
// Not a full parser — finds the earliest quote boundary and returns everything before it.
function extractLiveBody(text) {
    if (!text) return text;
    const lower = text.toLowerCase();
    let cutPoint = text.length;
    
    // Pattern 1: "On [date], [name] wrote:" (Gmail/Apple Mail)
    const onWroteMatch = lower.match(/\bon\s+(?:mon|tue|wed|thu|fri|sat|sun|jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec|\d).{10,120}wrote:\s/);
    if (onWroteMatch) cutPoint = Math.min(cutPoint, lower.indexOf(onWroteMatch[0]));
    
    // Pattern 2: Outlook "From: ... Sent: ..."
    // v5.2.2: Relaxed separators — accept newline OR 2+ spaces between From/Sent markers.
    // Outlook's text coercion sometimes flattens headers onto a single line with spaces
    // instead of preserving newlines, which broke the original \n-only pattern.
    const fromSentMatch = lower.match(/(?:\n|\s{2,})from:\s.{1,200}(?:\n|\s{2,})sent:\s/);
    if (fromSentMatch) cutPoint = Math.min(cutPoint, lower.indexOf(fromSentMatch[0]));
    
    // Pattern 3: "---- Original Message ----" / "-----Original Message-----"
    const origIdx = lower.indexOf('original message');
    if (origIdx > 0) {
        const before = lower.substring(Math.max(0, origIdx - 10), origIdx);
        if (before.includes('--')) cutPoint = Math.min(cutPoint, Math.max(0, origIdx - 10));
    }
    
    // Pattern 4: "Begin forwarded message:"
    const fwdIdx = lower.indexOf('begin forwarded message');
    if (fwdIdx !== -1) cutPoint = Math.min(cutPoint, fwdIdx);
    
    // v5.2.2 Density fallback: When no quote boundary matched and the body is long,
    // treat first ~40% (capped at 2500 chars) as "live" for mention_count evaluation.
    // Prevents long HTML-flattened threads from counting entire history as live content.
    if (cutPoint === text.length && text.length >= 4000) {
        cutPoint = Math.min(Math.floor(text.length * 0.4), 2500);
    }
    
    return text.substring(0, cutPoint);
}

// Helper: checks if a body-only brand mention has enough supporting context
// to indicate actual impersonation rather than a casual reference
function _brandBodyHasSupportingSignals(config, bodyLower, subjectLower, senderDomainLower, bodyOriginal) {
    // Signal 1: Brand keyword appears 3+ times in body (email is themed around the brand)
    // Exclude instances where keyword is part of a person's name (e.g., "Jacob Norton")
    // or an email address (e.g., "jacob.norton@invitedclubs.com")
    //
    // v5.2.0 SIG-01: Require at least 1 brand mention in the "live body" (author's new text,
    // before any quote boundary). This prevents repeated brokerage signatures in thread history
    // from inflating the count to 3+ when the author never mentioned the brand themselves.
    const liveBodyLower = extractLiveBody(bodyLower);
    const liveBodyOriginal = bodyOriginal ? extractLiveBody(bodyOriginal) : '';
    console.log('[DEBUG SIG-01] bodyLower length:', bodyLower.length, 'liveBodyLower length:', liveBodyLower.length, 'cutRatio:', Math.round(liveBodyLower.length / bodyLower.length * 100) + '%');
    let totalMentions = 0;
    let liveMentions = 0;
    const seenContexts = new Set(); // SIG-01: de-duplicate identical surrounding snippets
    for (const keyword of config.keywords) {
        const kw = keyword.toLowerCase();
        let pos = 0;
        while ((pos = bodyLower.indexOf(kw, pos)) !== -1) {
            let isProbablyPersonName = false;
            
            // Check 1: Is this keyword inside an email address? (word.keyword@ or word@...keyword)
            const surroundingStart = Math.max(0, pos - 40);
            const surroundingEnd = Math.min(bodyLower.length, pos + kw.length + 40);
            const surrounding = bodyLower.substring(surroundingStart, surroundingEnd);
            if (surrounding.match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/)) {
                isProbablyPersonName = true;
            }
            
            // Check 2: In the original (non-lowered) text, is this keyword preceded by
            // a capitalized word? e.g., "Jacob Norton" or "Coach Norton" = person name
            // vs "your Norton subscription" or "Norton 360" = brand reference
            // Exclude common sentence-starting words that happen to be capitalized
            if (!isProbablyPersonName && bodyOriginal && pos >= 2) {
                const origBefore = bodyOriginal.substring(Math.max(0, pos - 25), pos);
                // Look for a Title Case word immediately before: "Jacob ", "Coach ", "Mr. "
                const namePattern = origBefore.match(/([A-Z][a-z]+)\.?\s+$/);
                if (namePattern) {
                    const precedingWord = namePattern[1].toLowerCase();
                    // These are common words that start sentences, not proper names
                    const commonWords = ['the', 'this', 'that', 'your', 'our', 'my', 'his', 'her',
                        'its', 'their', 'please', 'dear', 'new', 'free', 'get', 'buy', 'use',
                        'how', 'why', 'what', 'when', 'where', 'who', 'which', 'with', 'from',
                        'about', 'after', 'before', 'between', 'into', 'through', 'during',
                        'each', 'every', 'all', 'any', 'both', 'few', 'more', 'most', 'some',
                        'such', 'than', 'too', 'very', 'can', 'will', 'just', 'should', 'now',
                        'also', 'not', 'only', 'then', 'but', 'and', 'for', 'are', 'was',
                        'has', 'had', 'have', 'been', 'would', 'could', 'may', 'might',
                        'call', 'visit', 'click', 'see', 'contact', 'email', 'download',
                        'try', 'start', 'join', 'sign', 'log', 'update', 'renew'];
                    if (!commonWords.includes(precedingWord)) {
                        isProbablyPersonName = true;
                    }
                }
            }
            
            if (!isProbablyPersonName) {
                // SIG-01: Context de-duplication. Extract keyword + ~50 chars AFTER it.
                // Forward-only window catches identical signatures regardless of what precedes them.
                // "Coldwell Banker Realty - California, Broker..." repeated 5x = 1 mention.
                const ctxEnd = Math.min(bodyLower.length, pos + kw.length + 50);
                const ctx = bodyLower.substring(pos, ctxEnd).replace(/\s+/g, ' ').trim();
                if (!seenContexts.has(ctx)) {
                    seenContexts.add(ctx);
                    totalMentions++;
                    const isLive = pos < liveBodyLower.length;
                    if (isLive) {
                        liveMentions++;
                    }
                    console.log('[DEBUG SIG-01] MATCH keyword:"' + kw + '" pos:' + pos + ' isLive:' + isLive + ' total:' + totalMentions + ' live:' + liveMentions + ' ctx:"' + ctx.substring(0, 60) + '"');
                }
            }
            pos += kw.length;
        }
        // SIG-01: Require at least 2 live-body mentions for the 3+ threshold to fire.
        // Single casual brand mention riding on quoted thread history is not impersonation.
        if (totalMentions >= 3 && liveMentions >= 2) {
            // v5.2.2: Conversion-vector proximity — external link host must not be in
            // provider/org-family (KNOWN_PROVIDER_MAP + brand legitimateDomains + KNOWN_PLATFORM_DOMAINS),
            // and phone must appear near a live brand mention (within ~500 chars) to prevent
            // signature phone numbers from satisfying the vector.
            const liveOriginal = (bodyOriginal || '').substring(0, liveBodyLower.length);
            // --- External link proximity ---
            let hasExternalLink = false;
            const urlRegex = /https?:\/\/([^\s<>"')\]/]+)/g;
            let urlMatch;
            while ((urlMatch = urlRegex.exec(liveOriginal)) !== null) {
                try {
                    const host = new URL(urlMatch[0]).hostname.toLowerCase();
                    // Skip provider family domains
                    const isProvider = Object.values(KNOWN_PROVIDER_MAP).some(family =>
                        family.some(pd => host === pd || host.endsWith('.' + pd))
                    );
                    if (isProvider) continue;
                    // Skip brand's own legitimate domains
                    const isBrandLegit = config.legitimateDomains.some(ld =>
                        host === ld || host.endsWith('.' + ld)
                    );
                    if (isBrandLegit) continue;
                    // Skip known platform domains
                    const isPlatform = KNOWN_PLATFORM_DOMAINS.some(p =>
                        host === p || host.endsWith('.' + p)
                    );
                    if (isPlatform) continue;
                    hasExternalLink = true;
                    break;
                } catch (e) { continue; }
            }
            // --- Phone proximity: phone must be within ~500 chars of a brand keyword in live body ---
            let hasPhoneNumber = false;
            const phoneRegex = /(?:\+\d{1,3}[\s.-])?\(?\d{2,4}\)?[\s.-]\d{3,4}[\s.-]\d{4}\b/g;
            let phoneMatch;
            while ((phoneMatch = phoneRegex.exec(liveOriginal)) !== null) {
                const phonePos = phoneMatch.index;
                const proximityWindow = 500;
                const windowStart = Math.max(0, phonePos - proximityWindow);
                const windowEnd = Math.min(liveBodyLower.length, phonePos + phoneMatch[0].length + proximityWindow);
                const windowText = liveBodyLower.substring(windowStart, windowEnd);
                const phoneNearBrand = config.keywords.some(kw => windowText.includes(kw.toLowerCase()));
                if (phoneNearBrand) { hasPhoneNumber = true; break; }
            }
            console.log('[DEBUG SIG-01] GATE PASSED total:' + totalMentions + ' live:' + liveMentions + ' hasLink:' + hasExternalLink + ' hasPhone:' + hasPhoneNumber);
            if (hasExternalLink || hasPhoneNumber) return 'mention_count';
        }
    }
    
    // Signal 2: Subject or body contains phishing urgency language
    const combinedText = subjectLower + ' ' + bodyLower;
    const hasUrgency = PHISHING_URGENCY_KEYWORDS.some(phrase => 
        combinedText.includes(phrase.toLowerCase())
    );
    if (hasUrgency) return 'urgency';
    
    // Signal 3: Sender domain contains suspicious words (e.g. "secure-paypal-login.com")
    const hasSuspiciousDomain = SUSPICIOUS_DOMAIN_WORDS.some(word => 
        senderDomainLower.includes(word)
    );
    if (hasSuspiciousDomain) return 'suspicious_domain_words';
    
    return false;
}

function detectOrganizationImpersonation(displayName, senderDomain) {
    if (!displayName || !senderDomain) return null;
    if (isTrustedDomain(senderDomain)) return null;
    
    const domLower = senderDomain.toLowerCase();
    const isESPDomain = KNOWN_ESP_DOMAINS.some(esp => domLower === esp || domLower.endsWith('.' + esp))
        || ESP_SENDER_DOMAINS.has(domLower)
        || Array.from(ESP_SENDER_DOMAINS).some(esp => domLower.endsWith('.' + esp));
    
    const searchText = displayName.toLowerCase();
    // Shared filler list for word counting (COP spec)
    const FILLERS = new Set(['the', 'a', 'an', 'of', 'for', 'and', 'by', 'at', 'in', 'to', 'from',
                             '&', 'co', 'company', 'inc', 'llc', 'ltd', 'asa', 'sa', 'group']);
    
    for (const [entityName, legitimateDomains] of Object.entries(IMPERSONATION_TARGETS)) {
        const entityPattern = new RegExp(`\\b${escapeRegex(entityName)}\\b`, 'i');
        
        if (!entityPattern.test(searchText)) continue;
        
        // Word analysis
        const entityWordsArr = entityName.toLowerCase().replace(/[^a-z0-9\s]/g, ' ').split(/\s+/).filter(w => w && !FILLERS.has(w));
        const displayWordsArr = displayName.toLowerCase().replace(/[^a-z0-9\s]/g, ' ').split(/\s+/).filter(w => w && !FILLERS.has(w));
        const entityWordCount = entityWordsArr.length;
        const extraWords = Math.max(0, displayWordsArr.length - entityWordCount);
        
        // v5.1.0 COP spec: Role suffix detection
        // "Orange Billing", "Chase Security" → brand + role suffix = force evaluation
        const entityLower = entityName.toLowerCase();
        let hasRoleSuffix = false;
        if (entityWordsArr.length === 1) {
            const brand = entityWordsArr[0];
            for (let i = 0; i < displayWordsArr.length - 1; i++) {
                if (displayWordsArr[i] === brand && ORG_ROLE_SUFFIXES.has(displayWordsArr[i + 1])) {
                    hasRoleSuffix = true;
                    break;
                }
            }
        }
        
        // v5.1.0 COP spec: Protected common-word brand check
        // "orange", "chase", "delta" etc. require exact or near-exact display name match
        const isProtectedBrand = PROTECTED_COMMON_WORD_BRANDS.has(entityLower);
        let isExactOrNearExact = false;
        if (isProtectedBrand && entityWordsArr.length === 1) {
            const brand = entityWordsArr[0];
            // exact: display is just "orange"
            if (displayWordsArr.length === 1 && displayWordsArr[0] === brand) isExactOrNearExact = true;
            // near-exact: "orange sa", "orange billing" (brand + 1 token)
            if (displayWordsArr.length === 2 && displayWordsArr[0] === brand) isExactOrNearExact = true;
        }
        
        // ESP suppression with exceptions (COP spec)
        // ESP suppression stands UNLESS: protected brand exact/near-exact OR role suffix present
        const forceEvalViaExceptions = (isProtectedBrand && isExactOrNearExact) || hasRoleSuffix;
        if (isESPDomain && !forceEvalViaExceptions) continue;
        
        // Proximity check (COP spec: keep threshold=2, override with role suffix)
        // "The Orange County Register" → extra=2, no role suffix → skip
        // "Orange Support Team" → extra=2, HAS role suffix → evaluate
        if (extraWords >= 2 && !hasRoleSuffix) continue;
        
        // Protected common-word brand: if not exact/near-exact, skip
        // This prevents "JP Morgan Chase Financial" from matching "chase"
        if (isProtectedBrand && !isExactOrNearExact && !hasRoleSuffix) continue;
        
        const isLegitimate = legitimateDomains.some(legit => {
            if (legit.startsWith('.')) {
                return senderDomain.endsWith(legit);
            }
            return senderDomain === legit || senderDomain.endsWith(`.${legit}`);
        });
        
        if (!isLegitimate) {
            const hasGovSuffix = legitimateDomains.some(d => d === '.gov');
            const displayDomains = hasGovSuffix ? 'official .gov domains' : legitimateDomains.join(', ');
            return {
                entityClaimed: formatEntityName(entityName),
                senderDomain: senderDomain,
                legitimateDomains: legitimateDomains,
                message: `Sender claims to be "${formatEntityName(entityName)}" but email comes from ${senderDomain}. Legitimate emails come from: ${displayDomains}`
            };
        }
    }
    
    return null;
}

function detectInternationalSender(domain) {
    const domainLower = domain.toLowerCase();
    
    for (const [tld, country] of Object.entries(COUNTRY_CODE_TLDS)) {
        if (tld.includes('.') && tld.split('.').length > 2) {
            if (domainLower.endsWith(tld)) {
                if (INTERNATIONAL_TLDS.some(t => domainLower.endsWith(t))) {
                    return { tld, country, genericUse: false };
                }
            }
        }
    }
    
    for (const [tld, message] of Object.entries(GENERIC_USE_CCTLDS)) {
        if (domainLower.endsWith(tld)) {
            const beforeTld = domainLower.slice(0, -tld.length);
            const isCompound = beforeTld.endsWith('.com') || beforeTld.endsWith('.net') || beforeTld.endsWith('.org');
            if (!isCompound) {
                const country = COUNTRY_CODE_TLDS[tld] || 'Unknown';
                return { tld, country, genericUse: true, genericMessage: message };
            }
        }
    }
    
    for (const tld of INTERNATIONAL_TLDS) {
        if (domainLower.endsWith(tld)) {
            const country = COUNTRY_CODE_TLDS[tld] || 'Unknown';
            return { tld, country, genericUse: false };
        }
    }
    
    return null;
}

function detectSuspiciousDomain(domain) {
    const domainLower = domain.toLowerCase();
    
    for (const fakeTld of FAKE_COUNTRY_TLDS) {
        if (domainLower.endsWith(fakeTld)) {
            return {
                pattern: fakeTld,
                reason: `This email was sent from a domain ending in <strong>${fakeTld}</strong>. This domain extension is designed to look like a legitimate country domain but is not. Proceed with caution.`
            };
        }
    }
    
    const suspiciousGenericTLDs = ['.biz', '.info', '.shop', '.club', '.top', '.xyz', '.buzz', '.icu'];
    const tld = '.' + domainLower.split('.').pop();
    if (suspiciousGenericTLDs.includes(tld)) {
        return {
            pattern: tld,
            reason: `This email was sent from a domain ending in <strong>${tld}</strong>. <strong>While some legitimate businesses use ${tld}</strong>, domains ending in ${tld} have been identified by Spamhaus and Symantec as frequently used in spam and phishing campaigns. If you don't recognize this sender, verify before clicking any links.`
        };
    }
    
    const registrableName = getRegistrableDomainName(domainLower);
    
    if (registrableName.includes('-')) {
        const parts = registrableName.split('-');
        for (const part of parts) {
            for (const word of SUSPICIOUS_DOMAIN_WORDS) {
                if (part === word) {
                    return {
                        pattern: word,
                        reason: `Domain contains "-${word}" which is commonly used in phishing attacks`
                    };
                }
            }
        }
        return null;
    }
    
    for (const word of SUSPICIOUS_DOMAIN_WORDS) {
        if (registrableName.endsWith(word) && registrableName !== word && registrableName.length > word.length + 3) {
            return {
                pattern: word,
                reason: `Domain ends with "${word}" which is commonly used in phishing attacks`
            };
        }
    }
    
    return null;
}

function getRegistrableDomainName(domain) {
    const compoundTlds = ['.co.uk', '.co.za', '.co.in', '.co.jp', '.co.kr', '.co.nz', 
                         '.com.ar', '.com.au', '.com.br', '.com.cn', '.com.co', '.com.mx',
                         '.com.ng', '.com.pk', '.com.ph', '.com.tr', '.com.ua', '.com.ve', '.com.vn',
                         '.net.br', '.net.co', '.org.br', '.org.co', '.org.uk'];
    
    for (const tld of compoundTlds) {
        if (domain.endsWith(tld)) {
            const withoutTld = domain.slice(0, -tld.length);
            const parts = withoutTld.split('.');
            return parts[parts.length - 1];
        }
    }
    
    const parts = domain.split('.');
    if (parts.length >= 2) {
        return parts[parts.length - 2];
    }
    return parts[0];
}

function detectSuspiciousDisplayName(displayName, senderDomain) {
    if (!displayName) return null;
    
    const nameLower = displayName.toLowerCase();
    const domainLower = senderDomain.toLowerCase();
    
    const genericDomains = [
        'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
        'icloud.com', 'mail.com', 'protonmail.com', 'zoho.com', 'yandex.com',
        'live.com', 'msn.com', 'me.com', 'inbox.com'
    ];
    
    const isGenericDomain = genericDomains.includes(domainLower);
    
    const companyPatterns = ['security', 'billing', 'account', 'verification', 'fraud alert', 'helpdesk'];
    for (const pattern of companyPatterns) {
        if (nameLower.includes(pattern) && isGenericDomain) {
            return {
                pattern: pattern,
                reason: `"${displayName}" sounds official but is from a free email provider (${senderDomain})`
            };
        }
    }
    
    return null;
}

function detectDisplayNameImpersonation(displayName, senderDomain) {
    if (!displayName) return null;
    
    const nameLower = displayName.toLowerCase();
    
    for (const domain of CONFIG.trustedDomains) {
        if (nameLower.includes(domain) && senderDomain !== domain) {
            return {
                reason: `The display name shows a different email address than the actual sender.`,
                impersonatedDomain: domain
            };
        }
    }
    
    const emailPattern = /[\w.-]+@[\w.-]+\.\w+/;
    const match = displayName.match(emailPattern);
    if (match) {
        const nameEmail = match[0].toLowerCase();
        if (!nameEmail.includes(senderDomain)) {
            return {
                reason: `The display name shows a different email address than the actual sender.`,
                impersonatedDomain: nameEmail
            };
        }
    }
    
    return null;
}

// Path 2: Display-name-vs-domain detection
// Catches brand impersonation for brands NOT in our detection lists.
// Logic: If display name looks organizational (not a personal name) and
// zero words from the display name appear in the sender domain, flag it.
// Viktor approved: buildable as supporting signal. Catches every brand
// the scammer puts in the display name, without needing a predefined list.
// v5.1.0: Person-vs-Org display name classifier
// Determines if a display name looks like a person's name vs an organization.
// Used to suppress Sender Identity Mismatch for individuals (e.g., "Mike McCaskell"
// from purelogicescrow.com is normal; "Pure Logic Escrow" from randomdomain.com is not).
// This classifier ONLY controls the display-name-vs-domain check.
// It NEVER suppresses lookalike/homoglyph, auth, content-risk, or domain-risk detectors.
// Viktor: "I'll use a real employee name + lookalike domain." → Lookalike detection catches that separately.
function displayLooksLikePerson(displayName) {
    if (!displayName) return false;
    
    const cleaned = displayName.replace(/[^\w\s'-]/g, ' ').trim();
    const words = cleaned.split(/\s+/).filter(w => w.length > 0);
    
    // Single word or empty: ambiguous, don't classify as person
    if (words.length < 1 || words.length > 4) return false;
    
    // Preposition patterns: "Max at WeVideo", "John from Acme"
    // Strip the preposition and everything after it, check if what remains is a person name
    const prepIndex = words.findIndex(w => ['at', 'from', 'via', 'with', 'of'].includes(w.toLowerCase()));
    const nameWords = prepIndex > 0 ? words.slice(0, prepIndex) : words;
    
    // Corporate/org indicators: if ANY word is one of these, it's an org
    const orgIndicators = new Set([
        'inc', 'corp', 'corporation', 'llc', 'ltd', 'limited', 'co', 'company',
        'group', 'holdings', 'partners', 'associates', 'foundation', 'institute',
        'association', 'society', 'authority', 'commission', 'council', 'committee',
        'bank', 'insurance', 'financial', 'credit', 'mortgage', 'lending',
        'realty', 'escrow', 'title', 'properties', 'property',
        'support', 'billing', 'team', 'dept', 'department', 'division',
        'service', 'services', 'solutions', 'systems', 'technologies', 'technology',
        'security', 'verification', 'helpdesk', 'help',
        'delivery', 'shipping', 'logistics', 'express',
        'alert', 'alerts', 'notification', 'notifications', 'notice',
        'account', 'accounts', 'rewards', 'membership', 'loyalty',
        'noreply', 'no-reply', 'donotreply', 'do-not-reply',
        'admin', 'administrator', 'webmaster', 'postmaster', 'info',
        'hr', 'payroll', 'finance', 'legal', 'compliance', 'operations'
    ]);
    
    for (const word of words) {
        if (orgIndicators.has(word.toLowerCase())) return false;
    }
    
    // Functional mailbox patterns (all caps, underscores, etc.)
    if (/^[A-Z_\-]+$/.test(displayName.trim())) return false; // "FAIR_PLAN_DO_NOT_REPLY"
    if (displayName.includes('_')) return false; // Underscores = system/functional name
    
    // Check if name words look like person names: Title Case, 1-3 words
    if (nameWords.length >= 1 && nameWords.length <= 3) {
        // All name words should be title case (first letter upper, rest lower)
        // or all caps (some people write "JOHN SMITH") or all lower ("john smith")
        const allTitleCase = nameWords.every(w => /^[A-Z][a-z]+$/.test(w));
        const allCaps = nameWords.every(w => /^[A-Z]+$/.test(w) && w.length >= 2);
        const allLower = nameWords.every(w => /^[a-z]+$/.test(w) && w.length >= 2);
        const mixedNormal = nameWords.every(w => /^[A-Z][a-z]+$/.test(w) || /^[A-Z]\.?$/.test(w)); // "J. Smith"
        // v5.2.0 SIM-06: Mixed case person names - each word is either all-lower or ALL-CAPS
        // Catches "johnny TIRADO", "amy WILSON", "JOHN smith". No brand styles itself this way.
        const mixedCasePerson = nameWords.length >= 2 && nameWords.every(w => 
            (/^[a-z]+$/.test(w) && w.length >= 2) || (/^[A-Z]+$/.test(w) && w.length >= 2)
        );
        
        if (allTitleCase || allCaps || allLower || mixedNormal || mixedCasePerson) {
            // Additional check: none of the name words should be a well-known brand
            // that's also a common first name (Chase, Wells, Liberty, etc.)
            // We DON'T resolve this here - the domain cluster check handles it.
            // If "Chase" sends from chase.com, the cluster matches. If from randomdomain.com,
            // brand impersonation catches it. Person-vs-org is just a gate, not the whole defense.
            return true;
        }
    }
    
    return false;
}

function detectDisplayNameDomainMismatch(displayName, senderDomain) {
    if (!displayName || !senderDomain) return null;
    
    // Skip trusted, platform, and ESP domains
    if (isTrustedDomain(senderDomain)) return null;
    if (isKnownPlatform(senderDomain)) return null;
    const domainLower = senderDomain.toLowerCase();
    if (KNOWN_ESP_DOMAINS.some(esp => domainLower === esp || domainLower.endsWith('.' + esp))) return null;
    // v5.1.0: Also check ESP_SENDER_DOMAINS (catches brevosend.com, sendgrid.net subdomains, etc.)
    if (ESP_SENDER_DOMAINS.has(domainLower) || Array.from(ESP_SENDER_DOMAINS).some(esp => domainLower.endsWith('.' + esp))) return null;
    
    // Skip if sender domain is a known brand's legitimate domain
    for (const [, config] of Object.entries(BRAND_CONTENT_DETECTION)) {
        if (config.legitimateDomains.some(legit => {
            if (legit.startsWith('.')) return domainLower.endsWith(legit);
            return domainLower === legit || domainLower.endsWith('.' + legit);
        })) return null;
    }
    for (const [, legDomains] of Object.entries(IMPERSONATION_TARGETS)) {
        if (Array.isArray(legDomains) && legDomains.some(legit => {
            if (legit.startsWith('.')) return domainLower.endsWith(legit);
            return domainLower === legit || domainLower.endsWith('.' + legit);
        })) return null;
    }
    
    // Skip free email providers (personal use, not organizational)
    const freeProviders = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
        'icloud.com', 'mail.com', 'protonmail.com', 'zoho.com', 'yandex.com',
        'live.com', 'msn.com', 'me.com', 'inbox.com', 'gmx.com', 'fastmail.com'];
    if (freeProviders.includes(domainLower)) return null;
    
    // Skip if display name contains an email address (handled by other detections)
    if (/[\w.-]+@[\w.-]+\.\w+/.test(displayName)) return null;
    
    // v5.2.0 Fix #SIM-05: Functional/system display-name skip.
    // "no-reply", "mailer-daemon", "postmaster" etc. are system labels, not org identities.
    // Normalize: lowercase, strip punctuation, collapse whitespace to single space.
    // Exact match only — "no-reply" skips but "No-Reply Netflix" does NOT (brand token present).
    // Viktor: "I gain nothing naming myself no-reply — brand/link/keyword detectors still catch me."
    const FUNCTIONAL_DISPLAY_NAMES = new Set([
        'noreply', 'no reply',
        'donotreply', 'do not reply',
        'automated', 'automated message', 'automated notification',
        'mailer daemon', 'postmaster',
        'webmaster', 'system', 'system notification',
        'notification', 'notifications', 'notifier',
        'daemon', 'bounce', 'delivery status',
        'message delivery', 'delivery subsystem',
        'noresponse', 'no response'
    ]);
    const normalizedDisplay = displayName.toLowerCase().replace(/[-]/g, ' ').replace(/[^a-z0-9\s]/g, '').replace(/\s+/g, ' ').trim();
    if (FUNCTIONAL_DISPLAY_NAMES.has(normalizedDisplay)) {
        console.log('SIM SKIP (functional_display_name) - "' + displayName + '" from ' + senderDomain);
        return null;
    }
    
    // v5.2.0 Fix #SIM-07: Functional prefix+suffix skip with brand guard.
    // "no-reply-fnhw", "noreply123", "notifications-abc" = system labels with routing suffixes.
    // Skip SIM if: starts with functional prefix + short generic suffix WITHOUT brand tokens.
    // Viktor: "no-reply-fnhw gains me nothing — brand/link/keyword detectors still catch me."
    const FUNCTIONAL_PREFIXES = [
        'noreply', 'no reply', 'donotreply', 'do not reply',
        'automated', 'notifications', 'notification',
        'mailer daemon', 'postmaster', 'webmaster',
        'system', 'bounce', 'daemon'
    ];
    for (const prefix of FUNCTIONAL_PREFIXES) {
        if (normalizedDisplay.startsWith(prefix) && normalizedDisplay.length > prefix.length) {
            const suffix = normalizedDisplay.substring(prefix.length).trim();
            if (suffix.length > 0 && suffix.length <= 15 && /^[a-z0-9 ]+$/.test(suffix)) {
                // Brand guard: reject if suffix contains any known brand token (≥3 chars)
                const suffixWords = suffix.split(/\s+/);
                let hasBrandToken = false;
                for (const brandKey of Object.keys(BRAND_CONTENT_DETECTION)) {
                    const bk = brandKey.toLowerCase();
                    if (bk.length < 3) continue;
                    // Check: is the brand key a single word that appears in the suffix?
                    if (!bk.includes(' ') && suffixWords.includes(bk)) { hasBrandToken = true; break; }
                    // Check: does the suffix contain a multi-word brand as substring?
                    if (bk.includes(' ') && suffix.includes(bk)) { hasBrandToken = true; break; }
                }
                if (!hasBrandToken) {
                    // Also check PROTECTED_COMMON_WORD_BRANDS
                    for (const pcb of PROTECTED_COMMON_WORD_BRANDS) {
                        if (suffixWords.includes(pcb)) { hasBrandToken = true; break; }
                    }
                }
                if (!hasBrandToken) {
                    console.log('SIM SKIP (functional_prefix_suffix) - "' + displayName + '" from ' + senderDomain);
                    return null;
                }
            }
        }
    }
    
    // Extract words from display name
    const cleanedName = displayName.replace(/[^\w\s]/g, ' ');
    const words = cleanedName.split(/\s+/).filter(w => w.length > 0);
    if (words.length < 2) return null; // Single word: too ambiguous
    
    // Filler words to ignore
    const fillerWords = new Set(['the', 'to', 'from', 'for', 'a', 'an', 'at', 'in', 'of',
        'on', 'by', 'and', 'or', 'is', 'it', 'be', 'as', 'do', 'no', 'so',
        'your', 'you', 'our', 'my', 'we', 'us', 'me', 'he', 'she',
        'this', 'that', 'with', 'has', 'have', 'will', 'was', 'are', 'been',
        'not', 'but', 'all', 'can', 'had', 'her', 'his', 'one', 'new',
        'now', 'get', 'may', 'who', 'did', 'its', 'let', 'say',
        'there', 'here', 'where', 'when', 'how', 'what', 'why',
        'greetings', 'hello', 'dear', 'welcome', 'welcomes', 'hi']);
    
    // Corporate/generic keywords: indicate organizational identity AND commonly appear
    // in scam domains (so they should NOT count as domain overlap evidence).
    const corporateKeywords = new Set(['inc', 'corp', 'corporation', 'llc', 'ltd', 'limited',
        'team', 'support', 'official', 'service', 'services', 'customer',
        'rewards', 'notification', 'notifications', 'alert', 'alerts',
        'billing', 'account', 'department', 'division', 'group', 'center', 'centre',
        'administration', 'office', 'helpdesk', 'security', 'verification',
        'delivery', 'shipping', 'logistics', 'express',
        'membership', 'loyalty', 'program', 'club',
        'foundation', 'institute', 'association', 'society',
        'bank', 'insurance', 'financial', 'credit', 'solutions',
        'update', 'updates', 'confirm', 'confirmation', 'notice',
        'deals', 'promo', 'offers', 'free', 'gift', 'gifts',
        'online', 'digital', 'portal', 'access', 'login', 'signin',
        'track', 'tracking', 'verify', 'secure', 'info', 'global',
        'direct', 'premium', 'plus', 'pro', 'enterprise', 'business']);
    
    // Get significant words (non-filler, 3+ chars)
    const significantWords = words.filter(w => {
        const lower = w.toLowerCase();
        if (fillerWords.has(lower)) return false;
        if (w.length < 3) return false;
        return true;
    });
    
    if (significantWords.length === 0) return null;
    
    // v5.1.0: Person-vs-Org classifier (replaces basic title-case check)
    // If display name looks like a person, skip the mismatch check entirely.
    // "Mike McCaskell" from purelogicescrow.com = normal employee email.
    // "Pure Logic Escrow" from randomdomain.com = suspicious.
    // This does NOT suppress lookalike/homoglyph/auth/content detections.
    if (displayLooksLikePerson(displayName)) return null;
    
    // Extract registrable domain name for comparison
    const registrableName = getRegistrableDomainName(domainLower);
    
    // Check word overlap: does ANY brand-specific word appear in the domain?
    // Corporate keywords (rewards, account, services, etc.) are excluded from overlap check
    // because scammers buy domains containing these generic words.
    let hasOverlap = false;
    for (const word of significantWords) {
        const wordLower = word.toLowerCase();
        if (wordLower.length < 4) continue; // Skip very short words for domain matching
        if (corporateKeywords.has(wordLower)) continue; // Skip generic corporate words
        
        // Check if word appears as substring of registrable domain name
        if (registrableName.includes(wordLower)) {
            hasOverlap = true;
            break;
        }
        // Also check full domain (catches subdomains like e.marriott.com)
        if (domainLower.includes(wordLower)) {
            hasOverlap = true;
            break;
        }
    }
    
    if (hasOverlap) return null; // Domain has relationship to display name
    
    // Zero overlap: display name claims organizational identity but domain is unrelated
    console.log('PATH 2 MATCH - Display name "' + displayName + '" has zero word overlap with domain ' + senderDomain);
    return {
        displayName: displayName,
        senderDomain: senderDomain,
        significantWords: significantWords.slice(0, 4).map(w => w.toLowerCase())
    };
}

function detectHomoglyphs(email) {
    // v4.3.1: Normalize before checking - catches zero-width insertions
    const normalizedEmail = stripUnicodeThreats(email);
    let found = [];
    for (const [homoglyph, latin] of Object.entries(HOMOGLYPHS)) {
        if (normalizedEmail.includes(homoglyph)) {
            found.push(`"${homoglyph}" looks like "${latin}"`);
        }
    }
    // Also flag if normalization changed the email (zero-width chars were present)
    if (normalizedEmail !== email && normalizedEmail.length < email.length) {
        found.push('Hidden invisible characters detected');
    }
    return found.length > 0 ? found.join(', ') : null;
}

function detectLookalikeDomain(domain) {
    // Check against hardcoded trusted domains
    for (const trusted of CONFIG.trustedDomains) {
        const distance = levenshteinDistance(domain, trusted);
        if (distance > 0 && distance <= 2) {
            return { trustedDomain: trusted, distance: distance };
        }
    }
    // Check against user-trusted domains (learned from Sent Items)
    for (const trusted of Object.keys(userTrustedDomains)) {
        const distance = levenshteinDistance(domain, trusted);
        if (distance > 0 && distance <= 2) {
            return { trustedDomain: trusted, distance: distance };
        }
    }
    return null;
}

// v5.2.1: KW-02 — Strip known disclaimer/signature blocks before keyword scanning.
// Wire fraud warning disclaimers and confidentiality notices contain keyword terms
// by design (they're WARNINGS about fraud, not fraud attempts).
// Viktor: Cannot exploit. Requires matching 2+ stable legal anchors in the bottom
// portion of the email. Attacker-crafted content appears in the top/middle.
function stripDisclaimerBlocks(text) {
    if (!text) return text;
    const lower = text.toLowerCase();
    const len = text.length;
    // Only look for disclaimers in the bottom 50% of the email
    const bottomHalfStart = Math.floor(len * 0.5);
    
    // Pattern 1: Wire fraud warning disclaimers (escrow/title/real estate signatures)
    const wfIdx = lower.indexOf('wire fraud warning', bottomHalfStart);
    if (wfIdx !== -1) {
        const nearby = lower.substring(wfIdx, Math.min(wfIdx + 1500, len));
        if (nearby.includes('escrow') || nearby.includes('cyber criminals') || 
            nearby.includes('phishing techniques') || nearby.includes('does not change')) {
            return text.substring(0, wfIdx).trimEnd();
        }
    }
    
    // Pattern 2: Confidentiality disclaimer (common in corporate signatures)
    const confPatterns = ['confidentiality:', 'confidentiality notice:', 'disclaimer:',
                          'this message is confidential', 'this email is confidential'];
    for (const pattern of confPatterns) {
        const cIdx = lower.indexOf(pattern, bottomHalfStart);
        if (cIdx !== -1) {
            const nearby = lower.substring(cIdx, Math.min(cIdx + 300, len));
            if (nearby.includes('intended') || nearby.includes('recipient') || 
                nearby.includes('unauthorized') || nearby.includes('privileged')) {
                return text.substring(0, cIdx).trimEnd();
            }
        }
    }
    
    return text;
}

// v5.2.1: KW-03 — Check if email body contains links to domains outside the sender's family.
// Used as a co-signal gate: body-only keyword matches without external links are low-signal.
// SafeLink-aware: decodes Outlook's URL rewriting before checking domains.
function hasExternalLinkMismatch(bodyText, senderDomain) {
    if (!bodyText || !senderDomain) return false;
    const senderLower = senderDomain.toLowerCase();
    const senderRoot = getRootDomain(senderLower);
    const urlRegex = /https?:\/\/[^\s<>"')\]},]+/gi;
    const matches = bodyText.match(urlRegex);
    if (!matches) return false;
    // Infrastructure/tracking domains that appear in legitimate emails — not external link mismatches
    const infraDomains = new Set(['google.com', 'gstatic.com', 'googleapis.com', 'microsoft.com',
        'office.com', 'outlook.com', 'live.com', 'cloudflare.com', 'akamaized.net', 'akamai.net',
        'amazonaws.com', 'doubleclick.net', 'facebook.com', 'twitter.com', 'linkedin.com',
        'apple.com', 'list-manage.com', 'mailchimp.com', 'sendgrid.net', 'mandrillapp.com',
        'createsend.com', 'constantcontact.com', 'mailgun.net', 'sparkpostmail.com',
        'protection.outlook.com', 'windows.net', 'azurewebsites.net', 'sharepoint.com',
        'svc.ms', 'aka.ms', 'office365.com', 'microsoftonline.com']);
    for (let i = 0; i < Math.min(matches.length, 30); i++) {
        try {
            let url = matches[i].replace(/[.,;:!?)>\]]+$/, '');
            // Decode Outlook SafeLinks
            try {
                const slObj = new URL(url);
                if (slObj.hostname.toLowerCase().endsWith('safelinks.protection.outlook.com')) {
                    const orig = slObj.searchParams.get('url') || slObj.searchParams.get('data');
                    if (orig) url = decodeURIComponent(orig);
                }
            } catch (e) { /* not a SafeLink */ }
            const urlObj = new URL(url);
            const host = urlObj.hostname.toLowerCase();
            const linkRoot = getRootDomain(host);
            if (linkRoot === senderRoot) continue;
            if (infraDomains.has(linkRoot)) continue;
            return true; // Found a non-infra, non-sender-family link
        } catch (e) { continue; }
    }
    return false;
}

// v5.2.1: KW-09 — Check if content contains transactional/financial terms near wire keywords.
// Wire fraud keywords in body are higher-signal when paired with actual financial data.
function hasTransactionalContext(content) {
    if (!content) return false;
    const lower = content.toLowerCase();
    const terms = ['$', '€', '£', '¥', 'usd', 'routing number', 'account number',
        'aba number', 'swift code', 'iban', 'bank name', 'beneficiary name',
        'cashier\'s check', 'certified check', 'invoice #', 'invoice number',
        'po number', 'purchase order', 'payment due', 'amount due', 'total due',
        'balance due', 'pay by', 'remit to', 'payable to'];
    return terms.some(t => lower.includes(t));
}

function detectWireFraudKeywords(content) {
    const found = [];
    const lowerContent = content.toLowerCase();
    const collapsedContent = collapseForMatch(lowerContent);
    for (const keyword of WIRE_FRAUD_KEYWORDS) {
        if (phraseMatchesContent(lowerContent, collapsedContent, keyword.toLowerCase())) {
            found.push(keyword);
        }
    }
    return found;
}

function detectFreeHostingSender(senderDomain) {
    if (!senderDomain) return null;
    const domainLower = senderDomain.toLowerCase();
    for (const hosting of SUSPICIOUS_FREE_HOSTING_DOMAINS) {
        if (domainLower === hosting || domainLower.endsWith('.' + hosting)) {
            return { senderDomain: domainLower, hostingPlatform: hosting };
        }
    }
    return null;
}

function detectContactLookalike(senderEmail) {
    const parts = senderEmail.toLowerCase().split('@');
    if (parts.length !== 2) return null;
    
    const senderLocal = parts[0];
    const senderDomain = parts[1];
    
    if (isTrustedDomain(senderDomain)) return null;
    
    const publicDomains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 
                           'icloud.com', 'mail.com', 'protonmail.com', 'zoho.com', 'yandex.com'];
    
    // v4.3.1: Cap comparison set to prevent UI lag on large contact lists.
    // Viktor: "I don't need to hack anything - just triggering slow analysis degrades trust in the tool."
    const MAX_CONTACT_COMPARE = 500;
    let compared = 0;
    
    for (const contact of knownContacts) {
        if (++compared > MAX_CONTACT_COMPARE) break;
        if (contact === senderEmail) continue;
        
        const contactParts = contact.toLowerCase().split('@');
        if (contactParts.length !== 2) continue;
        
        const contactLocal = contactParts[0];
        const contactDomain = contactParts[1];
        
        const usernameDiff = levenshteinDistance(senderLocal, contactLocal);
        
        // v5.2.0: Same-domain skip. If sender and contact share the exact domain,
        // they are coworkers/aliases, not impersonators. "staff@company.com" vs
        // "jeff@company.com" is not a lookalike — it's the same organization.
        // Skip entirely; only flag cross-domain near-matches.
        if (senderDomain === contactDomain) {
            continue;
        }
        
        const bothPublicSameDomain = publicDomains.includes(senderDomain) && 
                                      senderDomain === contactDomain;
        
        if (!bothPublicSameDomain || usernameDiff <= 4) {
            const domainDistance = levenshteinDistance(senderDomain, contactDomain);
            if (domainDistance > 0 && domainDistance <= 2) {
                // Ratio check: prevent false positives on short domains
                // "sold.com" vs "aol.com" = 2 edits on 3-char name = 67% different (not a lookalike)
                // "amazom.com" vs "amazon.com" = 1 edit on 6-char name = 17% different (real lookalike)
                const senderName = senderDomain.substring(0, senderDomain.lastIndexOf('.'));
                const contactName = contactDomain.substring(0, contactDomain.lastIndexOf('.'));
                const shorterNameLen = Math.min(senderName.length, contactName.length);
                const ratio = shorterNameLen > 0 ? domainDistance / shorterNameLen : 1;
                if (ratio <= 0.35) {
                    return {
                        incomingEmail: senderEmail,
                        matchedContact: contact,
                        reason: `Domain is ${domainDistance} character${domainDistance > 1 ? 's' : ''} different`
                    };
                }
            }
        }
    }
    
    return null;
}

// ============================================
// PHASE 2: SIGNAL DETECTION FUNCTIONS
// ============================================

function detectPhase2CredentialLanguage(content) {
    if (!content) return null;
    const lowerContent = content.toLowerCase();
    const collapsedContent = collapseForMatch(lowerContent);

    let hasExclusion = false;
    for (const exclusion of CREDENTIAL_EXCLUSION_PHRASES) {
        if (lowerContent.includes(exclusion)) {
            hasExclusion = true;
            break;
        }
    }

    const matched = [];
    for (const phrase of CREDENTIAL_REQUEST_PHRASES) {
        if (phraseMatchesContent(lowerContent, collapsedContent, phrase)) {
            matched.push(phrase);
        }
    }

    if (matched.length === 0) return null;
    if (hasExclusion && matched.length < 2) return null;

    return { signal: 'credential_language', matched: matched, count: matched.length };
}

function detectPhase2UnlockLanguage(content) {
    if (!content) return null;
    const lowerContent = content.toLowerCase();
    const collapsedContent = collapseForMatch(lowerContent);
    const matched = [];
    for (const phrase of UNLOCK_LANGUAGE_PHRASES) {
        if (phraseMatchesContent(lowerContent, collapsedContent, phrase)) matched.push(phrase);
    }
    if (matched.length === 0) return null;
    return { signal: 'unlock_language', matched: matched, count: matched.length };
}

function detectPhase2PaymentChangeLanguage(content) {
    if (!content) return null;
    const lowerContent = content.toLowerCase();
    const collapsedContent = collapseForMatch(lowerContent);
    const matchedPhrases = [];
    for (const phrase of PAYMENT_CHANGE_PHRASES) {
        if (phraseMatchesContent(lowerContent, collapsedContent, phrase)) matchedPhrases.push(phrase);
    }
    if (matchedPhrases.length === 0) return null;
    const matchedTokens = [];
    for (const token of BANKING_TOKENS) {
        if (phraseMatchesContent(lowerContent, collapsedContent, token)) matchedTokens.push(token);
    }
    if (matchedTokens.length === 0) return null;
    return { signal: 'payment_change_language', matchedPhrases: matchedPhrases, matchedTokens: matchedTokens };
}

function detectPhase2SecrecyLanguage(content) {
    if (!content) return null;
    const lowerContent = content.toLowerCase();
    const collapsedContent = collapseForMatch(lowerContent);
    const matched = [];
    for (const phrase of SECRECY_PHRASES) {
        if (phraseMatchesContent(lowerContent, collapsedContent, phrase)) matched.push(phrase);
    }
    if (matched.length === 0) return null;
    return { signal: 'secrecy_language', matched: matched };
}

// v4.3.2: Standalone banking token detection for Pattern E alternate path.
// Viktor paraphrases "updated wire instructions" but still needs to include
// actual banking details (routing number, SWIFT, etc.) to complete the scam.
// This catches BEC emails that avoid our payment change phrases but still
// contain the banking tokens that make the attack actionable.
function detectPhase2BankingTokensOnly(content) {
    if (!content) return null;
    const lowerContent = content.toLowerCase();
    const collapsedContent = collapseForMatch(lowerContent);
    const matched = [];
    for (const token of BANKING_TOKENS) {
        if (phraseMatchesContent(lowerContent, collapsedContent, token)) matched.push(token);
    }
    // Require 2+ banking tokens to reduce false positives on legit financial emails
    if (matched.length < 2) return null;
    return { signal: 'banking_tokens', matched: matched, count: matched.length };
}

function decodeSafeLink(url) {
    try {
        const urlObj = new URL(url);
        if (!urlObj.hostname.toLowerCase().endsWith('safelinks.protection.outlook.com')) return null;
        const orig = urlObj.searchParams.get('url') || urlObj.searchParams.get('data');
        if (!orig) return null;
        return decodeURIComponent(orig);
    } catch (e) { return null; }
}

function extractPhase2Urls(bodyText) {
    if (!bodyText) return [];
    if (bodyText.length > PHASE2_CONFIG.maxBodyLengthForUrlScan) return [];
    const matches = bodyText.match(PHASE2_URL_REGEX);
    if (!matches) return [];
    const results = [];
    const seenHosts = new Set();
    for (let i = 0; i < Math.min(matches.length, PHASE2_CONFIG.maxUrlsToExtract); i++) {
        try {
            let url = matches[i].replace(/[.,;:!?)>\]]+$/, '');
            const decoded = decodeSafeLink(url);
            if (decoded) url = decoded;
            const urlObj = new URL(url);
            const host = urlObj.hostname.toLowerCase();
            if (!seenHosts.has(host)) {
                seenHosts.add(host);
                results.push({ url: url, host: host, domain: getPhase2RegistrableDomain(host) });
            }
        } catch (e) { /* skip malformed */ }
    }
    return results;
}

function getPhase2RegistrableDomain(host) {
    const parts = host.split('.');
    if (parts.length <= 2) return host;
    const twoPartTlds = ['co.uk', 'com.au', 'co.nz', 'co.za', 'com.br', 'co.jp', 'co.kr', 'com.mx', 'co.in'];
    const lastTwo = parts.slice(-2).join('.');
    if (twoPartTlds.includes(lastTwo)) return parts.slice(-3).join('.');
    return parts.slice(-2).join('.');
}

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
    return { signal: 'suspicious_hosting_link', matched: matched };
}

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
    return { signal: 'legit_platform_link', matched: matched };
}

function detectPhase2SenderLinkMismatch(senderDomain, urls) {
    if (!senderDomain || !urls || urls.length === 0) return null;
    const senderDomainLower = senderDomain.toLowerCase();
    const mismatched = [];
    const infraDomains = ['google.com', 'gstatic.com', 'googleapis.com', 'microsoft.com',
        'office.com', 'outlook.com', 'live.com', 'cloudflare.com', 'akamai.net',
        'amazonaws.com', 'azurewebsites.net', 'doubleclick.net', 'googlesyndication.com',
        'googleadservices.com', 'facebook.com', 'fbcdn.net', 'twitter.com', 'linkedin.com'];
    // v4.3.2: User-content-hosting subdomains within infra providers.
    // These should NOT be excluded from mismatch detection because anyone can host
    // content on them. Viktor: "I just put my phishing page on Google Sites or
    // a public S3 bucket and your infra exclusion gives me a free pass."
    const userContentHosts = [
        'docs.google.com', 'sites.google.com', 'drive.google.com', 'forms.gle',
        'storage.googleapis.com', 'storage.cloud.google.com',
        's3.amazonaws.com',
        'azurewebsites.net',
        'sharepoint.com',
        'sway.office.com',
        'onedrive.live.com',
        'forms.office.com'
    ];
    for (const urlInfo of urls) {
        const linkDomain = urlInfo.domain;
        if (!linkDomain) continue;
        if (linkDomain === senderDomainLower) continue;
        if (linkDomain.endsWith('.' + senderDomainLower)) continue;
        if (senderDomainLower.endsWith('.' + linkDomain)) continue;
        // Check if this is a user-content host (do NOT exclude these)
        let isUserContent = false;
        for (const uch of userContentHosts) {
            if (urlInfo.host === uch || urlInfo.host.endsWith('.' + uch)) { isUserContent = true; break; }
        }
        if (!isUserContent) {
            let isInfra = false;
            for (const infra of infraDomains) {
                if (linkDomain === infra || linkDomain.endsWith('.' + infra)) { isInfra = true; break; }
            }
            if (isInfra) continue;
        }
        mismatched.push({ sender: senderDomainLower, linkDomain: linkDomain, url: urlInfo.url });
    }
    if (mismatched.length === 0) return null;
    return { signal: 'sender_link_mismatch', matched: mismatched };
}

function analyzePhase2Attachments(attachments) {
    if (!attachments || attachments.length === 0) return null;
    const results = {
        hasAttachments: true, hasDangerousType: false, hasHtml: false,
        hasArchive: false, hasDiskImage: false, hasExecutable: false, hasMacroCapable: false,
        dangerousFiles: [], htmlFiles: [], allFiles: []
    };
    for (const attachment of attachments) {
        // v4.3.2: Strip bidi control characters (including RLO) from filenames before analysis.
        // RLO (U+202E) can reverse visual rendering so "invoice_exe.pdf" displays as "invoice_fdp.exe"
        // but JavaScript string operations still see the original order.
        // Stripping them is cheap insurance against any edge case where rendering affects parsing.
        const name = (attachment.name || attachment.fileName || '').replace(/[\u202A-\u202E\u2066-\u2069]/g, '').toLowerCase();
        results.allFiles.push(name);
        const ext = '.' + name.split('.').pop();
        if (DANGEROUS_ATTACHMENT_EXTENSIONS.html.includes(ext)) {
            results.hasHtml = true; results.hasDangerousType = true;
            results.htmlFiles.push(name); results.dangerousFiles.push(name);
        }
        if (DANGEROUS_ATTACHMENT_EXTENSIONS.archive.includes(ext)) {
            results.hasArchive = true; results.hasDangerousType = true; results.dangerousFiles.push(name);
        }
        if (DANGEROUS_ATTACHMENT_EXTENSIONS.disk_image.includes(ext)) {
            results.hasDiskImage = true; results.hasDangerousType = true; results.dangerousFiles.push(name);
        }
        if (DANGEROUS_ATTACHMENT_EXTENSIONS.executable.includes(ext)) {
            results.hasExecutable = true; results.hasDangerousType = true; results.dangerousFiles.push(name);
        }
        if (DANGEROUS_ATTACHMENT_EXTENSIONS.macro_capable.includes(ext)) {
            results.hasMacroCapable = true; results.hasDangerousType = true; results.dangerousFiles.push(name);
        }
        // Double extension check
        const parts = name.split('.');
        if (parts.length >= 3) {
            const lastExt = '.' + parts[parts.length - 1];
            if (DANGEROUS_ATTACHMENT_EXTENSIONS.executable.includes(lastExt)) {
                results.hasExecutable = true; results.hasDangerousType = true;
                if (!results.dangerousFiles.includes(name)) results.dangerousFiles.push(name);
            }
        }
    }
    return results;
}

// ============================================
// PHASE 2: PATTERN EVALUATORS
// ============================================

function evaluatePatternA(signals) {
    const { credentialLanguage, senderLinkMismatch, urls } = signals;
    if (!credentialLanguage) return null;
    if (!urls || urls.length === 0) return null;
    if (!senderLinkMismatch) return null;
    return {
        patternId: 'pattern_a_credential_harvesting',
        patternName: 'Credential Harvesting Attempt',
        confidence: 'high',
        signals: { credential_language: credentialLanguage, sender_link_mismatch: senderLinkMismatch, links_present: { count: urls.length } },
        description: 'This email asks for login credentials and contains links pointing to domains that don\'t match the sender.',
        recommendation: 'Do NOT click any links. If you need to verify your account, go directly to the website by typing the address in your browser.'
    };
}

function evaluatePatternB(signals, coreWarnings) {
    const { credentialLanguage, suspiciousHostingLink, legitPlatformLink } = signals;
    const hasBrandMismatch = coreWarnings.some(w => w.type === 'brand-impersonation');
    if (!hasBrandMismatch) return null;
    if (suspiciousHostingLink) {
        const hasUrgency = coreWarnings.some(w => w.type === 'phishing-urgency');
        if (credentialLanguage || hasUrgency) {
            return {
                patternId: 'pattern_b_brand_free_hosting',
                patternName: 'Brand Impersonation with Suspicious Link',
                confidence: 'high',
                signals: { brand_mismatch: { fromCore: true }, suspicious_hosting_link: suspiciousHostingLink, credential_language: credentialLanguage || null, urgency: hasUrgency || null },
                description: 'This email impersonates a known brand but links to a free hosting platform.',
                recommendation: 'This is almost certainly a phishing attempt. Do not click any links. Report this email as phishing.'
            };
        }
    }
    if (legitPlatformLink) {
        let supportingSignalCount = 0;
        if (credentialLanguage) supportingSignalCount++;
        if (coreWarnings.some(w => w.type === 'phishing-urgency')) supportingSignalCount++;
        if (signals.senderLinkMismatch) supportingSignalCount++;
        if (signals.unlockLanguage) supportingSignalCount++;
        if (supportingSignalCount >= 2) {
            return {
                patternId: 'pattern_b_brand_free_hosting',
                patternName: 'Brand Impersonation with Suspicious Link',
                confidence: 'medium',
                signals: { brand_mismatch: { fromCore: true }, legit_platform_link: legitPlatformLink, supporting_signal_count: supportingSignalCount },
                description: 'This email impersonates a known brand and links to a file-sharing platform with multiple other suspicious indicators.',
                recommendation: 'Contact the supposed sender through a known, trusted channel before interacting with this email.'
            };
        }
    }
    return null;
}

function evaluatePatternC(signals, coreWarnings) {
    const { attachmentAnalysis, credentialLanguage, unlockLanguage, senderLinkMismatch } = signals;
    if (!attachmentAnalysis || !attachmentAnalysis.hasHtml) return null;
    if (!credentialLanguage && !unlockLanguage) return null;
    const hasBrandMismatch = coreWarnings.some(w => w.type === 'brand-impersonation');
    const hasDomainMismatch = senderLinkMismatch != null;
    if (!hasBrandMismatch && !hasDomainMismatch) return null;
    return {
        patternId: 'pattern_c_html_attachment_trap',
        patternName: 'HTML Attachment Phishing Trap',
        confidence: 'high',
        signals: { html_attachment: { files: attachmentAnalysis.htmlFiles }, credential_language: credentialLanguage || null, unlock_language: unlockLanguage || null, brand_mismatch: hasBrandMismatch || null, domain_mismatch: hasDomainMismatch ? senderLinkMismatch : null },
        description: 'This email contains an HTML file attachment that likely opens a fake login page in your browser.',
        recommendation: 'Do NOT open the HTML attachment. Delete this email. If you expected a document from this sender, contact them directly.'
    };
}

function evaluatePatternD(signals, coreWarnings) {
    const { attachmentAnalysis, unlockLanguage, credentialLanguage, paymentChangeLanguage } = signals;
    if (!attachmentAnalysis) return null;
    const hasDangerousNonHtml = attachmentAnalysis.hasArchive || attachmentAnalysis.hasDiskImage || attachmentAnalysis.hasExecutable || attachmentAnalysis.hasMacroCapable;
    if (!hasDangerousNonHtml) return null;
    if (!unlockLanguage) return null;
    const supportingSignals = [];
    if (signals.isUnknownSender) supportingSignals.push('unknown_sender');
    if (coreWarnings.some(w => w.type === 'phishing-urgency')) supportingSignals.push('urgency');
    if (coreWarnings.some(w => w.type === 'brand-impersonation')) supportingSignals.push('brand_mismatch');
    if (credentialLanguage) supportingSignals.push('credential_language');
    if (paymentChangeLanguage) supportingSignals.push('payment_language');
    const requiredCount = (signals.isTrustedKnownSender) ? 2 : 1;
    if (supportingSignals.length < requiredCount) return null;
    const attachTypes = [];
    if (attachmentAnalysis.hasArchive) attachTypes.push('archive');
    if (attachmentAnalysis.hasDiskImage) attachTypes.push('disk_image');
    if (attachmentAnalysis.hasExecutable) attachTypes.push('executable');
    if (attachmentAnalysis.hasMacroCapable) attachTypes.push('macro_capable');
    return {
        patternId: 'pattern_d_dangerous_attachment',
        patternName: 'Suspicious Protected Attachment',
        confidence: (attachmentAnalysis.hasExecutable || attachmentAnalysis.hasDiskImage) ? 'critical' : 'high',
        signals: { dangerous_attachment: { types: attachTypes, files: attachmentAnalysis.dangerousFiles }, unlock_language: unlockLanguage, supporting_signals: supportingSignals, trusted_sender_guardrail: signals.isTrustedKnownSender || false },
        description: 'This email contains a password-protected attachment with unlock instructions. Attackers use encryption to prevent email scanners from detecting malware.',
        recommendation: 'Do NOT open the attachment or use the provided password. Confirm through a separate communication channel before opening.'
    };
}

function evaluatePatternE(signals, coreWarnings) {
    const { paymentChangeLanguage, bankingTokensOnly, secrecyLanguage } = signals;
    // Primary path: explicit payment change phrases detected
    // Alternate path: no payment change phrases, but 2+ banking tokens present
    // Viktor: "I just reword 'updated wire instructions' to 'please redirect future remittances'
    // but I still need to include the routing number and account number to get paid."
    const hasPaymentSignal = paymentChangeLanguage || bankingTokensOnly;
    if (!hasPaymentSignal) return null;
    const hasReplyToMismatch = coreWarnings.some(w => w.type === 'replyto-mismatch');
    const hasOnBehalfOf = coreWarnings.some(w => w.type === 'on-behalf-of');
    if (!hasReplyToMismatch && !hasOnBehalfOf) return null;
    const hasUrgency = coreWarnings.some(w => w.type === 'phishing-urgency');
    if (!hasUrgency && !secrecyLanguage) return null;
    // Alternate path (banking tokens only, no explicit payment phrases) = medium confidence
    // Primary path (explicit payment change phrases) = critical confidence
    const confidence = paymentChangeLanguage ? 'critical' : 'high';
    return {
        patternId: 'pattern_e_payment_redirect',
        patternName: 'Payment Redirect / Business Email Compromise',
        confidence: confidence,
        signals: { payment_change_language: paymentChangeLanguage || null, banking_tokens: bankingTokensOnly || null, reply_to_mismatch: hasReplyToMismatch || null, on_behalf_of: hasOnBehalfOf || null, urgency: hasUrgency || null, secrecy_language: secrecyLanguage || null },
        description: paymentChangeLanguage 
            ? 'This email requests a change to payment instructions while using a spoofed sender identity and pressure tactics. This is a textbook BEC attack.'
            : 'This email contains banking details (routing numbers, account numbers) combined with a spoofed sender identity and pressure tactics. This is consistent with a BEC attack.',
        recommendation: 'STOP. Do NOT process any payment changes from this email. Call the supposed sender at a KNOWN phone number to verify.'
    };
}

// ============================================
// PHASE 2: ENGINE (Orchestrator)
// ============================================

function runPhase2Engine(emailData, coreWarnings) {
    const startTime = performance.now();
    if (!PHASE2_CONFIG.enabled) {
        return { finalWarnings: coreWarnings, phase2Ran: false, matchedPatterns: [], suppressedWarnings: [], runtime: 0 };
    }

    // Collect signals
    const body = emailData.body || '';
    const senderDomain = emailData.senderDomain || '';
    const attachments = emailData.attachments || [];
    const urls = extractPhase2Urls(body);

    const signals = {
        credentialLanguage: detectPhase2CredentialLanguage(body),
        unlockLanguage: detectPhase2UnlockLanguage(body),
        paymentChangeLanguage: detectPhase2PaymentChangeLanguage(body),
        bankingTokensOnly: detectPhase2BankingTokensOnly(body),
        secrecyLanguage: detectPhase2SecrecyLanguage(body),
        urls: urls,
        suspiciousHostingLink: detectPhase2SuspiciousHostingLink(urls),
        legitPlatformLink: detectPhase2LegitPlatformLink(urls),
        senderLinkMismatch: detectPhase2SenderLinkMismatch(senderDomain, urls),
        attachmentAnalysis: analyzePhase2Attachments(attachments),
        isUnknownSender: !emailData.isKnownContact && !isTrustedDomain(senderDomain),
        isTrustedKnownSender: emailData.isKnownContact && isTrustedDomain(senderDomain)
    };

    // Evaluate patterns
    const matchedPatterns = [];
    const pA = evaluatePatternA(signals); if (pA) matchedPatterns.push(pA);
    const pB = evaluatePatternB(signals, coreWarnings); if (pB) matchedPatterns.push(pB);
    const pC = evaluatePatternC(signals, coreWarnings); if (pC) matchedPatterns.push(pC);
    const pD = evaluatePatternD(signals, coreWarnings); if (pD) matchedPatterns.push(pD);
    const pE = evaluatePatternE(signals, coreWarnings); if (pE) matchedPatterns.push(pE);

    // Silent mode: log but don't modify warnings
    if (PHASE2_CONFIG.silentMode) {
        const runtime = performance.now() - startTime;
        if (matchedPatterns.length > 0) {
            console.log('%c[EFA Phase 2 SILENT] Patterns matched!', 'color: #ff6600; font-weight: bold;', {
                patterns: matchedPatterns.map(p => p.patternId),
                confidence: matchedPatterns.map(p => p.confidence),
                descriptions: matchedPatterns.map(p => p.description),
                signals: matchedPatterns.map(p => p.signals),
                wouldSuppress: matchedPatterns.flatMap(p => SUPPRESSION_MAP[p.patternId] || []),
                runtime: runtime.toFixed(1) + 'ms'
            });
        } else {
            console.log('[EFA Phase 2 SILENT] No patterns matched (' + runtime.toFixed(1) + 'ms)');
        }
        return { finalWarnings: coreWarnings, phase2Ran: true, matchedPatterns: matchedPatterns, suppressedWarnings: [], runtime: runtime, silentMode: true };
    }

    // Active mode (future): suppress and merge
    const suppressedTypes = new Set();
    for (const pattern of matchedPatterns) {
        const suppressList = SUPPRESSION_MAP[pattern.patternId];
        if (suppressList) {
            for (const type of suppressList) suppressedTypes.add(type);
        }
    }
    const filteredWarnings = [];
    const suppressedWarnings = [];
    for (const warning of coreWarnings) {
        if (suppressedTypes.has(warning.type)) suppressedWarnings.push(warning);
        else filteredWarnings.push(warning);
    }

    let finalWarnings = [...filteredWarnings];
    if (matchedPatterns.length > 0) {
        const confidencePriority = { 'critical': 3, 'high': 2, 'medium': 1 };
        let highestConfidence = 'medium';
        for (const p of matchedPatterns) {
            if ((confidencePriority[p.confidence] || 0) > (confidencePriority[highestConfidence] || 0)) highestConfidence = p.confidence;
        }
        finalWarnings.push({
            type: 'phase2-phishing-pattern',
            severity: highestConfidence === 'critical' ? 'critical' : highestConfidence === 'high' ? 'high' : 'medium',
            title: matchedPatterns.length === 1 ? matchedPatterns[0].patternName : 'Multiple Phishing Indicators Detected',
            description: matchedPatterns.map(p => p.description).join(' '),
            recommendation: matchedPatterns[0].recommendation,
            details: { patterns: matchedPatterns, suppressedCoreWarnings: suppressedWarnings, patternCount: matchedPatterns.length },
            isPhase2: true
        });
    }

    return { finalWarnings: finalWarnings, phase2Ran: true, matchedPatterns: matchedPatterns, suppressedWarnings: suppressedWarnings, runtime: performance.now() - startTime };
}

// ============================================
// MAIN ANALYSIS
// ============================================
async function analyzeCurrentEmail() {
    showLoading();
    
    try {
        currentUserEmail = Office.context.mailbox.userProfile.emailAddress;
        
        if (knownContacts.size === 0 && !contactsFetched) {
            await fetchAllKnownContacts();
        }
        
        // Sync user-trusted domains from Sent Items (non-blocking)
        syncSentItemsDomains().catch(e => console.log('Background sync:', e.message));
        
        const item = Office.context.mailbox.item;
        const from = item.from;
        const subject = item.subject;
        
        const toRecipients = Array.isArray(item.to) ? item.to : [];
        const ccRecipients = Array.isArray(item.cc) ? item.cc : [];
        const recipientCount = toRecipients.length + ccRecipients.length;
        
        // v4.2.0: Get attachments for Phase 2
        const attachments = item.attachments || [];
        
        item.body.getAsync(Office.CoercionType.Text, (bodyResult) => {
            if (item.getAllInternetHeadersAsync) {
                item.getAllInternetHeadersAsync((headerResult) => {
                    let replyTo = null;
                    let senderHeader = null;
                    let headers = null;
                    if (headerResult.status === Office.AsyncResultStatus.Succeeded) {
                        headers = headerResult.value;
                        const replyToMatch = headers.match(/^Reply-To:\s*(.+)$/mi);
                        if (replyToMatch) {
                            const emailMatch = replyToMatch[1].match(/<([^>]+)>/) || replyToMatch[1].match(/([^\s,]+@[^\s,]+)/);
                            if (emailMatch) {
                                replyTo = emailMatch[1].trim().replace(/^["']|["']$/g, '');
                            }
                        }
                        const senderMatch = headers.match(/^Sender:\s*(.+)$/mi);
                        if (senderMatch) {
                            const senderEmailMatch = senderMatch[1].match(/<([^>]+)>/) || senderMatch[1].match(/([^\s,]+@[^\s,]+)/);
                            if (senderEmailMatch) {
                                senderHeader = senderEmailMatch[1].trim().replace(/^["']|["']$/g, '');
                            }
                        }
                    }
                    
                    const emailData = {
                        from: from,
                        subject: subject,
                        body: bodyResult.value || '',
                        replyTo: replyTo,
                        senderHeader: senderHeader,
                        recipientCount: recipientCount,
                        headers: headers,
                        attachments: attachments  // v4.2.0: Phase 2
                    };
                    
                    processEmail(emailData);
                });
            } else {
                const emailData = {
                    from: from,
                    subject: subject,
                    body: bodyResult.value || '',
                    replyTo: null,
                    senderHeader: null,
                    recipientCount: recipientCount,
                    headers: null,
                    attachments: attachments  // v4.2.0: Phase 2
                };
                
                processEmail(emailData);
            }
        });
        
    } catch (error) {
        console.log('Analysis error:', error);
        showError('Unable to analyze email. Please try again.');
    }
}

async function processEmail(emailData) {
    const senderEmail = emailData.from.emailAddress.toLowerCase();
    const displayName = emailData.from.displayName || '';
    const senderDomain = senderEmail.split('@')[1] || '';
    
    // v5.2.0: Body-prep layer — run ONCE, feed outputs to all detectors.
    // Strips URL query strings/fragments from scanning surface.
    // cleanText = visible text with URLs replaced by hostnames only.
    // urlHosts = Set of extracted hostnames for brand-in-URL checks.
    const { cleanText, urlHosts } = prepareBodyForScanning(emailData.body || '');
    const content = (emailData.subject || '') + ' ' + cleanText;
    
    const replyTo = emailData.replyTo;
    const senderHeader = emailData.senderHeader;
    
    const isKnownContact = knownContacts.has(senderEmail);
    
    const warnings = [];
    
    // ============================================
    // v5.0.0: DOMAIN REPUTATION BACKEND CHECK
    // Checks threat feeds + WHOIS domain age
    // ============================================
    const reputationResult = await checkDomainReputation(senderDomain);
    if (reputationResult) {
        if (reputationResult.layer === 'threat_feed') {
            warnings.push({
                type: 'known-threat',
                severity: reputationResult.confidence === 'high' ? 'critical' : 'medium',
                title: 'Known Malicious Domain',
                description: 'This sender\'s domain (' + senderDomain + ') appears in threat intelligence databases.',
                senderEmail: senderEmail,
                matchedEmail: (reputationResult.sources || []).join(', ')
            });
        }
        if (reputationResult.layer === 'whois_age') {
            const ageDays = reputationResult.domainAge;
            let title, description;
            if (ageDays < 7) {
                title = 'Brand New Domain \u2014 Registered ' + ageDays + ' Day' + (ageDays !== 1 ? 's' : '') + ' Ago';
                description = 'This domain was created on ' + reputationResult.createdDate + '. No legitimate business operates from a domain this new. This is a strong indicator of a fraudulent domain created specifically for this attack.';
            } else if (ageDays < 30) {
                title = 'Recently Created Domain \u2014 ' + ageDays + ' Days Old';
                description = 'This domain was registered on ' + reputationResult.createdDate + '. Domains less than 30 days old are frequently used in targeted BEC and wire fraud attacks.';
            } else {
                title = 'New Domain \u2014 ' + ageDays + ' Days Old';
                description = 'This domain was created on ' + reputationResult.createdDate + '. While not necessarily malicious, domains under 90 days old deserve additional scrutiny.';
            }
            if (reputationResult.registrar) {
                description += ' Registrar: ' + reputationResult.registrar + '.';
            }
            warnings.push({
                type: 'new-domain',
                severity: reputationResult.confidence,
                title: title,
                description: description,
                senderEmail: senderEmail,
                matchedEmail: senderDomain
            });
        }
    }
    
    // ============================================
    // v3.5.0 CHECKS
    // ============================================
    
    const recipientSpoof = detectRecipientSpoofing(displayName, senderEmail);
    if (recipientSpoof) {
        warnings.push({
            type: 'recipient-spoof',
            severity: 'critical',
            title: 'Sender Impersonating You',
            description: 'The sender is using YOUR name as their display name. This is a common phishing tactic.',
            senderEmail: senderEmail,
            matchedEmail: recipientSpoof.displayName
        });
    }
    
    // Recipient-domain impersonation: display name claims to be recipient's organization
    const recipientDomainSpoof = detectRecipientDomainImpersonation(displayName, senderDomain);
    if (recipientDomainSpoof) {
        warnings.push({
            type: 'recipient-domain-impersonation',
            severity: 'critical',
            title: 'Impersonating Your Organization',
            description: `This sender is pretending to be ${recipientDomainSpoof.recipientOrgName} but is actually sending from ${recipientDomainSpoof.senderDomain}. This is a credential harvesting attack designed to steal your login credentials.`,
            senderEmail: senderEmail,
            senderDomain: recipientDomainSpoof.senderDomain,
            recipientDomain: recipientDomainSpoof.recipientDomain,
            recipientOrgName: recipientDomainSpoof.recipientOrgName,
            displayName: recipientDomainSpoof.displayName
        });
    }
    
    // v5.2.1: SW-01 — Feature flag gate; KW-02 — disclaimer stripping; SEV-01 — severity medium
    // v5.2.1: KW-06 — Subject hits stand alone; body-only requires co-signal
    // v5.2.1: KW-03 — Body-only phishing words require external link to different domain
    if (ENABLE_PHISHING_WORDS) {
        const strippedCleanText = stripDisclaimerBlocks(cleanText);
        const phishingUrgency = detectPhishingUrgency(strippedCleanText, emailData.subject);
        if (phishingUrgency) {
            // KW-06: Check if any matched keywords appear in the subject line (high signal)
            const subjectLower = (emailData.subject || '').toLowerCase();
            const inSubject = phishingUrgency.keywords.some(kw => subjectLower.includes(kw.toLowerCase()));
            // KW-03: Body-only matches require an external link pointing to a different domain
            const hasExtLink = hasExternalLinkMismatch(emailData.body || cleanText, senderDomain);
            
            if (inSubject || hasExtLink) {
                warnings.push({
                    type: 'phishing-urgency',
                    severity: 'medium',
                    title: 'Phishing Language Detected',
                    description: 'This email uses fear tactics commonly found in phishing scams.',
                    keywords: phishingUrgency.keywords,
                    keywordCategory: 'Phishing Tactics',
                    keywordExplanation: 'Scammers use threats of account deletion, suspension, or data loss to pressure you into clicking malicious links. Legitimate companies rarely threaten immediate action via email.'
                });
            }
            // else: body-only phishing language + no external links = low signal, suppress
        }
    }
    
    const gibberishDomain = detectGibberishDomain(senderEmail);
    if (gibberishDomain) {
        // v5.1.0: Skip gibberish/random domain warning for ESP subdomains
        // "5691434.brevosend.com" is normal Brevo infrastructure, not suspicious
        const gdLower = senderDomain ? senderDomain.toLowerCase() : '';
        const isESPGibberish = KNOWN_ESP_DOMAINS.some(esp => gdLower === esp || gdLower.endsWith('.' + esp))
            || ESP_SENDER_DOMAINS.has(gdLower)
            || Array.from(ESP_SENDER_DOMAINS).some(esp => gdLower.endsWith('.' + esp));
        if (!isESPGibberish) {
            warnings.push({
                type: 'gibberish-domain',
                severity: 'critical',
                title: 'Suspicious Random Domain',
                description: `This email comes from a domain that appears to be randomly generated (${gibberishDomain.reasons.join(', ')}). Legitimate companies use recognizable domain names.`,
                senderEmail: senderEmail,
                matchedEmail: gibberishDomain.domain
            });
        }
    }
    
    const gibberishUsername = detectGibberishUsername(senderEmail);
    if (gibberishUsername && !isKnownPlatform(senderDomain)) {
        warnings.push({
            type: 'gibberish-username',
            severity: 'critical',
            title: 'Gibberish Sender Address',
            description: `The sender's email username appears randomly generated (${gibberishUsername.reasons.join(', ')}). Real people and businesses don't use keyboard smashes as email addresses.`,
            senderEmail: senderEmail
        });
    }

    const freeHosting = senderDomain ? detectFreeHostingSender(senderDomain) : null;
    if (freeHosting) {
        warnings.push({
            type: 'free-hosting-sender',
            severity: 'critical',
            title: 'Sent from Free Hosting Platform',
            description: `This email was sent from ${freeHosting.hostingPlatform}, a free web hosting service. <b>No legitimate</b> business sends email from a web hosting platform.`,
            senderEmail: senderEmail,
            hostingPlatform: freeHosting.hostingPlatform
        });
    }
    
    const fakeTLD = detectFakeTLD(senderDomain);
    if (fakeTLD) {
        warnings.push({
            type: 'fake-tld',
            severity: 'critical',
            title: 'Fake Domain Extension',
            description: `The domain extension "${fakeTLD.fakeTLD}" is not a real top-level domain registered with IANA. This email cannot be from a legitimate source.`,
            senderEmail: senderEmail,
            tld: fakeTLD.fakeTLD
        });
    }
    
    const viaRouting = detectViaRouting(emailData.headers, senderDomain);
    if (viaRouting) {
        warnings.push({
            type: 'via-routing',
            severity: 'critical',
            title: 'Suspicious Routing Detected',
            description: 'This email was routed through a suspicious relay server with a randomly-generated domain name. Legitimate businesses use recognizable mail servers.',
            senderEmail: senderEmail,
            viaDomain: viaRouting.viaDomain
        });
    }
    
    const authFailure = detectAuthFailure(emailData.headers, senderDomain);
    if (authFailure) {
        warnings.push({
            type: 'auth-failure',
            severity: 'critical',
            title: 'Email Authentication Failed',
            description: 'This email failed security checks that verify the sender\'s identity. It may not be from who it claims. Verify the sender before clicking any links.',
            senderEmail: senderEmail,
            senderDomain: senderDomain,
            failures: authFailure.failures
        });
    }
    
    // v4.2.7: Provider-flagged warning - surfaces Outlook's own determination
    // This fires independently of EFA's auth scoring. If Microsoft says something is wrong,
    // we make sure the user sees it. EFA is just the messenger.
    // v4.2.11: Always show this warning regardless of other auth detections.
    // Microsoft's determination and EFA's detection are independent signals - both matter.
    let providerFlagged = false;
    
    // Check 1: Transport header compauth=fail
    if (emailData.headers) {
        const hasCompAuthFail = /compauth\s*=\s*fail/i.test(emailData.headers);
        if (hasCompAuthFail) {
            providerFlagged = true;
        }
    }
    
    // Check 2: Microsoft safety tip banners injected into email body
    // Microsoft injects HTML banners with specific warning text for phishing, spam, etc.
    // These are visible to users but EFA should amplify them so they're not ignored.
    if (!providerFlagged && emailData.body) {
        const bodyLower = emailData.body.toLowerCase();
        const microsoftSafetyPatterns = [
            'potential phishing warning',
            'this email looks like it could trick you',
            'this message was identified as phishing',
            'this sender failed our fraud checks',
            'this message looks suspicious',
            'we could not verify the identity of the sender',
            'this message was identified as junk',
            'this email was detected as spam'
        ];
        for (const pattern of microsoftSafetyPatterns) {
            if (bodyLower.includes(pattern)) {
                providerFlagged = true;
                console.log('PROVIDER FLAGGED (body banner) - Pattern: "' + pattern + '"');
                break;
            }
        }
    }
    
    if (providerFlagged) {
        warnings.push({
            type: 'provider-flagged',
            severity: 'critical',
            title: 'Flagged by Outlook',
            description: 'Outlook has flagged this email as suspicious. If this email contains links or buttons, proceed with extreme caution.',
            senderEmail: senderEmail
        });
    }

    // ============================================
    // EXISTING CHECKS
    // ============================================
    
    if (replyTo && replyTo.toLowerCase() !== senderEmail) {
        const replyToDomain = replyTo.split('@')[1] || '';
        // v4.3.0: Suppress when reply-to is the user's own email address.
        // If replies go back to the recipient, there is zero attack value.
        // Viktor: "I need replies to come to ME. If they go back to the victim, I get nothing."
        const isReplyToSelf = currentUserEmail && replyTo.toLowerCase() === currentUserEmail.toLowerCase();
        if (!isReplyToSelf && replyToDomain.toLowerCase() !== senderDomain) {
            // Check for parent-child subdomain relationship (v4.2.7)
            // e.g., newsletter.ocregister.com → ocregister.com is safe because
            // only the owner of ocregister.com can create subdomains on it.
            // An attacker cannot forge this DNS relationship.
            const replyToDomainLower = replyToDomain.toLowerCase();
            const isParentChild = senderDomain.endsWith('.' + replyToDomainLower) || replyToDomainLower.endsWith('.' + senderDomain);
            // Check for sibling subdomains (v4.2.12)
            // e.g., welcome.americanexpress.com → service.americanexpress.com is safe
            // because both share the same root domain owned by the same entity.
            // Excluded: free hosting platforms where anyone can get a subdomain.
            const senderRoot = getRootDomain(senderDomain);
            const replyRoot = getRootDomain(replyToDomainLower);
            const isSibling = senderRoot === replyRoot && !SUSPICIOUS_FREE_HOSTING_DOMAINS.includes(senderRoot);
            
            // v5.2.0: Org-family check. Some orgs legitimately use different root
            // domains for From vs Reply-To (e.g., gamechanger.io → gc.com).
            const isOrgFamily = ORG_FAMILY_MAP.some(family => 
                family.has(senderRoot) && family.has(replyRoot));
            
            if (!isParentChild && !isSibling && !isOrgFamily && !isKnownPlatform(senderDomain)) {
                // v5.2.1: Check if reply-to destination is a known ESP domain.
                // When a brand sends through Mailchimp/SendGrid/etc., the SENDER is the brand
                // (e.g., chrisstapleton.com) and the REPLY-TO is the ESP infrastructure
                // (e.g., inbound.mailchimpapp.net). Replies to ESP domains have zero attack
                // value — they go to Mailchimp's servers, not to an attacker.
                // Viktor: "I need replies to come to ME. Routing them to Mailchimp gives me nothing."
                const isESPReplyTo = KNOWN_ESP_DOMAINS.some(esp => 
                    replyToDomainLower === esp || replyToDomainLower.endsWith('.' + esp)
                ) || ESP_SENDER_DOMAINS.has(replyToDomainLower) || 
                    Array.from(ESP_SENDER_DOMAINS).some(esp => replyToDomainLower.endsWith('.' + esp));
                
                if (isESPReplyTo) {
                    // Reply-to goes to ESP infrastructure. Suppress from display but keep
                    // as signal for Pattern E (BEC detection). Viktor's play: register free
                    // Mailchimp account, route replies through ESP infrastructure to his inbox.
                    // Pattern E still catches this if wire fraud + urgency signals are present.
                    console.log('REPLY-TO SUPPRESSED (reply-to is known ESP:', replyToDomainLower, ') - from', senderDomain);
                    warnings.push({
                        type: 'replyto-mismatch',
                        severity: 'info',
                        title: 'Reply-To Mismatch',
                        description: 'Replies route through a known email service provider (' + replyToDomainLower + ').',
                        senderEmail: senderEmail,
                        matchedEmail: replyTo,
                        _espSuppressed: true
                    });
                }
                
                // v5.1.0: ESP-aware Reply-To mismatch with freemail override
                // Check both old KNOWN_ESP_DOMAINS list and new ESP_SENDER_DOMAINS set
                const isESPSender = KNOWN_ESP_DOMAINS.some(esp => 
                    senderDomain === esp || senderDomain.endsWith('.' + esp)
                ) || ESP_SENDER_DOMAINS.has(senderDomain) || 
                    Array.from(ESP_SENDER_DOMAINS).some(esp => senderDomain.endsWith('.' + esp));
                
                if (!isESPReplyTo && isESPSender) {
                    // ESP is sending this email. Check if reply-to destination is suspicious.
                    // Viktor's attack: free ESP account, legit DKIM, reply-to goes to burner.
                    // Fix: check WHERE replies go even when ESP is allowlisted.
                    const replyToIsFreemail = FREEMAIL_SET.has(replyToDomainLower);
                    
                    // Check for freemail reply-to + freemail-hosted CTA (Google Forms/Sites, Microsoft Forms)
                    // This is a textbook phishing pattern and should always be HIGH.
                    const bodyLower = (emailData.body || '').toLowerCase();
                    const freemailCTAPatterns = [
                        'docs.google.com/forms', 'forms.gle', 'sites.google.com',
                        'forms.office.com', 'forms.microsoft.com',
                        'docs.google.com/document'
                    ];
                    const hasFreemailCTA = replyToIsFreemail && 
                        freemailCTAPatterns.some(p => bodyLower.includes(p));
                    
                    if (hasFreemailCTA) {
                        // Reply-To freemail + CTA on freemail provider pages = HIGH
                        warnings.push({
                            type: 'replyto-mismatch',
                            severity: 'critical',
                            title: 'Suspicious Reply Destination',
                            description: 'This email was sent through a marketing platform, but replies go to a free email account and links point to a free form service. This is a common phishing pattern.',
                            senderEmail: senderEmail,
                            matchedEmail: replyTo
                        });
                    } else if (replyToIsFreemail) {
                        // ESP sender but reply-to is freemail → override ESP suppression, warn
                        // Viktor: "I need replies to come to ME at my burner Gmail."
                        warnings.push({
                            type: 'replyto-mismatch',
                            severity: 'medium',
                            title: 'Reply-To Mismatch',
                            description: 'This email was sent through a marketing platform, but replies go to a free email account (' + replyToDomainLower + '). Legitimate businesses typically use their own domain for replies.',
                            senderEmail: senderEmail,
                            matchedEmail: replyTo
                        });
                    } else {
                        // ESP sender, reply-to is not freemail → check high-risk blockers
                        // before suppressing. Max 1-tier downgrade, never below Medium
                        // if any high-risk signals exist.
                        let hasHighRiskBlocker = false;
                        
                        // Check DMARC fail from headers
                        if (emailData.headers && /dmarc\s*=\s*fail/i.test(emailData.headers)) {
                            hasHighRiskBlocker = true;
                        }
                        // Check reply-to domain age if reputation data available
                        // (reputationResult is from the Cloudflare Worker check earlier)
                        if (reputationResult && reputationResult.layer === 'whois_age' && 
                            reputationResult.domainAge < 90) {
                            hasHighRiskBlocker = true;
                        }
                        // Quick check for wire fraud / payment keywords in body
                        const riskKeywords = ['wire transfer', 'wire instructions', 'routing number',
                            'account number', 'bank account', 'payment details', 'updated bank',
                            'new account', 'verify your account', 'confirm your identity',
                            'suspended', 'unauthorized access', 'click here to verify'];
                        if (riskKeywords.some(k => bodyLower.includes(k))) {
                            hasHighRiskBlocker = true;
                        }
                        
                        if (hasHighRiskBlocker) {
                            // High-risk signals present → don't suppress even though ESP
                            warnings.push({
                                type: 'replyto-mismatch',
                                severity: 'medium',
                                title: 'Reply-To Mismatch',
                                description: 'Replies will go to a different address than the sender.',
                                senderEmail: senderEmail,
                                matchedEmail: replyTo
                            });
                        }
                        // else: ESP + no freemail + no high-risk blockers → suppress (legitimate newsletter)
                        // This is the Brevo/Mailchimp/SendGrid normal newsletter case.
                    }
                } else if (!isESPReplyTo) {
                    // Not an ESP sender, not an ESP reply-to → standard mismatch warning
                    warnings.push({
                        type: 'replyto-mismatch',
                        severity: 'medium',
                        title: 'Reply-To Mismatch',
                        description: 'Replies will go to a different address than the sender.',
                        senderEmail: senderEmail,
                        matchedEmail: replyTo
                    });
                }
            }
        }
    }
    
    if (senderHeader) {
        const senderHeaderLower = senderHeader.toLowerCase();
        const senderHeaderDomain = senderHeaderLower.split('@')[1] || '';
        if (senderHeaderDomain && senderHeaderDomain !== senderDomain) {
            // Check for parent-child subdomain relationship
            // e.g., mail.raziexchange.com sending on behalf of raziexchange.com is safe
            // because only the owner of raziexchange.com can create subdomains on it.
            // Viktor test: Passed. Cannot own mail.company.com without owning company.com.
            const isParentChild = senderDomain.endsWith('.' + senderHeaderDomain) || senderHeaderDomain.endsWith('.' + senderDomain);
            const oboSenderRoot = getRootDomain(senderDomain);
            const oboHeaderRoot = getRootDomain(senderHeaderDomain);
            const isOboSibling = oboSenderRoot === oboHeaderRoot && !SUSPICIOUS_FREE_HOSTING_DOMAINS.includes(oboSenderRoot);
            if (!isParentChild && !isOboSibling) {
                // v4.3.0: Suppress when Sender header domain is a calendar/notification infrastructure provider.
                // These providers set the Sender header from their own servers for calendar invites
                // and notifications. This is not spoofing - it's how Google Calendar, Outlook Calendar, etc. work.
                // Viktor: "Can't forge a Sender header of google.com without sending through Google's servers."
                const isCalendarInfra = CALENDAR_INFRASTRUCTURE_DOMAINS.some(cid =>
                    senderHeaderDomain === cid || senderHeaderDomain.endsWith('.' + cid)
                );
                // v4.3.1: Suppress when Sender header domain is a known ESP (Constant Contact, Mailchimp, etc.)
                // ESPs send on behalf of businesses - the Sender header mismatch is expected infrastructure.
                // The ESP is in the Sender header (senderHeaderDomain), not the From (senderDomain).
                // Viktor: "ccsend.com sending on behalf of mortgageeducators.com is just Constant Contact doing its job."
                const isKnownESP = KNOWN_ESP_DOMAINS.some(esp =>
                    senderHeaderDomain === esp || senderHeaderDomain.endsWith('.' + esp)
                );
                const isKnownPlatformOBO = isKnownPlatform(senderHeaderDomain);
                if (!isCalendarInfra && !isKnownESP && !isKnownPlatformOBO) {
                    warnings.push({
                        type: 'on-behalf-of',
                        severity: 'medium',
                        title: 'Sent On Behalf Of Another Domain',
                        description: 'This email was sent by one domain on behalf of a completely different domain. This is a common tactic used to disguise the true origin of an email.',
                        senderEmail: senderHeader,
                        matchedEmail: senderEmail
                    });
                }
            }
        }
    }
    
    // v5.2.0: Brand detection now scans cleanText (URL params stripped) instead of raw body
    // v5.2.1: Skip brand detection on trusted domains. If Jamie@purelogicescrow.com mentions
    // "Spotify" in a family email, that's not impersonation. Matches org-impersonation gate.
    // Viktor: If attacker compromises a trusted account to send Spotify phishing, EFA can't
    // distinguish that from legitimate use anyway. Other layers (SPF/DKIM) handle account compromise.
    let brandImpersonation = null;
    if (!isTrustedDomain(senderDomain)) {
        brandImpersonation = detectBrandImpersonation(emailData.subject, cleanText, senderDomain, displayName);
        if (brandImpersonation) {
            // GovDelivery (Granicus) exception: This is the official government email platform.
            // Only verified government agencies can send through it (not self-service).
            // Brand references from govdelivery.com are legitimate government communications.
            // Viktor test: Passed. Cannot sign up for govdelivery.com without government verification.
            // Do NOT extend this pattern to commercial ESPs (Mailchimp, SendGrid, etc.)
            const isGovDelivery = senderDomain === 'govdelivery.com' || senderDomain.endsWith('.govdelivery.com');
            if (!isGovDelivery) {
                warnings.push({
                    type: 'brand-impersonation',
                    severity: 'critical',
                    title: 'Brand Impersonation Suspected',
                    description: `This email references ${brandImpersonation.brandName} but was NOT sent from a verified ${brandImpersonation.brandName} domain.`,
                    senderEmail: senderEmail,
                    senderDomain: senderDomain,
                    brandClaimed: brandImpersonation.brandName,
                    legitimateDomains: brandImpersonation.legitimateDomains
                });
            }
        }
    }
    
    if (!isTrustedDomain(senderDomain)) {
        const orgImpersonation = detectOrganizationImpersonation(displayName, senderDomain);
        if (orgImpersonation) {
            const brandAlreadyCaught = brandImpersonation && 
                brandImpersonation.brandName.toLowerCase() === orgImpersonation.entityClaimed.toLowerCase();
            if (!brandAlreadyCaught) {
                warnings.push({
                    type: 'org-impersonation',
                    severity: 'critical',
                    title: 'Organization Impersonation',
                    description: orgImpersonation.message,
                    senderEmail: senderEmail,
                    entityClaimed: orgImpersonation.entityClaimed,
                    legitimateDomains: orgImpersonation.legitimateDomains
                });
            }
        }
    }
    
    const internationalSender = detectInternationalSender(senderDomain);
    if (internationalSender && !INTL_SAFE_DOMAINS.has(senderDomain) && !INTL_SAFE_DOMAINS.has(getRootDomain(senderDomain))) {
        warnings.push({
            type: 'international-sender',
            severity: 'medium',
            title: 'International Sender',
            description: '',
            senderEmail: senderEmail,
            senderDomain: senderDomain,
            country: internationalSender.country,
            tld: internationalSender.tld,
            genericUse: internationalSender.genericUse || false,
            genericMessage: internationalSender.genericMessage || null
        });
    }
    
    const suspiciousDomain = detectSuspiciousDomain(senderDomain);
    if (suspiciousDomain) {
        warnings.push({
            type: 'suspicious-domain',
            severity: 'medium',
            title: 'Suspicious Domain',
            description: suspiciousDomain.reason
        });
    }
    
    const hasStrongerIdentityWarning = warnings.some(w => 
        ['brand-impersonation', 'recipient-spoof', 'recipient-domain-impersonation', 'org-impersonation', 'impersonation'].includes(w.type)
    );
    
    // Path 2: Display-name-vs-domain mismatch (safety net for unlisted brands)
    const displayDomainMismatch = hasStrongerIdentityWarning ? null : detectDisplayNameDomainMismatch(displayName, senderDomain);
    if (displayDomainMismatch) {
        warnings.push({
            type: 'display-domain-mismatch',
            severity: 'medium',
            title: 'Sender Identity Mismatch',
            description: `The sender\'s display name "${displayDomainMismatch.displayName}" appears to represent an organization, but the sending domain ${displayDomainMismatch.senderDomain} has no connection to that name. Legitimate organizations send from domains that match their name.`,
            senderEmail: senderEmail,
            senderDomain: displayDomainMismatch.senderDomain,
            displayName: displayDomainMismatch.displayName,
            significantWords: displayDomainMismatch.significantWords
        });
    }
    
    const displaySuspicion = hasStrongerIdentityWarning ? null : detectSuspiciousDisplayName(displayName, senderDomain);
    if (displaySuspicion) {
        warnings.push({
            type: 'display-name-suspicion',
            severity: 'medium',
            title: 'Suspicious Display Name',
            description: displaySuspicion.reason,
            senderEmail: senderEmail,
            matchedEmail: displaySuspicion.pattern
        });
    }
    
    const impersonation = detectDisplayNameImpersonation(displayName, senderDomain);
    if (impersonation) {
        warnings.push({
            type: 'impersonation',
            severity: 'critical',
            title: 'Display Name Impersonation',
            description: impersonation.reason,
            senderEmail: senderEmail,
            matchedEmail: impersonation.impersonatedDomain
        });
    }
    
    const homoglyph = detectHomoglyphs(senderEmail);
    if (homoglyph) {
        warnings.push({
            type: 'homoglyph',
            severity: 'critical',
            title: 'Invisible Character Trick',
            description: 'This email contains deceptive characters that look identical to normal letters.',
            senderEmail: senderEmail,
            detail: homoglyph
        });
    }
    
    const lookalike = detectLookalikeDomain(senderDomain);
    if (lookalike) {
        warnings.push({
            type: 'lookalike-domain',
            severity: 'critical',
            title: 'Lookalike Domain',
            description: `This domain is similar to ${lookalike.trustedDomain}`,
            senderEmail: senderEmail,
            matchedEmail: lookalike.trustedDomain
        });
    }
    
    // v5.2.1: KW-02 — Strip disclaimer blocks before wire fraud keyword scanning
    // v5.2.1: SW-01 — Feature flag gate
    // v5.2.1: SEV-01 — Default severity 'medium' (was 'critical')
    // v5.2.1: KW-06 — Subject hits stand alone; body-only requires co-signal
    // v5.2.1: KW-09 — Body-only wire keywords require transactional context or external link
    if (ENABLE_DANGEROUS_KEYWORDS) {
        const strippedContent = stripDisclaimerBlocks(content);
        const wireKeywords = detectWireFraudKeywords(strippedContent);
        if (wireKeywords.length > 0) {
            // KW-06: Check if any matched keywords appear in the subject line
            const subjectLower = (emailData.subject || '').toLowerCase();
            const subjectCollapsed = collapseForMatch(subjectLower);
            const inSubject = wireKeywords.some(kw =>
                phraseMatchesContent(subjectLower, subjectCollapsed, kw.toLowerCase()));
            // KW-09: Body-only matches require transactional financial terms
            const hasCoTerms = hasTransactionalContext(strippedContent);
            // KW-03: Or external link to different domain
            const hasExtLink = hasExternalLinkMismatch(emailData.body || cleanText, senderDomain);
            
            if (inSubject || hasCoTerms || hasExtLink) {
                const keywordInfo = getKeywordExplanation(wireKeywords[0]);
                warnings.push({
                    type: 'wire-fraud',
                    severity: 'medium',
                    title: 'Dangerous Keywords Detected',
                    description: 'This email contains terms commonly used in wire fraud.',
                    keywords: wireKeywords,
                    keywordCategory: keywordInfo.category,
                    keywordExplanation: keywordInfo.explanation
                });
            }
            // else: body-only wire keywords without financial context or external links = suppress
        }
    }
    
    if (!isKnownContact && knownContacts.size > 0) {
        const contactLookalike = detectContactLookalike(senderEmail);
        if (contactLookalike) {
            warnings.push({
                type: 'contact-lookalike',
                severity: 'critical',
                title: 'Lookalike Email Address',
                description: 'This email is nearly identical to someone in your contacts, but slightly different.',
                senderEmail: contactLookalike.incomingEmail,
                matchedEmail: contactLookalike.matchedContact,
                reason: contactLookalike.reason
            });
        }
    }
    
    if (emailData.recipientCount >= 10) {
        warnings.push({
            type: 'mass-recipients',
            severity: 'medium',
            title: 'Mass-Distributed Email',
            description: `This email was sent to ${emailData.recipientCount}+ recipients. Legitimate invoices, payment confirmations, and account alerts are sent to individuals — not large groups.`
        });
    }
    
    // ============================================
    // v4.2.0: PHASE 2 PHISHING PATTERN ENGINE
    // ============================================
    const phase2EmailData = {
        body: emailData.body,
        senderDomain: senderDomain,
        attachments: emailData.attachments || [],
        isKnownContact: isKnownContact,
        platform: 'outlook'
    };
    
    const phase2Result = runPhase2Engine(phase2EmailData, warnings);
    const finalWarnings = phase2Result.finalWarnings;
    
    // ============================================
    // v4.3.0: KEYWORD-ONLY SUPPRESSION ON LEGITIMATE DOMAINS
    // If the sender domain is a verified legitimate domain (from BRAND_CONTENT_DETECTION
    // or KNOWN_PLATFORM_DOMAINS) AND keyword warnings are the ONLY warnings present,
    // suppress them. Banks say "account number." That's what banks do.
    // Viktor: "If I'm impersonating Wells Fargo, I'm sending from a domain I registered.
    // EFA catches me on brand impersonation, lookalike, or auth failure. The keywords
    // pile on top. But if the email is FROM wellsfargo.com, Wells Fargo sent it."
    // v5.2.1: KW-04 — Extended to trusted domains (user's own org, frequent senders).
    // Same Viktor logic: if the email is FROM purelogicescrow.com, PLE sent it.
    // Safety: Only suppresses when keywords are the sole warning. If ANY other detection
    // fires alongside keywords, they stay. Viktor can't send from domains he doesn't own.
    // ============================================
    const keywordTypes = ['wire-fraud', 'phishing-urgency'];
    const nonKeywordWarnings = finalWarnings.filter(w => !keywordTypes.includes(w.type));
    if (nonKeywordWarnings.length === 0 && finalWarnings.length > 0) {
        // All warnings are keyword-only. Check if sender is a legitimate domain.
        const isLegitBrandDomain = Object.values(BRAND_CONTENT_DETECTION).some(config =>
            config.legitimateDomains.some(ld => senderDomain === ld || senderDomain.endsWith('.' + ld))
        );
        if (isLegitBrandDomain || isKnownPlatform(senderDomain) || isTrustedDomain(senderDomain)) {
            finalWarnings.length = 0; // Clear all keyword warnings
        }
    }
    
    // v5.2.1: Filter ESP-suppressed reply-to warnings from display.
    // These were kept in coreWarnings so Pattern E (BEC) can still use them as signals,
    // but they shouldn't show as standalone warnings to the user.
    const displayWarnings = finalWarnings.filter(w => !w._espSuppressed);
    
    displayResults(displayWarnings);
}

// ============================================
// UI FUNCTIONS
// ============================================
function showLoading() {
    document.getElementById('loading').classList.remove('hidden');
    document.getElementById('results').classList.add('hidden');
    document.getElementById('error').classList.add('hidden');
    document.body.className = '';
}

function showError(message) {
    document.getElementById('loading').classList.add('hidden');
    document.getElementById('results').classList.add('hidden');
    document.getElementById('error').classList.remove('hidden');
    document.getElementById('error-message').textContent = message;
    document.body.className = '';
}

function escapeHtml(s) {
    if (!s) return s;
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function wrapDomain(domain) {
    return `<span style="white-space: nowrap;">${escapeHtml(domain)}</span>`;
}

function truncateText(text, maxLen = 38) {
    if (!text || text.length <= maxLen) return text;
    return text.substring(0, maxLen) + '\u2026';
}

function formatDomainsList(domains) {
    return domains.map(d => wrapDomain(d)).join(', ');
}

function displayResults(warnings) {
    document.getElementById('loading').classList.add('hidden');
    document.getElementById('error').classList.add('hidden');
    document.getElementById('results').classList.remove('hidden');
    
    const criticalCount = warnings.filter(w => w.severity === 'critical').length;
    const mediumCount = warnings.filter(w => w.severity === 'medium').length;
    
    document.body.classList.remove('status-critical', 'status-medium', 'status-info', 'status-safe');
    
    const statusBadge = document.getElementById('status-badge');
    const statusIcon = statusBadge.querySelector('.status-icon');
    const statusText = statusBadge.querySelector('.status-text');
    
    if (criticalCount > 0 || mediumCount > 0) {
        const totalWarnings = criticalCount + mediumCount;
        document.body.classList.add('status-critical');
        statusBadge.className = 'status-badge danger';
        statusIcon.textContent = '\uD83D\uDEA8';
        statusText.textContent = totalWarnings > 4 ? `Showing 4 of ${totalWarnings} Issues` : `${totalWarnings} Issue${totalWarnings > 1 ? 's' : ''} Found`;
    } else {
        document.body.classList.add('status-safe');
        statusBadge.className = 'status-badge safe';
        statusIcon.textContent = '\u2705';
        statusText.textContent = 'No Issues Detected';
    }
    
    const warningsSection = document.getElementById('warnings-section');
    const warningsList = document.getElementById('warnings-list');
    const warningsFooter = document.getElementById('warnings-footer');
    const safeMessage = document.getElementById('safe-message');
    
    if (warnings.length > 0) {
        // v5.2.1: Display priority ranking (locked). Tier 1 = always show; Tier 4 = context only.
        // Only 4 warnings display. This ranking determines which 4 the user sees.
        // Reviewed by Viktor. Do not reorder without adversarial review.
        const WARNING_PRIORITY = {
            // Tier 1 — Always show (confirmed/near-certain/human-invisible attacks)
            'known-threat': 1,
            'phase2-phishing-pattern': 2,
            'provider-flagged': 3,
            'recipient-spoof': 4,
            'homoglyph': 5,
            // Tier 2 — Very likely attack (strong individual signals)
            'replyto-mismatch': 6,
            'contact-lookalike': 7,
            'impersonation': 8,
            'recipient-domain-impersonation': 9,
            'lookalike-domain': 10,
            // Tier 3 — Strong but context-dependent (boosters, not solo headliners)
            'wire-fraud': 11,
            'brand-impersonation': 12,
            'on-behalf-of': 13,
            'org-impersonation': 14,
            'auth-failure': 15,
            'fake-tld': 16,
            'display-domain-mismatch': 17,
            'suspicious-domain': 18,
            // Tier 4 — Informational/context (show only when few signals fire)
            'new-domain': 19,
            'gibberish-domain': 20,
            'gibberish-username': 21,
            'free-hosting-sender': 22,
            'via-routing': 23,
            'display-name-suspicion': 24,
            'international-sender': 25,
            'mass-recipients': 26,
            'phishing-urgency': 27
        };
        warnings.sort((a, b) => (WARNING_PRIORITY[a.type] || 99) - (WARNING_PRIORITY[b.type] || 99));
        
        // v5.2.1: Wire-fraud force-include. If wire-fraud fires alongside any Tier 1/2
        // signal, force it into the top 4. This ensures "this email contains wire transfer
        // instructions" is visible during compound BEC attacks. Never demotes Tier 1/2.
        // Viktor: "If you detect my wire instructions and don't show the user, I win."
        const TIER_1_2_TYPES = new Set(['known-threat', 'phase2-phishing-pattern', 'provider-flagged',
            'recipient-spoof', 'homoglyph', 'replyto-mismatch', 'contact-lookalike',
            'impersonation', 'recipient-domain-impersonation', 'lookalike-domain']);
        const wireFraudIdx = warnings.findIndex(w => w.type === 'wire-fraud');
        if (wireFraudIdx >= 4 && warnings.some(w => TIER_1_2_TYPES.has(w.type))) {
            if (warnings.length > 3 && !TIER_1_2_TYPES.has(warnings[3].type)) {
                const [wf] = warnings.splice(wireFraudIdx, 1);
                warnings.splice(3, 0, wf);
            }
        }
        
        warningsSection.classList.remove('hidden');
        warningsFooter.classList.remove('hidden');
        safeMessage.classList.add('hidden');
        
        warningsList.innerHTML = warnings.slice(0, 4).map(w => {
            let emailHtml = '';
            
            // v4.2.0: Phase 2 merged warning rendering
            if (w.type === 'phase2-phishing-pattern' && w.details) {
                const patternHtml = w.details.patterns.map(p => 
                    `<div class="warning-email-row">
                        <span class="warning-email-label">${escapeHtml(p.patternName)}:</span>
                        <span class="warning-email-value suspicious">${escapeHtml(p.confidence)} confidence</span>
                    </div>`
                ).join('');
                emailHtml = `
                    <div class="warning-emails">
                        ${patternHtml}
                    </div>
                    <div class="warning-advice">
                        <strong>What to do:</strong> ${escapeHtml(w.recommendation)}
                    </div>
                `;
            } else if (w.type === 'known-threat') {
                emailHtml = `
                    <div class="warning-emails">
                        <div class="warning-email-row">
                            <span class="warning-email-label">Sender:</span>
                            <span class="warning-email-value suspicious">${formatEmailForDisplay(w.senderEmail)}</span>
                        </div>
                        <div class="warning-email-row">
                            <span class="warning-email-label">Threat sources:</span>
                            <span class="warning-email-value suspicious">${escapeHtml(w.matchedEmail)}</span>
                        </div>
                    </div>
                    <div class="warning-advice">
                        <strong>Do not interact with this email.</strong> This domain is actively flagged for distributing malware or phishing content.
                    </div>
                `;
            } else if (w.type === 'new-domain') {
                emailHtml = `
                    <div class="warning-emails">
                        <div class="warning-email-row">
                            <span class="warning-email-label">Sender:</span>
                            <span class="warning-email-value suspicious">${formatEmailForDisplay(w.senderEmail)}</span>
                        </div>
                        <div class="warning-email-row">
                            <span class="warning-email-label">Domain:</span>
                            <span class="warning-email-value suspicious">${wrapDomain(w.matchedEmail)}</span>
                        </div>
                    </div>
                    <div class="warning-advice">
                        <strong>Verify independently.</strong> Call the sender at a known phone number before taking any action on this email.
                    </div>
                `;
            } else if ((w.type === 'wire-fraud' || w.type === 'phishing-urgency') && w.keywords) {
                const keywordTags = w.keywords.slice(0, 5).map(k => 
                    `<span class="keyword-tag">${escapeHtml(k)}</span>`
                ).join('');
                emailHtml = `
                    <div class="warning-keywords-section">
                        <div class="warning-keywords-label">Triggered by:</div>
                        <div class="warning-keywords">${keywordTags}</div>
                    </div>
                    <div class="warning-advice">
                        <strong>Why this matters:</strong> ${escapeHtml(w.keywordExplanation)}
                    </div>
                `;
            } else if (w.type === 'org-impersonation') {
                emailHtml = `
                    <div class="warning-emails">
                        <div class="warning-email-row">
                            <span class="warning-email-label">Claims to be:</span>
                            <span class="warning-email-value known">${escapeHtml(w.entityClaimed)}</span>
                        </div>
                        <div class="warning-email-row">
                            <span class="warning-email-label">Actually from:</span>
                            <span class="warning-email-value suspicious">${formatEmailForDisplay(w.senderEmail)}</span>
                        </div>
                        <div class="warning-email-row">
                            <span class="warning-email-label">Legitimate domains:</span>
                            <span class="warning-email-value known">${formatDomainsList(w.legitimateDomains)}</span>
                        </div>
                    </div>
                `;
            } else if (w.type === 'brand-impersonation') {
                emailHtml = `
                    <div class="warning-emails">
                        <div class="warning-email-row">
                            <span class="warning-email-label">This email claims to be from:</span>
                            <span class="warning-email-value known">${escapeHtml(w.brandClaimed)}</span>
                        </div>
                        <div class="warning-email-row">
                            <span class="warning-email-label">But is actually from:</span>
                            <span class="warning-email-value suspicious">${wrapDomain(w.senderDomain)}</span>
                        </div>
                        <div class="warning-email-row">
                            <span class="warning-email-label">Legitimate domains:</span>
                            <span class="warning-email-value known">${formatDomainsList(w.legitimateDomains)}</span>
                        </div>
                    </div>
                `;
            } else if (w.type === 'display-domain-mismatch') {
                emailHtml = `
                    <div class="warning-emails">
                        <div class="warning-email-row">
                            <span class="warning-email-label">Display name:</span>
                            <span class="warning-email-value known">${escapeHtml(w.displayName)}</span>
                        </div>
                        <div class="warning-email-row">
                            <span class="warning-email-label">Sender domain:</span>
                            <span class="warning-email-value suspicious">${wrapDomain(w.senderDomain)}</span>
                        </div>
                        <div class="warning-email-row">
                            <span class="warning-email-label" style="font-size: 11px; margin-top: 4px;">Legitimate organizations send from domains that match their name. This domain has no connection to the sender's claimed identity.</span>
                        </div>
                    </div>
                `;
            } else if (w.type === 'international-sender') {
                if (w.genericUse && w.genericMessage) {
                    emailHtml = `
                        <div class="warning-international-info">
                            <p>${escapeHtml(w.genericMessage)}</p>
                        </div>
                    `;
                } else {
                    emailHtml = `
                        <div class="warning-international-info">
                            <p>This sender's email address includes a country code: ${escapeHtml(w.tld)}<br>(${escapeHtml(w.country)})</p>
                            <p style="margin-top: 8px;">Be careful, this could be a phishing attempt.</p>
                            <p style="margin-top: 8px;">Most legitimate business emails use .com domains.</p>
                        </div>
                    `;
                }
            } else if (w.type === 'mass-recipients') {
                emailHtml = `
                    <div class="warning-international-info">
                        <p style="margin-top: 8px;">Be suspicious of any email requesting action or payment that was sent to a large group.</p>
                    </div>
                `;
            } else if (w.type === 'impersonation') {
                emailHtml = `
                    <div class="warning-emails">
                        <div class="warning-email-row">
                            <span class="warning-email-label">This email claims to be from:</span>
                            <span class="warning-email-value known">${formatEmailForDisplay(w.matchedEmail)}</span>
                        </div>
                        <div class="warning-email-row">
                            <span class="warning-email-label">But is actually from:</span>
                            <span class="warning-email-value suspicious">${formatEmailForDisplay(w.senderEmail)}</span>
                        </div>
                    </div>
                `;
            } else if (w.type === 'recipient-spoof') {
                emailHtml = `
                    <div class="warning-emails">
                        <div class="warning-email-row">
                            <span class="warning-email-label">Display name shows:</span>
                            <span class="warning-email-value suspicious">${formatEmailForDisplay(w.matchedEmail)}</span>
                        </div>
                        <div class="warning-email-row">
                            <span class="warning-email-label">But actually from:</span>
                            <span class="warning-email-value suspicious">${formatEmailForDisplay(w.senderEmail)}</span>
                        </div>
                    </div>
                `;
            } else if (w.type === 'recipient-domain-impersonation') {
                emailHtml = `
                    <div class="warning-emails">
                        <div class="warning-email-row">
                            <span class="warning-email-label">Claims to be:</span>
                            <span class="warning-email-value known">${escapeHtml(w.displayName)}</span>
                        </div>
                        <div class="warning-email-row">
                            <span class="warning-email-label">Your organization:</span>
                            <span class="warning-email-value known">${escapeHtml(w.recipientDomain)}</span>
                        </div>
                        <div class="warning-email-row">
                            <span class="warning-email-label">Actually from:</span>
                            <span class="warning-email-value suspicious">${wrapDomain(w.senderDomain)}</span>
                        </div>
                        <div class="warning-email-row">
                            <span class="warning-email-label" style="font-size: 11px; margin-top: 4px;">Do NOT click any links. This email is impersonating your organization to steal your login credentials.</span>
                        </div>
                    </div>
                `;
            } else if (w.type === 'fake-tld') {
                emailHtml = `
                    <div class="warning-international-info">
                        <p>The domain extension <strong>${escapeHtml(w.tld)}</strong> is not a real top-level domain. No legitimate email can come from this address. This email is fraudulent. Do not interact with it.</p>
                    </div>
                `;
            } else if (w.type === 'via-routing') {
                emailHtml = `
                    <div class="warning-emails">
                        <div class="warning-email-row">
                            <span class="warning-email-label">Sender:</span>
                            <span class="warning-email-value">${formatEmailForDisplay(w.senderEmail)}</span>
                        </div>
                        <div class="warning-email-row">
                            <span class="warning-email-label">Routed via:</span>
                            <span class="warning-email-value suspicious">${escapeHtml(w.viaDomain)}</span>
                        </div>
                    </div>
                `;
            } else if (w.type === 'free-hosting-sender') {
                emailHtml = `
                    <div class="warning-emails">
                        <div class="warning-email-row">
                            <span class="warning-email-label">Sender:</span>
                            <span class="warning-email-value suspicious">${formatEmailForDisplay(w.senderEmail)}</span>
                        </div>
                        <div class="warning-email-row">
                            <span class="warning-email-label">Platform:</span>
                            <span class="warning-email-value suspicious">${escapeHtml(w.hostingPlatform)}</span>
                        </div>
                    </div>
                `;
            } else if (w.type === 'auth-failure') {
                emailHtml = `
                    <div class="warning-emails">
                        <div class="warning-email-row">
                            <span class="warning-email-label">Sender:</span>
                            <span class="warning-email-value suspicious">${formatEmailForDisplay(w.senderEmail)}</span>
                        </div>
                    </div>
                    <div class="warning-advice">
                        <strong>Why this matters:</strong> Every email goes through security checks to prove the sender is real. This email failed multiple checks. Legitimate senders almost always pass. Be cautious with any links, attachments, or requests in this email.
                    </div>
                `;
            } else if (w.type === 'provider-flagged' || w.type === 'gibberish-username') {
                emailHtml = `
                    <div class="warning-emails">
                        <div class="warning-email-row">
                            <span class="warning-email-label">Sender:</span>
                            <span class="warning-email-value suspicious">${formatEmailForDisplay(w.senderEmail)}</span>
                        </div>
                    </div>
                `;
            } else if (w.senderEmail && w.matchedEmail) {
                const matchLabel = w.type === 'replyto-mismatch' ? 'Replies go to' : w.type === 'on-behalf-of' ? 'On behalf of' : w.type === 'gibberish-domain' ? 'Domain' : 'Similar to';
                emailHtml = `
                    <div class="warning-emails">
                        <div class="warning-email-row">
                            <span class="warning-email-label">Sender:</span>
                            <span class="warning-email-value suspicious">${formatEmailForDisplay(w.senderEmail)}</span>
                        </div>
                        <div class="warning-email-row">
                            <span class="warning-email-label">${matchLabel}:</span>
                            <span class="warning-email-value ${w.type === 'gibberish-domain' ? 'suspicious' : 'known'}">${formatEmailForDisplay(w.matchedEmail)}</span>
                        </div>
                        ${w.reason ? `<div class="warning-reason">${escapeHtml(w.reason)}</div>` : ''}
                    </div>
                `;
            } else if (w.detail) {
                emailHtml = `<div class="warning-reason">${escapeHtml(w.detail)}</div>`;
            }
            
            return `
                <div class="warning-item ${w.severity}">
                    <div class="warning-title">${escapeHtml(w.title)}</div>
                    <div class="warning-description">${escapeHtml(w.description)}</div>
                    ${emailHtml}
                </div>
            `;
        }).join('');
    } else {
        warningsList.innerHTML = '';
        warningsSection.classList.add('hidden');
        warningsFooter.classList.add('hidden');
        safeMessage.classList.remove('hidden');
    }
}
