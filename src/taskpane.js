// Email Fraud Detector - Outlook Web Add-in
// Version 4.2.4 - Added brand sending domain whitelist (secondary/transactional email domains)
// Version 4.2.3 - Added ESP whitelist to reduce reply-to mismatch false positives
// Version 4.2.2 - Fixed brand impersonation false positives (tiered body-only detection)
// Version 4.2.1 - Added fake TLD detection (IANA validated)
// Version 4.2.0 - Phase 2 Phishing Pattern Detection Engine (Silent Mode)
// Version 4.1.5 - Added crypto wallet scam keyword detection
// Version 4.1.4 - Added email authentication failure detection (DMARC/DKIM/compauth)
// Version 4.1.3 - Added via routing detection for gibberish relay domains
// Version 4.1.2 - Fixed SCE false positive (requires context words)

// ============================================
// CONFIGURATION
// ============================================
const CONFIG = {
    clientId: '622f0452-d622-45d1-aab3-3a2026389dd3',
    redirectUri: 'https://journeybrennan22-bot.github.io/outlook-fraud-detector/src/taskpane.html',
    scopes: ['User.Read', 'Contacts.Read'],
    trustedDomains: []
};

// ============================================
// KNOWN EMAIL SERVICE PROVIDER (ESP) DOMAINS
// These platforms send on behalf of businesses,
// so reply-to mismatches are expected/legitimate.
// ============================================
const KNOWN_ESP_DOMAINS = [
    // Constant Contact
    'ccsend.com',
    // Mailchimp / Intuit
    'mailchimp.com', 'mandrillapp.com', 'mail.mailchimp.com', 'rsgsv.net', 'list-manage.com',
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
    'acsend.com', 'activehosted.com',
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
    'infusionmail.com', 'keap-link.com'
];

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
        legitimateDomains: ['microsoft.com', 'office.com', 'sharepoint.com', 'onedrive.com', 'live.com', 'outlook.com', 'office365.com', 'microsoftonline.com', 'microsoft365.com']
    },
    'google': {
        keywords: ['google drive', 'google docs', 'google account', 'google workspace'],
        legitimateDomains: ['google.com', 'gmail.com', 'googlemail.com']
    },
    'amazon': {
        keywords: ['amazon prime', 'amazon account', 'amazon order', 'amazon.com order'],
        legitimateDomains: ['amazon.com', 'amazon.co.uk', 'amazon.ca', 'amazonses.com', 'amazon.de', 'amazon.fr', 'amazon.es', 'amazon.it', 'amazon.co.jp', 'amazon.in', 'amazon.com.au', 'amazon.com.br', 'amazon.com.mx', 'amazon.sg', 'amazon.nl', 'amazon.pl', 'amazon.se', 'amazon.com.be', 'amazon.ae']
    },
    'paypal': {
        keywords: ['paypal'],
        legitimateDomains: ['paypal.com', 'paypal.co.uk', 'paypal.de', 'paypal.fr', 'paypal.it', 'paypal.es', 'paypal.com.au', 'paypal.ca']
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
        legitimateDomains: ['facebook.com', 'meta.com', 'facebookmail.com']
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
        legitimateDomains: ['dhl.com', 'dhl.de', 'dhl.co.uk', 'dhl.fr', 'dhl.nl', 'dpdhl.com']
    },
    'fedex': {
        keywords: ['fedex', 'federal express'],
        legitimateDomains: ['fedex.com']
    },
    'ups': {
        keywords: ['ups package', 'ups delivery', 'ups shipment', 'united parcel'],
        legitimateDomains: ['ups.com', 'upsemail.com']
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
        legitimateDomains: ['intuit.com', 'quickbooks.com', 'intuitmail.com']
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
        legitimateDomains: ['ebay.com', 'ebay.co.uk', 'ebay.de', 'ebay.fr', 'ebay.it', 'ebay.es', 'ebay.ca', 'ebay.com.au']
    },
    'dmv': {
        keywords: ['department of motor vehicles', 'dmv service desk', 'dmv appointment', 'dmv registration'],
        legitimateDomains: ['.gov']
    },
    'irs': {
        keywords: ['internal revenue service', 'irs refund', 'irs audit', 'tax return', 'irs notice'],
        legitimateDomains: ['irs.gov']
    },
    'social security': {
        keywords: ['social security administration', 'social security number', 'ssa benefit', 'social security statement'],
        legitimateDomains: ['ssa.gov']
    },
    'att': {
        keywords: ['at&t', 'att account', 'att wireless'],
        legitimateDomains: ['att.com', 'att.net']
    },
    'verizon': {
        keywords: ['verizon', 'verizon wireless', 'verizon fios'],
        legitimateDomains: ['verizon.com', 'verizonwireless.com', 'vzw.com', 'verizon.net']
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
    'whatsapp': {
        keywords: ['whatsapp'],
        legitimateDomains: ['whatsapp.com']
    },
    'instagram': {
        keywords: ['instagram account', 'instagram security'],
        legitimateDomains: ['instagram.com', 'mail.instagram.com']
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
        keywords: ['spotify', 'spotify premium', 'spotify account'],
        legitimateDomains: ['spotify.com']
    },
    'disney plus': {
        keywords: ['disney+', 'disney plus', 'disneyplus'],
        legitimateDomains: ['disneyplus.com', 'disney.com', 'go.com']
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
        legitimateDomains: ['airbnb.com']
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
        keywords: ['adobe account', 'adobe subscription', 'adobe creative cloud', 'adobe pdf'],
        legitimateDomains: ['adobe.com', 'adobeid.services.adobe.com']
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
        legitimateDomains: ['lyft.com', 'lyftmail.com', 'lyft.zendesk.com', 'lyft-new.zendesk.com']
    },
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
    "target": ["target.com"],
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
    "at&t": ["att.com", "att.net"],
    "att": ["att.com", "att.net"],
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
    "instagram": ["instagram.com", "mail.instagram.com"],
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
    "steam": ["steampowered.com", "store.steampowered.com", "steamcommunity.com"],
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
    "spotify": ["spotify.com"],
    "spotify support": ["spotify.com"],
    "disney+": ["disneyplus.com", "disney.com"],
    "disney plus": ["disneyplus.com", "disney.com"],
    "hulu": ["hulu.com"],
    "hulu support": ["hulu.com"],
    "hbo max": ["max.com", "hbomax.com"],
    "max": ["max.com"],
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
    "wise": ["wise.com"],
    "transferwise": ["wise.com"],
    "affirm": ["affirm.com"],
    "klarna": ["klarna.com"],
    "state farm": ["statefarm.com"],
    "state farm insurance": ["statefarm.com"],
    "geico": ["geico.com"],
    "progressive": ["progressive.com"],
    "progressive insurance": ["progressive.com"],
    "allstate": ["allstate.com"],
    "allstate insurance": ["allstate.com"],
    "liberty mutual": ["libertymutual.com"],
    "farmers insurance": ["farmers.com"],
    "farmers": ["farmers.com"],
    "nationwide": ["nationwide.com"],
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
    "prudential": ["prudential.com"],
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
    "airbnb": ["airbnb.com"],
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
    "lyft": ["lyft.com"],
    "lyft support": ["lyft.com"],
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
    "jc penney": ["jcpenney.com"]
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
            'wire to', 'remittance', 'wire payment'
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
            'dont mention this', 'between us',
            'dont tell anyone', 'private matter',
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
            'action required within', 'expires today', 'last chance'
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
    }
};

// Build flat keyword list for detection
const WIRE_FRAUD_KEYWORDS = Object.values(KEYWORD_CATEGORIES).flatMap(cat => cat.keywords);

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
    'keep this confidential', 'between us', 'do not tell',
    'dont tell', "don't tell", 'handle personally',
    'urgent and confidential', 'keep this quiet',
    'off the record', 'private matter',
    'do not share', 'do not discuss'
];

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
// INITIALIZATION
// ============================================
Office.onReady(async (info) => {
    console.log('Email Fraud Detector v4.2.1 (Phase 2 Silent) script loaded, host:', info.host);
    if (info.host === Office.HostType.Outlook) {
        console.log('Email Fraud Detector v4.2.1 initializing for Outlook...');
        await initializeMsal();
        setupEventHandlers();
        analyzeCurrentEmail();
        setupAutoScan();
        console.log('Email Fraud Detector v4.2.1 ready');
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
    if (isAutoScanEnabled) {
        analyzeCurrentEmail();
    }
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
function isTrustedDomain(domain) {
    return CONFIG.trustedDomains.includes(domain.toLowerCase());
}

function escapeRegex(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function formatEntityName(name) {
    return name.split(' ').map(word => 
        word.charAt(0).toUpperCase() + word.slice(1)
    ).join(' ');
}

function formatEmailForDisplay(email) {
    if (!email || !email.includes('@')) return email;
    return email.replace('@', '@<br>');
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

function detectPhishingUrgency(bodyText, subject) {
    if (!bodyText && !subject) return null;
    
    const textToCheck = ((subject || '') + ' ' + (bodyText || '')).toLowerCase();
    const foundKeywords = [];
    
    for (const keyword of PHISHING_URGENCY_KEYWORDS) {
        if (textToCheck.includes(keyword.toLowerCase())) {
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

function detectViaRouting(headers, senderDomain) {
    if (!headers) return null;
    
    const receivedLines = headers.match(/Received:\s*from\s+[^\r\n]+/gi) || [];
    
    for (const line of receivedLines) {
        const domainMatch = line.match(/from\s+([a-zA-Z0-9][a-zA-Z0-9\.\-]*\.[a-zA-Z]{2,})/i);
        if (!domainMatch) continue;
        
        const relayDomain = domainMatch[1].toLowerCase();
        
        if (senderDomain && relayDomain.includes(senderDomain.split('.')[0])) continue;
        
        const legitServices = ['google', 'gmail', 'googlemail', 'microsoft', 'outlook', 'office365', 
                              'sendgrid', 'mailchimp', 'amazonses', 'mailgun', 'postmark', 'sparkpost',
                              'mailjet', 'sendinblue', 'constantcontact', 'hubspot', 'salesforce',
                              'zoho', 'yahoo', 'aol', 'icloud', 'apple', 'protonmail'];
        if (legitServices.some(s => relayDomain.includes(s))) continue;
        
        const domainParts = relayDomain.split('.');
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
    
    const authMatch = headers.match(/Authentication-Results:[\s\S]*?(?=\nReceived:|\nReturn-Path:|\nFrom:|\nDate:|\nSubject:|\nMIME-Version:|\nContent-Type:|\nX-Priority:|\nX-SFDC|\nX-MS-Exchange)/i);
    const authText = authMatch ? authMatch[0].toLowerCase() : '';
    
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
    
    const subjectLower = (subject || '').toLowerCase();
    const bodyLower = (body || '').toLowerCase();
    const displayNameLower = (displayName || '').toLowerCase();
    
    for (const [brandName, config] of Object.entries(BRAND_CONTENT_DETECTION)) {
        // Check each location separately: subject, display name, body
        const inSubject = config.keywords.some(keyword => 
            subjectLower.includes(keyword.toLowerCase())
        );
        const inDisplayName = config.keywords.some(keyword => 
            displayNameLower.includes(keyword.toLowerCase())
        );
        const inBody = config.keywords.some(keyword => 
            bodyLower.includes(keyword.toLowerCase())
        );
        
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
                const hasSupport = _brandBodyHasSupportingSignals(config, bodyLower, subjectLower, domainLower);
                if (hasSupport) {
                    return {
                        brandName: formatEntityName(brandName),
                        senderDomain: senderDomain,
                        legitimateDomains: config.legitimateDomains
                    };
                }
                
                console.log('BRAND CHECK SKIPPED (body-only, no supporting signals) -', brandName, 'from', senderDomain);
            }
        }
    }
    
    return null;
}

// Helper: checks if a body-only brand mention has enough supporting context
// to indicate actual impersonation rather than a casual reference
function _brandBodyHasSupportingSignals(config, bodyLower, subjectLower, senderDomainLower) {
    // Signal 1: Brand keyword appears 3+ times in body (email is themed around the brand)
    let totalMentions = 0;
    for (const keyword of config.keywords) {
        const kw = keyword.toLowerCase();
        let pos = 0;
        while ((pos = bodyLower.indexOf(kw, pos)) !== -1) {
            totalMentions++;
            pos += kw.length;
        }
        if (totalMentions >= 3) return true;
    }
    
    // Signal 2: Subject or body contains phishing urgency language
    const combinedText = subjectLower + ' ' + bodyLower;
    const hasUrgency = PHISHING_URGENCY_KEYWORDS.some(phrase => 
        combinedText.includes(phrase.toLowerCase())
    );
    if (hasUrgency) return true;
    
    // Signal 3: Sender domain contains suspicious words (e.g. "secure-paypal-login.com")
    const hasSuspiciousDomain = SUSPICIOUS_DOMAIN_WORDS.some(word => 
        senderDomainLower.includes(word)
    );
    if (hasSuspiciousDomain) return true;
    
    return false;
}

function detectOrganizationImpersonation(displayName, senderDomain) {
    if (!displayName || !senderDomain) return null;
    if (isTrustedDomain(senderDomain)) return null;
    
    const searchText = displayName.toLowerCase();
    
    for (const [entityName, legitimateDomains] of Object.entries(IMPERSONATION_TARGETS)) {
        const entityPattern = new RegExp(`\\b${escapeRegex(entityName)}\\b`, 'i');
        
        if (entityPattern.test(searchText)) {
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
            reason: `This email was sent from a domain ending in <strong>${tld}</strong>. Domains ending in <strong>${tld}</strong> have been identified by Spamhaus and Symantec as frequently used in spam and phishing campaigns. Proceed with caution.`
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

function detectHomoglyphs(email) {
    let found = [];
    for (const [homoglyph, latin] of Object.entries(HOMOGLYPHS)) {
        if (email.includes(homoglyph)) {
            found.push(`"${homoglyph}" looks like "${latin}"`);
        }
    }
    return found.length > 0 ? found.join(', ') : null;
}

function detectLookalikeDomain(domain) {
    for (const trusted of CONFIG.trustedDomains) {
        const distance = levenshteinDistance(domain, trusted);
        if (distance > 0 && distance <= 2) {
            return { trustedDomain: trusted, distance: distance };
        }
    }
    return null;
}

function detectWireFraudKeywords(content) {
    const found = [];
    for (const keyword of WIRE_FRAUD_KEYWORDS) {
        if (content.toLowerCase().includes(keyword.toLowerCase())) {
            found.push(keyword);
        }
    }
    return found;
}

function detectContactLookalike(senderEmail) {
    const parts = senderEmail.toLowerCase().split('@');
    if (parts.length !== 2) return null;
    
    const senderLocal = parts[0];
    const senderDomain = parts[1];
    
    if (isTrustedDomain(senderDomain)) return null;
    
    const publicDomains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 
                           'icloud.com', 'mail.com', 'protonmail.com', 'zoho.com', 'yandex.com'];
    
    for (const contact of knownContacts) {
        if (contact === senderEmail) continue;
        
        const contactParts = contact.toLowerCase().split('@');
        if (contactParts.length !== 2) continue;
        
        const contactLocal = contactParts[0];
        const contactDomain = contactParts[1];
        
        const usernameDiff = levenshteinDistance(senderLocal, contactLocal);
        
        if (senderDomain === contactDomain) {
            if (usernameDiff > 0 && usernameDiff <= 4) {
                return {
                    incomingEmail: senderEmail,
                    matchedContact: contact,
                    reason: `Username is ${usernameDiff} character${usernameDiff > 1 ? 's' : ''} different`
                };
            }
        }
        
        const bothPublicSameDomain = publicDomains.includes(senderDomain) && 
                                      senderDomain === contactDomain;
        
        if (!bothPublicSameDomain || usernameDiff <= 4) {
            const domainDistance = levenshteinDistance(senderDomain, contactDomain);
            if (domainDistance > 0 && domainDistance <= 2) {
                return {
                    incomingEmail: senderEmail,
                    matchedContact: contact,
                    reason: `Domain is ${domainDistance} character${domainDistance > 1 ? 's' : ''} different`
                };
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
    if (hasExclusion && matched.length < 2) return null;

    return { signal: 'credential_language', matched: matched, count: matched.length };
}

function detectPhase2UnlockLanguage(content) {
    if (!content) return null;
    const lowerContent = content.toLowerCase();
    const matched = [];
    for (const phrase of UNLOCK_LANGUAGE_PHRASES) {
        if (lowerContent.includes(phrase)) matched.push(phrase);
    }
    if (matched.length === 0) return null;
    return { signal: 'unlock_language', matched: matched, count: matched.length };
}

function detectPhase2PaymentChangeLanguage(content) {
    if (!content) return null;
    const lowerContent = content.toLowerCase();
    const matchedPhrases = [];
    for (const phrase of PAYMENT_CHANGE_PHRASES) {
        if (lowerContent.includes(phrase)) matchedPhrases.push(phrase);
    }
    if (matchedPhrases.length === 0) return null;
    const matchedTokens = [];
    for (const token of BANKING_TOKENS) {
        if (lowerContent.includes(token)) matchedTokens.push(token);
    }
    if (matchedTokens.length === 0) return null;
    return { signal: 'payment_change_language', matchedPhrases: matchedPhrases, matchedTokens: matchedTokens };
}

function detectPhase2SecrecyLanguage(content) {
    if (!content) return null;
    const lowerContent = content.toLowerCase();
    const matched = [];
    for (const phrase of SECRECY_PHRASES) {
        if (lowerContent.includes(phrase)) matched.push(phrase);
    }
    if (matched.length === 0) return null;
    return { signal: 'secrecy_language', matched: matched };
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
            const url = matches[i].replace(/[.,;:!?)>\]]+$/, '');
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
    for (const urlInfo of urls) {
        const linkDomain = urlInfo.domain;
        if (!linkDomain) continue;
        if (linkDomain === senderDomainLower) continue;
        if (linkDomain.endsWith('.' + senderDomainLower)) continue;
        if (senderDomainLower.endsWith('.' + linkDomain)) continue;
        let isInfra = false;
        for (const infra of infraDomains) {
            if (linkDomain === infra || linkDomain.endsWith('.' + infra)) { isInfra = true; break; }
        }
        if (isInfra) continue;
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
        const name = (attachment.name || attachment.fileName || '').toLowerCase();
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
    const { paymentChangeLanguage, secrecyLanguage } = signals;
    if (!paymentChangeLanguage) return null;
    const hasReplyToMismatch = coreWarnings.some(w => w.type === 'replyto-mismatch');
    const hasOnBehalfOf = coreWarnings.some(w => w.type === 'on-behalf-of');
    if (!hasReplyToMismatch && !hasOnBehalfOf) return null;
    const hasUrgency = coreWarnings.some(w => w.type === 'phishing-urgency');
    if (!hasUrgency && !secrecyLanguage) return null;
    return {
        patternId: 'pattern_e_payment_redirect',
        patternName: 'Payment Redirect / Business Email Compromise',
        confidence: 'critical',
        signals: { payment_change_language: paymentChangeLanguage, reply_to_mismatch: hasReplyToMismatch || null, on_behalf_of: hasOnBehalfOf || null, urgency: hasUrgency || null, secrecy_language: secrecyLanguage || null },
        description: 'This email requests a change to payment instructions while using a spoofed sender identity and pressure tactics. This is a textbook BEC attack.',
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
            severity: highestConfidence === 'critical' ? 'critical' : 'critical',
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
                                replyTo = emailMatch[1].trim();
                            }
                        }
                        const senderMatch = headers.match(/^Sender:\s*(.+)$/mi);
                        if (senderMatch) {
                            const senderEmailMatch = senderMatch[1].match(/<([^>]+)>/) || senderMatch[1].match(/([^\s,]+@[^\s,]+)/);
                            if (senderEmailMatch) {
                                senderHeader = senderEmailMatch[1].trim();
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

function processEmail(emailData) {
    const senderEmail = emailData.from.emailAddress.toLowerCase();
    const displayName = emailData.from.displayName || '';
    const senderDomain = senderEmail.split('@')[1] || '';
    const content = (emailData.subject || '') + ' ' + (emailData.body || '');
    const replyTo = emailData.replyTo;
    const senderHeader = emailData.senderHeader;
    
    const isKnownContact = knownContacts.has(senderEmail);
    
    const warnings = [];
    
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
    
    const phishingUrgency = detectPhishingUrgency(emailData.body, emailData.subject);
    if (phishingUrgency) {
        warnings.push({
            type: 'phishing-urgency',
            severity: 'critical',
            title: 'Phishing Language Detected',
            description: 'This email uses fear tactics commonly found in phishing scams.',
            keywords: phishingUrgency.keywords,
            keywordCategory: 'Phishing Tactics',
            keywordExplanation: 'Scammers use threats of account deletion, suspension, or data loss to pressure you into clicking malicious links. Legitimate companies rarely threaten immediate action via email.'
        });
    }
    
    const gibberishDomain = detectGibberishDomain(senderEmail);
    if (gibberishDomain) {
        warnings.push({
            type: 'gibberish-domain',
            severity: 'critical',
            title: 'Suspicious Random Domain',
            description: `This email comes from a domain that appears to be randomly generated (${gibberishDomain.reasons.join(', ')}). Legitimate companies use recognizable domain names.`,
            senderEmail: senderEmail,
            matchedEmail: gibberishDomain.domain
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

    // ============================================
    // EXISTING CHECKS
    // ============================================
    
    if (replyTo && replyTo.toLowerCase() !== senderEmail) {
        const replyToDomain = replyTo.split('@')[1] || '';
        if (replyToDomain.toLowerCase() !== senderDomain) {
            // Check if sender domain is a known ESP (e.g., ccsend.com, mailchimp.com)
            // ESPs always have reply-to mismatches because they send on behalf of businesses
            const isKnownESP = KNOWN_ESP_DOMAINS.some(esp => 
                senderDomain === esp || senderDomain.endsWith('.' + esp)
            );
            if (!isKnownESP) {
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
    
    if (senderHeader) {
        const senderHeaderLower = senderHeader.toLowerCase();
        const senderHeaderDomain = senderHeaderLower.split('@')[1] || '';
        if (senderHeaderDomain && senderHeaderDomain !== senderDomain) {
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
    
    const brandImpersonation = detectBrandImpersonation(emailData.subject, emailData.body, senderDomain, displayName);
    if (brandImpersonation) {
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
    if (internationalSender) {
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
        ['brand-impersonation', 'recipient-spoof', 'org-impersonation', 'impersonation'].includes(w.type)
    );
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
    
    const wireKeywords = detectWireFraudKeywords(content);
    if (wireKeywords.length > 0) {
        const keywordInfo = getKeywordExplanation(wireKeywords[0]);
        warnings.push({
            type: 'wire-fraud',
            severity: 'critical',
            title: 'Dangerous Keywords Detected',
            description: 'This email contains terms commonly used in wire fraud.',
            keywords: wireKeywords,
            keywordCategory: keywordInfo.category,
            keywordExplanation: keywordInfo.explanation
        });
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
    
    displayResults(finalWarnings);
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

function wrapDomain(domain) {
    return `<span style="white-space: nowrap;">${domain}</span>`;
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
        statusText.textContent = `${totalWarnings} Issue${totalWarnings > 1 ? 's' : ''} Found`;
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
        const WARNING_PRIORITY = {
            'phase2-phishing-pattern': 0,
            'replyto-mismatch': 1,
            'on-behalf-of': 2,
            'fake-tld': 3,
            'impersonation': 4,
            'recipient-spoof': 5,
            'contact-lookalike': 6,
            'brand-impersonation': 7,
            'org-impersonation': 8,
            'suspicious-domain': 9,
            'via-routing': 10,
            'auth-failure': 11,
            'gibberish-domain': 12,
            'lookalike-domain': 13,
            'homoglyph': 14,
            'display-name-suspicion': 15,
            'international-sender': 16,
            'mass-recipients': 17,
            'wire-fraud': 18,
            'phishing-urgency': 19
        };
        warnings.sort((a, b) => (WARNING_PRIORITY[a.type] || 99) - (WARNING_PRIORITY[b.type] || 99));
        
        warningsSection.classList.remove('hidden');
        warningsFooter.classList.remove('hidden');
        safeMessage.classList.add('hidden');
        
        warningsList.innerHTML = warnings.map(w => {
            let emailHtml = '';
            
            // v4.2.0: Phase 2 merged warning rendering
            if (w.type === 'phase2-phishing-pattern' && w.details) {
                const patternHtml = w.details.patterns.map(p => 
                    `<div class="warning-email-row">
                        <span class="warning-email-label">${p.patternName}:</span>
                        <span class="warning-email-value suspicious">${p.confidence} confidence</span>
                    </div>`
                ).join('');
                emailHtml = `
                    <div class="warning-emails">
                        ${patternHtml}
                    </div>
                    <div class="warning-advice">
                        <strong>What to do:</strong> ${w.recommendation}
                    </div>
                `;
            } else if ((w.type === 'wire-fraud' || w.type === 'phishing-urgency') && w.keywords) {
                const keywordTags = w.keywords.slice(0, 5).map(k => 
                    `<span class="keyword-tag">${k}</span>`
                ).join('');
                emailHtml = `
                    <div class="warning-keywords-section">
                        <div class="warning-keywords-label">Triggered by:</div>
                        <div class="warning-keywords">${keywordTags}</div>
                    </div>
                    <div class="warning-advice">
                        <strong>Why this matters:</strong> ${w.keywordExplanation}
                    </div>
                `;
            } else if (w.type === 'org-impersonation') {
                emailHtml = `
                    <div class="warning-emails">
                        <div class="warning-email-row">
                            <span class="warning-email-label">Claims to be:</span>
                            <span class="warning-email-value known">${w.entityClaimed}</span>
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
                            <span class="warning-email-value known">${w.brandClaimed}</span>
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
            } else if (w.type === 'international-sender') {
                if (w.genericUse && w.genericMessage) {
                    emailHtml = `
                        <div class="warning-international-info">
                            <p>${w.genericMessage}</p>
                        </div>
                    `;
                } else {
                    emailHtml = `
                        <div class="warning-international-info">
                            <p>This sender's email address includes a country code: ${w.tld}<br>(${w.country})</p>
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
            } else if (w.type === 'fake-tld') {
                emailHtml = `
                    <div class="warning-international-info">
                        <p>The domain extension <strong>${w.tld}</strong> is not a real top-level domain. No legitimate email can come from this address. This email is fraudulent. Do not interact with it.</p>
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
                            <span class="warning-email-value suspicious">${w.viaDomain}</span>
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
                        ${w.reason ? `<div class="warning-reason">${w.reason}</div>` : ''}
                    </div>
                `;
            } else if (w.detail) {
                emailHtml = `<div class="warning-reason">${w.detail}</div>`;
            }
            
            return `
                <div class="warning-item ${w.severity}">
                    <div class="warning-title">${w.title}</div>
                    <div class="warning-description">${w.description}</div>
                    ${emailHtml}
                </div>
            `;
        }).join('');
    } else {
        warningsSection.classList.add('hidden');
        warningsFooter.classList.add('hidden');
        safeMessage.classList.remove('hidden');
    }
}
