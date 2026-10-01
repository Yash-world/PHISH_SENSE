
BRANDS = {
"paypal": {"paypal.com"},
"google": {"google.com"},
"microsoft": {"microsoft.com", "live.com", "office.com"},
"apple": {"apple.com"},
"amazon": {"amazon.com", "amazon.in"},
"facebook": {"facebook.com"},
"instagram": {"instagram.com"},
"netflix": {"netflix.com"},
"sbi": {"sbi.co.in", "onlinesbi.sbi"},
"hdfc": {"hdfcbank.com"},
"icici": {"icicibank.com"},
"axis": {"axisbank.com"},
"paytm": {"paytm.com"},
"phonepe": {"phonepe.com"},
"gpay": {"google.com"},
"upi": {"npci.org.in"},
"npci": {"npci.org.in"},
"irctc": {"irctc.co.in"},
"flipkart": {"flipkart.com"},
"whatsapp": {"whatsapp.com"},
"linkedin": {"linkedin.com"},
"github": {"github.com"},
"dropbox": {"dropbox.com"},
"dhl": {"dhl.com"},
"fedex": {"fedex.com"},
}

TRUSTED_DOMAINS = {
"google.com",
"github.com",
"microsoft.com",
"live.com",
"office.com",
"apple.com",
"amazon.com",
"amazon.in",
"facebook.com",
"instagram.com",
"netflix.com",
"sbi.co.in",
"onlinesbi.sbi",
"hdfcbank.com",
"icicibank.com",
"axisbank.com",
"paytm.com",
"phonepe.com",
"npci.org.in",
"irctc.co.in",
"flipkart.com",
"whatsapp.com",
"linkedin.com",
"dropbox.com",
"dhl.com",
"fedex.com",
}

SUSPICIOUS_TLDS = {
"xyz",
"top",
"tk",
"gq",
"ml",
"cf",
"ga",
"click",
"zip",
"work",
"support",
"rest",
"country",
"buzz",
}

SHORTENERS = {
"bit.ly",
"tinyurl.com",
"goo.gl",
"t.co",
"is.gd",
"cutt.ly",
"rb.gy",
"ow\.ly",
"tiny.cc",
"shorturl.at",
}

CREDENTIAL_KEYWORDS = {
"login",
"signin",
"verify",
"secure",
"account",
"update",
"confirm",
"wallet",
"bank",
"otp",
"password",
"kyc",
"refund",
"reward",
}

EMAIL_SUSPICIOUS_WORDS = {
"urgent",
"verify",
"login",
"password",
"bank",
"account",
"click",
"update",
"confirm",
"suspend",
"security alert",
}

EMAIL_URGENCY_PHRASES = {
"immediately",
"act now",
"limited time",
"within 24 hours",
"suspended",
}

EMAIL_INFO_REQUESTS = {
"enter password",
"send otp",
"share otp",
"credit card",
"debit card",
"cvv",
"pin",
}

SMS_KEYWORDS = {
"urgent",
"verify",
"update",
"click",
"login",
"bank",
"account",
"suspended",
"winner",
"free",
"prize",
"otp",
"kyc",
"pan",
"aadhaar",
"upi",
"refund",
"reward",
"fastag",
}

SMS_URGENCY_PHRASES = {
"immediately",
"now",
"within 24 hours",
"act fast",
"today",
}

FAKE_PATTERNS = {
"secure-login",
"verify-account",
"update-info",
}

INDIAN_PHISHING_PHRASES = (
"electricity bill",
"bill disconnect",
"parcel held",
"courier held",
"refund",
"reward points",
"download apk",
"remote access",
"anydesk",
"teamviewer",
)

SUSPICIOUS_EXTENSIONS = {
".exe",
".scr",
".js",
".iso",
".zip",
".html",
".apk",
}
