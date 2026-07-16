// GHAS Secret Scanning Demo
// These are FAKE, non-functional credentials - formatted only to match
// GitHub's built-in secret scanning detection patterns for a live demo.
// Do NOT use real secrets in any repository, ever.

// AWS Access Key ID (format: AKIA + 16 alphanumeric chars)
const AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";
const AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

// GitHub Personal Access Token (format: ghp_ + 36 chars)
const GITHUB_TOKEN = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";

// Stripe Secret Key (format: sk_live_ + random chars)
const STRIPE_SECRET_KEY = "sk_live_51HxampleFakeKeyDoNotUse1234567890abcd";

// Slack Webhook URL
const SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX";

// Google API Key (format: AIza + 35 chars)
const GOOGLE_API_KEY = "AIzaSyD-FAKEKEYFAKEKEYFAKEKEYFAKEKEY12";

module.exports = {
  AWS_ACCESS_KEY_ID,
  AWS_SECRET_ACCESS_KEY,
  GITHUB_TOKEN,
  STRIPE_SECRET_KEY,
  SLACK_WEBHOOK_URL,
  GOOGLE_API_KEY,
};
