// False positive samples - these should NOT be detected

// Placeholders
const apiKey = "YOUR_API_KEY";
const token = "your-token-here";
const secret = "xxx_replace_with_real_secret";
const key = "EXAMPLE_KEY_GOES_HERE";
const password = "changeme";
const credential = "dummy_credential";

// Template variables
const config = "${API_KEY}";
const envVar = process.env.OPENAI_API_KEY;
const envVar2 = process.env['STRIPE_SECRET_KEY'];

// Environment variable references (not actual keys)
export const apiUrl = process.env.API_URL ?? 'https://api.example.com';

// Short random strings (low entropy or too short)
const hash = "abc123";
const id = "user-12345";

// localhost URLs
const dbUrl = "postgres://admin:password@localhost:5432/mydb";
const redisUrl = "redis://localhost:6379";

// Test/example domain URLs
const testUrl = "https://user:pass@example.com/api";

// Documentation/comment references
// See: https://docs.example.com for your API_KEY
