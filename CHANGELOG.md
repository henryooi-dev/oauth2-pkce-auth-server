## [[1.2.0](https://github.com/henryooi-dev/oauth2-pkce/compare/1.1.1...1.2.0)] - 2026-02-06
🚜 Refactor
- refactor: extract PKCE and crypto helpers into helper module

🧪 Testing
- test: add Jest tests suite for OAuth PKCE flow

📚 Documentation
- Add test running instructions to README


## [[1.1.1](https://github.com/henryooi-dev/oauth2-pkce/compare/1.1.0...1.1.1)] - 2026-02-05
🐛 Bug Fixes
- (auth-server) profile information error after trigerring refresh access token (#1) - (45d3dcf)

⛰️ Features
📚 Documentation
⚙️ Miscellaneous Tasks


## [[1.1.0](https://github.com/henryooi-dev/oauth2-pkce/compare/1.0.0...1.1.0)] - 2026-02-04

### 🔐 Security
- Authorization codes are now single-use
- Implemented refresh token expiry
- Added refresh token rotation for improved token lifecycle security

### ⚡ Performance
- RSA keys are now preloaded during application startup to reduce runtime overhead

### 🧹 Maintenance
- Removed deprecated `body-parser` dependency

## [[1.0.0](https://github.com/henryooi-dev/oauth2-pkce/releases/tag/1.0.0)] - 2026-02-04

