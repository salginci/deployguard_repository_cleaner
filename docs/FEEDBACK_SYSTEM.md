# DeployGuard - ML Feedback System

## Overview

DeployGuard collects anonymized user feedback to continuously improve false positive detection. When users review detected secrets and mark items as "false positive" or "confirmed secret", this data helps train our ML models.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         User Workflow                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. User runs:  deployguard clean <repo>                            │
│                                                                      │
│  2. Interactive review:                                              │
│     ┌────────────────────────────────────────────────────┐          │
│     │ [1/15] Secret detected:                            │          │
│     │   File: src/config.js                              │          │
│     │   Type: api_key                                    │          │
│     │   Value: AIza***REDACTED***                        │          │
│     │   Suggested: DG_CONFIG_API_KEY_A1B2                │          │
│     │                                                    │          │
│     │ Clean this secret? [y/n/a/s/q/?]                   │          │
│     └────────────────────────────────────────────────────┘          │
│                                                                      │
│  3. User choices:                                                    │
│     y = Yes (confirmed secret)                                       │
│     n = No (false positive)                                          │
│     a = Approve all remaining                                        │
│     s = Skip this file                                               │
│     q = Quit                                                         │
│                                                                      │
│  4. Feedback collected and sent to server                           │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                │ HTTPS POST (HMAC signed)
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    feedback.deployguard.net                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  POST /v1/feedback                                                   │
│  ┌─────────────────────────────────────────────────────────┐        │
│  │ {                                                       │        │
│  │   "client_id": "a1b2c3...",     # Anonymous hash       │        │
│  │   "deployguard_version": "0.1.7",                      │        │
│  │   "total_detected": 15,                                │        │
│  │   "confirmed_secrets": 12,                             │        │
│  │   "false_positives": 3,                                │        │
│  │   "items": [                                           │        │
│  │     {                                                  │        │
│  │       "value_hash": "sha256...",  # NOT actual value  │        │
│  │       "value_pattern": "sha256:[hex:64]",             │        │
│  │       "secret_type": "generic_secret",                │        │
│  │       "file_type": "java",                            │        │
│  │       "is_true_positive": false,                      │        │
│  │       "context_hint": "certificate_pin"               │        │
│  │     }                                                  │        │
│  │   ]                                                    │        │
│  │ }                                                       │        │
│  └─────────────────────────────────────────────────────────┘        │
│                                                                      │
│  Security:                                                           │
│  • HMAC-SHA256 signature in X-Signature header                      │
│  • Timestamp freshness check (5 min window)                         │
│  • Rate limiting: 100 requests/hour per client                      │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       ML Training Pipeline                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. Aggregate feedback by pattern                                   │
│  2. Identify patterns with high false positive rate                 │
│  3. Update known_false_positive_patterns table                      │
│  4. Publish updated patterns to CLI clients                         │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## Data Collection

### What We Collect

| Data | Purpose | Privacy |
|------|---------|---------|
| Value Hash | Identify unique secrets | SHA256, cannot be reversed |
| Value Pattern | Understand format | e.g., `ghp_[alnum:36]` |
| Secret Type | Classification | api_key, password, etc. |
| File Type | Context understanding | java, python, yaml |
| User Decision | Training label | true/false positive |
| Context Hint | Why flagged | certificate_pin, test_data |

### What We DON'T Collect

- ❌ Actual secret values
- ❌ File paths or names
- ❌ Repository names or URLs
- ❌ User identity (only anonymous hash)
- ❌ Code content

## False Positive Hints

The CLI provides helpful hints when a detection might be a false positive:

### Automatically Detected

| Pattern | Hint | Common Source |
|---------|------|---------------|
| `sha256:[hex:64]` | Certificate pin | Android SSL pinning |
| `com.google.android.*` | Android namespace | Library references |
| `*Adapter`, `*Controller` | Class name | Java/Kotlin code |
| `test_*`, `mock_*` | Test data | Unit tests |
| `example.com` | Example domain | Documentation |

### Interactive Review Display

```
[3/15] Secret detected:
  File: app/src/main/java/Security.java
  Type: generic_secret
  Value: sha256/AAAAAAAAAA...

  ⚠️  Hint: This looks like a certificate pin (SHA256 hash format)
      Common in: SSL pinning configurations
      False positive likelihood: HIGH

Clean this secret? [y/n/a/s/q/?]
```

## API Endpoints

### POST /v1/feedback

Submit feedback from CLI.

**Headers:**
```
Content-Type: application/json
X-Timestamp: 1699123456
X-Client-ID: a1b2c3d4e5f6...
X-Signature: hmac-sha256-signature
```

**Body:**
```json
{
  "client_id": "a1b2c3d4e5f6...",
  "deployguard_version": "0.1.7",
  "total_detected": 15,
  "confirmed_secrets": 12,
  "false_positives": 3,
  "items": [...]
}
```

**Response:**
```json
{
  "status": "accepted",
  "feedback_id": "uuid",
  "message": "Thank you for contributing..."
}
```

### GET /v1/feedback/stats

Public statistics (no auth required).

**Response:**
```json
{
  "total_submissions": 1234,
  "total_items_reviewed": 15678,
  "false_positive_rate": 0.23,
  "top_false_positive_patterns": [
    {"pattern": "sha256:[hex:64]", "rate": 0.92},
    {"pattern": "com.google.android.*", "rate": 0.87}
  ]
}
```

### GET /v1/feedback/patterns

Get known false positive patterns for client-side filtering.

**Response:**
```json
{
  "patterns": [
    {
      "pattern": "sha256:[hex:64]",
      "confidence": 0.92,
      "reason": "Certificate pin hash"
    }
  ],
  "updated_at": "2024-01-15T10:30:00Z"
}
```

## Security

### Request Signing

```python
import hmac
import hashlib
import time

def sign_request(payload: dict, secret: str) -> str:
    timestamp = str(int(time.time()))
    message = f"{timestamp}:{json.dumps(payload, sort_keys=True)}"
    signature = hmac.new(
        secret.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()
    return signature
```

### Rate Limiting

- 100 requests per hour per client_id
- Burst limit: 10 requests per minute
- Exceeded: HTTP 429 with Retry-After header

### Timestamp Validation

- Requests older than 5 minutes are rejected
- Prevents replay attacks
- Server uses UTC time

## Local Feedback Storage

Feedback is also stored locally at `~/.deployguard/feedback/`:

```
~/.deployguard/
└── feedback/
    ├── 2024-01-15_143022_abc123.json
    ├── 2024-01-15_153045_def456.json
    └── ...
```

Use this for:
- Offline review of past decisions
- Local ML model training
- Debugging detection issues

## Opting Out

To disable feedback collection:

```bash
# Single run
deployguard clean <repo> --no-feedback

# Permanently (in config)
echo "feedback_enabled: false" >> ~/.deployguard/config.yaml
```

## Contributing

Help improve detection by:
1. Using interactive mode (default)
2. Carefully reviewing each detection
3. Marking obvious false positives as "n"
4. Reporting new patterns via GitHub issues
