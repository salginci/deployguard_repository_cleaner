# DeployGuard - Quality Improvement Playbook

## Overview

This document outlines the step-by-step process for improving false positive detection quality as user feedback accumulates. Follow this playbook regularly to continuously improve detection accuracy.

---

## Feedback Review Cadence

| Milestone | Action Required |
|-----------|-----------------|
| Every 100 submissions | Quick stats review |
| Every 500 submissions | Pattern analysis |
| Every 1,000 submissions | Rule updates |
| Every 5,000 submissions | Consider ML model |

---

## Phase 1: Quick Stats Review (Every 100 Submissions)

### Step 1.1: Check Overall False Positive Rate

```sql
-- Run this query on feedback database
SELECT 
    COUNT(*) as total_items,
    SUM(CASE WHEN is_true_positive = false THEN 1 ELSE 0 END) as false_positives,
    ROUND(100.0 * SUM(CASE WHEN is_true_positive = false THEN 1 ELSE 0 END) / COUNT(*), 2) as fp_rate_percent
FROM feedback_items;
```

**Target:** < 20% false positive rate

### Step 1.2: Identify Top False Positive Patterns

```sql
SELECT 
    value_pattern,
    COUNT(*) as occurrences,
    SUM(CASE WHEN is_true_positive = false THEN 1 ELSE 0 END) as false_positives,
    ROUND(100.0 * SUM(CASE WHEN is_true_positive = false THEN 1 ELSE 0 END) / COUNT(*), 2) as fp_rate
FROM feedback_items
GROUP BY value_pattern
HAVING COUNT(*) >= 5
ORDER BY fp_rate DESC
LIMIT 10;
```

**Action:** Flag patterns with >80% FP rate for investigation.

---

## Phase 2: Pattern Analysis (Every 500 Submissions)

### Step 2.1: Analyze by File Type

```sql
SELECT 
    file_type,
    COUNT(*) as total,
    ROUND(100.0 * SUM(CASE WHEN is_true_positive = false THEN 1 ELSE 0 END) / COUNT(*), 2) as fp_rate
FROM feedback_items
GROUP BY file_type
ORDER BY fp_rate DESC;
```

**Common Findings:**
- `.md` files → High FP (documentation examples)
- `.test.js` files → High FP (test data)
- `.yaml` config → Mixed (check context)

### Step 2.2: Analyze by Context Hint

```sql
SELECT 
    context_hint,
    COUNT(*) as total,
    ROUND(100.0 * SUM(CASE WHEN is_true_positive = false THEN 1 ELSE 0 END) / COUNT(*), 2) as fp_rate
FROM feedback_items
WHERE context_hint IS NOT NULL
GROUP BY context_hint
ORDER BY total DESC;
```

### Step 2.3: Identify New Patterns

```sql
-- Find patterns not in our known_false_positive_patterns table
SELECT DISTINCT fi.value_pattern, COUNT(*) as occurrences
FROM feedback_items fi
LEFT JOIN known_false_positive_patterns kfp ON fi.value_pattern = kfp.pattern
WHERE kfp.pattern IS NULL
  AND fi.is_true_positive = false
GROUP BY fi.value_pattern
HAVING COUNT(*) >= 3
ORDER BY occurrences DESC;
```

**Action:** Add confirmed patterns to `known_false_positive_patterns`.

---

## Phase 3: Rule Updates (Every 1,000 Submissions)

### Step 3.1: Update Known False Positive Patterns

When a pattern has:
- ≥10 samples
- ≥80% false positive rate
- Clear reason why it's not a secret

**Add to `known_false_positive_patterns`:**

```sql
INSERT INTO known_false_positive_patterns (pattern, confidence, sample_count, reason, created_at)
VALUES 
    ('sha256:[hex:64]', 0.92, 150, 'Certificate pin hash - SSL pinning configuration', NOW()),
    ('com.google.android.[alnum]+', 0.87, 89, 'Android library package name', NOW());
```

### Step 3.2: Update CLI Hint System

Edit `deployguard/cli/clean.py` → `_check_false_positive_hints()`:

```python
def _check_false_positive_hints(secret_type: str, value: str, file_path: str) -> List[str]:
    hints = []
    
    # Add new patterns discovered from feedback
    if re.match(r'^[A-Za-z0-9_]+Adapter$', value):
        hints.append("⚠️ This looks like a Java/Kotlin adapter class name")
    
    # ... existing hints ...
    
    return hints
```

### Step 3.3: Update Secret Patterns Config

Edit `config/secret_patterns.yaml` to exclude known false positives:

```yaml
patterns:
  - name: generic_api_key
    pattern: '(?i)api[_-]?key["\s]*[:=]["\s]*([a-zA-Z0-9_-]{20,})'
    # Add exclusions based on feedback
    exclude_patterns:
      - '^sha256/'           # Certificate pins
      - '^com\.google\.'     # Android packages
      - 'Adapter$'           # Class names
```

### Step 3.4: Version and Document Changes

```bash
# Create changelog entry
echo "## v0.1.8 - $(date +%Y-%m-%d)
### False Positive Improvements
- Added exclusion for certificate pins (sha256 format)
- Added exclusion for Android package names
- Reduced FP rate from X% to Y%
" >> CHANGELOG.md

# Bump version
# Edit pyproject.toml version
```

---

## Phase 4: ML Readiness Check (Every 5,000 Submissions)

### Step 4.1: Evaluate Data Quality

```sql
-- Check label distribution
SELECT 
    is_true_positive,
    COUNT(*) as count,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER(), 2) as percentage
FROM feedback_items
GROUP BY is_true_positive;
```

**Requirements for ML:**
- [ ] ≥5,000 labeled samples
- [ ] At least 30% of each class (true/false positive)
- [ ] Diverse file types represented
- [ ] Multiple secret types covered

### Step 4.2: Feature Availability Check

```sql
-- Ensure we have features for ML
SELECT 
    COUNT(*) as total,
    COUNT(value_pattern) as has_pattern,
    COUNT(file_type) as has_file_type,
    COUNT(context_hint) as has_context
FROM feedback_items;
```

### Step 4.3: Simple Model Training (When Ready)

```python
# scripts/train_fp_model.py
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib

# Load feedback data
df = pd.read_sql("SELECT * FROM feedback_items", connection)

# Feature engineering
df['entropy'] = df['value_hash'].apply(calculate_entropy)
df['length'] = df['value_pattern'].apply(extract_length)
df['is_test_file'] = df['file_type'].str.contains('test', case=False)

# Prepare features
X = df[['entropy', 'length', 'is_test_file', ...]]
y = df['is_true_positive']

# Train
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)
model = RandomForestClassifier(n_estimators=100)
model.fit(X_train, y_train)

# Evaluate
print(classification_report(y_test, model.predict(X_test)))

# Save model
joblib.dump(model, 'models/fp_classifier_v1.joblib')
```

---

## Monitoring Dashboard Queries

### Daily Metrics

```sql
-- Daily submission trend
SELECT 
    DATE(received_at) as date,
    COUNT(*) as submissions,
    SUM(false_positives) as total_fp,
    ROUND(AVG(false_positives::float / NULLIF(total_detected, 0)) * 100, 2) as avg_fp_rate
FROM feedback_submissions
WHERE received_at > NOW() - INTERVAL '30 days'
GROUP BY DATE(received_at)
ORDER BY date;
```

### Pattern Effectiveness

```sql
-- How well are our known patterns working?
SELECT 
    kfp.pattern,
    kfp.confidence as expected_fp_rate,
    ROUND(100.0 * SUM(CASE WHEN fi.is_true_positive = false THEN 1 ELSE 0 END) / COUNT(*), 2) as actual_fp_rate,
    COUNT(*) as sample_size
FROM known_false_positive_patterns kfp
JOIN feedback_items fi ON fi.value_pattern LIKE kfp.pattern
GROUP BY kfp.pattern, kfp.confidence
ORDER BY sample_size DESC;
```

---

## Action Checklist

### Weekly Review
- [ ] Run Phase 1 queries
- [ ] Note any patterns with >50% FP rate
- [ ] Check for anomalies in submission rate

### Monthly Review
- [ ] Run Phase 2 queries
- [ ] Identify top 5 patterns for improvement
- [ ] Update `_check_false_positive_hints()` if needed
- [ ] Update CHANGELOG with improvements

### Quarterly Review
- [ ] Run Phase 3 and 4 queries
- [ ] Update `known_false_positive_patterns` table
- [ ] Update `secret_patterns.yaml` exclusions
- [ ] Release new CLI version with improvements
- [ ] Evaluate ML readiness

---

## Escalation Criteria

**Immediate Action Required:**
- FP rate suddenly increases >10% week-over-week
- New pattern appears with >90% FP rate and >20 samples
- User complaints about specific pattern type

**Contact:**
- Create GitHub issue with `false-positive` label
- Include query results and sample data (hashed values only)

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-02-10 | Initial playbook |
