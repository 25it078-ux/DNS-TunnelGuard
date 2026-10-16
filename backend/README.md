# DNS-TunnelGuard — ML Backend API

FastAPI service powering machine-learning based DNS tunneling detection using 10 DNS traffic characteristics.

## Architecture

- **Framework**: FastAPI (asynchronous, high performance)
- **Model**: Supervised `RandomForestClassifier` trained on benign and DNS tunneling telemetry
- **Extracted Characteristics**:
  1. `domain_length`: Total FQDN character length
  2. `subdomain_length`: Character length of the subdomain prefix
  3. `subdomain_count`: Number of subdomain depth levels
  4. `shannon_entropy`: Character randomness score (identifies encrypted/encoded payloads)
  5. `numeric_ratio`: Proportion of digits (detects hex and base32 payloads)
  6. `vowel_ratio`: Proportion of vowels (machine-generated ciphertext anomaly)
  7. `consecutive_consonants`: Longest contiguous non-vowel sequence
  8. `special_char_ratio`: Hyphens and non-alphanumeric separator density
  9. `response_size`: DNS response size in bytes
  10. `ttl`: Time-to-Live in seconds (detects low-TTL C2 channels)

## Quick Start (Local)

1. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Train / Re-train Model** (Artifacts saved to `app/ml/`):
   ```bash
   python training/train.py
   ```

3. **Start the API Server**:
   ```bash
   python run.py
   ```
   Server will listen on `http://127.0.0.1:8000`. Interactive OpenAPI documentation is available at `http://127.0.0.1:8000/docs`.

## API Endpoints

- `GET /api/health` — Service and ML model health status
- `GET /api/model/info` — Model architecture, metrics, and feature importances
- `POST /api/predict` — Single DNS domain classification
- `POST /api/predict/csv` — Batch CSV upload with per-row threat classifications, confidence scoring, and ranked threat domains
