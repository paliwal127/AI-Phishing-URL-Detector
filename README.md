# SignalGuard

SignalGuard is a full-stack student project for checking URLs for phishing indicators. It explains the signals behind each score and deliberately avoids claiming that a URL is safe merely because no warning was found.

> **Model limitation:** local smoke tests classify several well-known legitimate URLs as phishing. Treat results as triage signals, not proof of maliciousness or safety; see [Evaluation and limitations](#evaluation-and-limitations).

## Contents

- [Features and technology](#features)
- [Architecture](#architecture)
- [Local setup](#local-setup)
- [API reference](#api)
- [Model training](#ml-workflow)
- [Deployment](#online-deployment-preparation-render-api--vercel-frontend)
- [College demo checklist](#college-demo-checklist)

## Problem and objectives

Phishing messages often disguise their destinations with lookalike domains, misleading subdomains, URL shorteners, and urgent account-related language. SignalGuard gives users a quick, explainable URL-level check before they follow a link.

Objectives:

- Extract reusable lexical URL features and flag common brand lookalikes.
- Persist scan results and user feedback, with private account history.
- Offer a dataset-driven Random Forest training and evaluation workflow.
- Provide URL, message-link, and QR-code scanning through one analysis pipeline.
- Keep outputs transparent about which checks ran and which advanced checks did not.

## Features

- Single URL scan, message/SMS link extraction, and QR image or camera scanning.
- Rule-based risk score with understandable reasons; optional trained Random Forest probability blended with URL rules.
- Brand lookalike and common digit-substitution detection for a curated set of brands.
- Feature record: URL and domain lengths, punctuation, subdomains, IP host, HTTPS, digits, keywords, shortening service, suffix, path, query count, fragment, entropy, brand match, punycode and port.
- JWT registration and login, account-scoped history and dashboard, and admin review of feedback.
- Manifest V3 Chromium extension prototype for scanning a selected link before the user chooses whether to open it.
- PostgreSQL support through `DATABASE_URL`; SQLite is the out-of-box local development default.

## Deliberate safety and capability limits

The scanner does **not** fetch, resolve, open, or follow submitted URLs. This keeps the URL API from acting as an SSRF proxy. Redirect-chain, remote HTML, screenshot, sandbox preview, and visual brand analysis are **not implemented**. Content analysis is returned as unavailable, not guessed. QR image decoding occurs in the browser; only the extracted URL is sent to the API. No external JavaScript from a scanned page is run.

This workspace includes a PhiUSIIL CSV and a trained model artifact. A fresh source checkout may not include these local data/model assets. If no compatible artifact is present, the API reports `analysis_mode: "rules"` rather than presenting a heuristic as a machine-learning prediction. Training generates metrics only from a held-out test split; Random Forest scores are not asserted to be calibrated real-world probabilities.

## Technology

- Frontend: React, JavaScript, Vite, Tailwind CSS, Lucide icons, ZXing browser decoder.
- Backend: Python, Django, Django REST Framework, SimpleJWT.
- Detection: reusable Python URL features, scikit-learn Random Forest, pandas, NumPy, joblib, bundled Public Suffix List via `tldextract`.
- Evaluation: Matplotlib reports with no network access during training or inference.
- Database: SQLite locally, PostgreSQL when configured.
- Extension: Chromium Manifest V3.

## Project layout

```text
backend/
  config/                 Django settings and routes
  scanner/                Models, API, features, rules, tests
  ml_model/train.py       CSV training and holdout evaluation
  ml_model/models/        Generated model artifact (not committed)
frontend/
  src/                    React pages, API client, styles
browser-extension/        Manifest V3 extension prototype
```

## Architecture

```mermaid
flowchart LR
  U[Browser user] --> R[React scanner]
  Q[QR image or camera] --> D[Browser QR decoder]
  D --> R
  R -->|URL JSON| A[Django REST API]
  A --> V[URL validation]
  V --> F[Feature extraction]
  F --> H[Explainable URL rules]
  F --> M{Trained model available?}
  M -->|No| H
  M -->|Yes| RF[Random Forest probability]
  RF --> S[Combined risk score]
  H --> S
  S --> DB[(SQLite or PostgreSQL)]
  DB --> R
  E[Chromium extension] --> A
```

## Data flow

```mermaid
sequenceDiagram
  actor User
  participant UI as React
  participant API as Django REST
  participant Detector as Feature and risk pipeline
  participant DB as Database
  User->>UI: Submit URL, message, or decoded QR URL
  UI->>API: POST /api/scan/ (or text/qr endpoint)
  API->>API: Validate scheme, hostname, credentials, and length
  API->>Detector: Extract lexical features; do not fetch URL
  Detector->>Detector: Explain rules; use trained artifact if present
  Detector-->>API: Verdict, risk, reasons, feature record
  API->>DB: Store scan and account owner when authenticated
  API-->>UI: JSON result and explicit analysis mode
  UI-->>User: Verdict, signals, recommendation, limits
```

## ML workflow

```mermaid
flowchart LR
  CSV[User-sourced labeled CSV] --> Clean[Validate labels and HTTP(S) URLs; remove ambiguous duplicates]
  Clean --> Features[Extract same URL features used at inference]
  Features --> Split[Stratified hostname-grouped 80/20 holdout]
  Split --> Tune[Stratified hostname-grouped CV on training groups only]
  Tune --> Threshold[Choose hybrid-score threshold from out-of-fold training scores]
  Tune --> Train[Select Random Forest configuration]
  Train --> Eval[Untouched grouped test metrics and error analysis]
  Train --> Save[Joblib artifact + versioned schema + threshold + dataset hash]
  Save --> API[Django loads artifact for inference]
  Feedback[User feedback] --> Review[Admin review and label]
  Review --> Approved[Export approved labeled records]
  Approved --> CSV
```

### Train from a real dataset

The training script accepts a CSV with `url,label` columns (column names are case-insensitive). A reproducible public source is the [UCI PhiUSIIL Phishing URL Dataset](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset): 235,795 URLs, published under CC BY 4.0. Its source labels use `1` for legitimate and `0` for phishing; the trainer normalizes them to `0=legitimate, 1=phishing`, so pass `--phishing-label 0`. Numeric-label datasets require that argument; text labels such as `legitimate` and `phishing` are mapped explicitly. Unsupported labels fail instead of being guessed. Credit Prasad and Chandra (2024), DOI [10.1016/j.cose.2023.103545](https://doi.org/10.1016/j.cose.2023.103545). A supplied dataset may be present in the current workspace but is not required to be committed with source code.

```powershell
New-Item -ItemType Directory -Force data | Out-Null
Invoke-WebRequest -Uri "https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip" -OutFile "data\phiusiil.zip"
Expand-Archive -Path "data\phiusiil.zip" -DestinationPath "data\phiusiil" -Force
Set-Location backend
..\.venv\Scripts\python.exe -m ml_model.train "..\data\phiusiil\PhiUSIIL_Phishing_URL_Dataset.csv" --phishing-label 0
```

The trainer reports class counts before and after cleaning, missing rows, malformed URLs, normalized conflicting URLs, and duplicate URLs. It normalizes only the scheme and hostname (preserving path, query, and fragment), removes conflicting duplicates, and keeps hostnames in only one split. The first fold from a seeded stratified five-fold hostname-grouped split is reserved as the final test set. Candidate Random Forest configurations are compared with stratified hostname-grouped CV on training groups only; the phishing F1 metric is used for selection. The hybrid risk-score decision threshold is selected from training-only out-of-fold predictions. If a class cannot be stratified across the requested groups, training stops with an actionable error rather than falling back to a random split.

Baseline and selected models are both scored on the same untouched test set. The report includes per-class precision and recall, phishing F1, balanced accuracy, macro/weighted F1, confusion matrix, classification report, ROC-AUC, PR-AUC, false-positive/false-negative counts and examples, and threshold comparisons. The trainer writes `backend/ml_model/reports/evaluation.json` plus confusion-matrix, ROC, precision-recall, feature-importance, and baseline-comparison charts. The final joblib artifact includes the exact ordered feature names, feature-semantics schema version, class mapping, validation-selected threshold, dataset SHA-256, training configuration, and test metrics. The backend verifies compatibility before inference. URLs are never fetched, resolved, or opened by training or scanning.

`tldextract` uses its bundled Public Suffix List snapshot (`suffix_list_urls=()`), so feature extraction does not download a suffix list at runtime. The 21 model feature names and order remain unchanged; the extractor semantics are versioned separately to prevent loading an artifact trained with incompatible feature values. Random Forest probabilities are raw scores, not calibrated real-world probabilities.

Artifacts created before the versioned feature schema and class mapping were added are rejected with an explicit log entry; retrain with the command above before enabling model-backed scans. Joblib artifacts are pickle-based: only load a model artifact from a trusted source.

Latest measured run in this workspace (UCI PhiUSIIL, `--phishing-label 0`; random seed 42):

- Cleaning: 235,795 source rows; 0 missing URL/label records; 18 invalid URLs; 0 conflicting URLs; 437 duplicate URLs removed; 235,340 rows remain. Before cleaning there were 134,850 legitimate and 100,945 phishing records; after cleaning, 134,850 legitimate and 100,490 phishing URLs.
- Split: stratified five-fold hostname-grouped split; first fold held out (47,069 test URLs across 43,813 host groups). Train/test hostname-group overlap was 0. CV used three stratified group folds on the training split only.
- Selected candidate: 150 trees, `class_weight=None`, `min_samples_leaf=2`, `max_features=0.8`, `max_depth=32`, and `min_samples_split=5`. Its validation phishing F1 was 0.995458 ± 0.000011 (mean ± sample standard deviation). The validation-selected hybrid risk threshold was 43/100, versus the default 60/100.

| Untouched test metric | Baseline config, threshold 60 | Selected config, threshold 43 |
| --- | ---: | ---: |
| Accuracy | 0.995305 | 0.996112 |
| Balanced accuracy | 0.994508 | 0.995511 |
| Phishing precision | 0.999950 | 0.999498 |
| Phishing recall | 0.989054 | 0.991392 |
| Phishing F1 | 0.994472 | 0.995429 |
| Legitimate precision | 0.991909 | 0.993624 |
| Legitimate recall | 0.999963 | 0.999629 |
| Macro F1 | 0.995196 | 0.996023 |
| Weighted F1 | 0.995301 | 0.996110 |
| ROC-AUC (raw model score) | 0.997586 | 0.996944 |
| PR-AUC (raw model score) | 0.998149 | 0.997732 |

Confusion matrices use rows/columns ordered **legitimate, phishing**: baseline `[[26970, 1], [220, 19878]]`; selected `[[26961, 10], [173, 19925]]`. On this test split, the lower threshold raised phishing recall and reduced false negatives from 220 to 173, while false positives increased from 1 to 10 and phishing precision/ROC-AUC/PR-AUC were slightly lower. Example selected-model false negatives include `www.faewood.com` and `www.quangtuantn.com`, which had no strong lexical rule signals; URL-only features cannot reliably identify every phishing URL. False positives include `www.beltran.work` and `www.westulverstoneprimary.education.tas.edu.au`.

The leading impurity feature importances were `uses_https` (0.4732), `path_length` (0.4585), `digit_count` (0.0333), and `subdomain_count` (0.0197). These are dataset-specific importance scores, not causal explanations; the dominance of HTTPS and path length is a reason to test against more diverse, temporally and registrable-domain-separated data. Baseline and selected metrics above were produced by training both configurations on the same training fold and evaluating them on the same untouched test fold. The baseline uses the previous 500-tree balanced configuration; the selected model uses the validation-tuned configuration and threshold. These offline dataset results are not a field-performance claim.

The machine-readable report and charts are saved under `backend/ml_model/reports/`. The run took about 609 seconds in this environment. Hostname grouping prevents the exact normalized hostname (with `www.` normalized) from appearing across folds, but does not prevent sibling subdomains or registrable domains from crossing folds and does not establish temporal generalization.

### Verify the saved model and scan API

From the project root, run these commands in separate PowerShell windows:

```powershell
Set-Location backend
..\.venv\Scripts\python.exe -m ml_model.verify_model
..\.venv\Scripts\python.exe manage.py test scanner
..\.venv\Scripts\python.exe manage.py runserver 127.0.0.1:8000
```

The model check validates the artifact's schema, ordered feature metadata, feature count, and class mapping, then predicts local test strings using the same feature extractor as training and inference. It never opens or requests the URLs; the example labels describe URL shape only and are not expected outcomes. If the classifier has native feature-name metadata, its order is checked too; this Random Forest was trained with positional rows, so the artifact's versioned ordered feature list is the source of feature-name metadata.

The current smoke check assigns `https://example.com/` to phishing with a raw model score of 1.0. This reserved example domain is a clear false positive outside the held-out evaluation, reinforcing that the dataset metrics do not guarantee generalization.

In another PowerShell window, start the frontend and create a production build:

```powershell
Set-Location frontend
npm run dev
npm run build
```

The development server proxies `/api` to `http://127.0.0.1:8000`. For a manual integration check, scan a valid URL and confirm the displayed verdict and risk score match the `/api/scan/` response; also try an empty input and a malformed hostname, and confirm an error is shown without navigating to a result. The frontend provides a loading state while scans are in progress. The Django API tests cover valid, empty/malformed, phishing, legitimate, missing-model, and prediction-error cases.

## Online deployment preparation (Render API + Vercel frontend)

The backend can be deployed from the root [render.yaml](./render.yaml) Blueprint to a Render Python web service and managed PostgreSQL database. The configuration uses a persistent disk for the model, requires Django production mode, serves Django static assets with WhiteNoise, runs migrations/`collectstatic` before deploy, and starts one Gunicorn worker. The one-worker setting limits duplicate model memory use. Persistent disks and the configured Render service/database plans are paid resources; check current provider pricing before confirming creation.

The saved model is deliberately ignored by Git and is not copied into the deployment automatically. The Render service expects the trusted artifact at `/var/data/phishing_rf.joblib`. Upload it to the mounted persistent disk using a private, short-lived HTTPS download URL or another trusted transfer method; verify its SHA-256 against the local file before restarting the service. Do not put a signed URL, storage credential, or model secret in source control or this README. Without the model file, the backend intentionally falls back to rules-only analysis.

The local model path remains the default when `PHISHING_MODEL_PATH` is unset. The Render mount path is supplied by the Blueprint; do not change the local model or commit a copy of the joblib file.

The workspace does not currently contain a Git repository. First create a private GitHub repository and push this project, keeping `data/`, local databases, virtual environments, and secrets out of it. The `.joblib` artifact is ignored as well; use the Render disk procedure above rather than making it public. In Render, create a Blueprint from that private repository. The Blueprint starts with the placeholder `https://your-project.vercel.app`; replace it with the exact Vercel frontend origin once that deployment exists.

For Vercel, import the same repository with **Root Directory** `frontend`. Use `npm run build` as the build command and `dist` as the output directory. Set the build environment variable `VITE_API_BASE` to the Render API origin (for example, `https://signalguard-api.onrender.com`, without a trailing slash). Vite embeds this value at build time. After Vercel assigns the frontend URL, add that exact `https://...` origin to Render's `CORS_ALLOWED_ORIGINS`, then redeploy/restart the API as required by the dashboard.

### Deployment environment variables

Set these in the Render dashboard/Blueprint environment. Never paste real values into Git or screenshots.

| Variable | Value/source |
| --- | --- |
| `DJANGO_ENV` | `production` (Blueprint) |
| `DJANGO_DEBUG` | `false` (Blueprint) |
| `DJANGO_SECRET_KEY` | Generated privately by Render (Blueprint); do not reuse the local development fallback |
| `DATABASE_URL` | Render PostgreSQL `connectionString` (Blueprint reference) |
| `CORS_ALLOWED_ORIGINS` | Exact Vercel HTTPS origin, e.g. `https://your-project.vercel.app` (replace the Blueprint placeholder) |
| `PHISHING_MODEL_PATH` | `/var/data/phishing_rf.joblib` (Blueprint persistent disk path) |
| `RENDER_EXTERNAL_HOSTNAME` | Supplied by Render; settings add it to `ALLOWED_HOSTS` |
| `VITE_API_BASE` | In Vercel project settings: Render API HTTPS origin, without trailing slash; build-time, not a secret |

Render dashboard: create the Blueprint from `render.yaml`; confirm the `signalguard-api` service is rooted at `backend`; confirm `signalguard-db` is connected; set the CORS origin after Vercel exists; wait for successful build/migrations; upload and checksum-verify the model on the mounted disk; then restart and test `/admin/login/` as the configured health path. The API uses the `PORT` supplied by Render. The optional Chrome extension is still local-only: its manifest permission and API address point to `127.0.0.1:8000`; deploying the website does not reconfigure the extension.

### Deployment steps and verification

1. Review the existing model generalization warning above. The current artifact flags several well-known legitimate URLs as phishing; deployment does not resolve this model-quality issue.
2. Create a private GitHub repository, push the project, and import its root `render.yaml` as a Render Blueprint. Confirm the paid web-service disk and PostgreSQL resources/pricing in the Render dashboard.
3. Configure `CORS_ALLOWED_ORIGINS` with the Vercel origin once known. Render generates `DJANGO_SECRET_KEY`; keep it private. The API service hostname is included automatically through Render's `RENDER_EXTERNAL_HOSTNAME` variable.
4. In the backend environment, confirm `PHISHING_MODEL_PATH=/var/data/phishing_rf.joblib`. Obtain the local checksum with:

   ```powershell
   Get-FileHash .\backend\ml_model\models\phishing_rf.joblib -Algorithm SHA256
   ```

   Upload that exact artifact to the Render persistent disk, then compare the remote SHA-256 with the local result. Restart the service after upload so its model loader reads the artifact.
5. Import the repository into Vercel using the `frontend` root directory. Set `VITE_API_BASE` to the Render API origin and deploy the frontend.
6. Set Render `CORS_ALLOWED_ORIGINS` to the exact deployed Vercel origin and redeploy/restart the API.
7. Verify the live API and frontend rather than assuming a successful build means deployment works. Submit a scan through the deployed frontend; in the response verify HTTP 201, `analysis_mode: "hybrid"`, and `model_available: true`. Check the browser console/network tab for CORS or request errors. A successful response does not establish prediction accuracy; the documented false positives still apply.

This project is prepared for, but has **not** been deployed by these local changes. Do not call it deployed until the actual Render and Vercel URLs pass the live checks above. Keep provider secrets in provider environment settings only.

### Publish to a private GitHub repository

This workspace has no Git repository configured. First create an **empty private** GitHub repository in your account. From PowerShell at the project root, initialize it and inspect the ignore rules before committing:

```powershell
Set-Location C:\Users\VED\OneDrive\Desktop\innovativeproject
git init
git add .
git status --short
git diff --cached --name-only
```

Confirm `.env` files, databases, `data/`, virtual environments, `node_modules/`, generated `staticfiles/`, and `backend/ml_model/models/*.joblib` are not staged. Then commit and connect the private remote (replace the placeholder with the repository URL copied from GitHub):

```powershell
git diff --cached
git commit -m "Prepare SignalGuard for deployment"
git branch -M main
git remote add origin https://github.com/<YOUR-ACCOUNT>/<YOUR-PRIVATE-REPOSITORY>.git
git push -u origin main
```

Do not commit the model to make deployment easier; use the private persistent-disk upload procedure. If any secret or model was staged, stop before committing, unstage it, and recheck the staged file list.

#### Independent inference smoke check: generalization warning

The post-training smoke check scored `https://example.org` and the official `https://paypal.com/` at 65/100 risk; neither hostname appears in the supplied dataset. `https://www.pythonanywhere.com` scored 64/100. This last URL is also a known selected-model false positive in the untouched test set (the source CSV labels it legitimate), so it is already included in the metrics above; it is not an independent sample. All three scores exceed the selected phishing threshold and were returned as phishing by this artifact. These false positives are a material generalization warning. Do not treat the high grouped holdout metrics as evidence that the model is ready for deployment or trust its predictions as proof a site is malicious. Evaluate on a separately sourced, reviewed dataset with domain- and time-separated splits before relying on model-backed verdicts.

### Feature extraction and explanations

`scanner.detection.features.extract_url_features(url)` is the shared feature entry point for scans and training. It uses a bundled Public Suffix List for registrable-domain parsing and checks common Unicode/punycode confusables in the registrable domain and deceptive subdomains. Brand matches are lexical warnings, not proof of impersonation. Rule explanations describe URL-only signals, not remote page content. The displayed model score is a raw classifier score blended with rules, not a calibrated probability. Per-scan model explanations are included only when optional SHAP is installed and can explain the artifact.

Install `backend/requirements-optional.txt` instead of the base requirements to enable local SHAP contributions for the trained Random Forest. If SHAP is not installed or cannot explain an artifact, the API still returns the rule-based explanations and the model risk score.

## Database design

```mermaid
erDiagram
  USER ||--o{ URL_SCAN : owns
  URL_SCAN ||--o{ FEEDBACK : receives
  USER o|--o{ FEEDBACK : submits
  USER {
    int id PK
    string username
    string email
    string password_hash
  }
  URL_SCAN {
    int id PK
    int user_id FK
    string url
    string verdict
    int risk_score
    string analysis_mode
    json features
    json reasons
    datetime created_at
  }
  FEEDBACK {
    int id PK
    int scan_id FK
    int user_id FK
    bool prediction_correct
    string suggested_label
    string review_status
    datetime created_at
  }
```

Brand names are a curated code-level list in the feature extractor; redirect chains are not stored because remote redirects are not requested or followed in this build. Django's user model stores password hashes. Anonymous scans have a null owner and are not exposed through account history.

## API

All endpoints are under `/api/`. JSON errors use a readable `error` message where applicable.

| Method | Endpoint | Access | Purpose |
| --- | --- | --- | --- |
| `POST` | `/auth/register/` | Public | Create account; password minimum 10 characters |
| `POST` | `/auth/token/` | Public | Obtain JWT access and refresh tokens |
| `POST` | `/auth/token/refresh/` | Public | Refresh an access token |
| `GET` | `/profile/` | JWT | Current account profile |
| `POST` | `/scan/` | Public, throttled | Analyze `{ "url": "https://example.org" }` |
| `POST` | `/scan/text/` | Public, throttled | Extract and analyze up to 20 unique HTTP(S) links from `{ "text": "..." }` |
| `POST` | `/scan/qr/` | Public, throttled | Analyze `{ "decoded_url": "https://example.org" }` from local QR decoding |
| `GET` | `/history/` | JWT | Current user's latest 100 scans |
| `GET` | `/scan/<id>/` | JWT | One of the current user's scans |
| `POST` | `/feedback/` | Public, throttled | Submit `{ "scan_id": 1, "prediction_correct": false }` |
| `GET` | `/dashboard/` | JWT | Counts, average risk, seven-day trend and recent scans for this user |
| `POST` | `/brand-check/` | Public, throttled | Check a URL for a possible brand lookalike |

Scan responses include `verdict`, `risk_score`, `analysis_mode`, `features`, `reasons`, `recommendations`, `content_analysis`, and `redirect_analysis`. `content_analysis` is `unavailable`; `redirect_analysis` is `not_performed`.

## User workflow

```mermaid
flowchart TD
  Start[Open SignalGuard] --> Choose{What should be checked?}
  Choose -->|A URL| Submit[Submit a URL]
  Choose -->|A message| Extract[Extract each link]
  Choose -->|A QR code| Decode[Decode in browser]
  Extract --> Analyze[Run URL analysis]
  Decode --> Analyze
  Submit --> Analyze
  Analyze --> Explain[Show risk, reasons and recommendation]
  Explain --> Feedback[Optional reviewed feedback]
  Explain --> Save{Signed in?}
  Save -->|Yes| History[Save to private history]
  Save -->|No| Guest[Return result without account history]
```

## Local setup

Requirements: Python 3.13.5 (the checked deployment runtime), Node.js 20+, npm. PostgreSQL is optional for local development; SQLite is the default. Commands below use PowerShell from the repository root.

1. Create the Python environment and install backend packages:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
```

2. Create the local database tables and run backend tests:

```powershell
.\.venv\Scripts\python.exe backend\manage.py migrate
.\.venv\Scripts\python.exe backend\manage.py test scanner
Set-Location backend
..\.venv\Scripts\python.exe -m ml_model.verify_model
Set-Location ..
```

3. Start Django in one terminal:

```powershell
.\.venv\Scripts\python.exe backend\manage.py runserver
```

4. Install and run the React app in another terminal:

```powershell
npm --prefix frontend install
npm --prefix frontend run dev
```

Open the Vite URL shown in the terminal (normally `http://localhost:5173`). The development server proxies `/api` to `http://127.0.0.1:8000`.
The backend uses Python and Django; run npm commands against `frontend`, not `backend`.

### PostgreSQL

Create a PostgreSQL database, install the `psycopg` dependency from `requirements.txt`, and set the connection URL before Django commands:

```powershell
$env:DATABASE_URL = "postgresql://signalguard:replace-me@localhost:5432/signalguard"
\.venv\Scripts\python.exe backend\manage.py migrate
\.venv\Scripts\python.exe backend\manage.py runserver
```

For a non-local deployment, set a random `DJANGO_SECRET_KEY`, `DJANGO_DEBUG=false`, an explicit `DJANGO_ALLOWED_HOSTS`, and `CORS_ALLOWED_ORIGINS` to the exact frontend origin(s). HTTPS termination and production database backups are deployment responsibilities.

### Admin and reviewed feedback

```powershell
\.venv\Scripts\python.exe backend\manage.py createsuperuser
```

Review scans and feedback at `/admin/`. An administrator must select `approved` and provide a reviewed `suggested_label` before exporting. This is a manual workflow; it never retrains on a user submission.

```powershell
Set-Location backend
..\.venv\Scripts\python.exe -m ml_model.export_approved_feedback ..\data\reviewed_feedback.csv
..\.venv\Scripts\python.exe -m ml_model.train ..\data\reviewed_feedback.csv
```

The export maps reviewed `safe` to the binary legitimate class and reviewed `suspicious`/`phishing` to the phishing class. Inspect that policy and the source records before training.

## Browser extension

Load `browser-extension/` as an unpacked extension at `chrome://extensions` with developer mode enabled. Start the local API at port 8000. The extension only asks to analyze a selected link; it never blocks or opens a link automatically. A high-risk result still has an explicit **Open link anyway** control. The prototype host permission is limited to `http://127.0.0.1:8000/*`; change permissions deliberately for another API origin.

## Security notes

- Django ORM handles SQL queries; passwords are handled by Django's password hasher.
- Anonymous API requests are throttled to 30 requests per minute by DRF's anonymous throttle.
- URL schemes, hosts, embedded credentials, URL lengths, image MIME types and image sizes are validated.
- The server does not resolve DNS or request target URLs, avoiding redirects and SSRF through the scan endpoints.
- CORS uses an explicit origin allowlist; JWT is passed in the `Authorization` header.
- QR images are limited to PNG/JPEG/WebP and 5 MB, decoded in the browser, and not uploaded.
- The Django development server and default key are for local development only.

## Screenshots

No screenshots are included yet. Use the [college demo checklist](#college-demo-checklist) to capture real local or deployed screenshots. Do not present screenshots of local runs as proof of a public deployment.

## Evaluation and limitations

The selected model's saved test results are reported above and in [evaluation.json](./backend/ml_model/reports/evaluation.json). Accuracy, phishing precision/recall/F1, and the confusion matrix use the hybrid rule/model risk score at threshold 43; ROC-AUC and PR-AUC use raw Random Forest scores. The held-out split has 47,069 URLs.

The source dataset's numeric convention is 0=phishing and 1=legitimate. Training with `--phishing-label 0` maps this to the inference convention **0=legitimate, 1=phishing**. The saved report and model metadata record this mapping, feature schema version 2, and the ordered 21-feature list shared by training and inference.

The recorded split has 437 exact normalized duplicate URLs removed, no conflicting labels, and zero overlap for the grouping key (normalized hostname with leading `www.` removed). This does not guarantee registrable-domain separation—sibling subdomains may cross the split—or temporal generalization. The model also classifies known legitimate examples such as `https://example.com/` as phishing in local smoke checks. These scores are dataset-specific results, not a real-world accuracy guarantee or deployment-readiness claim.

Frontend/backend browser integration, loading and validation behavior, Django scanner tests, model loading, and the frontend production build have been tested locally. No live hosted URL has been verified.

## College demo checklist

Analyze URL strings without visiting or opening the sites. Model predictions are not ground truth.

- [ ] Start Django and Vite with the local commands above; confirm the scanner page loads.
- [ ] Capture the main scanner and its URL-only/privacy notice.
- [ ] Scan `https://example.com/` as a **known false-positive demonstration**; explain that this reserved example domain was classified as phishing in the inspected model, which illustrates a current limitation.
- [ ] Scan `http://paypa1-login-security.xyz/verify` as a suspicious-looking test string. Show the result explanation, analysis mode, and risk score; do not open the URL.
- [ ] Submit an empty input and `https://example..com/`; capture the validation messages.
- [ ] Paste a harmless message containing `https://example.com/` into Message Scan and show the extracted link result.
- [ ] Capture the QR scanner screen; if demonstrating QR decoding, create a QR with `https://example.com/` and do not follow its decoded link.
- [ ] Optionally demonstrate registration/login, history, and dashboard with a demo account. Never include real passwords, JWTs, or personal history in screenshots.
- [ ] Capture the evaluation table and confusion matrix with the class order and false-positive warning visible.
- [ ] Label screenshots as local checks unless the deployed frontend and API URLs have both been tested successfully.

Store only screenshots actually captured, for example in `docs/screenshots/`. No screenshots are currently committed.

## Tests and evaluation

Backend tests cover feature extraction, brand lookalikes, API validation, persistence, user isolation, message scanning, and a real holdout model-training run. Run `python backend/manage.py test scanner` inside the configured environment. Frontend production build: `cd frontend; npm run build`.

Never interpret test fixture metrics as real-world model performance. For a project report, record the dataset name, version, license, label policy, split, and actual command output from your chosen dataset.

## Future scope

- Curated, provenance-tracked datasets and scheduled, reviewed model evaluation.
- SHAP/LIME explanations for a validated trained model.
- Isolated redirect and content analysis with strict egress controls and a disposable sandbox.
- Screenshot-based UI checks in an isolated capture service.
- Persistent brand records and multi-class calibration with a representative dataset.
- Production deployment hardening, monitoring, audit logs, and rate limiting by account/IP.