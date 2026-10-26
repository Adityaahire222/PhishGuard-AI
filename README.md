# PhishGuard AI

PhishGuard AI analyzes email text with the FastAPI backend and an Ollama model configured on your machine. It returns one of `PHISHING`, `LEGITIMATE`, `SUSPICIOUS`, or `INCONCLUSIVE`, along with a risk level, observed indicators, an explanation, and a recommended action. The model's assessment is not verified threat intelligence.

## Limitations

Results depend on the configured model and may include false positives or false negatives. The available small corpus and synthetic checks do not establish real-world detection accuracy. Email text is described to the model as untrusted data, but embedded instructions may still influence its output; prompt-injection resistance has not been established. Treat results as decision support, not as a substitute for independent verification.

## Architecture and data flow

The React frontend sends the email text to the FastAPI backend. The backend validates the request, packages the email as untrusted prompt data, and sends it to the Ollama endpoint configured by `OLLAMA_BASE_URL`. It validates the generated JSON before returning a result. Invalid model output becomes `INCONCLUSIVE` with `UNKNOWN` risk; Ollama request failures return an error. The application does not open or fetch URLs found in the email.

## API

- `GET /health` checks that the API process is responding and returns the configured model tag, prompt hash, and generation settings for evaluation provenance.
- `GET /health/llm` checks model inference and can take as long as a model request.
- `POST /detect` accepts JSON with an `email_text` string containing 1–20,000 characters. Whitespace-only input is rejected.

Example request:

```json
{"email_text":"Subject: Account notice\nPlease verify your account."}
```

The response contains `classification`, `risk_level`, `indicators` (an array of strings), `explanation`, and `recommended_action`. `INCONCLUSIVE` responses use `UNKNOWN` risk; other classifications use `LOW`, `MEDIUM`, or `HIGH`. Risk describes potential impact if the requested action is followed, not confidence or probability; `HIGH` is reserved for potentially serious actions such as credential disclosure, payment, account takeover, or executing/installing an attachment or software. These fields are generated assessments, not verified facts.

## Requirements

- Python 3.10 or newer
- Node.js 22.22.2 or newer in the 22.x line, Node.js 24.15.0 or newer in the 24.x line, or Node.js 26 or newer, plus npm
- [Ollama](https://ollama.com/download) installed locally

## Setup

Run these commands from the project root in PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
ollama pull qwen2.5:3b
```

Ollama must be running locally. If it is not already running as a service, start it in a separate terminal with `ollama serve`. The backend reads `OLLAMA_BASE_URL` and `OLLAMA_MODEL` from `.env`; email text is sent to that configured Ollama service. A non-loopback `OLLAMA_BASE_URL` triggers a startup warning that submitted email text will be sent to a remote service. The application does not fetch URLs found in email text.

## Run the application

Use three PowerShell terminals from the project root.

**Terminal 1 — Ollama:** ensure Ollama is running. If needed:

```powershell
ollama serve
```

**Terminal 2 — FastAPI:**

```powershell
.\.venv\Scripts\Activate.ps1
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

The backend is bound to loopback. Its health endpoints are `http://127.0.0.1:8000/health` and `http://127.0.0.1:8000/health/llm`; interactive API docs are at `http://127.0.0.1:8000/docs`.

**Terminal 3 — React frontend:**

```powershell
Set-Location frontend
npm ci
Copy-Item .env.example .env.local
npm run dev
```

Open the local URL printed by Vite (by default `http://127.0.0.1:5173`). The frontend API endpoint is configured by `VITE_API_BASE_URL` in `frontend/.env.local`; the default is `http://127.0.0.1:8000`. This frontend variable is a public endpoint setting, not a place for secrets. The backend permits browser requests from the two local Vite origins only. Keep the API bound to loopback; it has no authentication or rate limiting for network exposure.

## Frontend checks

Run from `frontend`:

```powershell
npm test
npm run build
```

## Backend tests

From the project root:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests
```

## Experimental detector comparison

The production `/detect` route uses the original single-stage detector. The two-stage detector is experimental and is used only by the comparison script. To run its fixed synthetic cases, including three repetitions of the with/without-instructions pair, use this command from the project root:

```powershell
.\.venv\Scripts\python.exe scripts/compare_detectors.py
```

This sends the synthetic messages to the configured Ollama endpoint and prints sanitized result metadata, prompt hashes, generation settings, and latency. It does not print or save message text. The two-stage path assigns evidence IDs after checking each exact quotation and fails closed to `INCONCLUSIVE` for malformed or unknown references. Analyzer-directed quotations are extracted for audit but withheld from Stage 2. An ID confirms only that a validated observation exists; it does not prove the model interpreted it correctly. Expected labels are provisional and the lexical indicator-support check is only a heuristic. This prototype has not been shown to improve accuracy or guarantee resistance to embedded instructions.

## Project license

No license has been selected for the project code. Choose a project license before public distribution. The source corpus has separate attribution and licensing requirements documented in [datasets/README.md](datasets/README.md).

## Dataset evaluation

Start the API in one terminal, then run the evaluator from the project root in another:

```powershell
uvicorn app.main:app --host 127.0.0.1 --port 8000
python scripts/evaluate_dataset.py datasets/my_labeled_emails.csv --output-dir evaluation-results
```

The CSV must contain `email_text,label`; allowed labels and validation details are documented in [datasets/README.md](datasets/README.md). The evaluator calls `/detect`, does not fetch email URLs, and saves predictions and metrics without email bodies. Failed API calls are reported separately and cause a nonzero exit code. Metrics are meaningful only for a suitable labeled dataset and a running local model.

The included processed corpus has eight unique messages: seven labeled `PHISHING` and one labeled `SUSPICIOUS`, with no `LEGITIMATE` examples. The separate synthetic smoke dataset is also small. These samples and saved runs are for pipeline checks, not representative evidence of detection accuracy. The dataset guide documents the source, CC BY 4.0 attribution, review process, and privacy limits. Raw email, processed email, review, and generated evaluation artifacts are ignored by Git by default; review and explicitly select any data before publishing it.

## Privacy and safe use

Email text is sent to the Ollama endpoint configured for the backend. Review that endpoint and your machine's privacy settings before submitting sensitive messages. The model's classification and explanation are generated assessments; verify unexpected requests through a trusted channel. The API accepts email text up to 20,000 characters.
