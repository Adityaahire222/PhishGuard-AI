from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from .detector import (
    DetectionError,
    classify_message,
)
from .ollama_client import OllamaError, generate_response, inference_metadata
from .schemas import DetectRequest, DetectResponse

app = FastAPI(
    title="PhishGuard AI",
    version="1.0.0",
    description="Local LLM-based phishing email detection",
)

# Local Vite development origins only. The API server should remain bound to loopback.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(_request: Request, exc: RequestValidationError):
    safe_errors = [
        {key: value for key, value in error.items() if key != "input"}
        for error in exc.errors()
    ]
    return JSONResponse(status_code=422, content={"detail": safe_errors})


@app.get("/health")
def health():
    return {"status": "ok", "inference": inference_metadata()}


@app.get("/health/llm")
def llm_health():
    try:
        # This checks actual model inference, not just server availability.
        generate_response("Return this JSON: {\"status\":\"ok\"}")

        return {"status": "ok", "model": "available"}

    except OllamaError:
        raise HTTPException(
            status_code=503,
            detail="The local LLM is unavailable.",
        )


@app.post("/detect", response_model=DetectResponse)
def detect(request: DetectRequest):
    try:
        return classify_message(request.email_text)

    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        ) from exc

    except DetectionError as exc:
        raise HTTPException(
            status_code=503,
            detail=str(exc),
        ) from exc
