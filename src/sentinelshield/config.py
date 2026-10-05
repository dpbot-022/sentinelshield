import os
from typing import Dict, Any
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    PROJECT_NAME: str = "SentinelShield"
    VERSION: str = "1.0.0"
    ENVIRONMENT: str = Field(default="development", description="Environment: development, staging, production")
    DEBUG: bool = Field(default=False, description="Debug mode")

    # Host & Port
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # Security & JWT
    JWT_SECRET_KEY: str = Field(
        default="sentinel-shield-ultra-secure-zero-trust-secret-key-2026-xyz",
        description="Cryptographic secret key for signing JWT tokens",
    )
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours

    # Rate Limiting Tier Defaults (requests per minute, burst allowance)
    RATE_LIMIT_TIERS: Dict[str, Dict[str, int]] = {
        "guest": {"rate": 5, "burst": 5, "window_seconds": 60},
        "tier-1": {"rate": 30, "burst": 10, "window_seconds": 60},
        "tier-2": {"rate": 90, "burst": 30, "window_seconds": 60},
        "admin": {"rate": 300, "burst": 50, "window_seconds": 60},
    }

    # Inference Providers
    DEFAULT_PROVIDER: str = "groq"  # "groq", "ollama", "simulator"
    OLLAMA_BASE_URL: str = Field(default="http://localhost:11434", description="Ollama local endpoint")
    OLLAMA_MODEL: str = Field(default="phi3:mini", description="Ollama target model name")
    GROQ_BASE_URL: str = Field(default="https://api.groq.com/openai/v1", description="Groq API base URL")
    GROQ_API_KEY: str = Field(default="", description="Groq API key")
    GROQ_MODEL: str = Field(default="qwen/qwen3.8-27b", description="Groq model name")
    DATABASE_PATH: str = Field(default="sentinelshield.db", description="SQLite database file path")

    # Guardrail Controls
    PROMPT_INJECTION_THRESHOLD: float = Field(
        default=0.65, description="Confidence threshold above which prompt injection is blocked"
    )
    ENABLE_IN_MEMORY_PII_REDACTION: bool = True
    CANARY_TOKEN_HEADER: str = "X-Sentinel-Canary"

    # Self-Healing JSON Loop
    SELF_HEALING_MAX_RETRIES: int = 3
    SELF_HEALING_TIMEOUT_SECONDS: float = 3.5

    model_config = {"env_file": ".env", "extra": "allow"}


settings = Settings()
