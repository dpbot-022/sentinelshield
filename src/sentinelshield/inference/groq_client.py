import httpx
from typing import Optional
from sentinelshield.config import settings
from sentinelshield.inference.base import BaseInferenceProvider


class GroqInferenceProvider(BaseInferenceProvider):
    """Asynchronous client for Groq Cloud API running open weights at ultra-fast speeds"""

    def __init__(
        self,
        api_key: str = settings.GROQ_API_KEY,
        base_url: str = settings.GROQ_BASE_URL,
        default_model: str = settings.GROQ_MODEL,
    ):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.default_model = default_model

    async def generate(
        self,
        prompt: str,
        system_prompt: str,
        json_mode: bool = True,
        temperature: float = 0.1,
        model: Optional[str] = None,
    ) -> str:
        if not self.api_key:
            raise ValueError("Groq API key not configured. Set GROQ_API_KEY environment variable.")

        target_model = model or self.default_model
        endpoint = f"{self.base_url}/chat/completions"

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": target_model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            "temperature": temperature,
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}

        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.post(endpoint, json=payload, headers=headers)
                response.raise_for_status()
                data = response.json()
                return data["choices"][0]["message"]["content"]
            except httpx.HTTPStatusError as e:
                raise RuntimeError(f"Groq API returned HTTP {e.response.status_code}: {e.response.text}")
