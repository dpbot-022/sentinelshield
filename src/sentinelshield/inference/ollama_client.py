import httpx
from typing import Optional
from sentinelshield.config import settings
from sentinelshield.inference.base import BaseInferenceProvider


class OllamaInferenceProvider(BaseInferenceProvider):
    """Asynchronous client for local Ollama server running open models (phi3, qwen2.5, llama3.2)"""

    def __init__(self, base_url: str = settings.OLLAMA_BASE_URL, default_model: str = settings.OLLAMA_MODEL):
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
        target_model = model or self.default_model
        endpoint = f"{self.base_url}/api/chat"

        payload = {
            "model": target_model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            "stream": False,
            "options": {
                "temperature": temperature,
            },
        }
        if json_mode:
            payload["format"] = "json"

        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.post(endpoint, json=payload)
                response.raise_for_status()
                data = response.json()
                return data.get("message", {}).get("content", "")
            except httpx.ConnectError:
                raise ConnectionError(
                    f"Could not connect to local Ollama at {self.base_url}. Ensure Ollama is running (`ollama serve`)."
                )
            except httpx.HTTPStatusError as e:
                raise RuntimeError(f"Ollama server returned error {e.response.status_code}: {e.response.text}")
