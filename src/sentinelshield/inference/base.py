from abc import ABC, abstractmethod
from typing import Optional


class BaseInferenceProvider(ABC):
    """Abstract interface for LLM inference providers"""

    @abstractmethod
    async def generate(
        self,
        prompt: str,
        system_prompt: str,
        json_mode: bool = True,
        temperature: float = 0.1,
        model: Optional[str] = None,
    ) -> str:
        """Execute text generation against the target model"""
        pass
