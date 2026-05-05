"""
Gemini Provider (Google)
"""

from typing import Dict
import google.genai as genai
from utils.logger import get_logger

logger = get_logger(__name__)


class GeminiProvider:
    """Google Gemini API provider."""

    def __init__(self, config: Dict):
        """Initialize Gemini provider."""
        self.config = config
        self.api_key = config.get('api_key')
        self.model = config.get('model', 'gemini-1.5-flash')
        self.temperature = config.get('temperature', 0.7)
        self.max_tokens = config.get('max_tokens', 2000)

        if not self.api_key:
            raise ValueError("Gemini API key not provided")

        self.client = genai.Client(api_key=self.api_key)

    def generate(self, prompt: str, **kwargs) -> str:
        """
        Generate response using Gemini.

        Args:
            prompt: Input prompt
            **kwargs: Additional arguments

        Returns:
            Generated response
        """
        try:
            model_name = kwargs.get('model', self.model)
            temperature = kwargs.get('temperature', self.temperature)
            max_tokens = kwargs.get('max_tokens', self.max_tokens)

            system_instruction = "You are a security expert specializing in penetration testing and vulnerability research."

            response = self.client.models.generate_content(
                model=model_name,
                contents=[
                    {"role": "user", "parts": [f"{system_instruction}\n\nUser: {prompt}"]}
                ],
                generation_config={
                    "temperature": temperature,
                    "max_output_tokens": max_tokens,
                }
            )

            return response.text

        except Exception as e:
            logger.error(f"Gemini generation error: {e}")
            raise
