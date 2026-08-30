import os
import json
import urllib.request
import urllib.error
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

class LLMProvider(ABC):
    """Abstract Base Class for AI Reasoning Providers."""
    
    @abstractmethod
    def generate_reasoning(self, prompt: str, context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Generate structured reasoning JSON or return None if provider fails."""
        pass

class MockLLMProvider(LLMProvider):
    """Mock Provider for deterministic offline testing and fallbacks."""
    
    def __init__(self, response_override: Optional[Dict[str, Any]] = None, should_fail: bool = False):
        self.response_override = response_override
        self.should_fail = should_fail

    def generate_reasoning(self, prompt: str, context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if self.should_fail:
            return None
        if self.response_override is not None:
            return self.response_override

        # Grounded mock response based on deterministic analysis context
        det = context.get("deterministic_findings", {})
        events = context.get("events", [])
        valid_event_ids = [e.get("event_id") for e in events if isinstance(e, dict) and e.get("event_id")]

        reasoning_steps = []
        for idx, step in enumerate(det.get("reasoning_steps", []), 1):
            source_id = valid_event_ids[idx - 1] if idx - 1 < len(valid_event_ids) else (valid_event_ids[0] if valid_event_ids else "EVT-0000")
            reasoning_steps.append({
                "step": idx,
                "action": f"AI Evaluated: {step.get('action')}",
                "finding": f"{step.get('finding')} [Ref: {source_id}]"
            })

        return {
            "summary": f"AI Assessment: {det.get('summary', 'Security incident analyzed.')}",
            "root_cause": f"AI Inferred Root Cause: {det.get('root_cause', 'Unknown attack vector.')}",
            "assessed_severity": det.get("assessed_severity", "LOW"),
            "confidence_score": det.get("confidence_score", 0.5),
            "reasoning_steps": reasoning_steps
        }

class OpenAIRouterProvider(LLMProvider):
    """Generic OpenAI-compatible HTTP API Provider (supports OpenRouter, Local Gateway, or OpenAI)."""
    
    def __init__(self, api_key: Optional[str] = None, api_base: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY") or os.environ.get("LLM_API_KEY")
        self.api_base = (api_base or os.environ.get("OPENAI_API_BASE") or "https://api.openai.com/v1").rstrip("/")
        self.model = model or os.environ.get("LLM_MODEL") or "gpt-4o-mini"

    def generate_reasoning(self, prompt: str, context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not self.api_key:
            return None

        url = f"{self.api_base}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "model": self.model,
            "response_format": {"type": "json_object"},
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are an expert SOC Security Agent. Analyze security incident telemetry and return JSON with keys: "
                        "summary, root_cause, assessed_severity, confidence_score, reasoning_steps. "
                        "Do not invent unreferenced events or entities."
                    )
                },
                {
                    "role": "user",
                    "content": f"{prompt}\nContext:\n{json.dumps(context)}"
                }
            ],
            "temperature": 0.1
        }

        try:
            req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=10) as response:
                if response.status == 200:
                    resp_body = json.loads(response.read().decode("utf-8"))
                    content_str = resp_body["choices"][0]["message"]["content"]
                    return json.loads(content_str)
        except Exception:
            return None

        return None

def get_provider() -> LLMProvider:
    """Factory to return configured LLMProvider based on environment."""
    api_key = os.environ.get("OPENAI_API_KEY") or os.environ.get("LLM_API_KEY")
    if api_key:
        return OpenAIRouterProvider()
    return MockLLMProvider()
