"""
LLM Integration — Provider abstraction, routing e agent per interpretation.

Componenti:
- LLMProvider: Protocol per provider LLM (Ollama, Claude, Gemini)
- OllamaProvider: Provider locale via Ollama /api/generate
- LLMRouter: Routing con fallback tra provider disponibili
- InterpretationAgent: Genera executive summary e risk narrative
"""
