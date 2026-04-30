"""GuardIAn assistant — bilingual FAQ knowledge base + LLM bridge.

Public surface
~~~~~~~~~~~~~~
- :func:`answer` — main entrypoint used by the API router.
- :func:`get_faq` — returns the full bilingual FAQ catalog.
- :func:`get_suggestions` — short list of suggested user prompts.
"""

from app.assistant.service import answer, get_faq_payload as get_faq, get_suggestions

__all__ = ["answer", "get_faq", "get_suggestions"]
