# SUDARSHAN — AI Safety, Circuit Breakers & Resilience

> **Classification:** AUTHORITATIVE  
> **Source Module:** `shared/sudarshan_core/ai/gemini_provider.py`  

---

## 1. 3-State Circuit Breaker Pattern

To prevent external API failures from crashing analyst workflows, the Gemini client implements a stateful circuit breaker:

```
[ AVAILABLE ] --(3 consecutive timeouts/failures)--> [ DEGRADED / OPEN ]
      ^                                                      |
      |-------------(Cooldown 60s passes & success)----------|
```

- **AVAILABLE:** Primary Gemini API key active and healthy.
- **DEGRADED:** Switches automatically to `GEMINI_FALLBACK_API_KEY` and fallback model.
- **OPEN:** External API unreachable. The platform disables generative chat gracefully while all deterministic analysis, scoring, and UI views continue functioning with 100% availability.
