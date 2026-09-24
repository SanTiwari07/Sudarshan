# SUDARSHAN — Historical Design Notes

---

- Initial prototypes evaluated monolithic backend execution before moving to a containerized microservice on port 8001.
- Scoring engine evolved from raw hook-count heuristics (v1) to volume-aware logarithmic tiers with temporal sequence detection (BFCI v2).
