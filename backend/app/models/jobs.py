from enum import Enum

class JobState(str, Enum):
    QUEUED = "QUEUED"
    VALIDATING = "VALIDATING"
    UPLOADING = "UPLOADING"
    STATIC_ANALYSIS = "STATIC_ANALYSIS"
    DYNAMIC_QUEUED = "DYNAMIC_QUEUED"
    DYNAMIC_ANALYSIS = "DYNAMIC_ANALYSIS"
    THREAT_INTEL = "THREAT_INTEL"
    RISK_SCORING = "RISK_SCORING"
    AI_ENRICHMENT = "AI_ENRICHMENT"
    REPORTING = "REPORTING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    RETRYING = "RETRYING"

    @classmethod
    def is_terminal(cls, state: "JobState") -> bool:
        return state in (cls.COMPLETED, cls.FAILED, cls.CANCELLED)

    @classmethod
    def is_active(cls, state: "JobState") -> bool:
        return not cls.is_terminal(state)
