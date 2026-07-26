from app.models.schemas import StaticAnalysisFlags

FAMILIES = ["Xenomorph", "Cerberus", "Anubis", "Hydra", "SpyNote", "Joker", "Drinik", "Unknown"]

def classify_family(flags: StaticAnalysisFlags) -> tuple[str, str]:
    """
    Returns (Family, Matched Rule)
    """
    if flags.has_accessibility_abuse and flags.has_sms_read_write and flags.targets_indian_banks:
        return "Xenomorph", "Accessibility + SMS + banking package match = Xenomorph-pattern"
    elif flags.has_system_alert_window and flags.has_sms_read_write and flags.targets_indian_banks:
        return "Cerberus", "System Alert Window (Overlay) + SMS + banking package match = Cerberus-pattern"
    elif flags.has_accessibility_abuse and "addJavascriptInterface" in flags.dangerous_apis_found:
        return "Anubis", "Accessibility + Webview Injection = Anubis-pattern"
    elif flags.has_accessibility_abuse and flags.has_system_alert_window:
        return "Hydra", "Accessibility + System Alert Window = Hydra-pattern"
    elif flags.has_accessibility_abuse and "Runtime.exec" in flags.dangerous_apis_found:
        return "SpyNote", "Accessibility + Command Execution = SpyNote-pattern"
    elif flags.has_sms_read_write and "System.loadLibrary" in flags.dangerous_apis_found:
        return "Joker", "SMS + Native Library Loading = Joker-pattern"
    elif flags.targets_indian_banks and "DexClassLoader" in flags.dangerous_apis_found:
        return "Drinik", "Banking Target + Dynamic Code Loading = Drinik-pattern"
    
    return "Unknown", "No specific family signature matched."
