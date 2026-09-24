import re
from pathlib import Path

p = Path('shared/sudarshan_core/engines/frida_sandbox.py')
content = p.read_text(encoding='utf-8')

content = re.sub(
    r'try:\s+from sudarshan_core\.engines\.analysis_history import AnalysisHistory\s+from sudarshan_core\.engines\.report_generator import ReportGenerator\s+except ImportError:\s+AnalysisHistory = None\s+ReportGenerator = None\s+logger\.warning\("\[Frida\] Wave 5 reporting modules not found\."\)',
    'try:\n    from sudarshan_core.engines.report_generator import ReportGenerator\nexcept ImportError:\n    ReportGenerator = None\n    logger.warning("[Frida] Wave 5 reporting modules not found.")',
    content
)

content = re.sub(
    r'    if AnalysisHistory is not None:\s+try:\s+history = AnalysisHistory\(\)\s+history\.save_run\(result, apk_sha256="unknown", stage_name="single"\)\s+except Exception as e:\s+logger\.error\(f"\[Frida\] Failed to save analysis history: {e}"\)\n',
    '',
    content
)

p.write_text(content, encoding='utf-8')
