import re

file_path = r'shared\sudarshan_core\engines\agentic\field_semantics.py'

with open(file_path, 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Move EMAIL_OTP above EMAIL
content = re.sub(r'\s*SemanticDefinition\(FieldType\.EMAIL_OTP.*?$', '', content, flags=re.MULTILINE)
content = content.replace(
    'SemanticDefinition(FieldType.EMAIL,',
    'SemanticDefinition(FieldType.EMAIL_OTP, ["email otp", "email code"]),\\n    SemanticDefinition(FieldType.EMAIL,'
)

# 2. Move BENEFICIARY_NAME above FULL_NAME
content = re.sub(r'\s*SemanticDefinition\(FieldType\.BENEFICIARY_NAME.*?$', '', content, flags=re.MULTILINE)
content = content.replace(
    'SemanticDefinition(FieldType.FIRST_NAME,',
    'SemanticDefinition(FieldType.BENEFICIARY_NAME, ["beneficiary name", "payee name", "recipient name"], ["textPersonName"]),\\n    SemanticDefinition(FieldType.FIRST_NAME,'
)

with open(file_path, 'w', encoding='utf-8') as f:
    f.write(content)
