import re

file_path = r'shared\sudarshan_core\engines\agentic\field_semantics.py'

with open(file_path, 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Remove existing BENEFICIARY lines
content = re.sub(r'\s*SemanticDefinition\(FieldType\.BENEFICIARY_NAME.*?$', '', content, flags=re.MULTILINE)
content = re.sub(r'\s*SemanticDefinition\(FieldType\.BENEFICIARY_ACCOUNT.*?$', '', content, flags=re.MULTILINE)

# 2. Insert missing and rearranged definitions before ACCOUNT_NUMBER
insert_block = '''
    SemanticDefinition(FieldType.EMPLOYEE_ID, ["employee id", "emp id"]),
    SemanticDefinition(FieldType.POLICY_NUMBER, ["policy number", "policy no"]),
    SemanticDefinition(FieldType.REFERRAL_CODE, ["referral code", "referral"]),
    SemanticDefinition(FieldType.RECOVERY_CODE, ["recovery code"]),
    SemanticDefinition(FieldType.BENEFICIARY_NAME, ["beneficiary name", "payee name", "recipient name"], ["textPersonName"]),
    SemanticDefinition(FieldType.BENEFICIARY_ACCOUNT, ["beneficiary account", "beneficiary account number", "payee account"], ["number"]),
'''
content = content.replace(
    'SemanticDefinition(FieldType.ACCOUNT_NUMBER',
    insert_block.lstrip('\n') + '    SemanticDefinition(FieldType.ACCOUNT_NUMBER'
)

# 3. Add EMAIL_OTP before OTP
content = content.replace(
    'SemanticDefinition(FieldType.OTP',
    'SemanticDefinition(FieldType.EMAIL_OTP, ["email otp", "email code"]),\\n    SemanticDefinition(FieldType.OTP'
)

# 4. Add SECURITY_ANSWER at the beginning or before USERNAME
content = content.replace(
    'SemanticDefinition(FieldType.USERNAME',
    'SemanticDefinition(FieldType.SECURITY_ANSWER, ["security answer", "security question answer", "secret answer"], ["text"]),\\n    SemanticDefinition(FieldType.USERNAME'
)

with open(file_path, 'w', encoding='utf-8') as f:
    f.write(content)
