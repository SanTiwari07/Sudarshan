"""
SUDARSHAN - Semantic Field Registry
Provides centralized keywords, input types, and disambiguation rules.
"""
from typing import Dict, List, Pattern
import re
from sudarshan_core.engines.agentic.field_taxonomy import FieldType

def _compile_fuzzy(keywords: List[str]) -> Pattern:
    safe_kws = []
    for kw in keywords:
        kw = kw.replace(" ", r"[\s\-_]*")
        safe_kws.append(f"\\b{kw}\\b")
    return re.compile("(" + "|".join(safe_kws) + ")", re.IGNORECASE)

class SemanticDefinition:
    def __init__(self, field_type: FieldType, keywords: List[str], input_types: List[str] = None):
        self.field_type = field_type
        self.keywords = keywords
        self.input_types = input_types or []
        self.pattern = _compile_fuzzy(keywords)

# 100+ types based on user's comprehensive list
SEMANTIC_REGISTRY = [
    SemanticDefinition(FieldType.PHONE, ["phone", "phone number", "phone no", "mobile", "mobile number", "mobile no", "contact number", "telephone"], ["phone"]),
    SemanticDefinition(FieldType.EMAIL_OTP, ["email otp", "email code"]),
    SemanticDefinition(FieldType.EMAIL, ["email", "email address", "email id", "e-mail", "mail address"], ["textEmailAddress"]),
    SemanticDefinition(FieldType.PASSWORD, ["login password", "password", "pass word", "passwd", "pwd"], ["textPassword", "numberPassword"]),
    SemanticDefinition(FieldType.PASSCODE, ["passcode", "pass code"], ["textPassword", "numberPassword"]),
    SemanticDefinition(FieldType.SECURITY_ANSWER, ["security answer", "security question answer", "secret answer"], ["text"]),
    SemanticDefinition(FieldType.USERNAME, ["username", "user name", "login", "login name", "profile username"]),
    SemanticDefinition(FieldType.USER_ID, ["user id", "userid", "login id"]),
    SemanticDefinition(FieldType.CUSTOMER_ID, ["customer id", "client id"]),
    SemanticDefinition(FieldType.CUSTOMER_NUMBER, ["customer number", "customer no", "crn"]),
    SemanticDefinition(FieldType.CIF, ["cif", "cif number"]),
    
    SemanticDefinition(FieldType.MPIN, ["mpin", "m-pin", "m pin", "mobile pin", "login mpin"], ["numberPassword"]),
    SemanticDefinition(FieldType.TPIN, ["tpin", "t-pin", "transaction pin"], ["numberPassword"]),
    SemanticDefinition(FieldType.UPI_PIN, ["upi pin", "upi passcode"], ["numberPassword"]),
    SemanticDefinition(FieldType.ATM_PIN, ["atm pin", "atm card pin"], ["numberPassword"]),
    SemanticDefinition(FieldType.CARD_PIN, ["card pin", "debit pin", "credit card pin"], ["numberPassword"]),
    SemanticDefinition(FieldType.PIN_CODE, ["pin code", "pincode", "postal pin"], ["number", "text"]),
    SemanticDefinition(FieldType.POSTAL_CODE, ["postal code", "postcode", "area code"], ["number", "text"]),
    SemanticDefinition(FieldType.ZIP_CODE, ["zip", "zip code", "zipcode"], ["number", "text"]),
    SemanticDefinition(FieldType.PIN, ["pin"], ["numberPassword", "number", "textPassword"]),
    SemanticDefinition(FieldType.OTP, ["otp", "one time password", "verification code", "verify code", "sms code", "security code", "auth code"], ["number", "text"]),
    
    SemanticDefinition(FieldType.BENEFICIARY_NAME, ["beneficiary name", "payee name", "recipient name"], ["textPersonName"]),
    SemanticDefinition(FieldType.FIRST_NAME, ["first name", "firstname", "given name"], ["textPersonName"]),
    SemanticDefinition(FieldType.LAST_NAME, ["last name", "lastname", "surname", "family name"], ["textPersonName"]),
    SemanticDefinition(FieldType.MOTHER_NAME, ["mother name", "mother's name", "mothers name", "mother's full name", "mothers full name"], ["textPersonName"]),
    SemanticDefinition(FieldType.MOTHER_MAIDEN_NAME, ["mother maiden name", "mother's maiden name", "mothers maiden name", "maiden name"], ["textPersonName"]),
    SemanticDefinition(FieldType.FATHER_NAME, ["father name", "father's name", "fathers name", "parent name", "parent's name", "parents name"], ["textPersonName"]),
    SemanticDefinition(FieldType.GUARDIAN_NAME, ["guardian name", "guardian's name", "guardians name", "legal guardian"], ["textPersonName"]),
    SemanticDefinition(FieldType.SPOUSE_NAME, ["spouse name", "husband name", "wife name"], ["textPersonName"]),
    SemanticDefinition(FieldType.FULL_NAME, ["name", "full name", "your name"], ["textPersonName"]),
    
    SemanticDefinition(FieldType.DATE_OF_BIRTH, ["date of birth", "dob", "birth date", "birthday"], ["date"]),
    SemanticDefinition(FieldType.AGE, ["age", "current age"], ["number"]),
    
    SemanticDefinition(FieldType.ADDRESS, ["address", "full address", "street address"], ["textPostalAddress"]),
    SemanticDefinition(FieldType.CITY, ["city", "town", "district"], ["textPostalAddress"]),
    SemanticDefinition(FieldType.STATE, ["state", "province"], ["textPostalAddress"]),
    SemanticDefinition(FieldType.COUNTRY, ["country", "nationality"], ["textPostalAddress"]),
    
    SemanticDefinition(FieldType.PAN, ["pan", "pan number", "pan card"], ["textVisiblePassword", "text"]),
    SemanticDefinition(FieldType.AADHAAR, ["aadhaar", "aadhar", "uid", "uidai"], ["number"]),
    SemanticDefinition(FieldType.PASSPORT, ["passport", "passport number"], ["text"]),
    SemanticDefinition(FieldType.VOTER_ID, ["voter id", "voter card", "epic"], ["text"]),
    SemanticDefinition(FieldType.DRIVING_LICENSE, ["driving license", "driving licence", "dl number"], ["text"]),
    
        SemanticDefinition(FieldType.EMPLOYEE_ID, ["employee id", "emp id"]),
    SemanticDefinition(FieldType.POLICY_NUMBER, ["policy number", "policy no"]),
    SemanticDefinition(FieldType.REFERRAL_CODE, ["referral code", "referral"]),
    SemanticDefinition(FieldType.RECOVERY_CODE, ["recovery code"]),
    SemanticDefinition(FieldType.BENEFICIARY_ACCOUNT, ["beneficiary account", "beneficiary account number", "payee account"], ["number"]),
    SemanticDefinition(FieldType.ACCOUNT_NUMBER, ["account number", "account no", "bank account number", "acct", "a/c"], ["number"]),
    SemanticDefinition(FieldType.ACCOUNT_HOLDER_NAME, ["account holder", "account holder name", "account name"], ["textPersonName"]),
    SemanticDefinition(FieldType.IFSC, ["ifsc", "ifsc code"], ["text"]),
    SemanticDefinition(FieldType.BRANCH_CODE, ["branch code"], ["text", "number"]),
    
    SemanticDefinition(FieldType.CARD_NUMBER, ["card number", "card no", "debit card", "credit card"], ["number"]),
    SemanticDefinition(FieldType.CARD_EXPIRY, ["expiry", "expiration", "valid thru", "mm/yy"], ["datetime", "text"]),
    SemanticDefinition(FieldType.CARD_CVV, ["cvv", "cvc", "security code"], ["numberPassword", "number"]),
    
    SemanticDefinition(FieldType.UPI_ID, ["upi id", "upi address", "vpa", "virtual payment address"], ["textEmailAddress"]),
    
    SemanticDefinition(FieldType.AMOUNT, ["amount", "payment amount", "transfer amount"], ["numberDecimal", "number"]),
    SemanticDefinition(FieldType.SEARCH_QUERY, ["search", "query", "find", "look up"], ["text", "textWebEditText"]),
    
    SemanticDefinition(FieldType.SECURITY_ANSWER, ["security answer", "secret answer"], ["text"]),
]

def resolve_contextual_ambiguity(candidate_type: FieldType, screen_type: str, input_type: str, max_length: int) -> FieldType:
    """Disambiguate overlapping words like PIN based on context."""
    st = (screen_type or "").upper()
    if candidate_type == FieldType.PIN:
        if st == "ADDRESS" or "ADDRESS" in st:
            return FieldType.PIN_CODE
        elif max_length == 6 and input_type in ["number", "text"] and st == "ADDRESS":
            return FieldType.PIN_CODE
        elif "numberPassword" in (input_type or "") or st in ["BANK_LOGIN", "PAYMENT", "TRANSFER", "LOGIN"]:
            if st == "UPI_PAYMENT":
                return FieldType.UPI_PIN
            return FieldType.MPIN
    return candidate_type
