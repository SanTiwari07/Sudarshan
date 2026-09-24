"""
SUDARSHAN - Field Taxonomy
"""

from __future__ import annotations

from enum import Enum
from typing import Dict, FrozenSet, Optional, Set

__all__ = [
    "FieldType",
    "LEGACY_FIELD_KINDS",
    "NUMERIC_FIELD_TYPES",
    "SECRET_FIELD_TYPES",
    "coerce_field_type",
    "is_secret_field",
    "legacy_kind_for",
]

class FieldType(str, Enum):
    UNKNOWN = "UNKNOWN"
    
    # Identity
    USERNAME = "USERNAME"
    USER_ID = "USER_ID"
    LOGIN_ID = "LOGIN_ID"
    CUSTOMER_ID = "CUSTOMER_ID"
    CUSTOMER_NUMBER = "CUSTOMER_NUMBER"
    CIF = "CIF"
    
    # Secrets
    EMAIL = "EMAIL"
    PASSWORD = "PASSWORD"
    PIN = "PIN"
    MPIN = "MPIN"
    TPIN = "TPIN"
    UPI_PIN = "UPI_PIN"
    ATM_PIN = "ATM_PIN"
    CARD_PIN = "CARD_PIN"
    PASSCODE = "PASSCODE"
    
    # One-time
    OTP = "OTP"
    EMAIL_OTP = "EMAIL_OTP"
    VERIFICATION_CODE = "VERIFICATION_CODE"
    AUTHENTICATION_CODE = "AUTHENTICATION_CODE"
    RECOVERY_CODE = "RECOVERY_CODE"
    
    # Contact
    PHONE = "PHONE"
    MOBILE = "MOBILE"
    
    # Person
    FULL_NAME = "FULL_NAME"
    FIRST_NAME = "FIRST_NAME"
    LAST_NAME = "LAST_NAME"
    MOTHER_NAME = "MOTHER_NAME"
    MOTHER_MAIDEN_NAME = "MOTHER_MAIDEN_NAME"
    FATHER_NAME = "FATHER_NAME"
    GUARDIAN_NAME = "GUARDIAN_NAME"
    SPOUSE_NAME = "SPOUSE_NAME"
    
    # Demographics
    DATE_OF_BIRTH = "DATE_OF_BIRTH"
    AGE = "AGE"
    DATE = "DATE"
    TIME = "TIME"
    
    # Address
    ADDRESS = "ADDRESS"
    ADDRESS_LINE_1 = "ADDRESS_LINE_1"
    ADDRESS_LINE_2 = "ADDRESS_LINE_2"
    HOUSE_NUMBER = "HOUSE_NUMBER"
    FLAT_NUMBER = "FLAT_NUMBER"
    STREET = "STREET"
    LANDMARK = "LANDMARK"
    CITY = "CITY"
    STATE = "STATE"
    DISTRICT = "DISTRICT"
    COUNTRY = "COUNTRY"
    TALUKA = "TALUKA"
    TEHSIL = "TEHSIL"
    PIN_CODE = "PIN_CODE"
    POSTAL_CODE = "POSTAL_CODE"
    ZIP_CODE = "ZIP_CODE"
    
    # Government IDs
    PAN = "PAN"
    AADHAAR = "AADHAAR"
    PASSPORT = "PASSPORT"
    VOTER_ID = "VOTER_ID"
    DRIVING_LICENSE = "DRIVING_LICENSE"
    
    # Instruments
    BANK_NAME = "BANK_NAME"
    ACCOUNT_NUMBER = "ACCOUNT_NUMBER"
    ACCOUNT_HOLDER_NAME = "ACCOUNT_HOLDER_NAME"
    BRANCH_CODE = "BRANCH_CODE"
    CARD_NUMBER = "CARD_NUMBER"
    CARD_HOLDER_NAME = "CARD_HOLDER_NAME"
    CARD_EXPIRY = "CARD_EXPIRY"
    CARD_CVV = "CARD_CVV"
    
    # Payment rails
    IFSC = "IFSC"
    UPI_ID = "UPI_ID"
    VPA = "VPA"
    
    # Counterparty
    BENEFICIARY_NAME = "BENEFICIARY_NAME"
    BENEFICIARY_ACCOUNT = "BENEFICIARY_ACCOUNT"
    PAYEE = "PAYEE"
    RECIPIENT = "RECIPIENT"
    MERCHANT = "MERCHANT"
    
    # Reference numbers
    EMPLOYEE_ID = "EMPLOYEE_ID"
    STUDENT_ID = "STUDENT_ID"
    ROLL_NUMBER = "ROLL_NUMBER"
    REGISTRATION_NUMBER = "REGISTRATION_NUMBER"
    APPLICATION_ID = "APPLICATION_ID"
    REFERRAL_CODE = "REFERRAL_CODE"
    PROMO_CODE = "PROMO_CODE"
    COUPON_CODE = "COUPON_CODE"
    POLICY_NUMBER = "POLICY_NUMBER"
    REFERENCE_NUMBER = "REFERENCE_NUMBER"
    ORDER_ID = "ORDER_ID"
    INVOICE_NUMBER = "INVOICE_NUMBER"
    TRANSACTION_ID = "TRANSACTION_ID"
    
    # Security Questions
    SECURITY_ANSWER = "SECURITY_ANSWER"
    
    # Profile info
    PROFILE_NAME = "PROFILE_NAME"
    COMPANY_NAME = "COMPANY_NAME"
    
    # Misc
    AMOUNT = "AMOUNT"
    QUANTITY = "QUANTITY"
    SEARCH_QUERY = "SEARCH_QUERY"
    SEARCH = "SEARCH"
    COMMENT = "COMMENT"
    DESCRIPTION = "DESCRIPTION"
    MESSAGE = "MESSAGE"
    NOTES = "NOTES"
    HOST = "HOST"
    PORT = "PORT"
    TEXT = "TEXT"


LEGACY_FIELD_KINDS: FrozenSet[str] = frozenset({
    "username", "password", "email", "phone", "amount", "account",
    "name", "address", "search", "port", "host", "otp", "text",
})

_LEGACY_KIND: Dict[FieldType, str] = {
    FieldType.UNKNOWN: "text",
    FieldType.USERNAME: "username",
    FieldType.USER_ID: "username",
    FieldType.LOGIN_ID: "username",
    FieldType.CUSTOMER_ID: "username",
    FieldType.CUSTOMER_NUMBER: "username",
    FieldType.CIF: "username",
    FieldType.EMAIL: "email",
    FieldType.PASSWORD: "password",
    FieldType.PIN: "password",
    FieldType.MPIN: "password",
    FieldType.TPIN: "password",
    FieldType.UPI_PIN: "password",
    FieldType.ATM_PIN: "password",
    FieldType.CARD_PIN: "password",
    FieldType.PASSCODE: "password",
    FieldType.OTP: "otp",
    FieldType.EMAIL_OTP: "otp",
    FieldType.VERIFICATION_CODE: "otp",
    FieldType.AUTHENTICATION_CODE: "otp",
    FieldType.RECOVERY_CODE: "otp",
    FieldType.PHONE: "phone",
    FieldType.MOBILE: "phone",
    FieldType.FULL_NAME: "name",
    FieldType.FIRST_NAME: "name",
    FieldType.LAST_NAME: "name",
    FieldType.MOTHER_NAME: "name",
    FieldType.MOTHER_MAIDEN_NAME: "name",
    FieldType.FATHER_NAME: "name",
    FieldType.GUARDIAN_NAME: "name",
    FieldType.SPOUSE_NAME: "name",
    FieldType.DATE_OF_BIRTH: "text",
    FieldType.AGE: "text",
    FieldType.DATE: "text",
    FieldType.TIME: "text",
    FieldType.ADDRESS: "address",
    FieldType.ADDRESS_LINE_1: "address",
    FieldType.ADDRESS_LINE_2: "address",
    FieldType.HOUSE_NUMBER: "address",
    FieldType.FLAT_NUMBER: "address",
    FieldType.STREET: "address",
    FieldType.LANDMARK: "address",
    FieldType.CITY: "address",
    FieldType.STATE: "address",
    FieldType.DISTRICT: "address",
    FieldType.COUNTRY: "address",
    FieldType.TALUKA: "address",
    FieldType.TEHSIL: "address",
    FieldType.PIN_CODE: "address",
    FieldType.POSTAL_CODE: "address",
    FieldType.ZIP_CODE: "address",
    FieldType.PAN: "text",
    FieldType.AADHAAR: "text",
    FieldType.PASSPORT: "text",
    FieldType.VOTER_ID: "text",
    FieldType.DRIVING_LICENSE: "text",
    FieldType.BANK_NAME: "text",
    FieldType.ACCOUNT_NUMBER: "account",
    FieldType.ACCOUNT_HOLDER_NAME: "name",
    FieldType.BRANCH_CODE: "text",
    FieldType.CARD_NUMBER: "account",
    FieldType.CARD_HOLDER_NAME: "name",
    FieldType.CARD_EXPIRY: "account",
    FieldType.CARD_CVV: "account",
    FieldType.IFSC: "account",
    FieldType.UPI_ID: "email",
    FieldType.VPA: "email",
    FieldType.BENEFICIARY_NAME: "name",
    FieldType.BENEFICIARY_ACCOUNT: "account",
    FieldType.PAYEE: "name",
    FieldType.RECIPIENT: "name",
    FieldType.MERCHANT: "name",
    FieldType.EMPLOYEE_ID: "text",
    FieldType.STUDENT_ID: "text",
    FieldType.ROLL_NUMBER: "text",
    FieldType.REGISTRATION_NUMBER: "text",
    FieldType.APPLICATION_ID: "text",
    FieldType.REFERRAL_CODE: "text",
    FieldType.PROMO_CODE: "text",
    FieldType.COUPON_CODE: "text",
    FieldType.POLICY_NUMBER: "text",
    FieldType.REFERENCE_NUMBER: "text",
    FieldType.ORDER_ID: "text",
    FieldType.INVOICE_NUMBER: "text",
    FieldType.TRANSACTION_ID: "text",
    FieldType.SECURITY_ANSWER: "text",
    FieldType.PROFILE_NAME: "name",
    FieldType.COMPANY_NAME: "name",
    FieldType.AMOUNT: "amount",
    FieldType.QUANTITY: "amount",
    FieldType.SEARCH_QUERY: "search",
    FieldType.SEARCH: "search",
    FieldType.COMMENT: "text",
    FieldType.DESCRIPTION: "text",
    FieldType.MESSAGE: "text",
    FieldType.NOTES: "text",
    FieldType.HOST: "host",
    FieldType.PORT: "port",
    FieldType.TEXT: "text",
}

SECRET_FIELD_TYPES: FrozenSet[FieldType] = frozenset({
    FieldType.PASSWORD,
    FieldType.PIN,
    FieldType.MPIN,
    FieldType.TPIN,
    FieldType.UPI_PIN,
    FieldType.ATM_PIN,
    FieldType.CARD_PIN,
    FieldType.PASSCODE,
    FieldType.OTP,
    FieldType.EMAIL_OTP,
    FieldType.VERIFICATION_CODE,
    FieldType.AUTHENTICATION_CODE,
    FieldType.RECOVERY_CODE,
    FieldType.CARD_CVV,
    FieldType.CARD_NUMBER,
    FieldType.SECURITY_ANSWER,
})

NUMERIC_FIELD_TYPES: FrozenSet[FieldType] = frozenset({
    FieldType.PIN,
    FieldType.MPIN,
    FieldType.TPIN,
    FieldType.UPI_PIN,
    FieldType.ATM_PIN,
    FieldType.CARD_PIN,
    FieldType.PASSCODE,
    FieldType.OTP,
    FieldType.EMAIL_OTP,
    FieldType.VERIFICATION_CODE,
    FieldType.AUTHENTICATION_CODE,
    FieldType.PHONE,
    FieldType.MOBILE,
    FieldType.ACCOUNT_NUMBER,
    FieldType.BENEFICIARY_ACCOUNT,
    FieldType.CARD_NUMBER,
    FieldType.CARD_CVV,
    FieldType.POSTAL_CODE,
    FieldType.PIN_CODE,
    FieldType.ZIP_CODE,
    FieldType.CUSTOMER_NUMBER,
    FieldType.AMOUNT,
    FieldType.QUANTITY,
    FieldType.PORT,
})

def legacy_kind_for(field_type: "FieldType | str") -> str:
    ft = coerce_field_type(field_type)
    return _LEGACY_KIND.get(ft, "text")

def coerce_field_type(value: "FieldType | str | None") -> FieldType:
    if isinstance(value, FieldType):
        return value
    if not value:
        return FieldType.UNKNOWN
    token = str(value).strip()
    try:
        return FieldType(token.upper())
    except ValueError:
        pass
    return _LEGACY_TO_TYPE.get(token.lower(), FieldType.UNKNOWN)

_LEGACY_TO_TYPE: Dict[str, FieldType] = {
    "username": FieldType.USERNAME,
    "password": FieldType.PASSWORD,
    "email":    FieldType.EMAIL,
    "phone":    FieldType.PHONE,
    "otp":      FieldType.OTP,
    "amount":   FieldType.AMOUNT,
    "account":  FieldType.ACCOUNT_NUMBER,
    "name":     FieldType.FULL_NAME,
    "address":  FieldType.ADDRESS,
    "search":   FieldType.SEARCH,
    "host":     FieldType.HOST,
    "port":     FieldType.PORT,
    "text":     FieldType.TEXT,
}

def is_secret_field(field_type: "FieldType | str") -> bool:
    return coerce_field_type(field_type) in SECRET_FIELD_TYPES
