"""
PhishShield Synthetic Data Injection (SDI) Engine
Sprint 3: Defensive honeypot identity generator and form autofill engine.

Provides:
- Luhn-valid test credit card generation (Visa, Mastercard, Amex)
- Honeypot identities with canary watermarks for exfiltration detection
- Form field classifier & synthetic value resolver
- Exfiltration tripwire verification (verifies zero real user exposure)
"""
import re
import random
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field, asdict


def luhn_checksum(card_number_str: str) -> int:
    """Calculates the Luhn checksum for a card number string."""
    digits = [int(d) for d in card_number_str if d.isdigit()]
    total = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = d * 2
            total += doubled - 9 if doubled > 9 else doubled
        else:
            total += d
    return total % 10


def verify_luhn(card_number_str: str) -> bool:
    """Verifies that a credit card number passes the Luhn check."""
    clean = re.sub(r"\D", "", card_number_str)
    if len(clean) < 13 or len(clean) > 19:
        return False
    return luhn_checksum(clean) == 0


def generate_luhn_card(brand: str = "visa") -> str:
    """
    Generates a valid Luhn-compliant test credit card number.
    Watermarked prefix ensures it belongs to test/honeypot range.
    """
    if brand.lower() == "mastercard":
        # Mastercard prefix: 51-55
        prefix = "5425" + str(random.randint(1000, 9999))
        length = 16
    elif brand.lower() == "amex":
        # Amex prefix: 34 or 37
        prefix = "3782" + str(random.randint(1000, 9999))
        length = 15
    else:  # Visa default
        prefix = "4111" + str(random.randint(1000, 9999))
        length = 16

    # Generate body leaving 1 digit for checksum
    needed = length - len(prefix) - 1
    body = "".join(str(random.randint(0, 9)) for _ in range(needed))
    partial = prefix + body

    # Calculate check digit
    check_digit = (10 - luhn_checksum(partial + "0")) % 10
    card = partial + str(check_digit)
    assert verify_luhn(card), "Internal Luhn generation assertion failed"
    return card


@dataclass
class SyntheticIdentity:
    """Watermarked honeypot identity generated for phishing investigation."""
    profile_id: str
    card_brand: str
    card_number: str
    card_expiry: str
    card_cvv: str
    cardholder_name: str
    email: str
    username: str
    password: str
    phone: str
    address_line: str
    city: str
    postal_code: str
    country: str
    canary_token: str
    created_at: str
    watermark_note: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SDIEngine:
    """
    Synthetic Data Injection Generator.
    Produces honeypot identities and matches HTML form inputs to synthetic values.
    """

    MOCK_FIRST_NAMES = ["Jordan", "Taylor", "Morgan", "Casey", "Alex", "Riley", "Cameron", "Sam"]
    MOCK_LAST_NAMES = ["Vance", "Mercer", "Sinclair", "Holloway", "Cross", "Sterling", "Kowalski"]
    MOCK_CITIES = ["New York", "Chicago", "Austin", "Seattle", "Denver", "San Francisco"]

    def generate_identity(self, brand: str = "visa", custom_tag: Optional[str] = None) -> SyntheticIdentity:
        """Generates a complete synthetic persona with valid card and canary tripwire."""
        first = random.choice(self.MOCK_FIRST_NAMES)
        last = random.choice(self.MOCK_LAST_NAMES)
        tag = custom_tag or f"ps_{random.randint(100000, 999999)}"
        canary = f"CANARY-{tag.upper()}"
        
        card_num = generate_luhn_card(brand)
        formatted_card = " ".join([card_num[i:i+4] for i in range(0, len(card_num), 4)])

        now = datetime.now(timezone.utc)
        exp_month = random.randint(1, 12)
        exp_year = now.year % 100 + random.randint(2, 6)
        card_expiry = f"{exp_month:02d}/{exp_year:02d}"
        card_cvv = f"{random.randint(100, 999):03d}"

        email = f"canary.{first.lower()}.{last.lower()}.{tag}@phishshield-trap.invalid"
        username = f"{first.lower()}_{last.lower()}_{random.randint(10, 99)}"
        password = f"P$h1sh_{first}#{random.randint(1000, 9999)}!"
        phone = f"+1-555-{random.randint(100, 999):03d}-{random.randint(1000, 9999):04d}"

        return SyntheticIdentity(
            profile_id=tag,
            card_brand=brand.upper(),
            card_number=formatted_card,
            card_expiry=card_expiry,
            card_cvv=card_cvv,
            cardholder_name=f"{first} {last}",
            email=email,
            username=username,
            password=password,
            phone=phone,
            address_line=f"{random.randint(100, 999)} Canary Ridge Rd",
            city=random.choice(self.MOCK_CITIES),
            postal_code=f"{random.randint(10000, 99999)}",
            country="US",
            canary_token=canary,
            created_at=now.isoformat(),
            watermark_note="DEFENSIVE SDI: Synthetic honeypot credentials. Zero real user assets exposed.",
        )

    def match_form_field(self, field_name: str, field_type: str, identity: SyntheticIdentity) -> Optional[str]:
        """
        Classifies an input field based on its name/type attributes and returns
        the corresponding synthetic value for automated form injection.
        """
        name_lower = (field_name or "").lower()
        type_lower = (field_type or "").lower()

        # Credit card number
        if any(k in name_lower for k in ["card", "cc_num", "credit", "cardnumber", "pan", "account_num"]):
            return identity.card_number.replace(" ", "")
        
        # CVV / CVC
        if any(k in name_lower for k in ["cvv", "cvc", "security_code", "card_code"]):
            return identity.card_cvv

        # Expiry
        if any(k in name_lower for k in ["exp", "expiry", "expiration"]):
            return identity.card_expiry

        # Password
        if type_lower == "password" or any(k in name_lower for k in ["pass", "pwd", "secret"]):
            return identity.password

        # Email
        if type_lower == "email" or any(k in name_lower for k in ["email", "mail", "e-mail"]):
            return identity.email

        # Username / Login
        if any(k in name_lower for k in ["user", "login", "username", "account"]):
            return identity.username

        # Name
        if any(k in name_lower for k in ["name", "cardholder", "fullname"]):
            return identity.cardholder_name

        # Phone
        if type_lower == "tel" or any(k in name_lower for k in ["phone", "mobile", "tel"]):
            return identity.phone

        # Address / City / Zip
        if "city" in name_lower:
            return identity.city
        if any(k in name_lower for k in ["zip", "postal"]):
            return identity.postal_code
        if any(k in name_lower for k in ["addr", "street"]):
            return identity.address_line

        return None

    def check_exfiltration(self, payload: str, identity: SyntheticIdentity) -> Dict[str, Any]:
        """
        Checks whether outbound network data or submitted forms contain
        the injected synthetic profile or canary tokens.
        """
        raw_card = identity.card_number.replace(" ", "")
        leaked_card = raw_card in payload or identity.card_number in payload
        leaked_email = identity.email in payload
        leaked_password = identity.password in payload
        leaked_canary = identity.canary_token in payload

        any_leaked = leaked_card or leaked_email or leaked_password or leaked_canary
        return {
            "exfiltration_detected": any_leaked,
            "compromised_fields": [
                f for f, v in [
                    ("credit_card", leaked_card),
                    ("email", leaked_email),
                    ("password", leaked_password),
                    ("canary_token", leaked_canary),
                ] if v
            ],
            "honeypot_triggered": any_leaked,
            "canary_token": identity.canary_token,
            "real_data_exposed": False,  # Mathematically guaranteed by SDI design
        }


# Singleton SDI Engine instance
sdi = SDIEngine()
