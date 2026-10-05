from flask import Flask, request, jsonify
import dns.resolver
import smtplib
import socket
import re
import random
import string
import time
import os

app = Flask(__name__)

# ============================================================
# CONFIGURATION
# ============================================================

# IMPORTANT:
# These must be DEDICATED verification identities.
# DO NOT put your production sending addresses here.
#
# Set these in Render Environment Variables:
#
# VERIFY_SENDER_IP
# VERIFY_SENDER_DRAWINGS
#
# Example:
# VERIFY_SENDER_IP=verify@your-test-domain.com
# VERIFY_SENDER_DRAWINGS=verify@your-test-domain.com

VERIFY_SENDER_IP = os.environ.get(
    "VERIFY_SENDER_IP",
    ""
).strip().lower()

VERIFY_SENDER_DRAWINGS = os.environ.get(
    "VERIFY_SENDER_DRAWINGS",
    ""
).strip().lower()

SMTP_TIMEOUT = 8

# Small delay between SMTP checks.
# This is intentionally conservative.
CHECK_DELAY = 0.5

# ============================================================
# GATEWAY DETECTION
# ============================================================

GATEWAY_PATTERNS = {
    "MIMECAST": [
        "mimecast"
    ],

    "MICROSOFT_365": [
        "protection.outlook.com",
        "outlook.com",
        "microsoft",
        "office365",
        "office.com"
    ],

    "GOOGLE_WORKSPACE": [
        "google.com",
        "googlemail.com",
        "aspmx.l.google.com"
    ],

    "PROOFPOINT": [
        "proofpoint"
    ],

    "BARRACUDA": [
        "barracuda"
    ],

    "FORTIMAIL": [
        "fortimail",
        "fortinet"
    ],

    "CISCO": [
        "cisco",
        "iphmx.com"
    ],

    "SYMANTEC": [
        "symantec",
        "messagelabs"
    ],

    "MAILCHANNELS": [
        "mailchannels"
    ],

    "SPAMEXPERTS": [
        "spamexperts"
    ],

    "MAILROUTE": [
        "mailroute"
    ],

    "HORNETSECURITY": [
        "hornetsecurity"
    ],

    "FORCEPOINT": [
        "forcepoint"
    ],

    "SOPHOS": [
        "sophos"
    ],

    "TREND_MICRO": [
        "trendmicro"
    ],

    "CLOUDMARK": [
        "cloudmark"
    ],

    "ZEROSPAM": [
        "zerospam"
    ],

    "SPAMHERO": [
        "spamhero"
    ]
}


# ============================================================
# EMAIL FORMAT
# ============================================================

def is_valid_email_format(email):
    pattern = (
        r"^[A-Za-z0-9._%+-]+@"
        r"[A-Za-z0-9.-]+\."
        r"[A-Za-z]{2,}$"
    )

    return re.match(pattern, email) is not None


# ============================================================
# DOMAIN
# ============================================================

def get_domain(email):
    try:
        return email.split("@", 1)[1].strip().lower()
    except Exception:
        return ""


# ============================================================
# MX LOOKUP
# ============================================================

def get_mx_records(domain):

    try:
        answers = dns.resolver.resolve(
            domain,
            "MX",
            lifetime=8
        )

        records = []

        for answer in answers:
            host = str(
                answer.exchange
            ).rstrip(".").lower()

            records.append({
                "priority": int(answer.preference),
                "host": host
            })

        records.sort(
            key=lambda x: x["priority"]
        )

        return records

    except Exception:
        return []


# ============================================================
# GATEWAY DETECTION
# ============================================================

def detect_gateway(mx_records):

    if not mx_records:
        return "UNKNOWN"

    combined = " ".join(
        item["host"].lower()
        for item in mx_records
    )

    for gateway, patterns in GATEWAY_PATTERNS.items():

        for pattern in patterns:

            if pattern.lower() in combined:
                return gateway

    return "OTHER"


# ============================================================
# SMTP RESPONSE CLASSIFICATION
# ============================================================

def classify_smtp_response(code, message):

    msg = (
        message or ""
    ).lower()

    # --------------------------------------------------------
    # Explicit mailbox rejection
    # --------------------------------------------------------

    rejection_patterns = [
        "user unknown",
        "unknown user",
        "unknown recipient",
        "mailbox unavailable",
        "mailbox not found",
        "no such user",
        "no such mailbox",
        "recipient not found",
        "invalid recipient",
        "invalid mailbox",
        "does not exist",
        "account does not exist",
        "recipient rejected",
        "user doesn't exist",
        "user does not exist",
        "5.1.1",
        "550 5.1.1"
    ]

    for pattern in rejection_patterns:

        if pattern in msg:
            return {
                "result": "REJECTED",
                "reason": "Recipient mailbox rejected by server"
            }

    # --------------------------------------------------------
    # Security / gateway block
    # --------------------------------------------------------

    security_patterns = [
        "security policy",
        "security policies",
        "blocked by policy",
        "blocked by mail flow rule",
        "mail flow rule",
        "transport rule",
        "sender blocked",
        "sender rejected",
        "spam policy",
        "anti-spam",
        "access denied",
        "policy rejection",
        "mimecast",
        "proofpoint",
        "barracuda"
    ]

    for pattern in security_patterns:

        if pattern in msg:
            return {
                "result": "UNKNOWN",
                "reason": "Recipient gateway/security policy prevented verification"
            }

    # --------------------------------------------------------
    # Temporary failure
    # --------------------------------------------------------

    if 400 <= code < 500:

        return {
            "result": "UNKNOWN",
            "reason": "Temporary SMTP rejection"
        }

    # --------------------------------------------------------
    # Successful RCPT
    # --------------------------------------------------------

    if 200 <= code < 300:

        return {
            "result": "ACCEPTED",
            "reason": "Recipient server accepted the SMTP recipient"
        }

    # --------------------------------------------------------
    # Permanent rejection
    # --------------------------------------------------------

    if 500 <= code < 600:

        return {
            "result": "REJECTED",
            "reason": "Recipient server permanently rejected the recipient"
        }

    return {
        "result": "UNKNOWN",
        "reason": "SMTP response could not be classified"
    }


# ============================================================
# SMTP RECIPIENT CHECK
# ============================================================

def smtp_recipient_check(
    email,
    mx_host,
    sender_email
):

    smtp = None

    try:

        # ----------------------------------------------------
        # Connect to recipient MX
        # ----------------------------------------------------

        smtp = smtplib.SMTP(
            timeout=SMTP_TIMEOUT
        )

        smtp.connect(
            mx_host,
            25
        )

        # ----------------------------------------------------
        # EHLO
        # ----------------------------------------------------

        code, message = smtp.ehlo()

        if code >= 400:

            return {
                "result": "UNKNOWN",
                "reason": "Recipient server rejected EHLO"
            }

        # ----------------------------------------------------
        # MAIL FROM
        #
        # IMPORTANT:
        # This does NOT send an email.
        # We stop at RCPT TO.
        # ----------------------------------------------------

        code, message = smtp.mail(
            sender_email
        )

        if code >= 400:

            return {
                "result": "UNKNOWN",
                "reason": (
                    "Recipient server rejected verification "
                    "sender"
                )
            }

        # ----------------------------------------------------
        # RCPT TO
        # ----------------------------------------------------

        code, message = smtp.rcpt(
            email
        )

        message_text = ""

        try:
            if isinstance(message, bytes):
                message_text = message.decode(
                    "utf-8",
                    errors="ignore"
                )
            else:
                message_text = str(message)
        except Exception:
            message_text = ""

        result = classify_smtp_response(
            code,
            message_text
        )

        return result

    except socket.timeout:

        return {
            "result": "UNKNOWN",
            "reason": "SMTP connection timed out"
        }

    except ConnectionRefusedError:

        return {
            "result": "UNKNOWN",
            "reason": "Recipient SMTP server refused connection"
        }

    except OSError as e:

        return {
            "result": "UNKNOWN",
            "reason": (
                "SMTP connection unavailable: "
                + str(e)
            )
        }

    except Exception as e:

        return {
            "result": "UNKNOWN",
            "reason": (
                "SMTP verification unavailable: "
                + str(e)
            )
        }

    finally:

        if smtp:

            try:
                smtp.rset()
            except Exception:
                pass

            try:
                smtp.quit()
            except Exception:
                pass


# ============================================================
# CHECK ONE SENDING DOMAIN
# ============================================================

def check_sending_domain(
    recipient_email,
    mx_records,
    sender_email
):

    if not sender_email:

        return {
            "result": "UNKNOWN",
            "confidence": "LOW",
            "reason": (
                "Dedicated verification sender "
                "is not configured"
            )
        }

    if not mx_records:

        return {
            "result": "UNKNOWN",
            "confidence": "LOW",
            "reason": "No MX server available"
        }

    # --------------------------------------------------------
    # Try MX servers in priority order
    # --------------------------------------------------------

    unknown_reasons = []

    for mx in mx_records:

        mx_host = mx["host"]

        result = smtp_recipient_check(
            recipient_email,
            mx_host,
            sender_email
        )

        if result["result"] == "ACCEPTED":

            return {
                "result": "ACCEPTED",
                "confidence": "HIGH",
                "reason": result["reason"],
                "mx_host": mx_host
            }

        if result["result"] == "REJECTED":

            return {
                "result": "REJECTED",
                "confidence": "HIGH",
                "reason": result["reason"],
                "mx_host": mx_host
            }

        unknown_reasons.append(
            result["reason"]
        )

        # Conservative delay
        time.sleep(
            CHECK_DELAY
        )

    return {
        "result": "UNKNOWN",
        "confidence": "LOW",
        "reason": (
            "SMTP verification could not obtain "
            "a reliable recipient decision"
        )
    }


# ============================================================
# COMPLETE EMAIL VERIFICATION
# ============================================================

def verify_email(email):

    email = email.strip().lower()

    # --------------------------------------------------------
    # Format
    # --------------------------------------------------------

    if not email:

        return {
            "status": "RISK",
            "reason": "Email address is empty"
        }

    if not is_valid_email_format(email):

        return {
            "status": "RISK",
            "reason": "Invalid email format"
        }

    # --------------------------------------------------------
    # Domain
    # --------------------------------------------------------

    domain = get_domain(email)

    if not domain:

        return {
            "status": "RISK",
            "reason": "Could not extract recipient domain"
        }

    # --------------------------------------------------------
    # MX
    # --------------------------------------------------------

    mx_records = get_mx_records(
        domain
    )

    if not mx_records:

        return {
            "status": "RISK",
            "reason": "No valid MX record found",
            "recipient_domain": domain,
            "gateway": "UNKNOWN",
            "ip_result": "UNKNOWN",
            "drawings_result": "UNKNOWN"
        }

    gateway = detect_gateway(
        mx_records
    )

    # --------------------------------------------------------
    # Prepare MX list
    # --------------------------------------------------------

    mx_hosts = [
        item["host"]
        for item in mx_records
    ]

    # --------------------------------------------------------
    # IP / immunisip.com
    # --------------------------------------------------------

    ip_check = check_sending_domain(
        email,
        mx_records,
        VERIFY_SENDER_IP
    )

    # --------------------------------------------------------
    # Small delay between tests
    # --------------------------------------------------------

    time.sleep(
        CHECK_DELAY
    )

    # --------------------------------------------------------
    # Drawings / immunisdrawings.com
    # --------------------------------------------------------

    drawings_check = check_sending_domain(
        email,
        mx_records,
        VERIFY_SENDER_DRAWINGS
    )

    # --------------------------------------------------------
    # Overall status
    # --------------------------------------------------------

    if (
        ip_check["result"] == "REJECTED"
        and
        drawings_check["result"] == "REJECTED"
    ):

        overall_status = "RISK"

    elif (
        ip_check["result"] == "ACCEPTED"
        or
        drawings_check["result"] == "ACCEPTED"
    ):

        overall_status = "VALID"

    else:

        overall_status = "UNKNOWN"

    # --------------------------------------------------------
    # Reason
    # --------------------------------------------------------

    reason = (
        "IP: "
        + ip_check["reason"]
        + " | Drawings: "
        + drawings_check["reason"]
    )

    return {

        "status": overall_status,

        "reason": reason,

        "recipient_email": email,

        "recipient_domain": domain,

        "gateway": gateway,

        "security_gateway": gateway,

        "mx_records": mx_hosts,

        "ip_result": ip_check["result"],

        "ip_confidence": ip_check["confidence"],

        "ip_reason": ip_check["reason"],

        "drawings_result": drawings_check["result"],

        "drawings_confidence": drawings_check["confidence"],

        "drawings_reason": drawings_check["reason"],

        "verification_level": (
            "SMTP recipient verification"
        )
    }


# ============================================================
# HOME
# ============================================================

@app.route("/", methods=["GET"])
def home():

    return jsonify({
        "status": "online",
        "service": "IMMUNIS Email Verification API",
        "version": "6.0",
        "method": "Conservative SMTP recipient verification"
    })


# ============================================================
# VERIFY
# ============================================================

@app.route(
    "/verify",
    methods=["GET", "POST"]
)
def verify():

    if request.method == "GET":

        email = request.args.get(
            "email",
            ""
        ).strip()

        full_name = request.args.get(
            "full_name",
            ""
        ).strip()

    else:

        data = request.get_json(
            silent=True
        ) or {}

        email = str(
            data.get("email", "")
        ).strip()

        full_name = str(
            data.get("full_name", "")
        ).strip()

    if not email:

        return jsonify({
            "full_name": full_name,
            "email": "",
            "status": "RISK",
            "reason": "Email address is missing"
        }), 400

    result = verify_email(
        email
    )

    response = {

        "full_name": full_name,

        "email": email,

        "status": result.get(
            "status",
            "UNKNOWN"
        ),

        "reason": result.get(
            "reason",
            "Unable to verify"
        ),

        "recipient_domain": result.get(
            "recipient_domain",
            ""
        ),

        "gateway": result.get(
            "gateway",
            "UNKNOWN"
        ),

        "security_gateway": result.get(
            "security_gateway",
            "UNKNOWN"
        ),

        "ip_result": result.get(
            "ip_result",
            "UNKNOWN"
        ),

        "ip_confidence": result.get(
            "ip_confidence",
            "LOW"
        ),

        "ip_reason": result.get(
            "ip_reason",
            ""
        ),

        "drawings_result": result.get(
            "drawings_result",
            "UNKNOWN"
        ),

        "drawings_confidence": result.get(
            "drawings_confidence",
            "LOW"
        ),

        "drawings_reason": result.get(
            "drawings_reason",
            ""
        ),

        "verification_level": result.get(
            "verification_level",
            "SMTP recipient verification"
        ),

        "mx_records": result.get(
            "mx_records",
            []
        )
    }

    return jsonify(
        response
    )


# ============================================================
# ERROR HANDLER
# ============================================================

@app.errorhandler(Exception)
def handle_exception(error):

    return jsonify({
        "status": "UNKNOWN",
        "reason": "Internal verification error: " + str(error)
    }), 500


# ============================================================
# START
# ============================================================

if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            10000
        )
    )

    app.run(
        host="0.0.0.0",
        port=port
    )
