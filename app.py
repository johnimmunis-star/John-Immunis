from flask import Flask, request, jsonify
import dns.resolver
import smtplib
import socket
import re
import os
import time

app = Flask(__name__)

# ============================================================
# CONFIGURATION
# ============================================================

# IMPORTANT:
# Use DEDICATED verification sender addresses here.
# DO NOT use your production sending addresses:
# john@immunisip.com
# john@immunisdrawings.com
#
# Add these as Render Environment Variables:
#
# VERIFY_SENDER_IP
# VERIFY_SENDER_DRAWINGS

VERIFY_SENDER_IP = os.environ.get(
    "VERIFY_SENDER_IP", ""
).strip().lower()

VERIFY_SENDER_DRAWINGS = os.environ.get(
    "VERIFY_SENDER_DRAWINGS", ""
).strip().lower()

SMTP_TIMEOUT = 8

# Conservative delay between checks
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
# EMAIL FORMAT CHECK
# ============================================================

def is_valid_email_format(email):

    pattern = (
        r"^[A-Za-z0-9._%+-]+@"
        r"[A-Za-z0-9.-]+\."
        r"[A-Za-z]{2,}$"
    )

    return re.match(pattern, email) is not None


# ============================================================
# GET DOMAIN
# ============================================================

def get_domain(email):

    try:
        return email.split("@", 1)[1].strip().lower()

    except Exception:
        return ""


# ============================================================
# MX RECORDS
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

            mx_host = str(
                answer.exchange
            ).rstrip(".").lower()

            records.append({
                "priority": int(answer.preference),
                "host": mx_host
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

    message = (
        message or ""
    ).lower()

    # --------------------------------------------------------
    # CLEAR MAILBOX REJECTION
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
        "550 5.1.1",
        "551 5.1.1",
        "553 5.1.1"
    ]

    for pattern in rejection_patterns:

        if pattern in message:

            return {
                "status": "NOT DELIVERABLE",
                "reason": "Recipient mailbox rejected by server"
            }

    # --------------------------------------------------------
    # SECURITY / GATEWAY BLOCK
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

        if pattern in message:

            return {
                "status": "UNKNOWN",
                "reason": (
                    "Recipient gateway or security "
                    "policy prevented verification"
                )
            }

    # --------------------------------------------------------
    # TEMPORARY FAILURE
    # --------------------------------------------------------

    if 400 <= code < 500:

        return {
            "status": "UNKNOWN",
            "reason": "Temporary SMTP rejection"
        }

    # --------------------------------------------------------
    # SMTP ACCEPTED
    # --------------------------------------------------------

    if 200 <= code < 300:

        return {
            "status": "DELIVERABLE",
            "reason": (
                "Recipient server accepted the "
                "SMTP recipient"
            )
        }

    # --------------------------------------------------------
    # PERMANENT REJECTION
    # --------------------------------------------------------

    if 500 <= code < 600:

        return {
            "status": "NOT DELIVERABLE",
            "reason": (
                "Recipient server permanently "
                "rejected the recipient"
            )
        }

    # --------------------------------------------------------
    # UNKNOWN
    # --------------------------------------------------------

    return {
        "status": "UNKNOWN",
        "reason": "SMTP response could not be classified"
    }


# ============================================================
# SMTP RECIPIENT CHECK
# ============================================================

def smtp_recipient_check(
    recipient_email,
    mx_host,
    sender_email
):

    smtp = None

    try:

        # ----------------------------------------------------
        # CONNECT TO RECIPIENT MAIL SERVER
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
                "status": "UNKNOWN",
                "reason": (
                    "Recipient server rejected EHLO"
                )
            }

        # ----------------------------------------------------
        # MAIL FROM
        #
        # This does NOT send an email.
        # We stop before DATA.
        # ----------------------------------------------------

        if not sender_email:

            return {
                "status": "UNKNOWN",
                "reason": (
                    "Verification sender is not configured"
                )
            }

        code, message = smtp.mail(
            sender_email
        )

        if code >= 400:

            return {
                "status": "UNKNOWN",
                "reason": (
                    "Recipient server rejected "
                    "verification sender"
                )
            }

        # ----------------------------------------------------
        # RCPT TO
        # ----------------------------------------------------

        code, message = smtp.rcpt(
            recipient_email
        )

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

        return classify_smtp_response(
            code,
            message_text
        )

    except socket.timeout:

        return {
            "status": "UNKNOWN",
            "reason": (
                "SMTP connection timed out"
            )
        }

    except ConnectionRefusedError:

        return {
            "status": "UNKNOWN",
            "reason": (
                "Recipient SMTP server refused connection"
            )
        }

    except OSError as error:

        return {
            "status": "UNKNOWN",
            "reason": (
                "SMTP connection unavailable: "
                + str(error)
            )
        }

    except Exception as error:

        return {
            "status": "UNKNOWN",
            "reason": (
                "SMTP verification unavailable: "
                + str(error)
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
# CHECK RECIPIENT AGAINST SENDING DOMAIN
# ============================================================

def check_sending_domain(
    recipient_email,
    mx_records,
    sender_email
):

    if not sender_email:

        return {
            "status": "UNKNOWN",
            "confidence": "LOW",
            "reason": (
                "Dedicated verification sender "
                "is not configured"
            )
        }

    if not mx_records:

        return {
            "status": "UNKNOWN",
            "confidence": "LOW",
            "reason": (
                "No MX server available"
            )
        }

    unknown_reasons = []

    # --------------------------------------------------------
    # TRY EACH MX SERVER
    # --------------------------------------------------------

    for mx in mx_records:

        mx_host = mx["host"]

        result = smtp_recipient_check(
            recipient_email,
            mx_host,
            sender_email
        )

        # ----------------------------------------------------
        # DELIVERABLE
        # ----------------------------------------------------

        if result["status"] == "DELIVERABLE":

            return {
                "status": "DELIVERABLE",
                "confidence": "HIGH",
                "reason": result["reason"],
                "mx_host": mx_host
            }

        # ----------------------------------------------------
        # NOT DELIVERABLE
        # ----------------------------------------------------

        if result["status"] == "NOT DELIVERABLE":

            return {
                "status": "NOT DELIVERABLE",
                "confidence": "HIGH",
                "reason": result["reason"],
                "mx_host": mx_host
            }

        # ----------------------------------------------------
        # UNKNOWN
        # ----------------------------------------------------

        unknown_reasons.append(
            result["reason"]
        )

        time.sleep(
            CHECK_DELAY
        )

    return {
        "status": "UNKNOWN",
        "confidence": "LOW",
        "reason": (
            "SMTP verification could not obtain "
            "a reliable recipient decision"
        )
    }


# ============================================================
# VERIFY EMAIL
# ============================================================

def verify_email(email):

    email = email.strip().lower()

    # --------------------------------------------------------
    # EMPTY
    # --------------------------------------------------------

    if not email:

        return {
            "status": "UNKNOWN",
            "reason": "Email address is empty"
        }

    # --------------------------------------------------------
    # FORMAT
    # --------------------------------------------------------

    if not is_valid_email_format(email):

        return {
            "status": "NOT DELIVERABLE",
            "reason": "Invalid email format",
            "recipient_domain": "",
            "gateway": "UNKNOWN",
            "ip_result": "NOT DELIVERABLE",
            "drawings_result": "NOT DELIVERABLE"
        }

    # --------------------------------------------------------
    # DOMAIN
    # --------------------------------------------------------

    domain = get_domain(email)

    if not domain:

        return {
            "status": "UNKNOWN",
            "reason": (
                "Could not extract recipient domain"
            )
        }

    # --------------------------------------------------------
    # MX
    # --------------------------------------------------------

    mx_records = get_mx_records(
        domain
    )

    if not mx_records:

        return {

            "status": "NOT DELIVERABLE",

            "reason": (
                "No valid MX record found "
                "for recipient domain"
            ),

            "recipient_domain": domain,

            "gateway": "UNKNOWN",

            "ip_result": "NOT DELIVERABLE",

            "drawings_result": "NOT DELIVERABLE",

            "ip_confidence": "HIGH",

            "drawings_confidence": "HIGH"
        }

    # --------------------------------------------------------
    # GATEWAY
    # --------------------------------------------------------

    gateway = detect_gateway(
        mx_records
    )

    mx_hosts = [
        item["host"]
        for item in mx_records
    ]

    # --------------------------------------------------------
    # IP TEST
    # --------------------------------------------------------

    ip_check = check_sending_domain(
        email,
        mx_records,
        VERIFY_SENDER_IP
    )

    time.sleep(
        CHECK_DELAY
    )

    # --------------------------------------------------------
    # DRAWINGS TEST
    # --------------------------------------------------------

    drawings_check = check_sending_domain(
        email,
        mx_records,
        VERIFY_SENDER_DRAWINGS
    )

    # --------------------------------------------------------
    # OVERALL STATUS
    # --------------------------------------------------------

    if (
        ip_check["status"] == "DELIVERABLE"
        or
        drawings_check["status"] == "DELIVERABLE"
    ):

        overall_status = "DELIVERABLE"

    elif (
        ip_check["status"] == "NOT DELIVERABLE"
        and
        drawings_check["status"] == "NOT DELIVERABLE"
    ):

        overall_status = "NOT DELIVERABLE"

    else:

        overall_status = "UNKNOWN"

    # --------------------------------------------------------
    # REASON
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

        "ip_result": ip_check["status"],

        "ip_confidence": ip_check["confidence"],

        "ip_reason": ip_check["reason"],

        "drawings_result": drawings_check["status"],

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

        "service": (
            "IMMUNIS Email Verification API"
        ),

        "version": "7.0",

        "verification": (
            "DELIVERABLE / NOT DELIVERABLE / UNKNOWN"
        )
    })


# ============================================================
# VERIFY ENDPOINT
# ============================================================

@app.route(
    "/verify",
    methods=["GET", "POST"]
)
def verify():

    # --------------------------------------------------------
    # GET
    # --------------------------------------------------------

    if request.method == "GET":

        email = request.args.get(
            "email",
            ""
        ).strip()

        full_name = request.args.get(
            "full_name",
            ""
        ).strip()

    # --------------------------------------------------------
    # POST
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # MISSING EMAIL
    # --------------------------------------------------------

    if not email:

        return jsonify({

            "full_name": full_name,

            "email": "",

            "status": "UNKNOWN",

            "reason": (
                "Email address is missing"
            )

        }), 400

    # --------------------------------------------------------
    # VERIFY
    # --------------------------------------------------------

    result = verify_email(
        email
    )

    # --------------------------------------------------------
    # RESPONSE
    # --------------------------------------------------------

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
# GLOBAL ERROR HANDLER
# ============================================================

@app.errorhandler(Exception)
def handle_exception(error):

    return jsonify({

        "status": "UNKNOWN",

        "reason": (
            "Internal verification error: "
            + str(error)
        )

    }), 500


# ============================================================
# START SERVER
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


@app.route("/smtp-test", methods=["GET"])
def smtp_test():

    test_host = "gmail-smtp-in.l.google.com"
    test_port = 25

    try:
        smtp = smtplib.SMTP(
            timeout=10
        )

        code, message = smtp.connect(
            test_host,
            test_port
        )

        smtp.quit()

        return jsonify({
            "status": "SUCCESS",
            "smtp_connection": "REACHABLE",
            "host": test_host,
            "port": test_port,
            "response_code": code,
            "message": str(message)
        })

    except socket.timeout:

        return jsonify({
            "status": "BLOCKED_OR_TIMEOUT",
            "smtp_connection": "NOT REACHABLE",
            "reason": "Connection timed out",
            "host": test_host,
            "port": test_port
        })

    except Exception as e:

        return jsonify({
            "status": "FAILED",
            "smtp_connection": "NOT REACHABLE",
            "reason": str(e),
            "host": test_host,
            "port": test_port
        })
