from flask import Flask, request, jsonify
import dns.resolver
import re

app = Flask(__name__)


# =========================================================
# CONFIGURATION
# =========================================================

SENDING_DOMAINS = [
    "immunisip.com",
    "immunisdrawings.com"
]


# =========================================================
# EMAIL FORMAT CHECK
# =========================================================

def is_valid_email_format(email):

    pattern = r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"

    return re.match(pattern, email) is not None


# =========================================================
# GET MX RECORDS
# =========================================================

def get_mx_records(domain):

    try:

        answers = dns.resolver.resolve(
            domain,
            "MX",
            lifetime=10
        )

        records = []

        for answer in answers:

            mx_host = str(
                answer.exchange
            ).rstrip(".").lower()

            records.append(mx_host)

        return records

    except Exception:

        return []


# =========================================================
# DETECT MAIL GATEWAY
# =========================================================

def detect_mail_gateway(mx_records):

    mx_text = " ".join(mx_records).lower()


    # -----------------------------------------------------
    # MIMECAST
    # -----------------------------------------------------

    mimecast_keywords = [
        "mimecast.com",
        "mimecast.co.uk",
        "mimecast.com.au",
        "mimecastcloud.com",
        "mimecast"
    ]

    for keyword in mimecast_keywords:

        if keyword in mx_text:

            return {
                "gateway": "MIMECAST",
                "provider": "Mimecast",
                "security_gateway": True
            }


    # -----------------------------------------------------
    # MICROSOFT 365
    # -----------------------------------------------------

    microsoft_keywords = [
        "mail.protection.outlook.com",
        "protection.outlook.com"
    ]

    for keyword in microsoft_keywords:

        if keyword in mx_text:

            return {
                "gateway": "MICROSOFT_365",
                "provider": "Microsoft 365 / Exchange Online",
                "security_gateway": True
            }


    # -----------------------------------------------------
    # GOOGLE WORKSPACE
    # -----------------------------------------------------

    google_keywords = [
        "aspmx.l.google.com",
        "alt1.aspmx.l.google.com",
        "alt2.aspmx.l.google.com",
        "alt3.aspmx.l.google.com",
        "alt4.aspmx.l.google.com"
    ]

    for keyword in google_keywords:

        if keyword in mx_text:

            return {
                "gateway": "GOOGLE_WORKSPACE",
                "provider": "Google Workspace",
                "security_gateway": False
            }


    # -----------------------------------------------------
    # PROOFPOINT
    # -----------------------------------------------------

    proofpoint_keywords = [
        "proofpoint.com",
        "pphosted.com",
        "proofpoint"
    ]

    for keyword in proofpoint_keywords:

        if keyword in mx_text:

            return {
                "gateway": "PROOFPOINT",
                "provider": "Proofpoint",
                "security_gateway": True
            }


    # -----------------------------------------------------
    # BARRACUDA
    # -----------------------------------------------------

    barracuda_keywords = [
        "barracudanetworks.com",
        "barracuda.com",
        "barracuda"
    ]

    for keyword in barracuda_keywords:

        if keyword in mx_text:

            return {
                "gateway": "BARRACUDA",
                "provider": "Barracuda",
                "security_gateway": True
            }


    # -----------------------------------------------------
    # FORTIMAIL
    # -----------------------------------------------------

    fortimail_keywords = [
        "fortimail",
        "fortimailcloud.com",
        "fortinet.com"
    ]

    for keyword in fortimail_keywords:

        if keyword in mx_text:

            return {
                "gateway": "FORTIMAIL",
                "provider": "Fortinet FortiMail",
                "security_gateway": True
            }


    # -----------------------------------------------------
    # CISCO SECURE EMAIL
    # -----------------------------------------------------

    cisco_keywords = [
        "iphmx.com",
        "cisco.com"
    ]

    for keyword in cisco_keywords:

        if keyword in mx_text:

            return {
                "gateway": "CISCO",
                "provider": "Cisco Secure Email",
                "security_gateway": True
            }


    # -----------------------------------------------------
    # OTHER SECURITY GATEWAYS
    # -----------------------------------------------------

    other_gateways = {

        "messagelabs": "Symantec / MessageLabs",

        "symantec": "Symantec",

        "mailchannels": "MailChannels",

        "spamexperts": "SpamExperts",

        "mailroute": "MailRoute",

        "hornetsecurity": "Hornetsecurity",

        "forcepoint": "Forcepoint",

        "sophos": "Sophos",

        "trendmicro": "Trend Micro",

        "cloudmark": "Cloudmark",

        "zerospam": "ZeroSpam",

        "spamhero": "SpamHero"

    }


    for keyword, provider in other_gateways.items():

        if keyword in mx_text:

            return {
                "gateway": "OTHER_GATEWAY",
                "provider": provider,
                "security_gateway": True
            }


    # -----------------------------------------------------
    # NORMAL / UNKNOWN MAIL SERVER
    # -----------------------------------------------------

    return {
        "gateway": "OTHER",
        "provider": "Unknown mail server",
        "security_gateway": False
    }


# =========================================================
# VERIFY EMAIL
# =========================================================

def verify_email(email):

    email = email.strip().lower()


    # -----------------------------------------------------
    # EMPTY EMAIL
    # -----------------------------------------------------

    if not email:

        return {
            "status": "INVALID",
            "reason": "Email address is empty"
        }


    # -----------------------------------------------------
    # EMAIL FORMAT
    # -----------------------------------------------------

    if not is_valid_email_format(email):

        return {
            "status": "INVALID",
            "reason": "Invalid email format"
        }


    # -----------------------------------------------------
    # EXTRACT DOMAIN
    # -----------------------------------------------------

    try:

        recipient_domain = email.split("@", 1)[1].strip().lower()

    except Exception:

        return {
            "status": "INVALID",
            "reason": "Could not extract recipient domain"
        }


    # -----------------------------------------------------
    # GET MX
    # -----------------------------------------------------

    mx_records = get_mx_records(
        recipient_domain
    )


    # -----------------------------------------------------
    # NO MX
    # -----------------------------------------------------

    if not mx_records:

        return {

            "status": "NO_MX",

            "reason": (
                "No valid MX record found for recipient domain"
            ),

            "recipient_email": email,

            "recipient_domain": recipient_domain,

            "gateway": "NONE",

            "provider": "None",

            "security_gateway": False,

            "mx_records": []
        }


    # -----------------------------------------------------
    # DETECT GATEWAY
    # -----------------------------------------------------

    gateway_info = detect_mail_gateway(
        mx_records
    )

    gateway = gateway_info["gateway"]

    provider = gateway_info["provider"]

    security_gateway = gateway_info["security_gateway"]


    # -----------------------------------------------------
    # DETERMINE STATUS
    # -----------------------------------------------------

    if gateway == "MIMECAST":

        status = "MIMECAST"

        reason = (
            "Mimecast mail gateway detected from "
            "recipient MX records"
        )


    elif gateway == "MICROSOFT_365":

        status = "MICROSOFT_365"

        reason = (
            "Microsoft 365 / Exchange Online "
            "mail gateway detected from recipient MX records"
        )


    elif gateway == "GOOGLE_WORKSPACE":

        status = "GOOGLE_WORKSPACE"

        reason = (
            "Google Workspace mail server detected "
            "from recipient MX records"
        )


    elif security_gateway:

        status = gateway

        reason = (
            provider +
            " mail gateway detected from recipient MX records"
        )


    else:

        status = "VALID"

        reason = (
            "Valid email format and recipient "
            "mail server found"
        )


    # -----------------------------------------------------
    # FINAL RESULT
    # -----------------------------------------------------

    return {

        "status": status,

        "reason": reason,

        "recipient_email": email,

        "recipient_domain": recipient_domain,

        "gateway": gateway,

        "provider": provider,

        "security_gateway": security_gateway,

        "mx_records": mx_records,

        "mailbox_verified": False,

        "verification_level": "DOMAIN_AND_MX_ONLY"

    }


# =========================================================
# HOME / API STATUS
# =========================================================

@app.route("/", methods=["GET"])
def home():

    return jsonify({

        "status": "online",

        "service": "IMMUNIS Email Verification API",

        "version": "5.0",

        "sending_domains": SENDING_DOMAINS,

        "verification": [
            "EMAIL_FORMAT",
            "DOMAIN",
            "MX",
            "MAIL_GATEWAY"
        ],

        "note": (
            "Individual mailbox existence cannot be "
            "guaranteed through DNS/MX alone."
        )
    })


# =========================================================
# VERIFY ENDPOINT
# =========================================================

@app.route("/verify", methods=["GET", "POST"])
def verify():


    # -----------------------------------------------------
    # GET REQUEST
    # -----------------------------------------------------

    if request.method == "GET":

        email = request.args.get(
            "email",
            ""
        ).strip()

        full_name = request.args.get(
            "full_name",
            ""
        ).strip()


    # -----------------------------------------------------
    # POST REQUEST
    # -----------------------------------------------------

    else:

        data = request.get_json(
            silent=True
        ) or {}

        email = str(
            data.get(
                "email",
                ""
            )
        ).strip()

        full_name = str(
            data.get(
                "full_name",
                ""
            )
        ).strip()


    # -----------------------------------------------------
    # MISSING EMAIL
    # -----------------------------------------------------

    if not email:

        return jsonify({

            "full_name": full_name,

            "recipient_email": "",

            "recipient_domain": "",

            "status": "INVALID",

            "reason": "Email address is missing"

        }), 400


    # -----------------------------------------------------
    # VERIFY
    # -----------------------------------------------------

    result = verify_email(email)


    # -----------------------------------------------------
    # RESPONSE
    # -----------------------------------------------------

    response = {

        "full_name": full_name,

        "recipient_email": result.get(
            "recipient_email",
            email
        ),

        "recipient_domain": result.get(
            "recipient_domain",
            ""
        ),

        "status": result.get(
            "status",
            "UNKNOWN"
        ),

        "reason": result.get(
            "reason",
            "Unable to verify"
        ),

        "gateway": result.get(
            "gateway",
            "UNKNOWN"
        ),

        "provider": result.get(
            "provider",
            "Unknown"
        ),

        "security_gateway": result.get(
            "security_gateway",
            False
        ),

        "mailbox_verified": result.get(
            "mailbox_verified",
            False
        ),

        "verification_level": result.get(
            "verification_level",
            "UNKNOWN"
        ),

        "mx_records": result.get(
            "mx_records",
            []
        )
    }


    return jsonify(response)


# =========================================================
# BOUNCE ANALYZER
# =========================================================
#
# This endpoint is for ACTUAL bounce messages.
#
# Example:
#
# POST /bounce
#
# {
#   "email": "person@example.com",
#   "sending_domain": "immunisdrawings.com",
#   "bounce_message": "550 User unknown"
# }
#
# =========================================================

@app.route("/bounce", methods=["POST"])
def bounce():

    data = request.get_json(
        silent=True
    ) or {}


    email = str(
        data.get(
            "email",
            ""
        )
    ).strip().lower()


    sending_domain = str(
        data.get(
            "sending_domain",
            ""
        )
    ).strip().lower()


    bounce_message = str(
        data.get(
            "bounce_message",
            ""
        )
    ).strip()


    # -----------------------------------------------------
    # MISSING DATA
    # -----------------------------------------------------

    if not email or not bounce_message:

        return jsonify({

            "status": "UNKNOWN",

            "reason": (
                "Recipient email and bounce message "
                "are required"
            )

        }), 400


    # -----------------------------------------------------
    # EXTRACT RECIPIENT DOMAIN
    # -----------------------------------------------------

    try:

        recipient_domain = email.split(
            "@",
            1
        )[1]

    except Exception:

        recipient_domain = ""


    # -----------------------------------------------------
    # LOWERCASE BOUNCE
    # -----------------------------------------------------

    bounce_text = bounce_message.lower()


    # -----------------------------------------------------
    # MAILBOX NOT FOUND
    # -----------------------------------------------------

    mailbox_keywords = [

        "user unknown",

        "unknown user",

        "mailbox unavailable",

        "mailbox not found",

        "recipient not found",

        "no such user",

        "no such mailbox",

        "user does not exist",

        "account does not exist",

        "address rejected",

        "invalid recipient",

        "recipient address rejected",

        "550 5.1.1",

        "550 5.1.10",

        "551 5.1.1"

    ]


    for keyword in mailbox_keywords:

        if keyword in bounce_text:

            return jsonify({

                "status": "REJECTED",

                "block_type": "MAILBOX",

                "reason": (
                    "Recipient mailbox appears to be "
                    "invalid or unavailable"
                ),

                "recipient_email": email,

                "recipient_domain": recipient_domain,

                "sending_domain": sending_domain,

                "bounce_match": keyword

            })


    # -----------------------------------------------------
    # MAIL FLOW RULE
    # -----------------------------------------------------

    mail_flow_keywords = [

        "blocked by mail flow rule",

        "mail flow rule",

        "transport rule",

        "message blocked by administrator",

        "organization policy",

        "organizational policy"

    ]


    for keyword in mail_flow_keywords:

        if keyword in bounce_text:

            return jsonify({

                "status": "BLOCKED",

                "block_type": "MAIL_FLOW",

                "reason": (
                    "Recipient organization blocked "
                    "the message through a mail flow or "
                    "transport rule"
                ),

                "recipient_email": email,

                "recipient_domain": recipient_domain,

                "sending_domain": sending_domain,

                "bounce_match": keyword

            })


    # -----------------------------------------------------
    # MIMECAST BLOCK
    # -----------------------------------------------------

    mimecast_keywords = [

        "mimecast",

        "email rejected due to security policies",

        "security policies",

        "mimecast security"

    ]


    for keyword in mimecast_keywords:

        if keyword in bounce_text:

            return jsonify({

                "status": "BLOCKED",

                "block_type": "MIMECAST",

                "reason": (
                    "Recipient mail gateway appears "
                    "to have rejected the message"
                ),

                "recipient_email": email,

                "recipient_domain": recipient_domain,

                "sending_domain": sending_domain,

                "bounce_match": keyword

            })


    # -----------------------------------------------------
    # MICROSOFT 365 BLOCK
    # -----------------------------------------------------

    microsoft_keywords = [

        "microsoft exchange",

        "microsoft 365",

        "office 365",

        "exchange online",

        "protection.outlook.com"

    ]


    for keyword in microsoft_keywords:

        if keyword in bounce_text:

            return jsonify({

                "status": "BLOCKED",

                "block_type": "MICROSOFT_365",

                "reason": (
                    "Microsoft 365 / Exchange appears "
                    "to have rejected the message"
                ),

                "recipient_email": email,

                "recipient_domain": recipient_domain,

                "sending_domain": sending_domain,

                "bounce_match": keyword

            })


    # -----------------------------------------------------
    # GENERIC SECURITY BLOCK
    # -----------------------------------------------------

    security_keywords = [

        "security policy",

        "security policies",

        "spam policy",

        "anti-spam",

        "antispam",

        "sender blocked",

        "sender rejected",

        "policy rejection",

        "blocked",

        "rejected"

    ]


    for keyword in security_keywords:

        if keyword in bounce_text:

            return jsonify({

                "status": "BLOCKED",

                "block_type": "SECURITY_POLICY",

                "reason": (
                    "Recipient server rejected "
                    "the message due to a security "
                    "or policy restriction"
                ),

                "recipient_email": email,

                "recipient_domain": recipient_domain,

                "sending_domain": sending_domain,

                "bounce_match": keyword

            })


    # -----------------------------------------------------
    # UNKNOWN BOUNCE
    # -----------------------------------------------------

    return jsonify({

        "status": "UNKNOWN",

        "block_type": "UNKNOWN",

        "reason": (
            "Bounce received but the rejection "
            "type could not be confidently classified"
        ),

        "recipient_email": email,

        "recipient_domain": recipient_domain,

        "sending_domain": sending_domain

    })


# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=10000
    )
