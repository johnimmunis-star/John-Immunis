from flask import Flask, request, jsonify
import dns.resolver
import re

app = Flask(__name__)


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

    # Combine all MX records
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
                "security_gateway": True,
                "provider": "Mimecast"
            }


    # -----------------------------------------------------
    # MICROSOFT 365 / EXCHANGE ONLINE
    # -----------------------------------------------------

    microsoft_keywords = [
        "mail.protection.outlook.com",
        "protection.outlook.com",
        "outlook.com"
    ]

    for keyword in microsoft_keywords:

        if keyword in mx_text:

            return {
                "gateway": "MICROSOFT_365",
                "security_gateway": True,
                "provider": "Microsoft 365 / Exchange Online"
            }


    # -----------------------------------------------------
    # GOOGLE WORKSPACE
    # -----------------------------------------------------

    google_keywords = [
        "aspmx.l.google.com",
        "alt1.aspmx.l.google.com",
        "alt2.aspmx.l.google.com",
        "alt3.aspmx.l.google.com",
        "alt4.aspmx.l.google.com",
        "google.com"
    ]

    for keyword in google_keywords:

        if keyword in mx_text:

            return {
                "gateway": "GOOGLE_WORKSPACE",
                "security_gateway": False,
                "provider": "Google Workspace"
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
                "security_gateway": True,
                "provider": "Proofpoint"
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
                "security_gateway": True,
                "provider": "Barracuda"
            }


    # -----------------------------------------------------
    # FORTIMAIL
    # -----------------------------------------------------

    fortimail_keywords = [
        "fortimail",
        "fortinet.com",
        "fortimailcloud.com"
    ]

    for keyword in fortimail_keywords:

        if keyword in mx_text:

            return {
                "gateway": "FORTIMAIL",
                "security_gateway": True,
                "provider": "Fortinet FortiMail"
            }


    # -----------------------------------------------------
    # CISCO SECURE EMAIL
    # -----------------------------------------------------

    cisco_keywords = [
        "iphmx.com",
        "cisco.com",
        "esa"
    ]

    for keyword in cisco_keywords:

        if keyword in mx_text:

            return {
                "gateway": "CISCO",
                "security_gateway": True,
                "provider": "Cisco Secure Email"
            }


    # -----------------------------------------------------
    # OTHER KNOWN SECURITY GATEWAYS
    # -----------------------------------------------------

    other_gateway_keywords = {

        "sophos": "Sophos",

        "trendmicro": "Trend Micro",

        "forcepoint": "Forcepoint",

        "spamhero": "SpamHero",

        "hornetsecurity": "Hornetsecurity",

        "mimecast": "Mimecast",

        "cloudmark": "Cloudmark",

        "messagelabs": "Symantec / MessageLabs",

        "symantec": "Symantec",

        "sendmail": "Sendmail",

        "mailchannels": "MailChannels",

        "mailroute": "MailRoute",

        "spamexperts": "SpamExperts",

        "spamrl": "SpamRLY",

        "zerospam": "ZeroSpam"

    }


    for keyword, provider in other_gateway_keywords.items():

        if keyword in mx_text:

            return {
                "gateway": "OTHER_GATEWAY",
                "security_gateway": True,
                "provider": provider
            }


    # -----------------------------------------------------
    # UNKNOWN / NORMAL MAIL SERVER
    # -----------------------------------------------------

    return {
        "gateway": "OTHER",
        "security_gateway": False,
        "provider": "Unknown mail server"
    }


# =========================================================
# EMAIL VERIFICATION
# =========================================================

def verify_email(email):

    email = email.strip().lower()


    # -----------------------------------------------------
    # CHECK EMPTY EMAIL
    # -----------------------------------------------------

    if not email:

        return {
            "status": "RISK",
            "reason": "Email address is empty"
        }


    # -----------------------------------------------------
    # CHECK EMAIL FORMAT
    # -----------------------------------------------------

    if not is_valid_email_format(email):

        return {
            "status": "RISK",
            "reason": "Invalid email format"
        }


    # -----------------------------------------------------
    # GET RECIPIENT DOMAIN
    # -----------------------------------------------------

    try:

        domain = email.split("@", 1)[1].strip().lower()

    except Exception:

        return {
            "status": "RISK",
            "reason": "Could not extract recipient domain"
        }


    # -----------------------------------------------------
    # GET MX RECORDS
    # -----------------------------------------------------

    mx_records = get_mx_records(domain)


    # -----------------------------------------------------
    # NO MX
    # -----------------------------------------------------

    if not mx_records:

        return {

            "status": "NO_MX",

            "reason": "No valid MX record found for recipient domain",

            "recipient_domain": domain,

            "mx_records": [],

            "gateway": "NONE",

            "provider": "None",

            "security_gateway": False
        }


    # -----------------------------------------------------
    # DETECT GATEWAY
    # -----------------------------------------------------

    gateway_info = detect_mail_gateway(mx_records)

    gateway = gateway_info["gateway"]

    provider = gateway_info["provider"]

    security_gateway = gateway_info["security_gateway"]


    # -----------------------------------------------------
    # SET STATUS
    # -----------------------------------------------------

    if gateway == "MIMECAST":

        status = "MIMECAST"

        reason = (
            "Mimecast mail gateway detected from recipient MX records"
        )


    elif gateway == "MICROSOFT_365":

        status = "MICROSOFT_365"

        reason = (
            "Microsoft 365 / Exchange Online mail gateway detected "
            "from recipient MX records"
        )


    elif gateway == "GOOGLE_WORKSPACE":

        status = "GOOGLE_WORKSPACE"

        reason = (
            "Google Workspace mail server detected from recipient MX records"
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
            "Valid email format and recipient mail server found"
        )


    # -----------------------------------------------------
    # RETURN RESULT
    # -----------------------------------------------------

    return {

        "status": status,

        "reason": reason,

        "recipient_email": email,

        "recipient_domain": domain,

        "gateway": gateway,

        "provider": provider,

        "security_gateway": security_gateway,

        "mx_records": mx_records
    }


# =========================================================
# HOME
# =========================================================

@app.route("/", methods=["GET"])
def home():

    return jsonify({

        "status": "online",

        "service": "Email Verification API",

        "version": "4.0"
    })


# =========================================================
# VERIFY ENDPOINT
# GET + POST
# =========================================================

@app.route("/verify", methods=["GET", "POST"])
def verify():


    # -----------------------------------------------------
    # GET
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
    # POST
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

            "status": "RISK",

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

        "recipient_email": email,

        "recipient_domain": result.get(
            "recipient_domain",
            ""
        ),

        "status": result.get(
            "status",
            "RISK"
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

        "mx_records": result.get(
            "mx_records",
            []
        )
    }


    return jsonify(response)


# =========================================================
# RUN
# =========================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=10000
    )
