from flask import Flask, request, jsonify
import dns.resolver
import re

app = Flask(__name__)


# ---------------------------------------------------------
# EMAIL FORMAT CHECK
# ---------------------------------------------------------

def is_valid_email_format(email):
    pattern = r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
    return re.match(pattern, email) is not None


# ---------------------------------------------------------
# GET MX RECORDS
# ---------------------------------------------------------

def get_mx_records(domain):
    try:
        answers = dns.resolver.resolve(
            domain,
            "MX",
            lifetime=10
        )

        records = []

        for answer in answers:
            mx_host = str(answer.exchange).rstrip(".").lower()
            records.append(mx_host)

        return records

    except Exception:
        return []


# ---------------------------------------------------------
# MIMECAST DETECTION
# ---------------------------------------------------------

def is_mimecast_mx(mx_records):
    """
    Detect Mimecast based on publicly visible MX records.
    """

    mimecast_keywords = [
        "mimecast.com",
        "mimecast.co.uk",
        "mimecast.com.au",
        "mimecastcloud.com"
    ]

    for mx in mx_records:
        mx_lower = mx.lower()

        for keyword in mimecast_keywords:
            if keyword in mx_lower:
                return True

    return False


# ---------------------------------------------------------
# EMAIL VERIFICATION
# ---------------------------------------------------------

def verify_email(email):

    email = email.strip().lower()

    # 1. Check email format
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

    # 2. Extract domain
    try:
        domain = email.split("@", 1)[1].strip().lower()

    except Exception:
        return {
            "status": "RISK",
            "reason": "Could not extract email domain"
        }

    # 3. Check MX records
    mx_records = get_mx_records(domain)

    if not mx_records:
        return {
            "status": "RISK",
            "reason": "No valid MX record found for this domain",
            "domain": domain,
            "mx_records": []
        }

    # 4. Check for Mimecast
    if is_mimecast_mx(mx_records):

        return {
            "status": "MIMECAST",
            "reason": "Mimecast mail protection detected from MX records",
            "domain": domain,
            "mx_records": mx_records
        }

    # 5. Normal mail server
    return {
        "status": "VALID",
        "reason": "Valid email format and mail server (MX) found",
        "domain": domain,
        "mx_records": mx_records
    }


# ---------------------------------------------------------
# HOME / API STATUS
# ---------------------------------------------------------

@app.route("/", methods=["GET"])
def home():

    return jsonify({
        "status": "online",
        "service": "Email Verification API",
        "version": "3.0"
    })


# ---------------------------------------------------------
# VERIFY ENDPOINT
# Supports GET and POST
# ---------------------------------------------------------

@app.route("/verify", methods=["GET", "POST"])
def verify():

    # ---------------------------------------------
    # GET REQUEST
    # Useful for browser testing
    # ---------------------------------------------

    if request.method == "GET":

        email = request.args.get("email", "").strip()
        full_name = request.args.get("full_name", "").strip()

    # ---------------------------------------------
    # POST REQUEST
    # Used by Google Apps Script
    # ---------------------------------------------

    else:

        data = request.get_json(silent=True) or {}

        email = str(
            data.get("email", "")
        ).strip()

        full_name = str(
            data.get("full_name", "")
        ).strip()

    # ---------------------------------------------
    # Missing email
    # ---------------------------------------------

    if not email:

        return jsonify({
            "full_name": full_name,
            "email": "",
            "status": "RISK",
            "reason": "Email address is missing"
        }), 400

    # ---------------------------------------------
    # Verify email
    # ---------------------------------------------

    result = verify_email(email)

    response = {
        "full_name": full_name,
        "email": email,
        "status": result["status"],
        "reason": result["reason"]
    }

    # Add domain if available
    if "domain" in result:
        response["domain"] = result["domain"]

    # Add MX records if available
    if "mx_records" in result:
        response["mx_records"] = result["mx_records"]

    return jsonify(response)


# ---------------------------------------------------------
# RUN APPLICATION
# ---------------------------------------------------------

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=10000
    )
