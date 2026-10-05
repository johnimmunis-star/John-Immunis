from flask import Flask, request, jsonify
import dns.resolver
import re

app = Flask(__name__)


def is_valid_email_format(email):
    pattern = r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
    return re.match(pattern, email) is not None


def get_mx_records(domain):
    try:
        answers = dns.resolver.resolve(
            domain,
            "MX",
            lifetime=10
        )

        records = []

        for answer in answers:
            mx_host = str(answer.exchange).rstrip(".")
            records.append(mx_host)

        return records

    except Exception:
        return []


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
            "reason": "No valid MX record found for this domain"
        }

    # 4. Domain has a mail server
    return {
        "status": "VALID",
        "reason": "Valid email format and mail server (MX) found",
        "domain": domain,
        "mx_records": mx_records
    }


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "status": "online",
        "service": "Email Verification API",
        "version": "2.0"
    })


@app.route("/verify", methods=["POST"])
def verify():

    data = request.get_json(silent=True) or {}

    email = str(data.get("email", "")).strip()
    full_name = str(data.get("full_name", "")).strip()

    if not email:
        return jsonify({
            "full_name": full_name,
            "email": "",
            "status": "RISK",
            "reason": "Email address is missing"
        }), 400

    result = verify_email(email)

    response = {
        "full_name": full_name,
        "email": email,
        "status": result["status"],
        "reason": result["reason"]
    }

    if "domain" in result:
        response["domain"] = result["domain"]

    if "mx_records" in result:
        response["mx_records"] = result["mx_records"]

    return jsonify(response)


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=10000
    )
