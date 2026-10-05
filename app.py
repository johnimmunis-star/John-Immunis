from flask import Flask, request, jsonify
import dns.resolver
import smtplib
import re

app = Flask(__name__)


def is_valid_email_format(email):
    pattern = r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
    return re.match(pattern, email) is not None


def get_mx_records(domain):
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=8)

        records = []
        for answer in answers:
            records.append(str(answer.exchange).rstrip("."))

        return records

    except Exception:
        return []


def verify_email(email):
    email = email.strip().lower()

    # 1. Basic email format
    if not is_valid_email_format(email):
        return {
            "status": "RISK",
            "reason": "Invalid email format"
        }

    # 2. Extract domain automatically
    try:
        domain = email.split("@", 1)[1]
    except Exception:
        return {
            "status": "RISK",
            "reason": "Invalid email domain"
        }

    # 3. Check MX records
    mx_records = get_mx_records(domain)

    if not mx_records:
        return {
            "status": "RISK",
            "reason": "No valid MX record found"
        }

    # 4. Try SMTP mailbox verification
    for mx_host in mx_records[:3]:

        try:
            smtp = smtplib.SMTP(timeout=10)
            smtp.connect(mx_host, 25)

            smtp.helo("email-verification-api.local")
            smtp.mail("verify@email-verification-api.local")

            code, message = smtp.rcpt(email)

            smtp.quit()

            # Common successful SMTP response
            if 200 <= code < 300:
                return {
                    "status": "VALID",
                    "reason": "Mailbox accepted by mail server"
                }

            # Temporary / policy / security response
            if 400 <= code < 500:
                return {
                    "status": "RISK",
                    "reason": f"Temporary or policy rejection ({code})"
                }

            # Permanent rejection
            if 500 <= code < 600:
                return {
                    "status": "RISK",
                    "reason": f"Mailbox rejected by mail server ({code})"
                }

        except Exception:
            continue

    # MX exists, but mailbox could not be conclusively verified
    return {
        "status": "RISK",
        "reason": "Mailbox could not be verified"
    }


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "status": "online",
        "service": "Email Verification API"
    })


@app.route("/verify", methods=["POST"])
def verify():

    data = request.get_json(silent=True) or {}

    email = data.get("email", "").strip()
    full_name = data.get("full_name", "").strip()

    if not email:
        return jsonify({
            "status": "RISK",
            "reason": "Email address is missing"
        }), 400

    result = verify_email(email)

    return jsonify({
        "full_name": full_name,
        "email": email,
        "status": result["status"],
        "reason": result["reason"]
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
