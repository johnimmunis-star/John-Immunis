from flask import Flask, request, jsonify
import requests
import os

app = Flask(__name__)

# ============================================================
# CONFIGURATION
# ============================================================

# Your temporary Cloudflare Tunnel URL
SMTP_WORKER_URL = os.environ.get(
    "SMTP_WORKER_URL",
    "https://scholar-conflicts-template-light.trycloudflare.com"
).rstrip("/")

REQUEST_TIMEOUT = 30


# ============================================================
# HOME
# ============================================================

@app.route("/", methods=["GET"])
def home():

    return jsonify({
        "status": "online",
        "service": "IMMUNIS Email Verification API",
        "version": "8.0",
        "verification": "Render -> Cloudflare Tunnel -> Local SMTP Worker"
    })


# ============================================================
# VERIFY
# ============================================================

@app.route("/verify", methods=["GET", "POST"])
def verify():

    # --------------------------------------------------------
    # GET REQUEST
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
    # POST REQUEST
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
    # CHECK EMAIL
    # --------------------------------------------------------

    if not email:

        return jsonify({
            "full_name": full_name,
            "email": "",
            "status": "UNKNOWN",
            "reason": "Email address is missing"
        }), 400

    # --------------------------------------------------------
    # SEND REQUEST TO LOCAL SMTP WORKER
    # --------------------------------------------------------

    worker_url = SMTP_WORKER_URL + "/verify"

    payload = {
        "email": email,
        "full_name": full_name
    }

    try:

        response = requests.post(
            worker_url,
            json=payload,
            timeout=REQUEST_TIMEOUT
        )

    except requests.exceptions.Timeout:

        return jsonify({

            "full_name": full_name,

            "email": email,

            "status": "UNKNOWN",

            "reason": (
                "SMTP verification worker timed out"
            )

        })

    except requests.exceptions.RequestException as error:

        return jsonify({

            "full_name": full_name,

            "email": email,

            "status": "UNKNOWN",

            "reason": (
                "Unable to reach SMTP verification worker: "
                + str(error)
            )

        })

    # --------------------------------------------------------
    # WORKER RESPONSE
    # --------------------------------------------------------

    try:

        result = response.json()

    except Exception:

        return jsonify({

            "full_name": full_name,

            "email": email,

            "status": "UNKNOWN",

            "reason": (
                "SMTP worker returned an invalid response"
            ),

            "worker_http_status": response.status_code

        })

    # --------------------------------------------------------
    # RETURN RESULT
    # --------------------------------------------------------

    return jsonify({

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
            result.get(
                "domain",
                ""
            )
        ),

        "gateway": result.get(
            "gateway",
            result.get(
                "security_gateway",
                "UNKNOWN"
            )
        ),

        "security_gateway": result.get(
            "security_gateway",
            result.get(
                "gateway",
                "UNKNOWN"
            )
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

    })


# ============================================================
# WORKER CONNECTION TEST
# ============================================================

@app.route("/worker-test", methods=["GET"])
def worker_test():

    try:

        response = requests.get(
            SMTP_WORKER_URL + "/",
            timeout=10
        )

        return jsonify({

            "render_status": "online",

            "worker_http_status": response.status_code,

            "worker_response": response.json()

        })

    except Exception as error:

        return jsonify({

            "render_status": "online",

            "worker_status": "UNREACHABLE",

            "reason": str(error)

        }), 502


# ============================================================
# ERROR HANDLER
# ============================================================

@app.errorhandler(Exception)
def handle_exception(error):

    return jsonify({

        "status": "UNKNOWN",

        "reason": (
            "Render API error: "
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
