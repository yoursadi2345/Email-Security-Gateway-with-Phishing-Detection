"""
app.py
------
Flask entry point for the Email Security Gateway.

Routes:
  GET  /          -> home page with a textarea to paste raw email (.eml content)
  POST /analyze   -> runs detector.analyze_email() and shows the result
  GET  /api/analyze (POST) -> JSON API version, for programmatic use / Postman
"""

from flask import Flask, render_template, request, jsonify
from detector import analyze_email

app = Flask(__name__)


@app.route("/", methods=["GET"])
def home():
    return render_template("index.html", result=None, raw_text="")


@app.route("/analyze", methods=["POST"])
def analyze():
    raw_text = request.form.get("email_content", "")
    if not raw_text.strip():
        return render_template("index.html", result=None, raw_text="", error="Please paste an email first.")
    result = analyze_email(raw_text)
    return render_template("index.html", result=result, raw_text=raw_text)


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    """
    JSON API:
      curl -X POST http://localhost:5000/api/analyze \
           -H "Content-Type: application/json" \
           -d '{"email_content": "..."}'
    """
    data = request.get_json(silent=True) or {}
    raw_text = data.get("email_content", "")
    if not raw_text.strip():
        return jsonify({"error": "email_content is required"}), 400
    result = analyze_email(raw_text)
    return jsonify(result)


if __name__ == "__main__":
    # For local dev only. On Render, gunicorn will serve this via Procfile.
    app.run(debug=True, host="0.0.0.0", port=5000)
