from flask import Flask, render_template, request
import subprocess
import os
import uuid

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"


@app.route("/")
def home():
    return render_template("index.html")


def clean_slither_output(output):
    lines = output.split("\n")

    high = set()
    medium = set()
    low = set()

    for line in lines:
        line = line.strip().lower()

        if not line:
            continue

        # HIGH RISK
        if "reentrancy-eth" in line or "reentrancy-no-eth" in line:
            high.add("Reentrancy vulnerability detected")

        elif "arbitrary-send-eth" in line:
            high.add("Unauthorized Ether transfer / access control issue detected")

        elif "suicidal" in line:
            high.add("Contract may be destructible by unauthorized users")

        elif "tx-origin" in line:
            high.add("Unsafe use of tx.origin detected")

        elif "solc-version" in line or "version constraint" in line:
            high.add("Solidity version may contain known issues")

        # MEDIUM RISK
        elif "low-level-calls" in line or "low level call" in line:
            medium.add("Low-level call usage detected")

        elif "unchecked-send" in line:
            medium.add("Unchecked send/call result detected")

        elif "delegatecall" in line:
            medium.add("delegatecall usage detected")

        elif "timestamp" in line:
            medium.add("Timestamp dependence detected")

        elif "warning:" in line and "spdx" in line:
            medium.add("SPDX License missing")

        # LOW RISK
        elif "naming-convention" in line:
            low.add("Naming convention issue")

        elif "immutable-states" in line:
            low.add("State variable could be immutable")

        elif "dead-code" in line:
            low.add("Dead code detected")

    result = ""

    if high:
        result += "🔴 HIGH RISK:\n"
        for item in sorted(high):
            result += f"- {item}\n"

    if medium:
        result += "\n🟡 MEDIUM RISK:\n"
        for item in sorted(medium):
            result += f"- {item}\n"

    if low:
        result += "\n🟢 LOW RISK:\n"
        for item in sorted(low):
            result += f"- {item}\n"

    if not result:
        result = "✅ No major vulnerabilities detected."

    return result, len(high), len(medium), len(low)

def run_slither(filepath):
    result = subprocess.run(
        ["slither", filepath],
        capture_output=True,
        text=True
    )

    combined_output = result.stdout + "\n" + result.stderr
    return clean_slither_output(combined_output)

def run_solc(filepath):
    result = subprocess.run(
        ["solc", "--bin", filepath],
        capture_output=True,
        text=True
    )

    output = result.stderr.strip()

    if not output:
        return "✅ Compilation Successful"

    lines = output.split("\n")

    warnings = set()
    errors = set()

    for line in lines:
        line = line.strip()

        if "Warning:" in line:
            warnings.add("SPDX License missing")

        elif "Error:" in line:
            errors.add(line)

    result_text = ""

    if errors:
        result_text += "🔴 COMPILER ERRORS:\n"
        for e in errors:
            result_text += f"- {e}\n"

    if warnings:
        result_text += "\n🟡 COMPILER WARNINGS:\n"
        for w in warnings:
            result_text += f"- {w}\n"

    if not result_text:
        return "✅ Compilation Successful"

    return result_text

@app.route("/analyze", methods=["POST"])
def analyze():
    if "contract" not in request.files:
        return render_template(
            "index.html",
            slither_result="No file uploaded.",
            solc_result=""
        )

    file = request.files["contract"]

    if file.filename == "":
        return render_template(
            "index.html",
            slither_result="No file selected.",
            solc_result=""
        )

    if not file.filename.lower().endswith(".sol"):
        return render_template(
            "index.html",
            slither_result="Only .sol files allowed.",
            solc_result=""
        )

    unique_name = f"{uuid.uuid4().hex}_{file.filename}"
    filepath = os.path.join(UPLOAD_FOLDER, unique_name)
    file.save(filepath)

    try:
        slither_result, high_count, medium_count, low_count = run_slither(filepath)
        solc_result = run_solc(filepath)

    except Exception as e:
        slither_result = f"Unexpected error: {str(e)}"
        solc_result = ""
        high_count = 0
        medium_count = 0
        low_count = 0

    finally:
        if os.path.exists(filepath):
            os.remove(filepath)

    return render_template(
    "index.html",
    slither_result=slither_result,
    solc_result=solc_result,
    high_count=high_count,
    medium_count=medium_count,
    low_count=low_count
    )


if __name__ == "__main__":
    app.run(debug=True)