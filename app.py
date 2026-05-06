from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import pandas as pd

app = Flask(__name__)
CORS(app)

# ===== LOAD MODELS SAFELY =====
try:
    re_model = joblib.load("reentrancy_model.pkl")
    re_scaler = joblib.load("scaler.pkl")

    ov_model = joblib.load("overflow_model.pkl")
    ov_scaler = joblib.load("overflow_scaler.pkl")
except Exception as e:
    print("❌ Model loading error:", e)

# ===== FEATURES =====
feature_names = [
    "call_value","low_level_call","delegatecall",
    "transfer","send","balance","msg_sender",
    "require","assert","code_length"
]

def extract_features(code):
    return [[
        code.count("call.value"),
        code.count(".call("),
        code.count("delegatecall"),
        code.count("transfer("),
        code.count("send("),
        code.count("balance"),
        code.count("msg.sender"),
        code.count("require"),
        code.count("assert"),
        len(code)
    ]]

@app.route("/analyze", methods=["POST"])
def analyze():
    try:
        file = request.files.get("file")

        if not file:
            return jsonify({"error": "No file uploaded"}), 400

        code = file.read().decode("utf-8", errors="ignore").lower()

        features = extract_features(code)
        df_features = pd.DataFrame(features, columns=feature_names)

        result = {}

        # ===== REENTRANCY =====
        re_scaled = re_scaler.transform(df_features)
        re_pred = re_model.predict(re_scaled)[0]

        re_reasons = []
        if ".call(" in code:
            re_reasons.append("Uses low-level call (.call)")
        if "call.value" in code:
            re_reasons.append("Transfers Ether using call.value")
        if "require" not in code:
            re_reasons.append("Missing require checks")

        result["reentrancy"] = {
            "label": "Vulnerable ⚠️" if re_pred else "Safe ✅",
            "reasons": re_reasons if re_pred else []
        }

        # ===== OVERFLOW =====
        ov_scaled = ov_scaler.transform(df_features)
        ov_pred = ov_model.predict(ov_scaled)[0]

        ov_reasons = []
        if "+" in code or "-" in code or "*" in code:
            ov_reasons.append("Uses arithmetic operations")
        if "safemath" not in code:
            ov_reasons.append("No SafeMath protection")

        result["overflow"] = {
            "label": "Vulnerable ⚠️" if ov_pred else "Safe ✅",
            "reasons": ov_reasons if ov_pred else []
        }

        print("✅ RESULT:", result)  # debug

        return jsonify(result)

    except Exception as e:
        print("❌ ERROR:", e)
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True)
