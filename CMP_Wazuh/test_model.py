import joblib
import re

# ================== CONFIG ==================
MODEL_FILE = "tfidf_multiclass_model.joblib"
LOG_FILE = "apache_obfuscated_sqli.log"
OUTPUT_FILE = "sqli_detection_result.txt"

SQLI_LABEL = 3
THRESHOLD = 0.5
# ===========================================


# ================== NORMALIZATION ==================
def normalize(text: str) -> str:
    """
    Phải giống hệt normalization lúc train
    """
    if not isinstance(text, str):
        return ""
    text = text.lower()
    text = re.sub(r"\s+", " ", text)
    return text.strip()


# ================== EXTRACT REQUEST ==================
def extract_request(line: str) -> str:
    """
    Trích phần request URI từ Apache combined log
    """
    m = re.search(r'"(?:GET|POST|PUT|DELETE)\s+([^"]+?)\s+HTTP', line, re.I)
    if m:
        return m.group(1)
    return ""


def main():
    print("🧪 TEST TF-IDF GENERALIZATION FROM APACHE LOG")
    print(f"📂 Log file: {LOG_FILE}")
    print(f"📝 Output file: {OUTPUT_FILE}")

    # ---------- LOAD MODEL ----------
    model = joblib.load(MODEL_FILE)

    total = 0
    detected = 0

    with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f, \
         open(OUTPUT_FILE, "w", encoding="utf-8") as out:

        out.write("🧪 TF-IDF SQLi Detection Result\n")
        out.write(f"Log file: {LOG_FILE}\n")
        out.write("=" * 60 + "\n\n")

        for line in f:
            line = line.strip()
            if not line:
                continue

            request = extract_request(line)
            if not request:
                continue

            total += 1
            text = normalize(request)

            proba = model.predict_proba([text])[0]
            sqli_score = proba[SQLI_LABEL]

            out.write(f"DEBUG | score={sqli_score:.3f} | {text}\n")

            if sqli_score >= THRESHOLD:
                detected += 1
                out.write(f"[SQLi ML:{sqli_score:.2f}] {text}\n")

        # ---------- SUMMARY ----------
        out.write("\n========== SUMMARY ==========\n")
        out.write(f"Total requests tested: {total}\n")
        out.write(f"Detected SQLi by ML: {detected}\n")

    print("✅ Done. Result saved to file.")


if __name__ == "__main__":
    main()
