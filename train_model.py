import pandas as pd
import joblib
import re

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

# ================== CONFIG ==================
DATA_FILE = "dataset_final.csv"
MODEL_FILE = "tfidf_multiclass_model.joblib"
RANDOM_STATE = 42
# ===========================================


# ================== NORMALIZATION ==================
def normalize(text: str) -> str:
    """
    Minimal normalization.
    Do NOT remove SQL symbols, comments, or obfuscation.
    """
    if not isinstance(text, str):
        return ""
    text = text.lower()
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def main():
    print("🚀 TRAIN TF-IDF MULTI-CLASS IDS MODEL")

    # ---------- LOAD DATA ----------
    df = pd.read_csv(DATA_FILE, low_memory=False)

    if "full_log_text" not in df.columns or "attack_type" not in df.columns:
        raise ValueError("Dataset thiếu cột full_log_text hoặc attack_type")

    # ---------- NORMALIZE ----------
    df["full_log_text"] = df["full_log_text"].fillna("").apply(normalize)

    X = df["full_log_text"]
    y = df["attack_type"]

    print("\n📊 Label distribution:")
    print(y.value_counts().sort_index())

    # ---------- TRAIN / TEST SPLIT ----------
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=RANDOM_STATE,
        stratify=y
    )

    # ---------- MODEL ----------
    model = Pipeline([
        ("tfidf", TfidfVectorizer(
            ngram_range=(1, 3),
            max_features=8000,
            min_df=2,
            sublinear_tf=True
        )),
        ("clf", LogisticRegression(
            solver="liblinear",
            multi_class="ovr",
            max_iter=4000,
            class_weight={
                0: 1,   # Benign
                1: 2,   # Bruteforce
                2: 2,   # WebScan
                3: 5    # SQL Injection (ưu tiên rule-miss)
            }
        ))
    ])

    # ---------- TRAIN ----------
    print(f"\n🧠 Training on {len(X_train)} samples...")
    model.fit(X_train, y_train)
    print("✅ Training completed")

    # ---------- EVALUATION ----------
    y_pred = model.predict(X_test)

    print("\n📈 Accuracy:", accuracy_score(y_test, y_pred))
    print("\n📋 Classification Report:")
    print(classification_report(
        y_test,
        y_pred,
        target_names=[
            "Benign (0)",
            "Bruteforce (1)",
            "WebScan (2)",
            "SQL Injection (3)"
        ],
        zero_division=0
    ))

    # ---------- SAVE ----------
    joblib.dump(model, MODEL_FILE)
    print(f"\n💾 Model saved to {MODEL_FILE}")
    print("🎉 TRAINING FINISHED")


if __name__ == "__main__":
    main()
