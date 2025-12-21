# đảm bảo dữ liệu để train chỉ gồm các sqli cơ bản 
import pandas as pd
import re

INPUT = "dataset_final.csv"
OUTPUT_TRAIN = "dataset_final.csv"
OUTPUT_TEST = "dataset_test_sqli_logic.csv"

# -----------------------------
# SQLi logic / blind keywords
# -----------------------------
LOGIC_PATTERN = r"(ascii\s*\(|substr\s*\(|length\s*\(|extractvalue\s*\(|sleep\s*\(|benchmark\s*\()"

df = pd.read_csv(INPUT, low_memory=False)

# -----------------------------
# SQLi logic (để TEST)
# -----------------------------
sqli_logic = df[
    (df["attack_type"] == 3) &
    (df["full_log_text"].str.contains(LOGIC_PATTERN, case=False, na=False))
]

# -----------------------------
# SQLi classic + all other logs (để TRAIN)
# -----------------------------
train_df = df.drop(sqli_logic.index)

# -----------------------------
# SAVE
# -----------------------------
train_df.to_csv(OUTPUT_TRAIN, index=False)
sqli_logic.to_csv(OUTPUT_TEST, index=False)

# -----------------------------
# REPORT
# -----------------------------
print("=== FILTER RESULT ===")
print("SQLi logic (for TEST):", len(sqli_logic))
print("Training dataset size:", len(train_df))
print("\nTrain label distribution:")
print(train_df["attack_type"].value_counts().sort_index())

print("\nSaved:")
print(f"- Train: {OUTPUT_TRAIN}")
print(f"- Test (SQLi logic): {OUTPUT_TEST}")
