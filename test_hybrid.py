
import sys
from pathlib import Path

import joblib
import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import app
from ml.features import feature_vector

DATASET = ROOT / "data" / "data_imbal - 55000.xlsx"
MODEL_PATH = ROOT / "ml" / "artifacts" / "model.joblib"
OUTPUT = ROOT / "data" / "hybrid_test_results.csv"


def main():
    df = pd.read_excel(DATASET).dropna(subset=["URLs", "Labels"])
    df["Labels"] = pd.to_numeric(df["Labels"], errors="coerce")
    df = df.dropna(subset=["Labels"])
    df = df[df["Labels"].isin([0, 1])]
    df["URLs"] = df["URLs"].astype(str).str.strip()
    df = df.drop_duplicates(subset=["URLs"]).reset_index(drop=True)

    model = joblib.load(MODEL_PATH)

    # Disable live network checks for this offline benchmark.
    app.check_safe_browsing = lambda url: (False, [])

    actual, predicted, rows = [], [], []
    print(f"Testing {len(df):,} URLs. Model loaded once.")

    for start in range(0, len(df), 500):
        batch = df.iloc[start:start + 500]
        urls = batch["URLs"].tolist()

        # Batch ML predictions; do not reload the model for every URL.
        vectors = [feature_vector(url) for url in urls]
        ml_labels = model.predict(vectors)

        for url, label, ml_label in zip(urls, batch["Labels"], ml_labels):
            # Reuse the app's rule-based calculation and hybrid decision logic.
            # Patch only the per-URL ML prediction to use the already-loaded model.
            original_predict = app.predict_url
            app.predict_url = lambda raw_url, artifact_dir, pred=int(ml_label): {
                "prediction": "phishing" if pred == 1 else "legitimate",
                "label": pred,
            }
            try:
                result = app.analyze_url(url)
            finally:
                app.predict_url = original_predict

            verdict = result["hybrid_verdict"]
            pred_label = 0 if verdict == "Safe" else 1

            actual.append(int(label))
            predicted.append(pred_label)
            rows.append({
                "url": url,
                "actual_label": int(label),
                "ml_prediction": "phishing" if ml_label == 1 else "legitimate",
                "hybrid_verdict": verdict,
                "hybrid_risk": result.get("hybrid_risk"),
                "rule_risk": result.get("rule_risk"),
                "predicted_label": pred_label,
            })

        print(f"Processed {min(start + 500, len(df)):,}/{len(df):,}")

    print("\n=== HYBRID EVALUATION ===")
    print(f"Accuracy: {accuracy_score(actual, predicted):.4f}")
    print(classification_report(
        actual, predicted,
        labels=[0, 1],
        target_names=["Legitimate", "Phishing"],
        zero_division=0,
    ))
    print("Confusion matrix (actual rows, predicted columns):")
    print(confusion_matrix(actual, predicted, labels=[0, 1]))

    pd.DataFrame(rows).to_csv(OUTPUT, index=False)
    print(f"Detailed results saved to: {OUTPUT}")


if __name__ == "__main__":
    main()
