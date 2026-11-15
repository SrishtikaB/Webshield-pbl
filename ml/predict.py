"""CLI prediction for a saved ML model. Not wired into the Flask app."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from ml.features import FEATURE_NAMES, extract_url_features, feature_vector
from ml.train import META_FILENAME, MODEL_FILENAME

DEFAULT_ARTIFACT_DIR = Path(__file__).resolve().parent / "artifacts"


def load_artifacts(artifact_dir: Path):
    model_path = artifact_dir / MODEL_FILENAME
    meta_path = artifact_dir / META_FILENAME
    if not model_path.is_file() or not meta_path.is_file():
        raise FileNotFoundError(
            "No saved model found. Training was not run because this repository "
            "does not include a labelled URL CSV. After you add data/urls.csv, run:\n"
            "  python ml/train.py"
        )
    try:
        import joblib
    except ImportError as exc:
        raise RuntimeError(
            "joblib/scikit-learn are required to load a trained model. "
            "Install them with: pip install -r ml/requirements.txt"
        ) from exc
    model = joblib.load(model_path)
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    names = tuple(meta.get("feature_names") or FEATURE_NAMES)
    if names != FEATURE_NAMES:
        raise ValueError(
            "Saved feature definitions do not match ml/features.py. Retrain the model."
        )
    return model, meta


def predict_url(url: str, artifact_dir: Path) -> dict:
    model, meta = load_artifacts(artifact_dir)
    features = extract_url_features(url)
    vector = feature_vector(url)
    raw = model.predict([vector])[0]
    label = int(raw)
    verdict = "phishing" if label == 1 else "legitimate"
    result = {
        "url": url,
        "prediction": verdict,
        "label": label,
        "model": meta.get("selected_model"),
        "features": features,
    }
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba([vector])[0]
        classes = [int(c) for c in model.classes_]
        result["probabilities"] = {
            "legitimate": float(proba[classes.index(0)]) if 0 in classes else None,
            "phishing": float(proba[classes.index(1)]) if 1 in classes else None,
        }
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Predict phishing vs legitimate from URL features.")
    parser.add_argument("url", help="URL to classify locally; it is not fetched")
    parser.add_argument(
        "--artifacts",
        default=str(DEFAULT_ARTIFACT_DIR),
        help="Directory containing model.joblib and model_meta.json",
    )
    args = parser.parse_args(argv)
    try:
        result = predict_url(args.url, Path(args.artifacts))
    except (FileNotFoundError, RuntimeError, ValueError) as exc:
        print(str(exc))
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
