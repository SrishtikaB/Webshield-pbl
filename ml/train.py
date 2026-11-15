"""Train Logistic Regression and Random Forest on a real labelled URL CSV.

Does not invent labels. Refuses to train if the dataset or sklearn is missing.
Splits by unique URL so the same URL cannot appear in both train and test.
Related domains are not grouped; that limitation is printed after training.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from ml.analyze_dataset import (
    analyze_csv,
    find_existing_dataset,
    required_schema_message,
    resolve_columns,
)
from ml.features import FEATURE_NAMES, feature_vector

POSITIVE_LABELS = {"1", "phishing", "phish", "malicious", "bad", "fake", "unsafe"}
NEGATIVE_LABELS = {"0", "legitimate", "legit", "benign", "good", "real", "safe"}

ARTIFACT_DIR_NAME = "artifacts"
MODEL_FILENAME = "model.joblib"
META_FILENAME = "model_meta.json"


def normalize_label(raw: str | None) -> int | None:
    text = str(raw or "").strip().lower()
    if text in POSITIVE_LABELS:
        return 1
    if text in NEGATIVE_LABELS:
        return 0
    return None


def _read_labelled_rows(path: Path) -> tuple[list[str], list[int], list[str]]:
    import csv

    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        url_col, label_col = resolve_columns(list(reader.fieldnames or []))
        if not url_col or not label_col:
            raise ValueError("CSV must include url and label columns (see ml/README.md).")

        urls: list[str] = []
        labels: list[int] = []
        skipped: list[str] = []
        for index, row in enumerate(reader, start=2):
            url = str(row.get(url_col, "")).strip()
            label = normalize_label(row.get(label_col))
            if not url:
                skipped.append(f"line {index}: empty URL")
                continue
            if label is None:
                skipped.append(f"line {index}: unrecognised label {row.get(label_col)!r}")
                continue
            urls.append(url)
            labels.append(label)
    return urls, labels, skipped


def dedupe_urls(urls: list[str], labels: list[int]) -> tuple[list[str], list[int], int, int]:
    """Keep one row per exact URL. Conflicting labels are dropped, not guessed."""
    grouped: dict[str, set[int]] = defaultdict(set)
    counts: Counter[str] = Counter()
    for url, label in zip(urls, labels):
        grouped[url].add(label)
        counts[url] += 1

    kept_urls: list[str] = []
    kept_labels: list[int] = []
    conflicts = 0
    dropped_dupes = sum(count - 1 for count in counts.values() if count > 1)
    for url, label_set in grouped.items():
        if len(label_set) != 1:
            conflicts += 1
            continue
        kept_urls.append(url)
        kept_labels.append(next(iter(label_set)))
    return kept_urls, kept_labels, dropped_dupes, conflicts


def split_by_unique_url(
    urls: list[str],
    labels: list[int],
    test_size: float = 0.2,
    seed: int = 42,
) -> tuple[list[int], list[int]]:
    """Return train/test index lists. Each URL appears in only one split."""
    if not 0.0 < test_size < 1.0:
        raise ValueError("test_size must be between 0 and 1")
    by_class: dict[int, list[int]] = {0: [], 1: []}
    for index, label in enumerate(labels):
        by_class[label].append(index)

    rng = random.Random(seed)
    train_idx: list[int] = []
    test_idx: list[int] = []
    for class_label, indices in by_class.items():
        shuffled = list(indices)
        rng.shuffle(shuffled)
        if len(shuffled) < 2:
            raise ValueError(
                f"Need at least 2 unique URLs for class {class_label} to split train/test."
            )
        n_test = max(1, int(round(len(shuffled) * test_size)))
        n_test = min(n_test, len(shuffled) - 1)
        test_idx.extend(shuffled[:n_test])
        train_idx.extend(shuffled[n_test:])
    return sorted(train_idx), sorted(test_idx)


def confusion_counts(y_true: list[int], y_pred: list[int]) -> dict[str, int]:
    tp = fp = tn = fn = 0
    for truth, pred in zip(y_true, y_pred):
        if truth == 1 and pred == 1:
            tp += 1
        elif truth == 0 and pred == 1:
            fp += 1
        elif truth == 0 and pred == 0:
            tn += 1
        else:
            fn += 1
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}


def classification_metrics(y_true: list[int], y_pred: list[int]) -> dict[str, float | dict]:
    counts = confusion_counts(y_true, y_pred)
    tp, fp, tn, fn = counts["tp"], counts["fp"], counts["tn"], counts["fn"]
    total = tp + fp + tn + fn
    accuracy = (tp + tn) / total if total else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": fpr,
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
    }


def sklearn_status() -> tuple[bool, str]:
    try:
        import joblib  # noqa: F401
        import sklearn  # noqa: F401
    except ImportError:
        return False, (
            "Training needs scikit-learn and joblib, which are not in the current "
            "virtual environment (Flask/requests only). They are required to fit "
            "Logistic Regression / Random Forest and to serialise the model. "
            "Install them only when you have a real labelled CSV:\n"
            "  pip install -r ml/requirements.txt"
        )
    return True, ""


def _fit_models(x_train, y_train, x_test, y_test):
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler

    models = {
        "logreg": Pipeline(
            [
                ("scaler", StandardScaler()),
                (
                    "clf",
                    LogisticRegression(max_iter=1000, solver="liblinear", random_state=42),
                ),
            ]
        ),
        "random_forest": RandomForestClassifier(
            n_estimators=200,
            random_state=42,
            n_jobs=1,
        ),
    }
    results = {}
    for name, model in models.items():
        model.fit(x_train, y_train)
        pred = [int(v) for v in model.predict(x_test)]
        results[name] = {
            "model": model,
            "metrics": classification_metrics(y_test, pred),
        }
    return results


def _select_model(results: dict) -> str:
    def key(name: str):
        metrics = results[name]["metrics"]
        return (metrics["f1"], metrics["recall"], metrics["accuracy"])

    return max(results, key=key)


def train_from_csv(csv_path: Path, artifact_dir: Path, seed: int = 42) -> dict:
    ready, message = sklearn_status()
    if not ready:
        raise RuntimeError(message)

    import joblib

    report = analyze_csv(csv_path)
    if not report["suitable"]:
        raise ValueError("CSV is not a suitable labelled URL dataset.")

    urls, labels, skipped = _read_labelled_rows(csv_path)
    if skipped:
        print(f"Skipped {len(skipped)} unusable row(s). First issues:")
        for line in skipped[:10]:
            print(f"  - {line}")

    urls, labels, dropped_dupes, conflicts = dedupe_urls(urls, labels)
    if conflicts:
        print(f"Dropped {conflicts} URL(s) with conflicting labels.")
    if dropped_dupes:
        print(f"Collapsed {dropped_dupes} extra duplicate-URL row(s) before splitting.")

    class_counts = Counter(labels)
    if class_counts.get(0, 0) == 0 or class_counts.get(1, 0) == 0:
        raise ValueError("Training requires both classes after cleaning (legitimate and phishing).")

    train_idx, test_idx = split_by_unique_url(urls, labels, test_size=0.2, seed=seed)
    train_urls = {urls[i] for i in train_idx}
    test_urls = {urls[i] for i in test_idx}
    leaked = train_urls & test_urls
    if leaked:
        raise RuntimeError(f"Duplicate-URL leakage detected: {len(leaked)} overlapping URLs.")

    x_train = [feature_vector(urls[i]) for i in train_idx]
    y_train = [labels[i] for i in train_idx]
    x_test = [feature_vector(urls[i]) for i in test_idx]
    y_test = [labels[i] for i in test_idx]

    results = _fit_models(x_train, y_train, x_test, y_test)
    selected = _select_model(results)

    artifact_dir.mkdir(parents=True, exist_ok=True)
    model_path = artifact_dir / MODEL_FILENAME
    meta_path = artifact_dir / META_FILENAME
    joblib.dump(results[selected]["model"], model_path)
    meta = {
        "feature_names": list(FEATURE_NAMES),
        "selected_model": selected,
        "label_mapping": {"0": "legitimate", "1": "phishing"},
        "metrics": results[selected]["metrics"],
        "all_model_metrics": {name: bundle["metrics"] for name, bundle in results.items()},
        "n_train": len(train_idx),
        "n_test": len(test_idx),
        "n_unique_urls": len(urls),
        "seed": seed,
        "dataset": str(csv_path),
        "limitations": (
            "Splits prevent the same exact URL from appearing in both train and test. "
            "Related domains (e.g. a.com vs login.a.com) are not grouped, because this "
            "project does not ship a public-suffix / registrable-domain table. "
            "Lexical URL features can overfit brand or dataset artefacts; metrics are "
            "only valid for the supplied labelled CSV."
        ),
    }
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return {
        "selected_model": selected,
        "metrics": results[selected]["metrics"],
        "all_model_metrics": meta["all_model_metrics"],
        "model_path": str(model_path),
        "meta_path": str(meta_path),
        "n_train": len(train_idx),
        "n_test": len(test_idx),
        "limitations": meta["limitations"],
    }


def _fmt_metrics(metrics: dict) -> str:
    lines = [
        f"  accuracy: {metrics['accuracy']:.4f}",
        f"  precision: {metrics['precision']:.4f}",
        f"  recall: {metrics['recall']:.4f}",
        f"  f1: {metrics['f1']:.4f}",
        f"  false_positive_rate: {metrics['false_positive_rate']:.4f}",
        f"  confusion_matrix: {metrics['confusion_matrix']}",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    project_root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description="Train phishing URL models on a real labelled CSV.")
    parser.add_argument("--csv", dest="csv_path", default=None, help="Path to labelled CSV")
    parser.add_argument(
        "--artifacts",
        dest="artifact_dir",
        default=str(Path(__file__).resolve().parent / ARTIFACT_DIR_NAME),
        help="Directory for the saved model and feature definitions",
    )
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args(argv)

    csv_path = Path(args.csv_path) if args.csv_path else find_existing_dataset(project_root)
    if csv_path is None or not csv_path.is_file():
        print("Training aborted: no real labelled dataset is available.")
        print(required_schema_message())
        print("No model was trained and no metrics were produced.")
        return 1

    ready, message = sklearn_status()
    if not ready:
        print("Training aborted: ML libraries are not installed.")
        print(message)
        print("No model was trained and no metrics were produced.")
        return 1

    try:
        outcome = train_from_csv(csv_path, Path(args.artifact_dir), seed=args.seed)
    except (ValueError, RuntimeError) as exc:
        print(f"Training aborted: {exc}")
        print("No fabricated metrics were reported.")
        return 1

    print(f"Selected model: {outcome['selected_model']}")
    print(f"Train URLs: {outcome['n_train']}  Test URLs: {outcome['n_test']}")
    print("Test metrics:")
    print(_fmt_metrics(outcome["metrics"]))
    print("All models:")
    for name, metrics in outcome["all_model_metrics"].items():
        print(f"- {name}")
        print(_fmt_metrics(metrics))
    print(f"Saved model: {outcome['model_path']}")
    print(f"Saved metadata: {outcome['meta_path']}")
    print("Limitation:")
    print(outcome["limitations"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
