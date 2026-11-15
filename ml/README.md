# WebShield ML module (offline URL features)

This package is **separate from the Flask rule-based detector** in `app.py`. It does not change existing scoring, templates, or API routes. It never visits a URL or makes network requests.

## Dataset used

Source files (copied from `C:\Users\srish\Desktop\WEBSHIELD final\data\`):

| File | Used for training? | Role |
|---|---|---|
| `data/clean_urls.csv` | **Yes** | Labelled `url,label` rows (64,306) |
| `data/dataset_cleaning_report.csv` | No | Prior cleaning summary |
| `data/dropped_records.csv` | No | 1 normalized duplicate that was dropped |
| `url_features.csv` (original folder only) | **No** | Precomputed rule/feature dump; not used so the ML model does not train on the existing detector’s columns |

`data/clean_urls.csv` analysis:

- Columns: `url`, `label`
- Records: 64,306
- Missing values: 0
- Duplicate records / duplicate URLs: 0
- Invalid URLs: 0
- Classes: legitimate 32,239 · phishing 32,067

## Virtual environment

```powershell
$py = "C:\Users\srish\Desktop\webshield-pbl-srishtika\.venv\Scripts\python.exe"
cd "C:\Users\srish\Desktop\webshield-pbl-srishtika\Webshield-pbl-main (13)\Webshield-pbl-main"
```

Installed for training (not used by the Flask app): `scikit-learn`, `joblib`, and their numpy/scipy dependencies.

```powershell
& $py -m pip install -r ml/requirements.txt
```

## Commands

### Feature extraction

```powershell
& $py ml/features.py "https://www.google.com"
& $py ml/features.py "http://192.168.1.1/login?account=1"
```

### Dataset inspection

```powershell
& $py ml/analyze_dataset.py
& $py ml/analyze_dataset.py --csv data/clean_urls.csv
```

### Tests

```powershell
& $py -m unittest tests.test_ml_features tests.test_ml_analyze tests.test_ml_train -v
```

### Training

```powershell
& $py ml/train.py --csv data/clean_urls.csv
```

Split: 51,445 train URLs / 12,861 test URLs. Same exact URL cannot appear in both splits. Related domains are **not** grouped (no public-suffix table), so metrics can look optimistic if sibling hostnames leak across the split.

Selected model: **random_forest** (vs logistic regression).

Held-out test metrics (this CSV only):

| Model | Accuracy | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|
| Logistic Regression | 0.9830 | 0.9928 | 0.9730 | 0.9828 | 0.0070 |
| Random Forest | **0.9934** | **0.9964** | **0.9903** | **0.9934** | **0.0036** |

Random Forest confusion matrix: TN 6425, FP 23, FN 62, TP 6351.

Saved artefacts:

- `ml/artifacts/model.joblib`
- `ml/artifacts/model_meta.json`

These numbers describe lexical URL features on this cleaned set. They are not a claim about live web accuracy, and they are not the Flask rule-based score.

### Prediction CLI (not wired into Flask)

```powershell
& $py ml/predict.py "https://www.google.com"
& $py ml/predict.py "http://192.168.1.1/login?account=1"
```
