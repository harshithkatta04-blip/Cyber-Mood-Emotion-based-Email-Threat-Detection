import argparse
import csv
import json
import random
from datetime import datetime, timezone
from pathlib import Path

import joblib
from sklearn.feature_extraction import DictVectorizer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
from sklearn.pipeline import Pipeline


def parse_args():
    parser = argparse.ArgumentParser(description="Train all CyberMood ML tasks with 70/10/20 split.")
    parser.add_argument(
        "--config",
        default="ml/config/training_plan.json",
        help="Path to training config JSON.",
    )
    parser.add_argument(
        "--target-accuracy",
        type=float,
        default=None,
        help="Override target accuracy threshold from config.",
    )
    return parser.parse_args()


def read_csv_rows(path: Path):
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        return list(reader), list(reader.fieldnames or [])


def write_csv_rows(path: Path, fieldnames, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def stratified_split(rows, label_column, split_cfg, seed):
    groups = {}
    for row in rows:
        label = row.get(label_column, "")
        groups.setdefault(label, []).append(row)

    rng = random.Random(seed)
    train_rows, val_rows, test_rows = [], [], []
    train_ratio = float(split_cfg["train"])
    val_ratio = float(split_cfg["validation"])

    for label_rows in groups.values():
        rng.shuffle(label_rows)
        n = len(label_rows)
        if n <= 1:
            n_train, n_val = 1, 0
        elif n == 2:
            n_train, n_val = 1, 0
        else:
            n_train = max(1, int(round(n * train_ratio)))
            n_val = max(1, int(round(n * val_ratio)))
            if n_train + n_val >= n:
                n_val = 1
                n_train = n - 2
        n_test = max(0, n - n_train - n_val)

        train_rows.extend(label_rows[:n_train])
        val_rows.extend(label_rows[n_train : n_train + n_val])
        test_rows.extend(label_rows[n_train + n_val : n_train + n_val + n_test])

    rng.shuffle(train_rows)
    rng.shuffle(val_rows)
    rng.shuffle(test_rows)
    return train_rows, val_rows, test_rows


def _safe_cast(value):
    if value is None:
        return ""
    text = str(value).strip()
    if text == "":
        return ""
    try:
        if "." in text or "e" in text.lower():
            return float(text)
        return int(text)
    except Exception:
        return text


def _to_feature_dict(row, label_column):
    features = {}
    for key, value in row.items():
        if key == label_column:
            continue
        if key.strip().lower() in {"id", "sample_id"}:
            continue
        features[key] = _safe_cast(value)
    return features


def _evaluate(model, x_rows, y_true):
    if not x_rows or not y_true:
        return {"accuracy": None, "report": "No samples."}
    y_pred = model.predict(x_rows)
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "report": classification_report(y_true, y_pred, digits=4, zero_division=0),
    }


def train_text_task(task, train_rows, val_rows, test_rows, label_column):
    text_column = task.get("text_column", "text")
    analyzer = str(task.get("text_analyzer", "word")).strip().lower()
    x_train = [row.get(text_column, "") for row in train_rows]
    y_train = [row.get(label_column, "") for row in train_rows]
    x_val = [row.get(text_column, "") for row in val_rows]
    y_val = [row.get(label_column, "") for row in val_rows]
    x_test = [row.get(text_column, "") for row in test_rows]
    y_test = [row.get(label_column, "") for row in test_rows]

    if analyzer == "char_wb":
        tfidf = TfidfVectorizer(
            lowercase=True,
            analyzer="char_wb",
            ngram_range=(3, 6),
            min_df=1,
            max_features=50000,
            strip_accents="unicode",
        )
    else:
        tfidf = TfidfVectorizer(
            lowercase=True,
            ngram_range=(1, 2),
            min_df=2,
            max_features=120000,
            strip_accents="unicode",
        )

    model = Pipeline(
        [
            ("tfidf", tfidf),
            (
                "clf",
                LogisticRegression(
                    max_iter=3000,
                    class_weight="balanced",
                    solver="liblinear",
                ),
            ),
        ]
    )
    model.fit(x_train, y_train)
    val_metrics = _evaluate(model, x_val, y_val)
    test_metrics = _evaluate(model, x_test, y_test)
    return model, val_metrics, test_metrics


def train_tabular_task(train_rows, val_rows, test_rows, label_column, model_name: str = "logreg"):
    x_train = [_to_feature_dict(row, label_column) for row in train_rows]
    y_train = [row.get(label_column, "") for row in train_rows]
    x_val = [_to_feature_dict(row, label_column) for row in val_rows]
    y_val = [row.get(label_column, "") for row in val_rows]
    x_test = [_to_feature_dict(row, label_column) for row in test_rows]
    y_test = [row.get(label_column, "") for row in test_rows]

    model_name = str(model_name).strip().lower()

    if model_name == "svc_rbf":
        from sklearn.svm import SVC

        clf = SVC(kernel="rbf", C=10, gamma="scale", class_weight="balanced")
    elif model_name == "random_forest":
        from sklearn.ensemble import RandomForestClassifier

        clf = RandomForestClassifier(
            n_estimators=700,
            random_state=42,
            class_weight="balanced_subsample",
            n_jobs=-1,
        )
    elif model_name == "extra_trees":
        from sklearn.ensemble import ExtraTreesClassifier

        clf = ExtraTreesClassifier(
            n_estimators=900,
            random_state=42,
            class_weight="balanced",
            n_jobs=-1,
        )
    elif model_name == "gradient_boosting":
        from sklearn.ensemble import GradientBoostingClassifier

        clf = GradientBoostingClassifier(random_state=42)
    else:
        clf = LogisticRegression(
            max_iter=3000,
            class_weight="balanced",
            solver="liblinear",
        )

    model = Pipeline([("dictvec", DictVectorizer(sparse=True)), ("clf", clf)])
    model.fit(x_train, y_train)
    val_metrics = _evaluate(model, x_val, y_val)
    test_metrics = _evaluate(model, x_test, y_test)
    return model, val_metrics, test_metrics


def main():
    args = parse_args()
    config_path = Path(args.config)
    config = json.loads(config_path.read_text(encoding="utf-8"))
    seed = int(config.get("seed", 42))
    split_cfg = config.get("split") or {"train": 0.7, "validation": 0.1, "test": 0.2}
    target_accuracy = (
        float(args.target_accuracy)
        if args.target_accuracy is not None
        else float(config.get("target_accuracy", 0.97))
    )

    model_dir = Path("ml/models")
    split_dir = Path("ml/data/splits")
    report_dir = Path("ml/reports")
    model_dir.mkdir(parents=True, exist_ok=True)
    split_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)

    report = {
        "generatedAtUtc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "targetAccuracy": target_accuracy,
        "split": split_cfg,
        "tasks": [],
    }

    for task in config.get("tasks", []):
        task_name = task["name"]
        label_column = task.get("label_column", "label")
        dataset_path = Path(task["dataset_path"])
        task_out_dir = split_dir / task_name
        task_report = {
            "task": task_name,
            "type": task["type"],
            "datasetPath": str(dataset_path),
            "status": "skipped",
            "reason": "",
        }

        if not dataset_path.exists():
            task_report["reason"] = "Dataset file missing."
            report["tasks"].append(task_report)
            continue

        rows, fieldnames = read_csv_rows(dataset_path)
        if not rows:
            task_report["reason"] = "Dataset is empty."
            report["tasks"].append(task_report)
            continue
        if label_column not in fieldnames:
            task_report["reason"] = f"Label column '{label_column}' not found."
            report["tasks"].append(task_report)
            continue

        train_rows, val_rows, test_rows = stratified_split(rows, label_column, split_cfg, seed)
        task_seed = int(task.get("split_seed", seed))
        if task_seed != seed:
            train_rows, val_rows, test_rows = stratified_split(rows, label_column, split_cfg, task_seed)
        write_csv_rows(task_out_dir / "train.csv", fieldnames, train_rows)
        write_csv_rows(task_out_dir / "validation.csv", fieldnames, val_rows)
        write_csv_rows(task_out_dir / "test.csv", fieldnames, test_rows)

        if len(train_rows) < 10 or len(test_rows) < 5:
            task_report["reason"] = "Insufficient rows after split (need >=10 train and >=5 test)."
            report["tasks"].append(task_report)
            continue

        if task["type"] == "text":
            model, val_metrics, test_metrics = train_text_task(task, train_rows, val_rows, test_rows, label_column)
        elif task["type"] == "tabular":
            model_name = str(task.get("model", "logreg")).strip().lower()
            model, val_metrics, test_metrics = train_tabular_task(
                train_rows, val_rows, test_rows, label_column, model_name=model_name
            )
        else:
            task_report["reason"] = f"Unsupported task type: {task['type']}"
            report["tasks"].append(task_report)
            continue

        model_path = model_dir / f"{task_name}.joblib"
        joblib.dump(model, model_path)

        val_acc = val_metrics["accuracy"]
        test_acc = test_metrics["accuracy"]
        meets_target = (
            val_acc is not None
            and test_acc is not None
            and val_acc >= target_accuracy
            and test_acc >= target_accuracy
        )

        task_report.update(
            {
                "status": "trained",
                "splitCounts": {
                    "train": len(train_rows),
                    "validation": len(val_rows),
                    "test": len(test_rows),
                },
                "modelPath": str(model_path),
                "validationAccuracy": val_acc,
                "testAccuracy": test_acc,
                "meetsTarget": meets_target,
                "validationReport": val_metrics["report"],
                "testReport": test_metrics["report"],
            }
        )
        report["tasks"].append(task_report)

    trained = [t for t in report["tasks"] if t["status"] == "trained"]
    if trained:
        report["trainedTasks"] = len(trained)
        report["allTrainedMeetTarget"] = all(t.get("meetsTarget", False) for t in trained)
    else:
        report["trainedTasks"] = 0
        report["allTrainedMeetTarget"] = False

    latest_path = report_dir / "latest_metrics.json"
    dated_path = report_dir / f"metrics_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
    latest_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    dated_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"Report written: {latest_path}")
    print(f"Trained tasks: {report['trainedTasks']}")
    print(f"All trained tasks >= {target_accuracy:.2%}: {report['allTrainedMeetTarget']}")
    for t in report["tasks"]:
        if t["status"] == "trained":
            print(
                f"- {t['task']}: val={t['validationAccuracy']:.4f}, "
                f"test={t['testAccuracy']:.4f}, meets_target={t['meetsTarget']}"
            )
        else:
            print(f"- {t['task']}: skipped ({t['reason']})")


if __name__ == "__main__":
    main()
