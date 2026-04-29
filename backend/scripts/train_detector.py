"""Train the unified detector on synthetic + provided samples.

This is intentionally minimal but functional: it builds a small labeled
feature dataset from a set of folders (benign/ and malicious/), trains a
RandomForestClassifier wrapped with a StandardScaler, and writes
`detector.joblib` into ${MODELS_DIR}.

Usage:
    python -m scripts.train_detector \
        --benign /var/lib/ransomguard/samples/benign \
        --malicious /var/lib/ransomguard/samples/malicious

If folders are missing, a synthetic dataset is generated so the binary
still produces a usable model for development and demo.
"""

from __future__ import annotations

import argparse
import random
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from app.core.config import settings
from app.ml.features import FileFeatures, extract_features


def _vec(feats: FileFeatures) -> list[float]:
    return feats.to_vector()


def _scan_folder(folder: Path, label: int, cap: int = 500) -> list[tuple[list[float], int]]:
    out: list[tuple[list[float], int]] = []
    if not folder.exists():
        return out
    for path in folder.rglob("*"):
        if not path.is_file():
            continue
        feats = extract_features(path)
        if feats.error:
            continue
        out.append((_vec(feats), label))
        if len(out) >= cap:
            break
    return out


def _synthetic(n: int = 600) -> tuple[np.ndarray, np.ndarray]:
    rng = random.Random(42)
    X: list[list[float]] = []
    y: list[int] = []
    for i in range(n):
        is_mal = i % 2 == 0
        # 14 features in features.py to_vector — keep in sync
        if is_mal:
            v = [
                rng.uniform(0.01, 0.6),  # size norm
                rng.uniform(0.85, 1.0),  # entropy/8
                float(rng.random() > 0.4),  # magic_mismatch
                rng.uniform(0.4, 0.9),  # ext_score
                rng.uniform(0.3, 1.0),  # pattern_count norm
                float(rng.random() > 0.3),  # high entropy block
                float(rng.random() > 0.4),  # encryption_api
                float(rng.random() > 0.5),  # ransom_note
                float(rng.random() > 0.7),  # vss delete
                float(rng.random() > 0.5),  # ps obf
                float(rng.random() > 0.6),  # downloader
                float(rng.random() > 0.6),  # persistence
                float(rng.random() > 0.8),  # tor
                float(rng.random() > 0.7),  # btc
            ]
        else:
            v = [
                rng.uniform(0.0, 0.8),
                rng.uniform(0.2, 0.7),
                0.0,
                rng.uniform(0.0, 0.2),
                rng.uniform(0.0, 0.2),
                0.0,
                0.0,
                0.0,
                0.0,
                0.0,
                0.0,
                0.0,
                0.0,
                0.0,
            ]
        X.append(v)
        y.append(1 if is_mal else 0)
    return np.array(X), np.array(y)


def main() -> None:
    parser = argparse.ArgumentParser(description="Train RansomGuard unified detector")
    parser.add_argument("--benign", type=Path, default=None)
    parser.add_argument("--malicious", type=Path, default=None)
    parser.add_argument(
        "--out",
        type=Path,
        default=Path(settings.models_dir) / "detector.joblib",
    )
    args = parser.parse_args()

    samples: list[tuple[list[float], int]] = []
    if args.benign:
        samples.extend(_scan_folder(args.benign, 0))
    if args.malicious:
        samples.extend(_scan_folder(args.malicious, 1))

    if len(samples) < 50:
        print(f"[train] Only {len(samples)} real samples — augmenting with synthetic data.")
        Xs, ys = _synthetic()
        if samples:
            X_real = np.array([s[0] for s in samples])
            y_real = np.array([s[1] for s in samples])
            X = np.vstack([Xs, X_real])
            y = np.concatenate([ys, y_real])
        else:
            X, y = Xs, ys
    else:
        X = np.array([s[0] for s in samples])
        y = np.array([s[1] for s in samples])

    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    scaler = StandardScaler().fit(X_tr)
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        n_jobs=-1,
        class_weight="balanced",
        random_state=42,
    )
    pipe = Pipeline([("scaler", scaler), ("model", model)])
    pipe.fit(X_tr, y_tr)

    print("\n[train] Test report:")
    print(classification_report(y_te, pipe.predict(X_te), digits=3))

    args.out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": pipe.named_steps["model"], "scaler": pipe.named_steps["scaler"]}, args.out)
    print(f"[train] Wrote {args.out}")


if __name__ == "__main__":
    main()
