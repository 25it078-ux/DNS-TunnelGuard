import json
import os
import sys
from pathlib import Path

# Add project root to sys.path so we can import app modules
CURRENT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = CURRENT_DIR.parent
sys.path.insert(0, str(BACKEND_DIR))

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score, accuracy_score
from sklearn.model_selection import train_test_split

from app.ml.feature_extractor import FEATURE_NAMES, extract_features
from training.dataset import generate_dataset

def train():
    print("Generating synthetic DNS traffic dataset (benign + tunneling)...")
    data = generate_dataset(n_samples=5000)
    
    X = []
    y = []
    
    for row in data:
        extracted = extract_features(
            domain=row["domain"],
            query_type=row["query_type"],
            response_size=row["response_size"],
            ttl=row["ttl"]
        )
        X.append(extracted["vector"])
        y.append(row["label"])
        
    X = np.array(X)
    y = np.array(y)
    
    print(f"Total samples: {len(X)} (Benign: {np.sum(y == 0)}, Tunneling: {np.sum(y == 1)})")
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print("Training RandomForestClassifier...")
    clf = RandomForestClassifier(
        n_estimators=120,
        max_depth=12,
        min_samples_split=4,
        random_state=42,
        class_weight="balanced"
    )
    clf.fit(X_train, y_train)
    
    # Evaluate
    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1]
    
    acc = accuracy_score(y_test, y_pred)
    roc = roc_auc_score(y_test, y_prob)
    
    print("\n--- Evaluation Results ---")
    print(f"Accuracy: {acc * 100:.2f}%")
    print(f"ROC-AUC:  {roc:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["Benign", "Tunneling"]))
    
    # Feature importances
    importances = dict(zip(FEATURE_NAMES, [round(float(val), 4) for val in clf.feature_importances_]))
    sorted_importances = dict(sorted(importances.items(), key=lambda item: item[1], reverse=True))
    print("\nFeature Importances:")
    for k, v in sorted_importances.items():
        print(f"  - {k}: {v * 100:.2f}%")
        
    # Save model artifact
    output_dir = BACKEND_DIR / "app" / "ml"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    model_path = output_dir / "model.joblib"
    meta_path = output_dir / "model_meta.json"
    
    joblib.dump(clf, model_path)
    print(f"\nModel saved to: {model_path}")
    
    meta = {
        "model_name": "Random Forest DNS Tunnel Classifier",
        "algorithm": "RandomForestClassifier(n_estimators=120, max_depth=12)",
        "features": FEATURE_NAMES,
        "feature_importances": sorted_importances,
        "accuracy": round(float(acc), 4),
        "roc_auc": round(float(roc), 4),
        "classes": ["NORMAL", "DNS TUNNELING"],
        "total_training_samples": len(X),
        "status": "Ready for Analysis"
    }
    
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    print(f"Metadata saved to: {meta_path}")

if __name__ == "__main__":
    train()
