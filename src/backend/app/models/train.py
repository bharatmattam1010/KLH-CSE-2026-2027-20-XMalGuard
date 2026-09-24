import os
import json
import logging
from datetime import datetime
import pandas as pd
import joblib

from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def train_models():
    """Train machine learning models on the processed dataset."""
    base_dir = os.path.join(os.path.dirname(__file__), "..", "..", "..")
    processed_dir = os.path.join(base_dir, "data", "processed")
    models_dir = os.path.join(base_dir, "models")
    
    os.makedirs(models_dir, exist_ok=True)
    
    train_path = os.path.join(processed_dir, "train.csv")
    val_path = os.path.join(processed_dir, "val.csv")
    
    if not os.path.exists(train_path) or not os.path.exists(val_path):
        logging.error("Processed train.csv or val.csv not found. Please run prepare_dataset.py first.")
        return
        
    logging.info("Loading training and validation data...")
    train_df = pd.read_csv(train_path)
    val_df = pd.read_csv(val_path)
    
    X_train = train_df.drop(columns=['label'])
    y_train = train_df['label']
    X_val = val_df.drop(columns=['label'])
    y_val = val_df['label']
    
    feature_names = list(X_train.columns)
    
    logging.info("Scaling features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)
    
    models = {
        "LogisticRegression": LogisticRegression(max_iter=1000, random_state=42),
        "RandomForestClassifier": RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1),
        "XGBClassifier": XGBClassifier(n_estimators=100, random_state=42, eval_metric='logloss'),
        "SVC": SVC(kernel='rbf', probability=True, random_state=42)
    }
    
    performances = {}
    
    for name, model in models.items():
        logging.info(f"Training {name}...")
        model.fit(X_train_scaled, y_train)
        
        y_pred = model.predict(X_val_scaled)
        y_prob = model.predict_proba(X_val_scaled)[:, 1] if hasattr(model, "predict_proba") else y_pred
        
        acc = accuracy_score(y_val, y_pred)
        prec = precision_score(y_val, y_pred, zero_division=0)
        rec = recall_score(y_val, y_pred, zero_division=0)
        f1 = f1_score(y_val, y_pred, zero_division=0)
        roc_auc = roc_auc_score(y_val, y_prob)
        
        performances[name] = {
            "accuracy": float(acc),
            "precision": float(prec),
            "recall": float(rec),
            "f1": float(f1),
            "roc_auc": float(roc_auc)
        }
        
        # Save model
        joblib.dump(model, os.path.join(models_dir, f"{name}.joblib"))
        logging.info(f"Saved {name} to models/{name}.joblib")

    # Save scaler and feature names
    joblib.dump(scaler, os.path.join(models_dir, "scaler.joblib"))
    with open(os.path.join(models_dir, "feature_names.json"), "w") as f:
        json.dump(feature_names, f, indent=4)
        
    # Save training metadata
    metadata = {
        "timestamp": datetime.now().isoformat(),
        "train_size": len(X_train),
        "val_size": len(X_val),
        "feature_count": len(feature_names),
        "model_performances": performances
    }
    
    with open(os.path.join(models_dir, "training_metadata.json"), "w") as f:
        json.dump(metadata, f, indent=4)
        
    logging.info("Training complete. Validation metrics:")
    perf_df = pd.DataFrame(performances).T
    print("\n" + perf_df.to_string())

if __name__ == "__main__":
    train_models()
