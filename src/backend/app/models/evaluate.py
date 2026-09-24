import os
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix, roc_curve, precision_recall_curve

def evaluate_model(model, X_test, y_test, model_name: str) -> dict:
    """Evaluate a trained model and return various metrics."""
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1] if hasattr(model, "predict_proba") else y_pred
    
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
    
    return {
        "model_name": model_name,
        "accuracy": accuracy_score(y_test, y_pred),
        "precision": precision_score(y_test, y_pred, zero_division=0),
        "recall": recall_score(y_test, y_pred, zero_division=0),
        "f1": f1_score(y_test, y_pred, zero_division=0),
        "roc_auc": roc_auc_score(y_test, y_prob),
        "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
        "fpr": fpr,
        "fnr": fnr
    }

def generate_comparison_table(results: dict) -> pd.DataFrame:
    """Format model evaluation results as a pandas DataFrame."""
    rows = []
    for m_name, metrics in results.items():
        row = metrics.copy()
        if 'confusion_matrix' in row:
            del row['confusion_matrix']
        rows.append(row)
    df = pd.DataFrame(rows)
    if not df.empty:
        df.set_index('model_name', inplace=True)
    return df

def plot_confusion_matrix(y_true, y_pred, model_name: str, save_path: str):
    """Save confusion matrix plot using Plotly."""
    cm = confusion_matrix(y_true, y_pred)
    fig = px.imshow(cm, text_auto=True, color_continuous_scale='Blues',
                    labels=dict(x="Predicted Label", y="True Label"),
                    x=['Benign (0)', 'Malicious (1)'],
                    y=['Benign (0)', 'Malicious (1)'],
                    title=f"Confusion Matrix - {model_name}")
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    fig.write_html(f"{save_path}.html")
    try:
        fig.write_image(f"{save_path}.png")
    except Exception:
        pass  # Kaleido might not be installed

def plot_roc_curves(models_dict: dict, X_test, y_test, save_path: str):
    """Plot ROC curves for all models on a single chart."""
    fig = go.Figure()
    fig.add_shape(type='line', line=dict(dash='dash'), x0=0, x1=1, y0=0, y1=1)
    
    for name, model in models_dict.items():
        y_prob = model.predict_proba(X_test)[:, 1] if hasattr(model, "predict_proba") else model.predict(X_test)
        fpr, tpr, _ = roc_curve(y_test, y_prob)
        auc_score = roc_auc_score(y_test, y_prob)
        fig.add_trace(go.Scatter(x=fpr, y=tpr, name=f"{name} (AUC={auc_score:.3f})", mode='lines'))
        
    fig.update_layout(title="ROC Curves", xaxis_title="False Positive Rate", yaxis_title="True Positive Rate")
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    fig.write_html(f"{save_path}.html")
    try:
        fig.write_image(f"{save_path}.png")
    except Exception:
        pass

def plot_precision_recall_curves(models_dict: dict, X_test, y_test, save_path: str):
    """Plot Precision-Recall curves for all models."""
    fig = go.Figure()
    for name, model in models_dict.items():
        y_prob = model.predict_proba(X_test)[:, 1] if hasattr(model, "predict_proba") else model.predict(X_test)
        prec, rec, _ = precision_recall_curve(y_test, y_prob)
        fig.add_trace(go.Scatter(x=rec, y=prec, name=name, mode='lines'))
        
    fig.update_layout(title="Precision-Recall Curves", xaxis_title="Recall", yaxis_title="Precision")
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    fig.write_html(f"{save_path}.html")
    try:
        fig.write_image(f"{save_path}.png")
    except Exception:
        pass

def plot_model_comparison(results: dict, save_path: str):
    """Create grouped bar chart comparing metrics across models."""
    df = generate_comparison_table(results).reset_index()
    if df.empty:
        return
        
    df_melt = pd.melt(df, id_vars=['model_name'], value_vars=['accuracy', 'precision', 'recall', 'f1', 'roc_auc'],
                      var_name='Metric', value_name='Score')
                      
    fig = px.bar(df_melt, x='Metric', y='Score', color='model_name', barmode='group',
                 title="Model Performance Comparison")
    
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    fig.write_html(f"{save_path}.html")
    try:
        fig.write_image(f"{save_path}.png")
    except Exception:
        pass
