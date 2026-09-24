import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def select_best_model(results: dict) -> tuple[str, dict]:
    """
    Select the best model based on evaluation metrics.
    Primary: F1-score
    Secondary: ROC-AUC
    Tertiary: Lowest False Positive Rate (FPR)
    """
    if not results:
        raise ValueError("Results dictionary is empty.")
        
    best_model = None
    best_metrics = None
    
    for model_name, metrics in results.items():
        if best_model is None:
            best_model = model_name
            best_metrics = metrics
            continue
            
        # Primary: F1
        if metrics['f1'] > best_metrics['f1']:
            best_model = model_name
            best_metrics = metrics
        elif metrics['f1'] == best_metrics['f1']:
            # Secondary: ROC-AUC
            if metrics['roc_auc'] > best_metrics['roc_auc']:
                best_model = model_name
                best_metrics = metrics
            elif metrics['roc_auc'] == best_metrics['roc_auc']:
                # Tertiary: Lowest FPR
                if metrics.get('fpr', 1.0) < best_metrics.get('fpr', 1.0):
                    best_model = model_name
                    best_metrics = metrics
                    
    logging.info(f"Selected Best Model: {best_model} with F1: {best_metrics['f1']:.4f}, AUC: {best_metrics['roc_auc']:.4f}")
    return best_model, best_metrics

def generate_selection_report(results: dict, selected: str) -> str:
    """Generate a markdown formatted report explaining the selection rationale."""
    metrics = results.get(selected)
    if not metrics:
        return "Error: Selected model not found in results."
        
    report = f"# Model Selection Report\n\n"
    report += f"**Selected Model:** `{selected}`\n\n"
    
    report += "## Rationale\n"
    report += "The model was selected based on the following prioritized criteria:\n"
    report += "1. **F1-Score** (Primary)\n"
    report += "2. **ROC-AUC** (Secondary)\n"
    report += "3. **Lowest FPR** (Tertiary)\n\n"
    
    report += "## Performance of Selected Model\n"
    report += f"- **F1-Score:** {metrics['f1']:.4f}\n"
    report += f"- **ROC-AUC:** {metrics['roc_auc']:.4f}\n"
    report += f"- **Accuracy:** {metrics['accuracy']:.4f}\n"
    report += f"- **Precision:** {metrics['precision']:.4f}\n"
    report += f"- **Recall:** {metrics['recall']:.4f}\n"
    report += f"- **False Positive Rate:** {metrics.get('fpr', 'N/A'):.4f}\n\n"
    
    report += "## All Models Summary\n"
    report += "| Model | F1-Score | ROC-AUC | Accuracy | Precision | Recall | FPR |\n"
    report += "|---|---|---|---|---|---|---|\n"
    
    for name, m in results.items():
        fpr_str = f"{m.get('fpr', 0):.4f}" if 'fpr' in m else "N/A"
        report += f"| {name} | {m['f1']:.4f} | {m['roc_auc']:.4f} | {m['accuracy']:.4f} | {m['precision']:.4f} | {m['recall']:.4f} | {fpr_str} |\n"
        
    return report
