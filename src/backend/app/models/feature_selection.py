import os
import numpy as np
import pandas as pd
import plotly.express as px
from sklearn.feature_selection import mutual_info_classif, SelectKBest, f_classif

def get_feature_importance(model, feature_names: list[str], method: str = 'auto') -> pd.DataFrame:
    """Extract feature importance from tree-based or linear models."""
    importances = None
    
    if hasattr(model, 'feature_importances_'):
        importances = model.feature_importances_
    elif hasattr(model, 'coef_'):
        importances = np.abs(model.coef_[0])
        
    if importances is None:
        raise ValueError(f"Model {type(model)} does not support feature importance extraction.")
        
    df = pd.DataFrame({
        'feature': feature_names,
        'importance': importances
    })
    df = df.sort_values(by='importance', ascending=False).reset_index(drop=True)
    df['rank'] = df.index + 1
    return df

def mutual_information_scores(X, y, feature_names: list[str]) -> pd.DataFrame:
    """Calculate mutual information scores for features."""
    mi_scores = mutual_info_classif(X, y, random_state=42)
    df = pd.DataFrame({
        'feature': feature_names,
        'importance': mi_scores
    })
    df = df.sort_values(by='importance', ascending=False).reset_index(drop=True)
    df['rank'] = df.index + 1
    return df

def select_k_best(X, y, feature_names: list[str], k: int = 20) -> pd.DataFrame:
    """Select K best features using ANOVA F-value (f_classif)."""
    selector = SelectKBest(score_func=f_classif, k=min(k, len(feature_names)))
    selector.fit(X, y)
    
    df = pd.DataFrame({
        'feature': feature_names,
        'importance': selector.scores_,
        'p_value': selector.pvalues_
    })
    df = df.sort_values(by='importance', ascending=False).reset_index(drop=True)
    df['rank'] = df.index + 1
    return df

def plot_feature_importance(df: pd.DataFrame, title: str, save_path: str, top_n: int = 20):
    """Plot horizontal bar chart of feature importances using Plotly."""
    df_top = df.head(top_n).copy()
    df_top = df_top.sort_values(by='importance', ascending=True) # reverse for bottom-to-top display
    
    fig = px.bar(df_top, x='importance', y='feature', orientation='h',
                 title=f"{title} (Top {top_n})", labels={'importance': 'Score', 'feature': 'Feature'})
    
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    fig.write_html(f"{save_path}.html")
    try:
        fig.write_image(f"{save_path}.png")
    except Exception:
        pass

def get_top_features(df: pd.DataFrame, n: int = 10) -> list[str]:
    """Return a list of the top N feature names from an importance DataFrame."""
    return df.head(n)['feature'].tolist()
