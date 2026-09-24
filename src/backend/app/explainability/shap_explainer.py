import os
import json
import logging
import base64
from io import BytesIO
from typing import Dict, Any, List, Optional, Tuple

import numpy as np
import pandas as pd
import joblib
import shap
import plotly.graph_objects as go

logger = logging.getLogger(__name__)

class ShapExplainer:
    """
    Module for explaining machine learning model predictions using SHAP (SHapley Additive exPlanations).
    """

    def __init__(self, model_path: str, scaler_path: str, feature_names_path: str, background_data_path: str = None):
        """
        Initialize the ShapExplainer.

        Args:
            model_path: Path to the trained model (.joblib or .pkl).
            scaler_path: Path to the fitted scaler (.joblib or .pkl).
            feature_names_path: Path to the JSON file containing the list of feature names.
            background_data_path: Optional path to background data for KernelExplainer.
        """
        self.model_path = model_path
        self.scaler_path = scaler_path
        self.feature_names_path = feature_names_path
        self.background_data_path = background_data_path
        
        self.model = None
        self.scaler = None
        self.feature_names = []
        self.explainer = None
        
        self._load_assets()
        self._create_explainer()

    def _load_assets(self) -> None:
        """Load the model, scaler, and feature names from disk."""
        try:
            if not os.path.exists(self.model_path):
                raise RuntimeError(f"Model file not found at {self.model_path}")
            if not os.path.exists(self.scaler_path):
                raise RuntimeError(f"Scaler file not found at {self.scaler_path}")
            if not os.path.exists(self.feature_names_path):
                raise RuntimeError(f"Feature names file not found at {self.feature_names_path}")
                
            self.model = joblib.load(self.model_path)
            self.scaler = joblib.load(self.scaler_path)
            
            with open(self.feature_names_path, 'r') as f:
                self.feature_names = json.load(f)
                
            logger.info("Successfully loaded model, scaler, and feature names.")
        except Exception as e:
            logger.error(f"Error loading assets: {e}")
            raise RuntimeError(f"Failed to load assets: {e}")

    def _create_explainer(self) -> None:
        """Create the appropriate SHAP explainer based on the model type."""
        try:
            # Check if model is tree-based (has feature_importances_)
            if hasattr(self.model, 'feature_importances_'):
                logger.info("Using TreeExplainer for tree-based model.")
                self.explainer = shap.TreeExplainer(self.model)
            else:
                logger.info("Using KernelExplainer for non-tree model.")
                background_data = None
                if self.background_data_path and os.path.exists(self.background_data_path):
                    background_data = np.load(self.background_data_path)
                else:
                    logger.warning("No background data found. Using zero-filled background.")
                    background_data = np.zeros((1, len(self.feature_names)))
                
                # We need predict_proba for probabilities, or just predict if not available
                predict_fn = getattr(self.model, "predict_proba", self.model.predict)
                self.explainer = shap.KernelExplainer(predict_fn, background_data)
        except Exception as e:
            logger.error(f"Failed to create SHAP explainer: {e}")
            raise RuntimeError(f"Failed to create explainer: {e}")

    def explain(self, features: Dict[str, float]) -> Dict[str, Any]:
        """
        Compute SHAP values for the given features.

        Args:
            features: Dictionary mapping feature names to their values.

        Returns:
            Dictionary containing SHAP values, base value, top contributors, and plot data.
        """
        if self.explainer is None:
            raise RuntimeError("Explainer not initialized.")
            
        try:
            # Ensure all features are present and ordered correctly
            feature_array = []
            for name in self.feature_names:
                if name not in features:
                    logger.warning(f"Feature {name} not found in input. Using 0.")
                    feature_array.append(0.0)
                else:
                    feature_array.append(features[name])
                    
            X = np.array(feature_array).reshape(1, -1)
            X_scaled = self.scaler.transform(X)
            
            # Compute SHAP values
            shap_values_raw = self.explainer.shap_values(X_scaled)
            
            # For classification, shap_values might be a list of arrays (one per class)
            # We want the values for class 1 (malicious)
            if isinstance(shap_values_raw, list):
                shap_values_array = shap_values_raw[1][0]
                base_value = float(self.explainer.expected_value[1])
            else:
                # Some versions/models return shape (samples, features, classes)
                if len(shap_values_raw.shape) == 3:
                    shap_values_array = shap_values_raw[0, :, 1]
                    base_value = float(self.explainer.expected_value[1])
                elif len(shap_values_raw.shape) == 2 and shap_values_raw.shape[0] == 1:
                    shap_values_array = shap_values_raw[0]
                    base_value = float(self.explainer.expected_value) if not isinstance(self.explainer.expected_value, list) else float(self.explainer.expected_value[1])
                else:
                    shap_values_array = shap_values_raw[0]
                    base_value = float(self.explainer.expected_value)
            
            # Pair features with their SHAP values
            shap_pairs = list(zip(self.feature_names, shap_values_array))
            
            # Sort by absolute SHAP value descending
            shap_pairs.sort(key=lambda x: abs(x[1]), reverse=True)
            
            # Format top contributors
            positive_contributors = sorted([p for p in shap_pairs if p[1] > 0], key=lambda x: x[1], reverse=True)
            negative_contributors = sorted([p for p in shap_pairs if p[1] < 0], key=lambda x: x[1])
            
            top_malicious = positive_contributors[:5]
            top_benign = negative_contributors[:5]
            
            # Prepare plot data for frontend (top 10 overall)
            top_10 = shap_pairs[:10]
            plot_names = [p[0] for p in top_10]
            plot_values = [p[1] for p in top_10]
            plot_colors = ['red' if v > 0 else 'blue' for v in plot_values]
            
            plot_data = {
                'features': plot_names,
                'values': plot_values,
                'colors': plot_colors
            }
            
            return {
                'shap_values': [{'feature': p[0], 'value': float(p[1])} for p in shap_pairs],
                'base_value': base_value,
                'top_malicious_contributors': [{'feature': p[0], 'value': float(p[1])} for p in top_malicious],
                'top_benign_contributors': [{'feature': p[0], 'value': float(p[1])} for p in top_benign],
                'plot_data': plot_data
            }
            
        except Exception as e:
            logger.error(f"Error computing SHAP values: {e}")
            return {
                'error': f"Failed to compute explanations: {str(e)}",
                'shap_values': [],
                'base_value': 0.0,
                'top_malicious_contributors': [],
                'top_benign_contributors': [],
                'plot_data': {}
            }

    def generate_shap_plot(self, shap_values: List[Dict[str, Any]], save_path: Optional[str] = None) -> str:
        """
        Generate a horizontal bar chart of the SHAP values using Plotly.

        Args:
            shap_values: List of dictionaries with 'feature' and 'value'.
            save_path: Optional path to save the plot as an HTML file.

        Returns:
            Base64 encoded PNG string of the plot.
        """
        if not shap_values:
            return ""
            
        # Get top 10 features sorted by absolute value
        sorted_vals = sorted(shap_values, key=lambda x: abs(x['value']), reverse=True)[:10]
        
        # Sort again by value for plotting (so bars are ordered nicely)
        sorted_vals.sort(key=lambda x: x['value'])
        
        features = [x['feature'] for x in sorted_vals]
        values = [x['value'] for x in sorted_vals]
        colors = ['red' if v > 0 else 'blue' for v in values]
        
        fig = go.Figure(go.Bar(
            x=values,
            y=features,
            orientation='h',
            marker_color=colors
        ))
        
        fig.update_layout(
            title="Top 10 Feature Contributions",
            xaxis_title="SHAP Value (Impact on Model Output)",
            yaxis_title="Feature",
            template="plotly_white",
            height=500,
            width=800,
            margin=dict(l=200, r=20, t=40, b=40)
        )
        
        if save_path:
            try:
                fig.write_html(save_path)
            except Exception as e:
                logger.error(f"Failed to save SHAP plot HTML: {e}")
                
        # Generate base64 image
        try:
            img_bytes = fig.to_image(format="png")
            encoded = base64.b64encode(img_bytes).decode('utf-8')
            return f"data:image/png;base64,{encoded}"
        except Exception as e:
            logger.error(f"Failed to generate SHAP plot image: {e}")
            return ""
