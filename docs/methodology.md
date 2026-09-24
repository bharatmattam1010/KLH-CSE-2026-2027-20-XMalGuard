# Research Methodology

## Research Approach Overview
XMalGuard utilizes a multi-phased methodology combining static program analysis, machine learning classification, and explainable AI to create a comprehensive malware detection framework.

## Phase 1: Feature Extraction & ML
- **Rationale**: Static PE feature extraction is safe and rapid, avoiding the risks of dynamic execution.
- **Feature Categories**: PE Headers, Sections, Imports, Strings, Entropy.
- **ML Selection**: Tree-based models (Random Forest, XGBoost) are preferred for their balance of high performance on tabular data and inherent explainability.

## Phase 2: Explainable AI Integration
- **Approach**: Integration of SHAP (SHapley Additive exPlanations) to provide feature-level contributions for individual predictions.
- **Metrics**: Explainability is evaluated qualitatively through decision transparency and feature importance distributions.

## Phase 3: Threat Intelligence & Risk Scoring
- **Enrichment**: Querying external threat intelligence providers to complement static predictions.
- **Risk Scoring Formula**:
  - **ML Score (0-50)**: `malicious_probability * 50`
  - **Static Indicators (0-20)**: `entropy + suspicious imports + packing + section anomalies + suspicious strings`
  - **Threat Intelligence (0-20)**: `detection_rate * 20`
  - **Other Indicators (0-10)**: `network + crypto + process + debug imports`

## Phase 4: Integration
- **Approach**: Containerized integration mapping backend analysis securely to a reactive frontend dashboard.
- **Dashboard Rationale**: Designed for security analysts to quickly triage threats while offering deep dives into SHAP explanations.

## Dataset Methodology
- **Data Preparation**: Feature scaling, handling missing values, stratified splitting.
- **Cross-validation**: K-fold cross validation to ensure model generalization.

## Evaluation Methodology
- **Metrics**: Accuracy, Precision, Recall, F1-Score, ROC-AUC.
- **Model Comparison**: Benchmarking against baseline models.
