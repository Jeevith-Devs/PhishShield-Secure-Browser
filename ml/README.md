# PhishShield: Machine Learning & Deep Learning Pipeline

## Overview
This directory houses the training, calibration, feature engineering, and evaluation code for the PhishShield detection engine.

### Subdirectories
- `features/`: 38-feature lexical, structural, and TLD feature extraction algorithms.
- `models/`: Model architecture definitions:
  - Baseline: Logistic Regression, Random Forest.
  - Advanced ML: XGBoost, LightGBM classifiers.
  - Deep Learning: Character-level CNN + BiLSTM sequence classifiers.
- `datasets/`: Dataset curation scripts (PhishTank, URLhaus, OpenPhish, Tranco Top 1M benign domains).
- `evaluation/`: Scientific benchmark pipelines (Precision, Recall, F1, ROC-AUC, FPR/FNR, Inference Latency).
