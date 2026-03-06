import torch
import torch.nn as nn
import joblib
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix, classification_report, roc_curve, auc
from sklearn.preprocessing import label_binarize
from sklearn.model_selection import train_test_split
import glob
import os

# Model Definition
class CICDetectorDNN(nn.Module):
    def __init__(self, input_size, num_classes):
        super(CICDetectorDNN, self).__init__()
        self.network = nn.Sequential(
            nn.Linear(input_size, 512),
            nn.BatchNorm1d(512),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(512, 256),
            nn.BatchNorm1d(256),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(256, 128),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Linear(64, num_classes)
        )
        
    def forward(self, x):
        return self.network(x)

def evaluate():
    device = torch.device("mps" if torch.backends.mps.is_available() else "cpu")
    print(f"Evaluating on {device}")
    
    # Load Assets
    scaler = joblib.load("models/cic_scaler_v1.joblib")
    le = joblib.load("models/cic_label_encoder_v1.joblib")
    feature_names = joblib.load("models/cic_features_v1.joblib")
    
    model = CICDetectorDNN(len(feature_names), len(le.classes_)).to(device)
    model.load_state_dict(torch.load("models/cic_model_v1.pt", map_location=device))
    model.eval()
    
    # Re-generate Test Set (Same as training script)
    print("Loading ALL files to extract the 20% test subset...")
    csv_files = glob.glob("dataset/MachineLearningCVE/*.csv")
    all_df = []
    for f in csv_files:
        df = pd.read_csv(f)
        df.columns = df.columns.str.strip()
        all_df.append(df)
    df = pd.concat(all_df, ignore_index=True)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    
    X = df[feature_names]
    y = df['Label']
    
    # Re-split to get the exact test set
    _, X_test, _, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    # Stratified Sampling for visualization (avoiding memory crash on full 500k test set)
    print(f"Full test set size: {len(X_test)}. Sampling 50,000 stratified samples for visualization...")
    X_sample, _, y_sample, _ = train_test_split(X_test, y_test, train_size=50000, random_state=42, stratify=y_test)
    
    X_scaled = scaler.transform(X_sample)
    X_tensor = torch.tensor(X_scaled, dtype=torch.float32).to(device)
    y_encoded = le.transform(y_sample)
    
    with torch.no_grad():
        outputs = model(X_tensor)
        probabilities = torch.softmax(outputs, dim=1).cpu().numpy()
        predictions = np.argmax(probabilities, axis=1)
    
    # Correct classes present in the SAMPLE
    present_labels = np.unique(np.concatenate((y_encoded, predictions)))
    target_names = [le.classes_[label] for label in present_labels]
    
    # 1. Confusion Matrix (Multiclass)
    cm = confusion_matrix(y_encoded, predictions, labels=present_labels)
    plt.figure(figsize=(14, 12))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=target_names, yticklabels=target_names)
    plt.title('Honest Multiclass Confusion Matrix (No Leakage)')
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.tight_layout()
    plt.savefig("src/ml/plots/confusion_matrix.png")
    plt.close()
    
    # 2. Classification Report
    report = classification_report(y_encoded, predictions, labels=present_labels, target_names=target_names, output_dict=True)
    report_df = pd.DataFrame(report).transpose()
    report_df.to_csv("src/ml/plots/classification_report.csv")
    print(f"\nHonest Accuracy: {report['accuracy']:.4f}")
    
    # 3. Precision, Recall, F1 Table Plot
    plt.figure(figsize=(12, 6))
    metrics_to_plot = report_df.iloc[:-3, :3]
    metrics_to_plot.plot(kind='bar', figsize=(15, 7))
    plt.title('Honest Precision, Recall, and F1-Score per Class')
    plt.xticks(rotation=45, ha='right')
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.tight_layout()
    plt.savefig("src/ml/plots/metrics_comparison.png")
    plt.close()
    
    # 4. ROC-AUC Curves (Top Present Classes)
    y_bin = label_binarize(y_encoded, classes=present_labels)
    if y_bin.shape[1] == 1:
        y_bin = np.hstack((1 - y_bin, y_bin))
        
    n_classes = y_bin.shape[1]
    plt.figure(figsize=(12, 10))
    for i in range(min(10, n_classes)):
        fpr, tpr, _ = roc_curve(y_bin[:, i], probabilities[:, present_labels[i]])
        roc_auc = auc(fpr, tpr)
        plt.plot(fpr, tpr, lw=2, label=f'ROC {target_names[i]} (AUC = {roc_auc:.2f})')
        
    plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('Honest Multi-class ROC Curves')
    plt.legend(loc="lower right")
    plt.tight_layout()
    plt.savefig("src/ml/plots/roc_auc_curves.png")
    plt.close()
    
    print("All honest visualizations generated in src/ml/plots/")

if __name__ == "__main__":
    evaluate()
