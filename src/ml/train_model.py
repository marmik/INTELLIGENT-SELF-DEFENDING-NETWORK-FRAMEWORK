import argparse
import glob
import json
import os
import random
import time
from pathlib import Path
from typing import Dict, List, Tuple

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
import torch
import torch.nn as nn
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import (
    auc,
    classification_report,
    confusion_matrix,
    precision_recall_curve,
    roc_curve,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler, label_binarize
from torch.utils.data import DataLoader, TensorDataset


FEATURE_NAMES = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean",
    "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean",
    "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean",
    "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Bwd PSH Flags",
    "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Length", "Bwd Header Length",
    "Fwd Packets/s", "Bwd Packets/s", "Min Packet Length", "Max Packet Length",
    "Packet Length Mean", "Packet Length Std", "Packet Length Variance", "FIN Flag Count",
    "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count",
    "URG Flag Count", "CWE Flag Count", "ECE Flag Count", "Down/Up Ratio",
    "Average Packet Size", "Avg Fwd Segment Size", "Avg Bwd Segment Size", "Fwd Header Length.1",
    "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate", "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate", "Subflow Fwd Packets", "Subflow Fwd Bytes",
    "Subflow Bwd Packets", "Subflow Bwd Bytes", "Init_Win_bytes_forward", "Init_Win_bytes_backward",
    "act_data_pkt_fwd", "min_seg_size_forward", "Active Mean", "Active Std", "Active Max",
    "Active Min", "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
]


class CICDetectorDNN(nn.Module):
    def __init__(self, input_size: int, num_classes: int, dropout: float = 0.35):
        super().__init__()
        self.network = nn.Sequential(
            nn.Linear(input_size, 512),
            nn.BatchNorm1d(512),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(512, 256),
            nn.BatchNorm1d(256),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(256, 128),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Linear(64, num_classes),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.network(x)


class TemperatureScaler(nn.Module):
    def __init__(self, init_temp: float = 1.2):
        super().__init__()
        self.temperature = nn.Parameter(torch.ones(1) * init_temp)

    def forward(self, logits: torch.Tensor) -> torch.Tensor:
        return logits / torch.clamp(self.temperature, min=1e-3)


def set_seed(seed: int = 42) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.backends.mps.is_available():
        torch.mps.manual_seed(seed)
    torch.use_deterministic_algorithms(False)
    print(f"Seed set to {seed}")


def choose_device(force_mps: bool = True) -> torch.device:
    if force_mps and torch.backends.mps.is_available():
        return torch.device("mps")
    if torch.cuda.is_available():
        return torch.device("cuda")
    return torch.device("cpu")


def _safe_div(num: float, den: float) -> float:
    if den == 0:
        return 0.0
    return float(num / den)


def _common_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> Dict[str, float]:
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)
    acc = _safe_div(float((y_true == y_pred).sum()), float(len(y_true)))
    labels = np.unique(np.concatenate([y_true, y_pred]))

    weighted_precision = 0.0
    weighted_recall = 0.0
    weighted_f1 = 0.0
    macro_precision = 0.0
    macro_recall = 0.0
    macro_f1 = 0.0
    total = len(y_true)

    for lbl in labels:
        tp = float(((y_true == lbl) & (y_pred == lbl)).sum())
        fp = float(((y_true != lbl) & (y_pred == lbl)).sum())
        fn = float(((y_true == lbl) & (y_pred != lbl)).sum())
        support = float((y_true == lbl).sum())
        precision = _safe_div(tp, tp + fp)
        recall = _safe_div(tp, tp + fn)
        f1 = _safe_div(2.0 * precision * recall, precision + recall)

        macro_precision += precision
        macro_recall += recall
        macro_f1 += f1
        weighted_precision += precision * support
        weighted_recall += recall * support
        weighted_f1 += f1 * support

    n_labels = float(len(labels)) if len(labels) else 1.0
    return {
        "accuracy": acc,
        "precision_macro": macro_precision / n_labels,
        "recall_macro": macro_recall / n_labels,
        "f1_macro": macro_f1 / n_labels,
        "precision_weighted": _safe_div(weighted_precision, float(total)),
        "recall_weighted": _safe_div(weighted_recall, float(total)),
        "f1_weighted": _safe_div(weighted_f1, float(total)),
    }


def load_dataset(dataset_glob: str) -> pd.DataFrame:
    csv_files = sorted(glob.glob(dataset_glob))
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found for pattern: {dataset_glob}")

    parts = []
    for f in csv_files:
        print(f"Loading {f}")
        df = pd.read_csv(f, low_memory=False)
        df.columns = df.columns.str.strip()
        parts.append(df)
    data = pd.concat(parts, ignore_index=True)
    data.replace([np.inf, -np.inf], np.nan, inplace=True)
    return data


def split_dataset(
    data: pd.DataFrame,
    val_size: float,
    test_size: float,
    seed: int,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    labels = data["Label"].astype(str)
    counts = labels.value_counts()

    rare_labels = set(counts[counts < 3].index.tolist())
    rare_mask = labels.isin(rare_labels)
    rare_data = data[rare_mask]
    common_data = data[~rare_mask]

    if common_data.empty:
        raise ValueError("All classes are too rare for stratified split.")

    train_part, test_part = train_test_split(
        common_data,
        test_size=test_size,
        random_state=seed,
        stratify=common_data["Label"],
    )
    val_ratio_in_train = val_size / (1.0 - test_size)
    train_part, val_part = train_test_split(
        train_part,
        test_size=val_ratio_in_train,
        random_state=seed,
        stratify=train_part["Label"],
    )

    if not rare_data.empty:
        print(f"Keeping rare labels only in train split: {sorted(list(rare_labels))}")
        train_part = pd.concat([train_part, rare_data], ignore_index=True)

    return train_part, val_part, test_part


def clean_xy(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]:
    x = df[FEATURE_NAMES].copy()
    y = df["Label"].astype(str).copy()
    valid = ~x.isna().any(axis=1)
    x = x[valid]
    y = y[valid]
    return x, y


def dataloader_from_numpy(x: np.ndarray, y: np.ndarray, batch_size: int, shuffle: bool) -> DataLoader:
    ds = TensorDataset(
        torch.tensor(x, dtype=torch.float32),
        torch.tensor(y, dtype=torch.long),
    )
    return DataLoader(ds, batch_size=batch_size, shuffle=shuffle, num_workers=0)


def train_dnn(
    model: CICDetectorDNN,
    train_loader: DataLoader,
    val_loader: DataLoader,
    class_weights: torch.Tensor,
    device: torch.device,
    max_epochs: int,
    patience: int,
    lr: float,
    weight_decay: float,
    max_hours: float,
) -> Dict[str, List[float]]:
    criterion = nn.CrossEntropyLoss(weight=class_weights.to(device))
    optimizer = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=weight_decay)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
        optimizer,
        mode="max",
        factor=0.5,
        patience=max(2, patience // 3),
        min_lr=1e-5,
    )

    history = {
        "train_loss": [],
        "val_loss": [],
        "val_f1_macro": [],
        "val_recall_macro": [],
        "val_precision_macro": [],
        "lr": [],
    }

    best_score = -1.0
    best_state = None
    no_improve = 0
    start = time.time()

    for epoch in range(1, max_epochs + 1):
        model.train()
        train_loss = 0.0
        for xb, yb in train_loader:
            xb = xb.to(device)
            yb = yb.to(device)
            optimizer.zero_grad()
            logits = model(xb)
            loss = criterion(logits, yb)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=3.0)
            optimizer.step()
            train_loss += float(loss.item())

        train_loss /= max(1, len(train_loader))

        model.eval()
        val_loss = 0.0
        all_pred = []
        all_true = []
        with torch.no_grad():
            for xb, yb in val_loader:
                xb = xb.to(device)
                yb = yb.to(device)
                logits = model(xb)
                loss = criterion(logits, yb)
                val_loss += float(loss.item())
                pred = torch.argmax(logits, dim=1).cpu().numpy()
                all_pred.extend(pred)
                all_true.extend(yb.cpu().numpy())

        val_loss /= max(1, len(val_loader))
        metrics = _common_metrics(np.asarray(all_true), np.asarray(all_pred))
        val_f1 = metrics["f1_macro"]

        scheduler.step(val_f1)
        history["train_loss"].append(train_loss)
        history["val_loss"].append(val_loss)
        history["val_f1_macro"].append(val_f1)
        history["val_recall_macro"].append(metrics["recall_macro"])
        history["val_precision_macro"].append(metrics["precision_macro"])
        history["lr"].append(float(optimizer.param_groups[0]["lr"]))

        print(
            f"[Epoch {epoch:03d}] "
            f"train_loss={train_loss:.4f} "
            f"val_loss={val_loss:.4f} "
            f"val_f1_macro={val_f1:.4f} "
            f"val_recall_macro={metrics['recall_macro']:.4f}"
        )

        if val_f1 > best_score + 1e-4:
            best_score = val_f1
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
            no_improve = 0
        else:
            no_improve += 1

        elapsed_h = (time.time() - start) / 3600.0
        if no_improve >= patience:
            print(f"Early stopping triggered by patience at epoch {epoch}.")
            break
        if elapsed_h >= max_hours:
            print(f"Stopping due to max_hours budget ({max_hours:.2f}h).")
            break

    if best_state is not None:
        model.load_state_dict(best_state)
    return history


def collect_logits_and_probs(model: CICDetectorDNN, loader: DataLoader, device: torch.device) -> Tuple[np.ndarray, np.ndarray]:
    model.eval()
    all_logits = []
    all_targets = []
    with torch.no_grad():
        for xb, yb in loader:
            xb = xb.to(device)
            logits = model(xb).cpu().numpy()
            all_logits.append(logits)
            all_targets.append(yb.numpy())
    logits = np.vstack(all_logits)
    targets = np.concatenate(all_targets)
    return logits, targets


def temperature_scale(logits: np.ndarray, labels: np.ndarray, device: torch.device) -> float:
    tscaler = TemperatureScaler().to(device)
    logits_t = torch.tensor(logits, dtype=torch.float32, device=device)
    labels_t = torch.tensor(labels, dtype=torch.long, device=device)
    criterion = nn.CrossEntropyLoss()
    opt = torch.optim.LBFGS([tscaler.temperature], lr=0.05, max_iter=60)

    def closure():
        opt.zero_grad()
        loss = criterion(tscaler(logits_t), labels_t)
        loss.backward()
        return loss

    opt.step(closure)
    temp = float(torch.clamp(tscaler.temperature.detach().cpu(), min=1e-3).item())
    print(f"Optimal temperature: {temp:.4f}")
    return temp


def softmax_np(logits: np.ndarray) -> np.ndarray:
    shifted = logits - np.max(logits, axis=1, keepdims=True)
    exps = np.exp(shifted)
    return exps / np.sum(exps, axis=1, keepdims=True)


def per_class_thresholds(y_true: np.ndarray, probs: np.ndarray, classes: List[str]) -> Dict[str, float]:
    thresholds = {}
    for i, cname in enumerate(classes):
        if cname == "BENIGN":
            thresholds[cname] = 0.50
            continue
        y_bin = (y_true == i).astype(int)
        if y_bin.sum() == 0:
            thresholds[cname] = 0.50
            continue
        p, r, t = precision_recall_curve(y_bin, probs[:, i])
        if len(t) == 0:
            thresholds[cname] = 0.50
            continue
        f1 = (2 * p[:-1] * r[:-1]) / (p[:-1] + r[:-1] + 1e-8)
        best_idx = int(np.argmax(f1))
        thresholds[cname] = float(t[best_idx])
    return thresholds


def classification_artifacts(
    y_true: np.ndarray,
    probs: np.ndarray,
    classes: List[str],
    report_csv: Path,
) -> Dict[str, float]:
    pred = np.argmax(probs, axis=1)
    report = classification_report(
        y_true,
        pred,
        labels=np.arange(len(classes)),
        target_names=classes,
        output_dict=True,
        zero_division=0,
    )
    pd.DataFrame(report).transpose().to_csv(report_csv)
    metrics = _common_metrics(y_true, pred)
    return metrics


def plot_training_history(history: Dict[str, List[float]], out_path: Path) -> None:
    fig, axes = plt.subplots(2, 2, figsize=(14, 9))

    axes[0, 0].plot(history["train_loss"], label="Train Loss")
    axes[0, 0].plot(history["val_loss"], label="Val Loss")
    axes[0, 0].set_title("Loss Curves")
    axes[0, 0].legend()

    axes[0, 1].plot(history["val_f1_macro"], label="Val Macro F1")
    axes[0, 1].plot(history["val_recall_macro"], label="Val Macro Recall")
    axes[0, 1].plot(history["val_precision_macro"], label="Val Macro Precision")
    axes[0, 1].set_title("Validation Macro Metrics")
    axes[0, 1].legend()

    axes[1, 0].plot(history["lr"], label="Learning Rate")
    axes[1, 0].set_title("LR Schedule")
    axes[1, 0].legend()

    axes[1, 1].axis("off")
    axes[1, 1].text(
        0.05,
        0.9,
        "Early Stopping + LR Scheduler\n"
        "Objective: maximize macro F1\n"
        "Model selection: best validation macro F1",
        fontsize=11,
        va="top",
    )
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def plot_conf_mat(y_true: np.ndarray, y_pred: np.ndarray, classes: List[str], out_path: Path, normalize: bool = False) -> None:
    cm = confusion_matrix(y_true, y_pred, labels=np.arange(len(classes)))
    if normalize:
        cm = cm.astype(float)
        row_sums = cm.sum(axis=1, keepdims=True)
        cm = np.divide(cm, row_sums, out=np.zeros_like(cm), where=row_sums != 0)

    plt.figure(figsize=(12, 10))
    sns.heatmap(
        cm,
        cmap="Blues",
        xticklabels=classes,
        yticklabels=classes,
        annot=False,
        cbar=True,
    )
    plt.title("Confusion Matrix" + (" (Normalized)" if normalize else ""))
    plt.ylabel("True")
    plt.xlabel("Predicted")
    plt.xticks(rotation=45, ha="right")
    plt.yticks(rotation=0)
    plt.tight_layout()
    plt.savefig(out_path, dpi=160)
    plt.close()


def plot_class_metrics(report_csv: Path, out_path: Path) -> None:
    df = pd.read_csv(report_csv, index_col=0)
    class_rows = df[~df.index.isin(["accuracy", "macro avg", "weighted avg"])]
    class_rows = class_rows[["precision", "recall", "f1-score"]].fillna(0.0)

    plt.figure(figsize=(14, 7))
    class_rows.plot(kind="bar", ax=plt.gca())
    plt.title("Per-Class Precision / Recall / F1")
    plt.ylabel("Score")
    plt.ylim(0.0, 1.05)
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()


def plot_pr_roc(y_true: np.ndarray, probs: np.ndarray, classes: List[str], pr_path: Path, roc_path: Path, top_n: int = 8) -> None:
    y_bin = label_binarize(y_true, classes=np.arange(len(classes)))
    supports = y_bin.sum(axis=0)
    order = np.argsort(-supports)
    selected = [idx for idx in order if supports[idx] > 0][:top_n]

    plt.figure(figsize=(12, 9))
    for i in selected:
        p, r, _ = precision_recall_curve(y_bin[:, i], probs[:, i])
        pr_auc = auc(r, p)
        plt.plot(r, p, label=f"{classes[i]} (AUC={pr_auc:.3f})")
    plt.title("One-vs-Rest Precision-Recall Curves")
    plt.xlabel("Recall")
    plt.ylabel("Precision")
    plt.legend(loc="best", fontsize=8)
    plt.grid(alpha=0.2)
    plt.tight_layout()
    plt.savefig(pr_path, dpi=160)
    plt.close()

    plt.figure(figsize=(12, 9))
    for i in selected:
        fpr, tpr, _ = roc_curve(y_bin[:, i], probs[:, i])
        roc_auc = auc(fpr, tpr)
        plt.plot(fpr, tpr, label=f"{classes[i]} (AUC={roc_auc:.3f})")
    plt.plot([0, 1], [0, 1], "k--", alpha=0.6)
    plt.title("One-vs-Rest ROC Curves")
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.legend(loc="best", fontsize=8)
    plt.grid(alpha=0.2)
    plt.tight_layout()
    plt.savefig(roc_path, dpi=160)
    plt.close()


def plot_model_comparison(scores: Dict[str, Dict[str, float]], out_path: Path) -> None:
    rows = []
    for name, s in scores.items():
        rows.append(
            {
                "model": name,
                "precision_macro": s["precision_macro"],
                "recall_macro": s["recall_macro"],
                "f1_macro": s["f1_macro"],
                "accuracy": s["accuracy"],
            }
        )
    comp = pd.DataFrame(rows).set_index("model")
    comp.to_csv(out_path.with_suffix(".csv"))

    comp.plot(kind="bar", figsize=(11, 6))
    plt.title("Model Comparison (Macro + Accuracy)")
    plt.ylim(0.0, 1.05)
    plt.xticks(rotation=0)
    plt.tight_layout()
    plt.savefig(out_path, dpi=160)
    plt.close()


def run_training(args: argparse.Namespace) -> None:
    set_seed(args.seed)
    device = choose_device(force_mps=args.force_mps)
    print(f"Using device: {device}")

    plots_dir = Path("src/ml/plots")
    models_dir = Path("models")
    plots_dir.mkdir(parents=True, exist_ok=True)
    models_dir.mkdir(parents=True, exist_ok=True)

    data = load_dataset(args.dataset_glob)
    print(f"Loaded rows: {len(data):,}")

    if args.max_rows and len(data) > args.max_rows:
        print(f"Applying max_rows={args.max_rows:,} with stratified sampling")
        data, _ = train_test_split(
            data,
            train_size=args.max_rows,
            random_state=args.seed,
            stratify=data["Label"],
        )

    train_df, val_df, test_df = split_dataset(data, args.val_size, args.test_size, args.seed)
    print(f"Split sizes | train={len(train_df):,} val={len(val_df):,} test={len(test_df):,}")

    x_train_raw, y_train_raw = clean_xy(train_df)
    x_val_raw, y_val_raw = clean_xy(val_df)
    x_test_raw, y_test_raw = clean_xy(test_df)
    print(
        f"After cleaning | train={len(x_train_raw):,} val={len(x_val_raw):,} test={len(x_test_raw):,}"
    )

    scaler = StandardScaler()
    x_train = scaler.fit_transform(x_train_raw)
    x_val = scaler.transform(x_val_raw)
    x_test = scaler.transform(x_test_raw)

    le = LabelEncoder()
    y_train = le.fit_transform(y_train_raw)
    y_val = le.transform(y_val_raw)
    y_test = le.transform(y_test_raw)
    classes = list(le.classes_)
    n_classes = len(classes)
    print(f"Classes ({n_classes}): {classes}")

    class_counts = np.bincount(y_train, minlength=n_classes)
    priors = class_counts / np.maximum(1, class_counts.sum())
    inv_freq = 1.0 / np.maximum(class_counts, 1)
    class_weights_np = inv_freq / inv_freq.sum() * n_classes
    class_weights = torch.tensor(class_weights_np, dtype=torch.float32)
    sample_weights = class_weights_np[y_train]

    train_loader = dataloader_from_numpy(x_train, y_train, args.batch_size, True)
    val_loader = dataloader_from_numpy(x_val, y_val, args.batch_size, False)
    test_loader = dataloader_from_numpy(x_test, y_test, args.batch_size, False)

    dnn = CICDetectorDNN(x_train.shape[1], n_classes, dropout=args.dropout).to(device)
    history = train_dnn(
        dnn,
        train_loader,
        val_loader,
        class_weights,
        device,
        args.max_epochs,
        args.patience,
        args.lr,
        args.weight_decay,
        args.max_hours,
    )
    plot_training_history(history, plots_dir / "training_curves.png")

    val_logits, val_targets = collect_logits_and_probs(dnn, val_loader, device)
    temperature = temperature_scale(val_logits, val_targets, device)

    val_probs_dnn = softmax_np(val_logits / max(temperature, 1e-3))
    dnn_val_metrics = classification_artifacts(
        val_targets,
        val_probs_dnn,
        classes,
        plots_dir / "classification_report_dnn_val.csv",
    )
    print(
        "DNN val metrics: "
        f"precision_macro={dnn_val_metrics['precision_macro']:.4f}, "
        f"recall_macro={dnn_val_metrics['recall_macro']:.4f}, "
        f"f1_macro={dnn_val_metrics['f1_macro']:.4f}"
    )

    print("Training boosted tree model (HistGradientBoostingClassifier)...")
    hgb_can_early_stop = int(class_counts.min()) >= 2
    if not hgb_can_early_stop:
        print("Disabling HGB early_stopping due to rare classes with <2 samples.")
    hgb = HistGradientBoostingClassifier(
        learning_rate=args.boost_lr,
        max_depth=args.boost_max_depth,
        max_iter=args.boost_max_iter,
        early_stopping=hgb_can_early_stop,
        validation_fraction=0.1,
        n_iter_no_change=max(8, args.patience // 2),
        random_state=args.seed,
    )
    hgb.fit(x_train, y_train, sample_weight=sample_weights)

    val_probs_hgb = hgb.predict_proba(x_val)
    hgb_val_metrics = classification_artifacts(
        y_val,
        val_probs_hgb,
        classes,
        plots_dir / "classification_report_hgb_val.csv",
    )
    print(
        "HGB val metrics: "
        f"precision_macro={hgb_val_metrics['precision_macro']:.4f}, "
        f"recall_macro={hgb_val_metrics['recall_macro']:.4f}, "
        f"f1_macro={hgb_val_metrics['f1_macro']:.4f}"
    )

    dnn_w = max(1e-6, dnn_val_metrics["f1_macro"])
    hgb_w = max(1e-6, hgb_val_metrics["f1_macro"])
    norm = dnn_w + hgb_w
    dnn_w /= norm
    hgb_w /= norm
    print(f"Ensemble blend weights | DNN={dnn_w:.3f}, HGB={hgb_w:.3f}")

    val_probs_ens = dnn_w * val_probs_dnn + hgb_w * val_probs_hgb
    ens_val_metrics = classification_artifacts(
        y_val,
        val_probs_ens,
        classes,
        plots_dir / "classification_report_ensemble_val.csv",
    )

    thresholds = per_class_thresholds(y_val, val_probs_ens, classes)
    percentiles = {}
    for i, cname in enumerate(classes):
        if cname == "BENIGN":
            percentiles[cname] = 0.20
            continue
        cls_probs = val_probs_ens[y_val == i, i]
        if len(cls_probs):
            percentiles[cname] = float(max(0.05, np.percentile(cls_probs, 20)))
        else:
            percentiles[cname] = 0.05

    test_logits, test_targets = collect_logits_and_probs(dnn, test_loader, device)
    test_probs_dnn = softmax_np(test_logits / max(temperature, 1e-3))
    test_probs_hgb = hgb.predict_proba(x_test)
    test_probs_ens = dnn_w * test_probs_dnn + hgb_w * test_probs_hgb

    dnn_test_metrics = classification_artifacts(
        test_targets,
        test_probs_dnn,
        classes,
        plots_dir / "classification_report_dnn_test.csv",
    )
    hgb_test_metrics = classification_artifacts(
        y_test,
        test_probs_hgb,
        classes,
        plots_dir / "classification_report_hgb_test.csv",
    )
    ens_test_metrics = classification_artifacts(
        y_test,
        test_probs_ens,
        classes,
        plots_dir / "classification_report.csv",
    )

    y_pred_ens = np.argmax(test_probs_ens, axis=1)
    plot_conf_mat(y_test, y_pred_ens, classes, plots_dir / "confusion_matrix.png", normalize=False)
    plot_conf_mat(y_test, y_pred_ens, classes, plots_dir / "confusion_matrix_normalized.png", normalize=True)
    plot_class_metrics(plots_dir / "classification_report.csv", plots_dir / "metrics_comparison.png")
    plot_pr_roc(
        y_test,
        test_probs_ens,
        classes,
        plots_dir / "precision_recall_curves.png",
        plots_dir / "roc_auc_curves.png",
        top_n=10,
    )
    plot_model_comparison(
        {
            "DNN": dnn_test_metrics,
            "HGB": hgb_test_metrics,
            "Ensemble": ens_test_metrics,
        },
        plots_dir / "model_comparison.png",
    )

    torch.save(dnn.state_dict(), models_dir / "cic_model_v1.pt")
    joblib.dump(hgb, models_dir / "cic_hgb_model_v1.joblib")
    joblib.dump(scaler, models_dir / "cic_scaler_v1.joblib")
    joblib.dump(le, models_dir / "cic_label_encoder_v1.joblib")
    joblib.dump(FEATURE_NAMES, models_dir / "cic_features_v1.joblib")
    joblib.dump(priors, models_dir / "cic_priors_v1.joblib")
    joblib.dump(
        {
            "temperature": float(temperature),
            "thresholds": thresholds,
            "ensemble_weights": {"dnn": dnn_w, "hgb": hgb_w},
        },
        models_dir / "cic_calibration_v1.joblib",
    )
    joblib.dump(
        {
            "percentiles": percentiles,
            "margin_tau": 0.01,
        },
        models_dir / "cic_decision_metadata_v1.joblib",
    )

    summary = {
        "device": str(device),
        "classes": classes,
        "rows": {
            "train": int(len(x_train)),
            "val": int(len(x_val)),
            "test": int(len(x_test)),
        },
        "ensemble_weights": {"dnn": dnn_w, "hgb": hgb_w},
        "val_metrics": {
            "dnn": dnn_val_metrics,
            "hgb": hgb_val_metrics,
            "ensemble": ens_val_metrics,
        },
        "test_metrics": {
            "dnn": dnn_test_metrics,
            "hgb": hgb_test_metrics,
            "ensemble": ens_test_metrics,
        },
        "files": {
            "main_report": "src/ml/plots/classification_report.csv",
            "training_curves": "src/ml/plots/training_curves.png",
            "confusion": "src/ml/plots/confusion_matrix.png",
            "confusion_normalized": "src/ml/plots/confusion_matrix_normalized.png",
            "pr_curves": "src/ml/plots/precision_recall_curves.png",
            "roc_curves": "src/ml/plots/roc_auc_curves.png",
            "model_comparison": "src/ml/plots/model_comparison.png",
        },
    }
    (plots_dir / "training_summary.json").write_text(json.dumps(summary, indent=2))

    print("\nTraining and evaluation complete.")
    print(json.dumps(summary["test_metrics"]["ensemble"], indent=2))
    print(f"Plots and reports saved under {plots_dir}")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="CICIDS training pipeline with MPS + ensemble + rich evaluation")
    p.add_argument("--dataset-glob", default="dataset/MachineLearningCVE/*.csv")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--val-size", type=float, default=0.15)
    p.add_argument("--test-size", type=float, default=0.15)
    p.add_argument("--max-rows", type=int, default=0, help="0 means full dataset")
    p.add_argument("--batch-size", type=int, default=4096)
    p.add_argument("--max-epochs", type=int, default=220)
    p.add_argument("--patience", type=int, default=30)
    p.add_argument("--max-hours", type=float, default=2.0)
    p.add_argument("--lr", type=float, default=1e-3)
    p.add_argument("--weight-decay", type=float, default=1e-4)
    p.add_argument("--dropout", type=float, default=0.35)
    p.add_argument("--boost-lr", type=float, default=0.06)
    p.add_argument("--boost-max-depth", type=int, default=10)
    p.add_argument("--boost-max-iter", type=int, default=450)
    p.add_argument("--force-mps", action="store_true", default=True)
    return p.parse_args()


if __name__ == "__main__":
    run_training(parse_args())
