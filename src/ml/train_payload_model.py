import pandas as pd
import sys
from pathlib import Path

# Add src to sys.path
sys.path.append(str(Path(__file__).parent.parent))

from ml.payload_model import PayloadClassifier

def train_from_csv(csv_path):
    print(f"Loading dataset from {csv_path}...")
    df = pd.read_csv(csv_path)
    
    if 'payload' not in df.columns or 'label' not in df.columns:
        print("Error: CSV must contain 'payload' and 'label' columns.")
        return

    classifier = PayloadClassifier()
    texts = df['payload'].values.astype(str)
    labels = df['label'].values
    
    print(f"Training on {len(texts)} samples...")
    classifier.train(texts, labels)
    
    # Simple validation
    print("\n--- Model Validation ---")
    vals = [
        "id=1",
        "user=' OR 1=1--",
        "<script>alert('xss')</script>",
        "search=normal_query"
    ]
    for v in vals:
        prob = classifier.predict_proba({}, v)
        print(f"Input: {v:30} | Prob: {prob:.4f}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--csv', default='datasets/seed_exploits.csv')
    args = parser.parse_args()
    
    train_from_csv(args.csv)
