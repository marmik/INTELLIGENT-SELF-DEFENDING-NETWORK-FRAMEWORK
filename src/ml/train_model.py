from .model import IsolationModel
from pathlib import Path


def train_from_flows(flows_csv: str, out_model: str = 'models/isolation_model.joblib'):
    m = IsolationModel()
    Path(out_model).parent.mkdir(parents=True, exist_ok=True)
    path = m.train(flows_csv, out_model)
    return path


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--flows', required=True)
    parser.add_argument('--out', default='models/isolation_model.joblib')
    args = parser.parse_args()
    print('Training model from', args.flows)
    p = train_from_flows(args.flows, args.out)
    print('Saved model to', p)
