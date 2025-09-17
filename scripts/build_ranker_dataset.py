#!/usr/bin/env python3
import argparse, subprocess, sys
from pathlib import Path

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--glob', default='backend/data/jobs/**/_*.json', help='evidence glob')
    ap.add_argument('--out', default='backend/modules/ml/data/ranker', help='output directory')
    ap.add_argument('--min-conf', type=float, default=0.0)
    args = ap.parse_args()

    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)

    cmd = [
        sys.executable,
        'backend/modules/ml/prepare_ranker_data.py',
        '--in-glob', args.glob,
        '--out-dir', str(outdir),
        '--min-conf', str(args.min_conf),
    ]
    print('Running:', ' '.join(cmd))
    subprocess.check_call(cmd)

if __name__ == '__main__':
    main()

