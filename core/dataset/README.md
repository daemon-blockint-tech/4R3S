# ARES V3 Benchmark Dataset

This directory contains the benchmark dataset used to evaluate ARES V3, comprising both deterministic regression stubs (Segment A) and raw audit reports for production protocols (Segment B).

## Git LFS Required

Because the raw audit reports and some test vectors can be large, this directory is managed using [Git Large File Storage (LFS)](https://git-lfs.com/).

If you cloned this repository without Git LFS installed, these files might just be text pointers. To fetch the actual files, run:

```bash
git lfs install
git lfs pull
```

## Structure

- `raw-audits/`: Contains the original audit report text files from professional firms (e.g., Neodyme, Trail of Bits, Kudelski, OtterSec) used to establish ground truth for Segment B.
- `solana-common-attack-vectors/`: (If populated) contains the 11 deterministic stubs for Segment A regression testing and `ground_truth.json` defining the expected findings.

## Usage

To run the benchmark suite against this dataset:

```bash
ares benchmark --dataset ./dataset
```
