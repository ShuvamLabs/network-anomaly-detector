# Models

This directory is intended to store the trained machine learning model used by the Network Anomaly Detector.

## Model File

The final trained model has been exported in **ONNX (`.onnx`) format**.

However, the ONNX model file is **not included in this GitHub repository because its file size is too large** for practical repository storage.

The model file is therefore excluded using `.gitignore`.

## Why is the model not included?

The model is fully trained and ready for inference, but storing large model artifacts directly in the Git repository is avoided to keep the repository lightweight and manageable.

The repository contains the code and configuration required to understand and reproduce the model, while the large `.onnx` artifact is kept separately.

> **Note:** The absence of the `.onnx` file from this directory does not mean the model is incomplete. The model has already been trained and exported; only the large model artifact is excluded from GitHub.
