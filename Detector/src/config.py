from pathlib import Path


# Project root
BASE_DIR = Path(__file__).resolve().parent.parent


# Data directories
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"


# Dataset
DATA_FILE = DATA_DIR / "UNSW-NB15.csv"


# Model files
MODEL_FILE = MODELS_DIR / "network_anomaly_detector.onnx"
DETECTOR_FILE = MODELS_DIR / "attack_detector.pkl"
CLASSIFIER_FILE = MODELS_DIR / "attack_classifier.pkl"


# Target columns
BINARY_TARGET = "Label"
CATEGORY_TARGET = "attack_cat"


# Categorical features
categorical_columns = [
    "proto",
    "state",
    "service",
]


# Number of rare categories to keep
RARE_CATEGORY_TOP_N = 7


# Random state for reproducibility
RANDOM_STATE = 42