from pathlib import Path


# Project root
BASE_DIR = Path(__file__).resolve().parent.parent


# Data directories
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"


# Dataset
DATA_FILE = DATA_DIR / "UNSW-NB15.csv"


# Model files
BINARY_MODEL_PATH = MODELS_DIR / "binary_detector.pkl"
CATEGORY_MODEL_PATH = MODELS_DIR / "attack_category_detector.pkl"


# Target columns
BINARY_TARGET = "Label"
CATEGORY_TARGET = "attack_cat"


# Categorical features
CATEGORICAL_COLUMNS = [
    "proto",
    "state",
    "service",
]


# Number of rare categories to keep
RARE_CATEGORY_TOP_N = 7


# Random state for reproducibility
RANDOM_STATE = 42