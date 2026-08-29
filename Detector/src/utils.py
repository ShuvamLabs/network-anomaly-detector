from pathlib import Path

import joblib
import pandas as pd


def load_unsw_nb15(data_path):

    data_path = Path(data_path)

    if not data_path.exists():
        raise FileNotFoundError(
            f"Merged dataset not found: {data_path}"
        )

    print(f"Loading merged dataset: {data_path.name}")

    df = pd.read_csv(
        data_path,
        low_memory=False
    )

    print(f"Rows loaded: {len(df):,}")
    print(f"Dataset shape: {df.shape}")

    return df


def save_model(model, model_path):
    """
    Save a trained model/pipeline using joblib.
    """

    model_path = Path(model_path)

    model_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    joblib.dump(
        model,
        model_path
    )

    print(f"Model saved to: {model_path}")


def load_model(model_path):
    """
    Load a trained model/pipeline using joblib.
    """

    model_path = Path(model_path)

    if not model_path.exists():
        raise FileNotFoundError(
            f"Model not found: {model_path}"
        )

    model = joblib.load(model_path)

    print(f"Model loaded from: {model_path}")

    return model


def get_feature_columns(df, target_column, categorical_columns):
    """
    Separate feature columns into numerical and categorical columns.
    """

    feature_columns = [
        column
        for column in df.columns
        if column != target_column
    ]
    numeric_columns = [
        column
        for column in feature_columns
        if column not in categorical_columns
    ]

    return numeric_columns, categorical_columns