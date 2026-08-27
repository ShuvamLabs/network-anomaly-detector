from pathlib import Path

import joblib
import pandas as pd


def load_unsw_nb15(data_dir):
    """
    Load and combine the four UNSW-NB15 CSV files.

    Expected files:
        UNSW-NB15_1.csv
        UNSW-NB15_2.csv
        UNSW-NB15_3.csv
        UNSW-NB15_4.csv
    """

    data_dir = Path(data_dir)

    csv_files = [
        data_dir / "UNSW-NB15_1.csv",
        data_dir / "UNSW-NB15_2.csv",
        data_dir / "UNSW-NB15_3.csv",
        data_dir / "UNSW-NB15_4.csv",
    ]

    missing_files = [
        file for file in csv_files
        if not file.exists()
    ]

    if missing_files:
        raise FileNotFoundError(
            "The following dataset files are missing:\n"
            + "\n".join(str(file) for file in missing_files)
        )

    dataframes = []

    for file in csv_files:
        print(f"Loading: {file.name}")

        df = pd.read_csv(
            file,
            low_memory=False
        )

        dataframes.append(df)

        print(f"Rows loaded: {len(df):,}")

    combined_df = pd.concat(
        dataframes,
        ignore_index=True
    )

    print(f"\nCombined dataset shape: {combined_df.shape}")

    return combined_df


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