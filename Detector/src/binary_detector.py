import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

from config import (
    DATA_DIR,
    BINARY_MODEL_PATH,
    BINARY_TARGET,
    CATEGORICAL_COLUMNS,
    RARE_CATEGORY_TOP_N,
    RANDOM_STATE,
)

from preprocessing import create_preprocessor
from utils import (
    load_unsw_nb15,
    save_model,
)


def main():

    # --------------------------------------------------
    # 1. Load dataset
    # --------------------------------------------------

    print("Loading UNSW-NB15 dataset...")

    df = load_unsw_nb15(DATA_DIR)

    print(f"Dataset shape: {df.shape}")


    # --------------------------------------------------
    # 2. Remove unnecessary columns
    # --------------------------------------------------

    # The UNSW-NB15 dataset can contain an ID column.
    # It should not be used as a predictive feature.

    columns_to_drop = [
        "id",
    ]

    columns_to_drop = [
        column
        for column in columns_to_drop
        if column in df.columns
    ]

    if columns_to_drop:
        df = df.drop(
            columns=columns_to_drop
        )


    # --------------------------------------------------
    # 3. Remove rows with missing target
    # --------------------------------------------------

    df = df.dropna(
        subset=[BINARY_TARGET]
    )


    # --------------------------------------------------
    # 4. Separate features and target
    # --------------------------------------------------

    X = df.drop(
        columns=[BINARY_TARGET]
    )

    y = df[BINARY_TARGET]


    # --------------------------------------------------
    # 5. Determine numerical columns
    # --------------------------------------------------

    categorical_columns = [
        column
        for column in CATEGORICAL_COLUMNS
        if column in X.columns
    ]

    numeric_columns = [
        column
        for column in X.columns
        if column not in categorical_columns
    ]

    print(
        f"Numerical features   : {len(numeric_columns)}"
    )

    print(
        f"Categorical features : {len(categorical_columns)}"
    )


    # --------------------------------------------------
    # 6. Train / test split
    # --------------------------------------------------

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    print(
        f"\nTraining samples : {len(X_train):,}"
    )

    print(
        f"Testing samples  : {len(X_test):,}"
    )


    # --------------------------------------------------
    # 7. Create preprocessing pipeline
    # --------------------------------------------------

    preprocessor = create_preprocessor(
        numeric_columns=numeric_columns,
        categorical_columns=categorical_columns,
        top_n=RARE_CATEGORY_TOP_N,
    )


    # --------------------------------------------------
    # 8. Create Random Forest
    # --------------------------------------------------

    classifier = RandomForestClassifier(
        n_estimators=300,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )


    # --------------------------------------------------
    # 9. Create complete ML pipeline
    # --------------------------------------------------

    model = Pipeline(
        steps=[
            (
                "preprocessor",
                preprocessor
            ),
            (
                "classifier",
                classifier
            ),
        ]
    )


    # --------------------------------------------------
    # 10. Train model
    # --------------------------------------------------

    print("\nTraining Random Forest...")

    model.fit(
        X_train,
        y_train
    )

    print("Training completed.")


    # --------------------------------------------------
    # 11. Make predictions
    # --------------------------------------------------

    print("\nGenerating predictions...")

    y_pred = model.predict(
        X_test
    )


    # --------------------------------------------------
    # 12. Calculate metrics
    # --------------------------------------------------

    accuracy = accuracy_score(
        y_test,
        y_pred
    )

    precision = precision_score(
        y_test,
        y_pred,
        zero_division=0
    )

    recall = recall_score(
        y_test,
        y_pred,
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        y_pred,
        zero_division=0
    )


    # --------------------------------------------------
    # 13. Display metrics
    # --------------------------------------------------

    print("\n" + "=" * 50)
    print("Random Forest - Binary Attack Detection")
    print("=" * 50)

    print(f"Accuracy : {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall   : {recall:.4f}")
    print(f"F1 Score : {f1:.4f}")


    # --------------------------------------------------
    # 14. Classification report
    # --------------------------------------------------

    print("\nClassification Report:")

    print(
        classification_report(
            y_test,
            y_pred,
            zero_division=0
        )
    )


    # --------------------------------------------------
    # 15. Confusion matrix
    # --------------------------------------------------

    print("Confusion Matrix:")

    cm = confusion_matrix(
        y_test,
        y_pred
    )

    print(cm)


    # --------------------------------------------------
    # 16. Save model
    # --------------------------------------------------

    save_model(
        model,
        BINARY_MODEL_PATH
    )

    print("\nBinary detector training finished.")


if __name__ == "__main__":
    main()