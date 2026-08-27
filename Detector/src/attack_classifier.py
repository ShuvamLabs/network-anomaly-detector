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
    CATEGORY_MODEL_PATH,
    CATEGORY_TARGET,
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
    # 3. Remove rows without attack category
    # --------------------------------------------------

    df = df.dropna(
        subset=[CATEGORY_TARGET]
    )


    # --------------------------------------------------
    # 4. Remove empty attack categories
    # --------------------------------------------------

    df[CATEGORY_TARGET] = (
        df[CATEGORY_TARGET]
        .astype(str)
        .str.strip()
    )

    df = df[
        df[CATEGORY_TARGET] != ""
    ]


    # --------------------------------------------------
    # 5. Separate features and target
    # --------------------------------------------------

    X = df.drop(
        columns=[CATEGORY_TARGET]
    )

    y = df[CATEGORY_TARGET]


    # --------------------------------------------------
    # 6. Remove binary label from features
    # --------------------------------------------------

    # Label tells us whether traffic is normal/attack.
    # It should NOT be used to predict attack_cat.

    if BINARY_TARGET in X.columns:
        X = X.drop(
            columns=[BINARY_TARGET]
        )


    # --------------------------------------------------
    # 7. Remove Normal class
    # --------------------------------------------------

    # Attack-category classification should classify
    # the type of attack, not Normal traffic.

    normal_mask = (
        y.str.lower() == "normal"
    )

    X = X.loc[~normal_mask]
    y = y.loc[~normal_mask]


    # --------------------------------------------------
    # 8. Display class distribution
    # --------------------------------------------------

    print("\nAttack category distribution:")

    print(
        y.value_counts()
    )


    # --------------------------------------------------
    # 9. Determine categorical features
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
        f"\nNumerical features   : {len(numeric_columns)}"
    )

    print(
        f"Categorical features : {len(categorical_columns)}"
    )


    # --------------------------------------------------
    # 10. Train / test split
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
    # 11. Create preprocessing pipeline
    # --------------------------------------------------

    preprocessor = create_preprocessor(
        numeric_columns=numeric_columns,
        categorical_columns=categorical_columns,
        top_n=RARE_CATEGORY_TOP_N,
    )


    # --------------------------------------------------
    # 12. Create Random Forest classifier
    # --------------------------------------------------

    classifier = RandomForestClassifier(
        n_estimators=300,
        random_state=RANDOM_STATE,
        n_jobs=-1,
        class_weight="balanced",
    )


    # --------------------------------------------------
    # 13. Create complete pipeline
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
    # 14. Train
    # --------------------------------------------------

    print("\nTraining attack-category Random Forest...")

    model.fit(
        X_train,
        y_train
    )

    print("Training completed.")


    # --------------------------------------------------
    # 15. Predictions
    # --------------------------------------------------

    print("\nGenerating predictions...")

    y_pred = model.predict(
        X_test
    )


    # --------------------------------------------------
    # 16. Metrics
    # --------------------------------------------------

    accuracy = accuracy_score(
        y_test,
        y_pred
    )

    precision = precision_score(
        y_test,
        y_pred,
        average="weighted",
        zero_division=0
    )

    recall = recall_score(
        y_test,
        y_pred,
        average="weighted",
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        y_pred,
        average="weighted",
        zero_division=0
    )

    f1_macro = f1_score(
        y_test,
        y_pred,
        average="macro",
        zero_division=0
    )


    # --------------------------------------------------
    # 17. Display metrics
    # --------------------------------------------------

    print("\n" + "=" * 55)
    print("Random Forest - Attack Category")
    print("=" * 55)

    print(f"Accuracy  : {accuracy:.4f}")
    print(f"Precision : {precision:.4f}")
    print(f"Recall    : {recall:.4f}")
    print(f"F1 Score  : {f1:.4f}")
    print(f"F1 Macro  : {f1_macro:.4f}")


    # --------------------------------------------------
    # 18. Classification report
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
    # 19. Confusion matrix
    # --------------------------------------------------

    print("Confusion Matrix:")

    cm = confusion_matrix(
        y_test,
        y_pred,
        labels=sorted(y.unique())
    )

    print(cm)


    # --------------------------------------------------
    # 20. Save model
    # --------------------------------------------------

    save_model(
        model,
        CATEGORY_MODEL_PATH
    )

    print(
        "\nAttack-category model training finished."
    )


if __name__ == "__main__":
    main()