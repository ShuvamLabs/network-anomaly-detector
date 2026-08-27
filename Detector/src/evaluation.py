import argparse

import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
)

from config import (
    BINARY_MODEL_PATH,
    CATEGORY_MODEL_PATH,
)

from utils import (
    load_model,
    load_unsw_nb15,
)


def evaluate_model(model, X_test, y_test, model_type):
    """
    Evaluate a trained model and display metrics.
    """

    y_pred = model.predict(X_test)

    print("\n" + "=" * 60)
    print(f"Evaluation - {model_type}")
    print("=" * 60)

    if model_type == "Binary Detection":

        accuracy = accuracy_score(y_test, y_pred)

        precision = precision_score(
            y_test,
            y_pred,
            zero_division=0,
        )

        recall = recall_score(
            y_test,
            y_pred,
            zero_division=0,
        )

        f1 = f1_score(
            y_test,
            y_pred,
            zero_division=0,
        )

        print(f"Accuracy : {accuracy:.4f}")
        print(f"Precision: {precision:.4f}")
        print(f"Recall   : {recall:.4f}")
        print(f"F1 Score : {f1:.4f}")

    else:

        accuracy = accuracy_score(
            y_test,
            y_pred,
        )

        precision = precision_score(
            y_test,
            y_pred,
            average="weighted",
            zero_division=0,
        )

        recall = recall_score(
            y_test,
            y_pred,
            average="weighted",
            zero_division=0,
        )

        f1 = f1_score(
            y_test,
            y_pred,
            average="weighted",
            zero_division=0,
        )

        f1_macro = f1_score(
            y_test,
            y_pred,
            average="macro",
            zero_division=0,
        )

        print(f"Accuracy  : {accuracy:.4f}")
        print(f"Precision : {precision:.4f}")
        print(f"Recall    : {recall:.4f}")
        print(f"F1 Score  : {f1:.4f}")
        print(f"F1 Macro  : {f1_macro:.4f}")

    print("\nClassification Report:")

    print(
        classification_report(
            y_test,
            y_pred,
            zero_division=0,
        )
    )

    return y_test, y_pred


def plot_confusion_matrix(
    y_test,
    y_pred,
    title,
):
    """
    Plot the confusion matrix.
    """

    labels = sorted(
        set(y_test) | set(y_pred)
    )

    cm = confusion_matrix(
        y_test,
        y_pred,
        labels=labels,
    )

    plt.figure(
        figsize=(10, 8)
    )

    sns.heatmap(
        cm,
        annot=True,
        fmt="d",
        cmap="Blues",
        xticklabels=labels,
        yticklabels=labels,
    )

    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.title(title)

    plt.tight_layout()
    plt.show()


def prepare_binary_data(df):
    """
    Prepare data for binary model evaluation.
    """

    df = df.copy()

    if "id" in df.columns:
        df = df.drop(
            columns=["id"]
        )

    df = df.dropna(
        subset=["Label"]
    )

    X = df.drop(
        columns=["Label"]
    )

    y = df["Label"]

    return X, y


def prepare_category_data(df):
    """
    Prepare data for attack-category model evaluation.
    """

    df = df.copy()

    if "id" in df.columns:
        df = df.drop(
            columns=["id"]
        )

    df = df.dropna(
        subset=["attack_cat"]
    )

    df["attack_cat"] = (
        df["attack_cat"]
        .astype(str)
        .str.strip()
    )

    df = df[
        df["attack_cat"] != ""
    ]

    # Remove Normal because this model
    # predicts attack categories only.
    normal_mask = (
        df["attack_cat"]
        .str.lower()
        == "normal"
    )

    df = df[
        ~normal_mask
    ]

    X = df.drop(
        columns=["attack_cat"]
    )

    y = df["attack_cat"]

    # Label is not a feature for category prediction.
    if "Label" in X.columns:
        X = X.drop(
            columns=["Label"]
        )

    return X, y


def main():

    parser = argparse.ArgumentParser(
        description="Evaluate Network Anomaly Detector models."
    )

    parser.add_argument(
        "--model",
        choices=[
            "binary",
            "category",
        ],
        required=True,
        help="Model to evaluate.",
    )

    args = parser.parse_args()


    # --------------------------------------------------
    # Load dataset
    # --------------------------------------------------

    print("Loading dataset...")

    df = load_unsw_nb15(
        "data"
    )


    # --------------------------------------------------
    # Binary model
    # --------------------------------------------------

    if args.model == "binary":

        print("Loading binary model...")

        model = load_model(
            BINARY_MODEL_PATH
        )

        X, y = prepare_binary_data(
            df
        )

        # Use the same test split used during
        # the training stage.
        from sklearn.model_selection import train_test_split

        _, X_test, _, y_test = train_test_split(
            X,
            y,
            test_size=0.20,
            random_state=42,
            stratify=y,
        )

        y_test, y_pred = evaluate_model(
            model,
            X_test,
            y_test,
            "Binary Detection",
        )

        plot_confusion_matrix(
            y_test,
            y_pred,
            "Binary Attack Detection - Confusion Matrix",
        )


    # --------------------------------------------------
    # Attack category model
    # --------------------------------------------------

    elif args.model == "category":

        print("Loading attack-category model...")

        model = load_model(
            CATEGORY_MODEL_PATH
        )

        X, y = prepare_category_data(
            df
        )

        from sklearn.model_selection import train_test_split

        _, X_test, _, y_test = train_test_split(
            X,
            y,
            test_size=0.20,
            random_state=42,
            stratify=y,
        )

        y_test, y_pred = evaluate_model(
            model,
            X_test,
            y_test,
            "Attack Category",
        )

        plot_confusion_matrix(
            y_test,
            y_pred,
            "Attack Category - Confusion Matrix",
        )


if __name__ == "__main__":
    main()