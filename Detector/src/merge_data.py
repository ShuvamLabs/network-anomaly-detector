from pathlib import Path

import pandas as pd


def merge_unsw_nb15(data_dir, output_path):

    data_dir = Path(data_dir)
    output_path = Path(output_path)

    # Feature definition file
    features_path = data_dir / "UNSW-NB15_features.csv"

    # Raw dataset files
    data_files = [
        data_dir / "UNSW-NB15_1.csv",
        data_dir / "UNSW-NB15_2.csv",
        data_dir / "UNSW-NB15_3.csv",
        data_dir / "UNSW-NB15_4.csv",
    ]

    # Check feature file
    if not features_path.exists():
        raise FileNotFoundError(
            f"Feature definition file not found: {features_path}"
        )

    # Check raw dataset files
    missing_files = [
        file for file in data_files
        if not file.exists()
    ]

    if missing_files:
        raise FileNotFoundError(
            "The following dataset files are missing:\n"
            + "\n".join(str(file) for file in missing_files)
        )

    # Load column names
    features = pd.read_csv(
        features_path,
        encoding="ISO-8859-1"
    )

    columns = features["Name"].tolist()

    # Create output directory if necessary
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    # Merge files using chunks
    first_chunk = True

    for file in data_files:
        print(f"Processing: {file.name}")

        for chunk in pd.read_csv(
            file,
            header=None,
            names=columns,
            chunksize=100_000,
            low_memory=False
        ):
            chunk.to_csv(
                output_path,
                header=first_chunk,
                mode="w" if first_chunk else "a",
                index=False
            )

            first_chunk = False

        print(f"Finished: {file.name}")

    print(f"\nMerged dataset saved to: {output_path}")

    return output_path


if __name__ == "__main__":

    # Project data directory
    data_dir = Path("../data")

    # Output merged dataset
    output_path = data_dir / "UNSW-NB15.csv"

    # Run merge
    merged_path = merge_unsw_nb15(
        data_dir=data_dir,
        output_path=output_path
    )

    print(f"Output path: {merged_path}")

