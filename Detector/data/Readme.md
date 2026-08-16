# Dataset

This project uses the **UNSW-NB15** dataset.

Due to GitHub's file size limits, the dataset is not included in this repository.

Download these four files from the official UNSW-NB15 source and place them in this folder:

* `UNSW-NB15_1.csv`
* `UNSW-NB15_2.csv`
* `UNSW-NB15_3.csv`
* `UNSW-NB15_4.csv`

## Combine the dataset

After downloading the four files, combine them into a single dataset before training or running the model.

From the project's `src` folder, run:

```bash
python merge-data.py
```

This will create a merged dataset (e.g., `UNSW-NB15.csv`) inside the `data` folder, which is used by the project.

