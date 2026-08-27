import pandas as pd

from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler


class RareCategories(BaseEstimator, TransformerMixin):
    """
    Keep only the top N most frequent categories in each categorical column.
    All other categories are replaced with 'other'.
    """

    def __init__(self, top_n=7):
        self.top_n = top_n
        self.top_categories_ = {}

    def fit(self, X, y=None):
        X = pd.DataFrame(X).copy()

        for column in X.columns:
            self.top_categories_[column] = (
                X[column]
                .value_counts()
                .head(self.top_n)
                .index
                .tolist()
            )

        return self

    def transform(self, X):
        X = pd.DataFrame(X).copy()

        for column in X.columns:
            top_categories = self.top_categories_.get(column, [])

            X[column] = X[column].where(
                X[column].isin(top_categories),
                "other"
            )

        return X


def create_preprocessor(numeric_columns, categorical_columns, top_n=7):
    """
    Create the preprocessing pipeline for UNSW-NB15.
    """

    numeric_pipeline = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="most_frequent")),
            ("scaler", StandardScaler()),
        ]
    )

    categorical_pipeline = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="most_frequent")),
            (
                "rare_categories",
                RareCategories(top_n=top_n)
            ),
            (
                "onehot",
                OneHotEncoder(
                    handle_unknown="ignore"
                )
            ),
        ]
    )

    preprocessor = ColumnTransformer(
        transformers=[
            (
                "num",
                numeric_pipeline,
                numeric_columns
            ),
            (
                "cat",
                categorical_pipeline,
                categorical_columns
            ),
        ]
    )

    return preprocessor