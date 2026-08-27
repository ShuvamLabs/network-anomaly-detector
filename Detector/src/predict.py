import pandas as pd

from config import (
    BINARY_MODEL_PATH,
    CATEGORY_MODEL_PATH,
)

from utils import load_model


class NetworkAnomalyDetector:
    """
    Two-stage network anomaly detector.

    Stage 1:
        Normal vs Attack

    Stage 2:
        Attack category classification
    """

    def __init__(
        self,
        binary_model_path=BINARY_MODEL_PATH,
        category_model_path=CATEGORY_MODEL_PATH,
    ):
        self.binary_model = load_model(
            binary_model_path
        )

        self.category_model = load_model(
            category_model_path
        )


    def predict(self, data):
        """
        Predict network traffic.

        Parameters
        ----------
        data : pandas.DataFrame or dict
            Network traffic features.

        Returns
        -------
        pandas.DataFrame
            Prediction results.
        """

        # ----------------------------------------------
        # Convert dictionary to DataFrame
        # ----------------------------------------------

        if isinstance(data, dict):
            data = pd.DataFrame([data])

        elif not isinstance(data, pd.DataFrame):
            raise TypeError(
                "data must be a pandas DataFrame or dictionary."
            )

        data = data.copy()


        # ----------------------------------------------
        # Remove ID if present
        # ----------------------------------------------

        if "id" in data.columns:
            data = data.drop(
                columns=["id"]
            )


        # ----------------------------------------------
        # Stage 1: Binary detection
        # ----------------------------------------------

        binary_prediction = (
            self.binary_model.predict(data)
        )


        results = []


        # ----------------------------------------------
        # Process each sample
        # ----------------------------------------------

        for index, prediction in enumerate(
            binary_prediction
        ):

            if prediction == 0:

                results.append(
                    {
                        "prediction": "Normal",
                        "attack_category": "Normal",
                    }
                )

            else:

                # --------------------------------------
                # Stage 2 requires Label to be removed
                # --------------------------------------

                category_input = data.iloc[
                    index:index + 1
                ].copy()

                if "Label" in category_input.columns:
                    category_input = category_input.drop(
                        columns=["Label"]
                    )


                # --------------------------------------
                # Predict attack category
                # --------------------------------------

                category_prediction = (
                    self.category_model.predict(
                        category_input
                    )[0]
                )

                results.append(
                    {
                        "prediction": "Attack",
                        "attack_category": str(
                            category_prediction
                        ),
                    }
                )


        return pd.DataFrame(
            results,
            index=data.index,
        )


    def predict_single(self, data):
        """
        Predict a single network-flow record.

        Parameters
        ----------
        data : dict
            Feature dictionary.

        Returns
        -------
        dict
            Prediction result.
        """

        result = self.predict(
            data
        )

        return result.iloc[0].to_dict()


if __name__ == "__main__":

    detector = NetworkAnomalyDetector()

    # Example:
    #
    # sample = {
    #     "dur": 0.12,
    #     "proto": "tcp",
    #     "service": "http",
    #     "state": "FIN",
    #     ...
    # }
    #
    # result = detector.predict_single(sample)
    #
    # print(result)

    print(
        "Network Anomaly Detector loaded successfully."
    )