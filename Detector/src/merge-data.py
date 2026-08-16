from pathlib import Path
import pandas as pd

data_dir = Path(r'C:\Users\HP\Documents\PycharmProjects\network-anomaly-detector\Detector\data')
f_des = data_dir/'UNSW-NB15.csv'

features = pd.read_csv(data_dir/'UNSW-NB15_features.csv', encoding='ISO-8859-1')
columns = features["Name"].tolist()

data_files = [
    data_dir/'UNSW-NB15_1.csv',
    data_dir/'UNSW-NB15_2.csv',
    data_dir/'UNSW-NB15_3.csv',
    data_dir/'UNSW-NB15_4.csv',
]

first = True

for file in data_files:
    for chunk in pd.read_csv(file, header = None,names = columns, chunksize = 100000 , low_memory=False ):
        chunk.to_csv(
            f_des,
            header = first,
            mode = "w" if first else "a",
            index = False,
        )
        first = False