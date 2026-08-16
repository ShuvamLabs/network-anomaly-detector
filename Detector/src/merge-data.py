from pathlib import Path
import pandas as pd
import glob

data_dir = Path(r'C:\Users\HP\Documents\PycharmProjects\network-anomaly-detector\Detector\data')
f_des = data_dir/'UNSW-NB15.csv'

data_files = sorted(
    f for f in data_dir.glob('*.csv')
    if f.name != 'UNSW-NB15.csv'
)

first = True

for file in data_files:
    for chunk in pd.read_csv(file, header = None , chunksize = 100000 , low_memory=False ):
        chunk.to_csv(
            f_des,
            mode = "w" if first else "a",
            header = False,
            index = False,
        )
        first = False