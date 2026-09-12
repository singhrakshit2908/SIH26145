import pandas as pd
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

input_file = (
    BASE_DIR
    / "datasets"
    / "processed"
    / "dga_dataset.csv"
)

output_file = (
    BASE_DIR
    / "datasets"
    / "processed"
    / "dga_sample.csv"
)

SAMPLE_SIZE = 50000

print("Reading DGA records...")

dga_sample = []
benign_sample = []

for chunk in pd.read_csv(input_file, chunksize=100000):

    dga = chunk[chunk["threat"] == "dga"]
    benign = chunk[chunk["threat"] == "benign"]

    remaining_dga = SAMPLE_SIZE - sum(len(x) for x in dga_sample)
    remaining_benign = SAMPLE_SIZE - sum(len(x) for x in benign_sample)

    if remaining_dga > 0:
        dga_sample.append(dga.head(remaining_dga))

    if remaining_benign > 0:
        benign_sample.append(benign.head(remaining_benign))

    if (
        sum(len(x) for x in dga_sample) >= SAMPLE_SIZE
        and sum(len(x) for x in benign_sample) >= SAMPLE_SIZE
    ):
        break


df_dga = pd.concat(dga_sample)
df_benign = pd.concat(benign_sample)

final_df = pd.concat([df_dga, df_benign])

# Shuffle the dataset
final_df = final_df.sample(frac=1, random_state=42)

final_df.to_csv(output_file, index=False)

print("\nSample created successfully!")
print(final_df["threat"].value_counts())
print("Total samples:", len(final_df))
print("Saved to:", output_file)