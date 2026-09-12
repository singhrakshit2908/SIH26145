import gzip
import json
import pandas as pd
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

input_file = (
    BASE_DIR
    / "datasets"
    / "raw"
    / "dga-training-data-encoded.json.gz"
)

output_file = (
    BASE_DIR
    / "datasets"
    / "processed"
    / "dga_dataset.csv"
)

records = []

print("Reading DGA dataset...")

with gzip.open(input_file, "rt", encoding="utf-8") as file:

    for line in file:

        # Remove extra spaces
        line = line.strip()

        # Skip empty lines and comments
        if not line or line.startswith("#"):
            continue

        # Convert each JSON line into a Python dictionary
        record = json.loads(line)

        records.append(record)

print("Total records read:", len(records))

# Convert records into a DataFrame
df = pd.DataFrame(records)

print("\nFirst 5 records:")
print(df.head())

print("\nThreat counts:")
print(df["threat"].value_counts())

# Save as CSV
df.to_csv(output_file, index=False)

print("\nDataset saved successfully!")
print("Location:", output_file)