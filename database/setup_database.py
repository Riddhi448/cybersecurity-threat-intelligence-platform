
import sqlite3
from pathlib import Path

import pandas as pd

# Project folders
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATABASE_PATH = PROJECT_ROOT / "database" / "cybersecurity.db"

def create_database(csv_path):
    """Load network traffic data into a local SQLite database."""
    print("Reading CSV file...")

    df = pd.read_csv(csv_path, low_memory=False)
    df.columns = df.columns.astype(str).str.strip()

    # Standardize the column names for SQL queries
    df.columns = [
        column.lower()
        .replace(" ", "_")
        .replace("-", "_")
        .replace("/", "_")
        for column in df.columns
    ]

    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(DATABASE_PATH) as connection:
        df.to_sql(
            "network_traffic",
            connection,
            if_exists="replace",
            index=False,
            chunksize=5000,
        )

    print(f"Database created: {DATABASE_PATH}")
    print(f"Rows imported: {len(df):,}")
    print("Table created: network_traffic")

if __name__ == "__main__":
    csv_file = input("Enter the full path to your CIC-IDS2017 CSV file: ").strip().strip('"')

    if not Path(csv_file).is_file():
        print("File not found. Please check the CSV path.")
    else:
        create_database(csv_file)
