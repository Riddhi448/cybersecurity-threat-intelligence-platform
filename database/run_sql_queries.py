
import sqlite3
from pathlib import Path
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATABASE_PATH = PROJECT_ROOT / "database" / "cybersecurity.db"

query = """
SELECT
    label,
    COUNT(*) AS total_flows
FROM network_traffic
GROUP BY label
ORDER BY total_flows DESC;
"""

with sqlite3.connect(DATABASE_PATH) as connection:
    results = pd.read_sql_query(query, connection)

print("\nNetwork Traffic by Label:")
print(results.to_string(index=False))
