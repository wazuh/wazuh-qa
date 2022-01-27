import sqlite3
import sys

db_path = sys.argv[1]
query = " ".join(sys.argv[2:])

conn = sqlite3.connect(db_path)
cursor = conn.cursor()
cursor.execute(query)
print(cursor.fetchall())