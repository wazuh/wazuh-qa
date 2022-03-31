import sqlite3
import argparse

parser = argparse.ArgumentParser()

parser.add_argument('--db_path', type=str, required=True)
parser.add_argument('--query', type=str, required=True)

args = parser.parse_args()
conn = sqlite3.connect(args.db_path)
cursor = conn.cursor()
cursor.execute(args.query)
print(cursor.fetchall())
