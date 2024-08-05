import csv
from datetime import datetime


def init_csv_header(report_path, csv_header_fields):
    with open(report_path, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(csv_header_fields)


def write_counts_to_csv(report_path, data):
    measurement_datetime = datetime.utcnow().isoformat()

    with open(report_path, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(data)
