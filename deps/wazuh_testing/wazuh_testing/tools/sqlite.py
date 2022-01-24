import sqlite3


def load_db(db_path):
    """Load a sqlite database

    Args:
        db_path (str): Path where is located the DB.
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    return conn, cursor


def make_query(db_path, query_list):
    """Make a query to the database for each passed query.

    Args:
        db_path (string): Path where is located the DB.
        query_list (list): List with queries to run.
    """
    connect = sqlite3.connect(db_path)

    try:
        with connect:
            for item in query_list:
                connect.execute(item)
    finally:
        connect.close()


def get_query_result(db_path, query):
    """Get a query result.

    Args:
        db_path (str): Path where is located the DB.
        query (str): SQL query. e.g(SELECT * ..)

    Returns:
        result (List[list]): Each row is the query result row and each column is the query field value
    """
    try:
        db, cursor = load_db(db_path)
        cursor.execute(query)
        records = cursor.fetchall()
        result = []

        for row in records:
            result.append(', '.join([f"{item}" for item in row]))

        return result

    finally:
        cursor.close()
        db.close()
