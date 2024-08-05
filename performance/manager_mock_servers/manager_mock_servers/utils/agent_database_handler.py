import sqlite3


def check_if_agent_exists(database_path, agent_name):
    """Testing."""
    with sqlite3.connect(database_path) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM agents WHERE name = ?', (agent_name,))
        existing_agent = cursor.fetchone()

    return existing_agent


def insert_new_agent(database_path, uuid, key, name):
    """Insert a new agent into the database."""
    with sqlite3.connect(database_path) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO agents (uuid, credential, name)
            VALUES (?, ?, ?)
        ''', (uuid, key, name))
        conn.commit()
