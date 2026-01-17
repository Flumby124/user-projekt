from dotenv import load_dotenv
import os
from mysql.connector import pooling

# Load .env variables
load_dotenv()
DB_CONFIG = {
    "host": os.getenv("DB_HOST"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "database": os.getenv("DB_DATABASE")
}

# Init db
pool = pooling.MySQLConnectionPool(pool_name="pool", pool_size=1, **DB_CONFIG)
def get_conn():
    return pool.get_connection()

# DB-Helper
def db_write(sql, params=None):
    conn = get_conn()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(sql, params or ())
        conn.commit()
        return cur.lastrowid
    finally:
        try:
            cur.close()
        except:
            pass
        conn.close()


def db_write(sql, params=None):
    cnx = get_connection()
    cursor = cnx.cursor(dictionary=True)
    cursor.execute(sql, params or ())
    cnx.commit()
    return cursor.lastrowid  # <--- gibt ID zurück


import mysql.connector

