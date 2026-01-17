from dotenv import load_dotenv
import os
from mysql.connector import pooling

load_dotenv()

DB_CONFIG = {
    "host": os.getenv("DB_HOST"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "database": os.getenv("DB_DATABASE"),
}

pool = pooling.MySQLConnectionPool(
    pool_name="pool",
    pool_size=5,
    **DB_CONFIG
)

def get_conn():
    return pool.get_connection()


def db_read(sql, params=None, single=False):
    conn = get_conn()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(sql, params or ())
        if single:
            row = cur.fetchone()
            print("db_read(single=True) ->", row)
            return row
        else:
            rows = cur.fetchall()
            print("db_read(single=False) ->", rows)
            return rows
    except Exception as e:
        print("🔥 DB_READ ERROR 🔥")
        print("SQL:", sql)
        print("PARAMS:", params)
        print("ERROR:", e)
        raise
    finally:
        cur.close()
        conn.close()



def db_write(sql, params=None):
    cnx = get_connection()
    try:
        cursor = cnx.cursor(dictionary=True)
        cursor.execute(sql, params or ())
        cnx.commit()
        return cursor.lastrowid
    except Exception as e:
        print("🔥 DB_WRITE ERROR 🔥")
        print("SQL:", sql)
        print("PARAMS:", params)
        print("ERROR:", e)
        raise  # Damit Flask auch die Traceback ausgibt
    finally:
        cursor.close()
        cnx.close()
