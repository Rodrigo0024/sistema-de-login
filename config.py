# config.py
import MySQLdb

DB = MySQLdb.connect(
    host="localhost",
    user="root",
    password="geladeira12",
    database="login_system"
)

CURSOR = DB.cursor()