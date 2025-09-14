import sqlite3

conn = sqlite3.connect('lab.db')
cursor = conn.cursor()
cursor.execute('SELECT name FROM sqlite_master WHERE type="table"')
tables = cursor.fetchall()
print('Tables:', tables)

cursor.execute('SELECT * FROM products LIMIT 5')
products = cursor.fetchall()
print('Products:', products)
conn.close()
