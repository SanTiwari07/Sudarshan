import sqlite3
conn = sqlite3.connect('/app/data/sudarshan.db')
cur = conn.cursor()
rows = cur.execute('SELECT id, username, hashed_pw FROM users').fetchall()
print('All users in /app/data/sudarshan.db:')
for r in rows:
    print(r[0], r[1], repr(r[2]))
