import sqlite3

for p in ['/app/data/sudarshan.db', '/app/sudarshan.db', '/app/app/sudarshan.db']:
    try:
        conn = sqlite3.connect(p)
        cur = conn.cursor()
        rows = cur.execute('SELECT id, username, hashed_pw FROM users').fetchall()
        print(f'=== DB: {p} ===')
        for r in rows:
            print(r[0], r[1], repr(r[2]))
        conn.close()
    except Exception as e:
        print(f'=== DB: {p} ERROR: {e} ===')
