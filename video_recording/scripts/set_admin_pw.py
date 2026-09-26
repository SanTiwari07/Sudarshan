import sqlite3
import asyncio
from app.auth.auth import hash_password, verify_password
from app.db.database import set_password

new_hash = hash_password('Admin123!')
print('Generated hash:', new_hash)
print('Verifies directly:', verify_password('Admin123!', new_hash))

# Update SQLite
conn = sqlite3.connect('/app/data/sudarshan.db')
conn.execute('UPDATE users SET hashed_pw = ? WHERE username = ?', (new_hash, 'admin'))
conn.commit()
conn.close()
print('SQLite updated!')

# Update DB
async def update():
    await set_password(1, new_hash)
    print('DB set_password updated!')

asyncio.run(update())
