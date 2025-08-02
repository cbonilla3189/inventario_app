from werkzeug.security import generate_password_hash
import psycopg2

hashed = generate_password_hash("mi_contraseña_segura")

conn = psycopg2.connect(
    host="10.120.0.2",
    database="login_db",
    user="cbonilla",
    password="Cb_2024!xR7mZq"
)

cur = conn.cursor()
cur.execute("UPDATE users SET password = %s WHERE username = %s", (hashed, "carlos"))
conn.commit()
cur.close()
conn.close()

print("🔁 Contraseña actualizada correctamente")
