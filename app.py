import os
import re
import csv
import random
import smtplib
from email.mime.text import MIMEText
from email.header import Header
from io import StringIO
from datetime import datetime, timedelta
from flask import (
    Flask, render_template, request, redirect,
    session, url_for, Response, g
)
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
from psycopg2 import sql, pool
from dotenv import load_dotenv

# Cargar variables de entorno desde el archivo .env
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

# Configuración de seguridad para sesiones
app.config.update(
    SESSION_COOKIE_SECURE=True,     # Solo enviar sobre HTTPS (activa en producción)
    SESSION_COOKIE_HTTPONLY=True,   # No accesible desde JavaScript
    SESSION_COOKIE_SAMESITE='Lax',  # Protección contra CSRF
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30)
)

# Obtener credenciales de entorno
DB_HOST = os.getenv('DB_HOST')
DB_NAME = os.getenv('DB_NAME')
DB_USER = os.getenv('DB_USER')
DB_PASSWORD = os.getenv('DB_PASSWORD')
EMAIL_USER = os.getenv('EMAIL_USER')
EMAIL_PASS = os.getenv('EMAIL_PASS')
SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', 587))

# Crear pool de conexiones
connection_pool = pool.SimpleConnectionPool(
    minconn=1,
    maxconn=10,
    host=DB_HOST,
    database=DB_NAME,
    user=DB_USER,
    password=DB_PASSWORD
)

def get_db_connection():
    """Obtiene una conexión del pool."""
    g.db_conn = connection_pool.getconn()
    return g.db_conn

@app.teardown_appcontext
def close_conn(e):
    """Devuelve la conexión al pool al final del request."""
    db_conn = getattr(g, 'db_conn', None)
    if db_conn is not None:
        connection_pool.putconn(db_conn)

# Inyectar íconos de roles en todas las plantillas
@app.context_processor
def inject_role_icons():
    role_icons = {
        'admin': ('Admin', 'rol-admin'),
        'editor': ('Editor', 'rol-editor'),
        'viewer': ('Viewer', 'rol-viewer')
    }
    return dict(role_icons=role_icons)

# Funciones de validación
def es_correo_valido(correo):
    return re.match(r"[^@ \t\r\n]+@[^@ \t\r\n]+\.[^@ \t\r\n]+", correo)

def es_contrasena_valida(password):
    pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*\W).{8,}$'
    return re.match(pattern, password)

def send_verification_email(to_email, code):
    body = f"Tu código de verificación es: {code}"
    msg = MIMEText(body, _subtype='plain', _charset='utf-8')
    msg['Subject'] = Header('Verificación de correo', 'utf-8')
    msg['From'] = EMAIL_USER
    msg['To'] = to_email

    server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
    server.starttls()
    server.login(EMAIL_USER, EMAIL_PASS)
    server.send_message(msg)
    server.quit()

def asegurar_esquema():
    conn = get_db_connection()
    cur = conn.cursor()

    # Crear tabla empresas si no existe
    cur.execute("""
        CREATE TABLE IF NOT EXISTS empresas (
            id SERIAL PRIMARY KEY,
            nombre VARCHAR(100) UNIQUE,
            fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Añadir columnas adicionales si no existen
    for col, tipo in [
        ('direccion', 'VARCHAR(200)'),
        ('telefono', 'VARCHAR(50)'),
        ('correo', 'VARCHAR(100)')
    ]:
        cur.execute("""
            SELECT 1 FROM information_schema.columns
             WHERE table_name='empresas' AND column_name=%s
        """, (col,))
        if not cur.fetchone():
            cur.execute(f"ALTER TABLE empresas ADD COLUMN {col} {tipo}")

    # Añadir empresa_id a users si no existe
    cur.execute("""
        SELECT 1 FROM information_schema.columns
         WHERE table_name='users' AND column_name='empresa_id'
    """)
    if not cur.fetchone():
        cur.execute("ALTER TABLE users ADD COLUMN empresa_id INTEGER")

    # Crear tabla verifications
    cur.execute("""
        CREATE TABLE IF NOT EXISTS verifications (
            id SERIAL PRIMARY KEY,
            nombre_empresa VARCHAR(100),
            direccion VARCHAR(200),
            telefono VARCHAR(50),
            correo_empresa VARCHAR(100),
            username VARCHAR(100),
            password VARCHAR(200),
            code CHAR(6),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Crear tabla inventario
    cur.execute("""
        CREATE TABLE IF NOT EXISTS inventario (
            id SERIAL PRIMARY KEY,
            empresa_id INTEGER REFERENCES empresas(id) ON DELETE CASCADE,
            nombre VARCHAR(150) NOT NULL,
            descripcion TEXT,
            cantidad INTEGER NOT NULL CHECK (cantidad >= 0),
            fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    cur.close()
    conn.close()

# Rutas de la aplicación
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username'].strip().lower()
        password = request.form['password']
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, password, rol FROM users WHERE username=%s", (username,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if user and check_password_hash(user[1], password):
            session['user_id'] = user[0]
            session['username'] = username
            session['rol'] = user[2]
            return redirect('/admin_panel' if user[2] == 'admin' else '/dashboard')
        error = "Usuario o contraseña incorrectos"
    return render_template('login.html', error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        nombre_emp = request.form['nombre_empresa'].strip()
        direccion = request.form.get('direccion', '').strip()
        telefono = request.form.get('telefono', '').strip()
        correo_emp = request.form.get('correo_empresa', '').strip().lower()
        username = request.form['username'].strip().lower()
        password = request.form['password']

        if not nombre_emp or not username or not password:
            error = "Los campos marcados con * son obligatorios."
        elif not es_correo_valido(username):
            error = "Correo de usuario inválido."
        elif not es_contrasena_valida(password):
            error = ("La contraseña debe tener 8+ caracteres, "
                     "1 minúsc. 1 mayúsc. 1 dígito y 1 especial.")
        else:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("SELECT id FROM empresas WHERE LOWER(nombre)=LOWER(%s)", (nombre_emp,))
            if cur.fetchone():
                error = f"La compañía «{nombre_emp}» ya existe."
                cur.close()
                conn.close()
            else:
                code = ''.join(random.choices('0123456789', k=6))
                hashed = generate_password_hash(password)
                cur.execute("""
                    INSERT INTO verifications (
                      nombre_empresa, direccion, telefono,
                      correo_empresa, username, password, code
                    ) VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id
                """, (nombre_emp, direccion, telefono,
                      correo_emp, username, hashed, code))
                verif_id = cur.fetchone()[0]
                conn.commit()
                cur.close()
                conn.close()

                send_verification_email(username, code)
                return redirect(url_for('verify', verif_id=verif_id))
    return render_template('register.html', error=error)

@app.route('/verify/<int:verif_id>', methods=['GET', 'POST'])
def verify(verif_id):
    error = None
    resent = request.args.get('resent')
    if request.method == 'POST':
        code_input = request.form['code'].strip()
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT nombre_empresa, direccion, telefono, correo_empresa,
                   username, password, code, created_at
              FROM verifications WHERE id=%s
        """, (verif_id,))
        row = cur.fetchone()

        if not row:
            error = "Registro no encontrado."
        else:
            (nombre_emp, direccion, telefono, correo_emp,
             username, hashed, code_db, created_at) = row

            if datetime.utcnow() - created_at > timedelta(minutes=15):
                error = "El código caducó. Solicita uno nuevo."
            elif code_input != code_db:
                error = "Código incorrecto. Intenta de nuevo."
            else:
                cur.execute("""
                    INSERT INTO empresas (nombre, direccion, telefono, correo)
                    VALUES (%s,%s,%s,%s) RETURNING id
                """, (nombre_emp, direccion, telefono, correo_emp))
                empresa_id = cur.fetchone()[0]

                cur.execute("""
                    INSERT INTO users (username, password, rol, empresa_id)
                    VALUES (%s,%s,'editor',%s)
                """, (username, hashed, empresa_id))

                cur.execute("DELETE FROM verifications WHERE id=%s", (verif_id,))
                conn.commit()
                cur.close()
                conn.close()
                return redirect('/')

        cur.close()
        conn.close()
    return render_template('verify.html', error=error, resent=resent, verif_id=verif_id)

@app.route('/resend/<int:verif_id>')
def resend(verif_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT username FROM verifications WHERE id = %s", (verif_id,))
    row = cur.fetchone()
    if not row:
        cur.close()
        conn.close()
        return "Verificación no encontrada.", 404

    username = row[0]
    new_code = ''.join(random.choices('0123456789', k=6))
    cur.execute("""
        UPDATE verifications
           SET code = %s, created_at = CURRENT_TIMESTAMP
         WHERE id = %s
    """, (new_code, verif_id))
    conn.commit()
    cur.close()
    conn.close()

    send_verification_email(username, new_code)
    return redirect(url_for('verify', verif_id=verif_id, resent=1))

@app.route('/dashboard')
def dashboard():
    if 'username' not in session or session['rol'] == 'admin':
        return redirect('/')
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    # Obtener información del usuario y empresa
    cur.execute("""
        SELECT u.username, u.rol, u.empresa_id, e.nombre
          FROM users u
          JOIN empresas e ON u.empresa_id = e.id
         WHERE u.username = %s
    """, (session['username'],))
    user_data = cur.fetchone()
    
    if not user_data:
        cur.close()
        conn.close()
        return "Usuario no encontrado.", 404
        
    username, rol, empresa_id, nombre_empresa = user_data

    # Obtener inventario de la empresa
    cur.execute("""
        SELECT id, nombre, descripcion, cantidad
          FROM inventario
         WHERE empresa_id = %s
    """, (empresa_id,))
    inventario_items = cur.fetchall()

    cur.close()
    conn.close()
    
    return render_template(
        'dashboard.html',
        username=username,
        rol=rol,
        company=nombre_empresa,
        inventario=inventario_items
    )

@app.route('/exportar_inventario')
def exportar_inventario():
    if 'username' not in session or session['rol'] == 'admin':
        return redirect('/')
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    # Obtener información de la empresa
    cur.execute("""
        SELECT e.nombre, u.empresa_id
          FROM users u
          JOIN empresas e ON u.empresa_id = e.id
         WHERE u.username = %s
    """, (session['username'],))
    empresa_data = cur.fetchone()
    
    if not empresa_data:
        cur.close()
        conn.close()
        return "Empresa no encontrada.", 404
        
    nombre_empresa, empresa_id = empresa_data

    # Obtener datos del inventario
    cur.execute("""
        SELECT nombre, descripcion, cantidad, fecha_registro
          FROM inventario
         WHERE empresa_id = %s
    """, (empresa_id,))
    inventario_items = cur.fetchall()
    colnames = [desc[0] for desc in cur.description]
    
    cur.close()
    conn.close()

    # Generar CSV
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(colnames)
    writer.writerows(inventario_items)
    
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-disposition": f"attachment; filename=inventario_{nombre_empresa}.csv"}
    )

@app.route('/admin_panel', methods=['GET', 'POST'])
def admin_panel():
    if 'username' not in session or session['rol'] != 'admin':
        return redirect('/')

    section = request.args.get('section', 'users')
    tabla_sel = request.args.get('tabla')

    conn = get_db_connection()
    cur = conn.cursor()

    if request.method == 'POST':
        accion = request.form.get('accion')

        # Restringir operaciones peligrosas solo a superadmin
        if accion in ['eliminar_tabla', 'eliminar_compania', 'eliminar_campo_tabla']:
            if session.get('username') != 'superadmin@dominio.com':
                return "Acceso no autorizado", 403

        # Resto de acciones...
        # (Mantener la lógica existente pero con validaciones adicionales)

    # Resto de la lógica del panel de administración...
    # (Mantener la lógica existente)

    cur.close()
    conn.close()
    
    return render_template(
        'admin.html',
        section=section,
        # ... otros parámetros
    )

@app.route('/inventario/editar/<int:item_id>', methods=['GET', 'POST'])
def editar_articulo(item_id):
    if 'username' not in session or session['rol'] == 'admin':
        return redirect('/')
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    # Obtener la empresa del usuario actual
    cur.execute("""
        SELECT u.empresa_id, e.nombre
          FROM users u
          JOIN empresas e ON u.empresa_id = e.id
         WHERE u.username = %s
    """, (session['username'],))
    empresa_data = cur.fetchone()
    
    if not empresa_data:
        cur.close()
        conn.close()
        return "Usuario sin empresa asignada.", 403
        
    empresa_id, nombre_empresa = empresa_data

    # Lista blanca de columnas editables
    allowed_columns = ['nombre', 'descripcion', 'cantidad']

    if request.method == 'POST':
        updates = []
        values = []
        
        # Recoger solo campos permitidos
        for col in allowed_columns:
            if col in request.form:
                updates.append(f"{col} = %s")
                values.append(request.form[col])
        
        if updates:
            values.append(item_id)
            values.append(empresa_id)  # Asegurar que solo edita su empresa
            
            update_query = f"""
                UPDATE inventario
                   SET {', '.join(updates)}
                 WHERE id = %s AND empresa_id = %s
            """
            cur.execute(update_query, values)
            conn.commit()
            cur.close()
            conn.close()
            return redirect(url_for('dashboard'))
        else:
            error = "No se proporcionaron datos válidos para actualizar."
            return render_template('editar_articulo.html', error=error)

    # Obtener el artículo específico de la empresa
    cur.execute("""
        SELECT id, nombre, descripcion, cantidad
          FROM inventario
         WHERE id = %s AND empresa_id = %s
    """, (item_id, empresa_id))
    articulo = cur.fetchone()
    
    cur.close()
    conn.close()

    if not articulo:
        return "Artículo no encontrado o no pertenece a tu empresa.", 404

    # Convertir a diccionario para fácil acceso en plantilla
    columnas = ['id', 'nombre', 'descripcion', 'cantidad']
    datos = dict(zip(columnas, articulo))
    
    return render_template(
        'editar_articulo.html',
        datos=datos,
        nombre_empresa=nombre_empresa
    )

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    asegurar_esquema()
    app.run(debug=True)
