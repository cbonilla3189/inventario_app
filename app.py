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

# Cargar variables de entorno
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

# Configuración de seguridad para sesiones
app.config.update(
    SESSION_COOKIE_SECURE=True,     # Activar en producción con HTTPS
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30)
)

# Configuración de PostgreSQL
DB_HOST = os.getenv('DB_HOST')
DB_PORT = os.getenv('DB_PORT', '5432')
DB_NAME = os.getenv('DB_NAME')
DB_USER = os.getenv('DB_USER')
DB_PASSWORD = os.getenv('DB_PASSWORD')

# Configuración de correo
EMAIL_USER = os.getenv('EMAIL_USER')
EMAIL_PASS = os.getenv('EMAIL_PASS')
SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', 587))

# Pool de conexiones PostgreSQL
connection_pool = pool.SimpleConnectionPool(
    minconn=1,
    maxconn=10,
    host=DB_HOST,
    port=DB_PORT,
    database=DB_NAME,
    user=DB_USER,
    password=DB_PASSWORD
)

def get_db_connection():
    """Obtiene una conexión del pool."""
    if 'db_conn' not in g:
        g.db_conn = connection_pool.getconn()
    return g.db_conn

@app.teardown_appcontext
def close_conn(e):
    """Devuelve la conexión al pool."""
    db_conn = g.pop('db_conn', None)
    if db_conn is not None:
        connection_pool.putconn(db_conn)

# Inyectar íconos de roles en plantillas
@app.context_processor
def inject_role_icons():
    return {
        'admin': ('Admin', 'rol-admin'),
        'editor': ('Editor', 'rol-editor'),
        'viewer': ('Viewer', 'rol-viewer')
    }

# Funciones de validación
def es_correo_valido(correo):
    return re.match(r"[^@ \t\r\n]+@[^@ \t\r\n]+\.[^@ \t\r\n]+", correo)

def es_contrasena_valida(password):
    pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*\W).{8,}$'
    return re.match(pattern, password)

def send_verification_email(to_email, code):
    """Envía código de verificación por email."""
    body = f"Tu código de verificación es: {code}"
    msg = MIMEText(body, 'plain', 'utf-8')
    msg['Subject'] = Header('Verificación de correo', 'utf-8')
    msg['From'] = EMAIL_USER
    msg['To'] = to_email

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASS)
        server.send_message(msg)

def asegurar_esquema():
    """Crea las tablas necesarias si no existen."""
    conn = get_db_connection()
    cur = conn.cursor()
    
    # Tabla de empresas
    cur.execute("""
        CREATE TABLE IF NOT EXISTS empresas (
            id SERIAL PRIMARY KEY,
            nombre VARCHAR(100) UNIQUE NOT NULL,
            direccion VARCHAR(200),
            telefono VARCHAR(50),
            correo VARCHAR(100),
            fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Tabla de usuarios
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(100) UNIQUE NOT NULL,
            password VARCHAR(200) NOT NULL,
            rol VARCHAR(20) NOT NULL DEFAULT 'editor',
            empresa_id INTEGER REFERENCES empresas(id) ON DELETE CASCADE,
            fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Tabla de verificaciones
    cur.execute("""
        CREATE TABLE IF NOT EXISTS verifications (
            id SERIAL PRIMARY KEY,
            nombre_empresa VARCHAR(100) NOT NULL,
            direccion VARCHAR(200),
            telefono VARCHAR(50),
            correo_empresa VARCHAR(100),
            username VARCHAR(100) NOT NULL,
            password VARCHAR(200) NOT NULL,
            code CHAR(6) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Tabla de inventario
    cur.execute("""
        CREATE TABLE IF NOT EXISTS inventario (
            id SERIAL PRIMARY KEY,
            empresa_id INTEGER NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
            nombre VARCHAR(150) NOT NULL,
            descripcion TEXT,
            cantidad INTEGER NOT NULL DEFAULT 0 CHECK (cantidad >= 0),
            precio NUMERIC(10, 2),
            ubicacion VARCHAR(100),
            fecha_actualizacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    conn.commit()
    cur.close()

# ===================== RUTAS DE LA APLICACIÓN =====================

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
        cur.execute("""
            SELECT id, password, rol, empresa_id 
            FROM users 
            WHERE username = %s
        """, (username,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if user and check_password_hash(user[1], password):
            session['user_id'] = user[0]
            session['username'] = username
            session['rol'] = user[2]
            session['empresa_id'] = user[3]
            
            if user[2] == 'admin':
                return redirect(url_for('admin_panel'))
            return redirect(url_for('dashboard'))
        
        error = "Usuario o contraseña incorrectos"
    
    return render_template('login.html', error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        # Recoger datos del formulario
        nombre_emp = request.form['nombre_empresa'].strip()
        username = request.form['username'].strip().lower()
        password = request.form['password']
        direccion = request.form.get('direccion', '').strip()
        telefono = request.form.get('telefono', '').strip()
        correo_emp = request.form.get('correo_empresa', '').strip().lower()

        # Validaciones
        if not nombre_emp or not username or not password:
            error = "Los campos marcados con * son obligatorios."
        elif not es_correo_valido(username):
            error = "Formato de correo inválido."
        elif not es_contrasena_valida(password):
            error = "La contraseña debe tener 8+ caracteres, 1 minúscula, 1 mayúscula, 1 número y 1 símbolo."
        else:
            conn = get_db_connection()
            cur = conn.cursor()
            
            # Verificar si la empresa ya existe
            cur.execute("SELECT id FROM empresas WHERE LOWER(nombre) = LOWER(%s)", (nombre_emp,))
            if cur.fetchone():
                error = f"La empresa '{nombre_emp}' ya está registrada."
            else:
                # Generar código de verificación
                code = ''.join(random.choices('0123456789', k=6))
                hashed = generate_password_hash(password)
                
                # Guardar en verificaciones
                cur.execute("""
                    INSERT INTO verifications (
                        nombre_empresa, direccion, telefono, 
                        correo_empresa, username, password, code
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                """, (
                    nombre_emp, direccion, telefono, 
                    correo_emp, username, hashed, code
                ))
                verif_id = cur.fetchone()[0]
                conn.commit()
                
                # Enviar correo
                send_verification_email(username, code)
                return redirect(url_for('verify', verif_id=verif_id))
            
            cur.close()
            conn.close()
    
    return render_template('register.html', error=error)

@app.route('/verify/<int:verif_id>', methods=['GET', 'POST'])
def verify(verif_id):
    error = None
    resent = request.args.get('resent')
    
    if request.method == 'POST':
        code_input = request.form['code'].strip()
        
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Obtener datos de verificación
        cur.execute("""
            SELECT nombre_empresa, direccion, telefono, correo_empresa,
                   username, password, code, created_at
            FROM verifications 
            WHERE id = %s
        """, (verif_id,))
        row = cur.fetchone()
        
        if not row:
            error = "Registro de verificación no encontrado."
        else:
            nombre_emp, direccion, telefono, correo_emp, username, hashed, code_db, created_at = row
            
            # Validar código y tiempo
            if datetime.utcnow() - created_at > timedelta(minutes=15):
                error = "El código ha caducado. Solicita uno nuevo."
            elif code_input != code_db:
                error = "Código incorrecto. Intenta nuevamente."
            else:
                # Registrar empresa
                cur.execute("""
                    INSERT INTO empresas (nombre, direccion, telefono, correo)
                    VALUES (%s, %s, %s, %s)
                    RETURNING id
                """, (nombre_emp, direccion, telefono, correo_emp))
                empresa_id = cur.fetchone()[0]
                
                # Registrar usuario
                cur.execute("""
                    INSERT INTO users (username, password, rol, empresa_id)
                    VALUES (%s, %s, 'editor', %s)
                """, (username, hashed, empresa_id))
                
                # Eliminar verificación
                cur.execute("DELETE FROM verifications WHERE id = %s", (verif_id,))
                conn.commit()
                
                return redirect(url_for('login'))
        
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
        return "Registro de verificación no encontrado.", 404
    
    username = row[0]
    new_code = ''.join(random.choices('0123456789', k=6))
    
    # Actualizar código
    cur.execute("""
        UPDATE verifications
        SET code = %s, created_at = CURRENT_TIMESTAMP
        WHERE id = %s
    """, (new_code, verif_id))
    conn.commit()
    
    # Reenviar correo
    send_verification_email(username, new_code)
    
    return redirect(url_for('verify', verif_id=verif_id, resent=1))

@app.route('/dashboard')
def dashboard():
    if 'username' not in session or session['rol'] == 'admin':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    # Obtener información de la empresa
    cur.execute("""
        SELECT e.nombre 
        FROM empresas e
        WHERE e.id = %s
    """, (session['empresa_id'],))
    empresa = cur.fetchone()
    
    # Obtener inventario
    cur.execute("""
        SELECT id, nombre, descripcion, cantidad, precio, ubicacion
        FROM inventario
        WHERE empresa_id = %s
        ORDER BY nombre
    """, (session['empresa_id'],))
    inventario = cur.fetchall()
    
    # Obtener usuarios de la empresa
    cur.execute("""
        SELECT username, rol 
        FROM users 
        WHERE empresa_id = %s
        ORDER BY username
    """, (session['empresa_id'],))
    usuarios = cur.fetchall()
    
    cur.close()
    conn.close()
    
    return render_template(
        'dashboard.html',
        username=session['username'],
        rol=session['rol'],
        empresa=empresa[0] if empresa else '',
        inventario=inventario,
        usuarios=usuarios
    )

@app.route('/exportar_inventario')
def exportar_inventario():
    if 'username' not in session or session['rol'] == 'admin':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    # Obtener nombre de empresa
    cur.execute("""
        SELECT nombre 
        FROM empresas 
        WHERE id = %s
    """, (session['empresa_id'],))
    empresa_nombre = cur.fetchone()[0]
    
    # Obtener inventario
    cur.execute("""
        SELECT nombre, descripcion, cantidad, precio, ubicacion
        FROM inventario
        WHERE empresa_id = %s
    """, (session['empresa_id'],))
    inventario = cur.fetchall()
    colnames = [desc[0] for desc in cur.description]
    
    # Generar CSV
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(colnames)
    writer.writerows(inventario)
    
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={
            'Content-Disposition': 
                f'attachment; filename=inventario_{empresa_nombre}.csv'
        }
    )

@app.route('/admin_panel')
def admin_panel():
    if 'username' not in session or session['rol'] != 'admin':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    # Obtener todas las empresas
    cur.execute("SELECT id, nombre, fecha_registro FROM empresas ORDER BY nombre")
    empresas = cur.fetchall()
    
    # Obtener todos los usuarios
    cur.execute("""
        SELECT u.id, u.username, u.rol, e.nombre 
        FROM users u
        LEFT JOIN empresas e ON u.empresa_id = e.id
        ORDER BY u.username
    """)
    usuarios = cur.fetchall()
    
    # Obtener estadísticas
    cur.execute("SELECT COUNT(*) FROM empresas")
    num_empresas = cur.fetchone()[0]
    
    cur.execute("SELECT COUNT(*) FROM users")
    num_usuarios = cur.fetchone()[0]
    
    cur.execute("SELECT COUNT(*) FROM inventario")
    num_items = cur.fetchone()[0]
    
    cur.close()
    conn.close()
    
    return render_template(
        'admin.html',
        empresas=empresas,
        usuarios=usuarios,
        num_empresas=num_empresas,
        num_usuarios=num_usuarios,
        num_items=num_items
    )

@app.route('/inventario/editar/<int:item_id>', methods=['GET', 'POST'])
def editar_articulo(item_id):
    if 'username' not in session or session['rol'] not in ['admin', 'editor']:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    # Verificar que el artículo pertenece a la empresa del usuario
    cur.execute("""
        SELECT id, nombre, descripcion, cantidad, precio, ubicacion
        FROM inventario
        WHERE id = %s AND empresa_id = %s
    """, (item_id, session['empresa_id']))
    articulo = cur.fetchone()
    
    if not articulo:
        return "Artículo no encontrado o no tienes permiso", 404
    
    if request.method == 'POST':
        # Lista blanca de campos editables
        nombre = request.form['nombre'].strip()
        descripcion = request.form.get('descripcion', '').strip()
        cantidad = int(request.form['cantidad'])
        precio = request.form.get('precio')
        ubicacion = request.form.get('ubicacion', '').strip()
        
        # Validar cantidad
        if cantidad < 0:
            return "Cantidad no puede ser negativa", 400
        
        # Actualizar en base de datos
        cur.execute("""
            UPDATE inventario
            SET nombre = %s, descripcion = %s, cantidad = %s, 
                precio = %s, ubicacion = %s, fecha_actualizacion = CURRENT_TIMESTAMP
            WHERE id = %s
        """, (nombre, descripcion, cantidad, precio, ubicacion, item_id))
        
        conn.commit()
        cur.close()
        conn.close()
        return redirect(url_for('dashboard'))
    
    # Convertir a diccionario para la plantilla
    columnas = ['id', 'nombre', 'descripcion', 'cantidad', 'precio', 'ubicacion']
    datos = dict(zip(columnas, articulo))
    
    cur.close()
    conn.close()
    
    return render_template('editar_articulo.html', datos=datos)

@app.route('/inventario/agregar', methods=['GET', 'POST'])
def agregar_inventario():
    if 'username' not in session or session['rol'] not in ['admin', 'editor']:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        nombre = request.form['nombre'].strip()
        descripcion = request.form.get('descripcion', '').strip()
        cantidad = int(request.form['cantidad'])
        precio = request.form.get('precio')
        ubicacion = request.form.get('ubicacion', '').strip()
        
        if cantidad < 0:
            return "Cantidad no puede ser negativa", 400
        
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute("""
            INSERT INTO inventario (
                empresa_id, nombre, descripcion, cantidad, precio, ubicacion
            ) VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            session['empresa_id'], nombre, descripcion, 
            cantidad, precio, ubicacion
        ))
        
        conn.commit()
        cur.close()
        conn.close()
        return redirect(url_for('dashboard'))
    
    return render_template('agregar_inventario.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    asegurar_esquema()
    app.run(host='0.0.0.0', port=5000)
