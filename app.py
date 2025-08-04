import os
import re
import csv
import random
import smtplib
import logging
from email.mime.text import MIMEText
from email.header import Header
from io import StringIO
from datetime import datetime, timedelta
from flask import (
    Flask, render_template, request, redirect,
    session, url_for, Response, g, flash
)
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
from psycopg2 import pool
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

# Configuración de logging
logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)

# Configuración de seguridad para sesiones
app.config.update(
    SESSION_COOKIE_SECURE=True,
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
try:
    connection_pool = pool.SimpleConnectionPool(
        minconn=1,
        maxconn=10,
        host=DB_HOST,
        port=DB_PORT,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )
    app.logger.info("Pool de conexiones a PostgreSQL creado exitosamente")
except psycopg2.OperationalError as e:
    app.logger.error(f"Error al crear pool de conexiones: {str(e)}")
    connection_pool = None

def get_db_connection():
    """Obtiene una conexión del pool."""
    if connection_pool is None:
        app.logger.error("El pool de conexiones no está inicializado")
        return None
        
    if 'db_conn' not in g:
        try:
            g.db_conn = connection_pool.getconn()
            app.logger.info("Conexión obtenida del pool")
        except Exception as e:
            app.logger.error(f"Error al obtener conexión: {str(e)}")
            return None
    return g.db_conn

@app.teardown_appcontext
def close_conn(e=None):
    """Devuelve la conexión al pool."""
    db_conn = g.pop('db_conn', None)
    if db_conn is not None:
        try:
            connection_pool.putconn(db_conn)
            app.logger.info("Conexión devuelta al pool")
        except Exception as e:
            app.logger.error(f"Error al devolver conexión: {str(e)}")

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

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASS)
            server.send_message(msg)
        app.logger.info(f"Correo de verificación enviado a {to_email}")
        return True
    except Exception as e:
        app.logger.error(f"Error enviando correo a {to_email}: {str(e)}")
        return False

def asegurar_esquema():
    """Crea las tablas necesarias si no existen."""
    conn = get_db_connection()
    if conn is None:
        app.logger.error("No se pudo obtener conexión para crear esquema")
        return False
        
    try:
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
        app.logger.info("Esquema de base de datos verificado/creado")
        return True
    except Exception as e:
        app.logger.error(f"Error creando esquema: {str(e)}")
        return False
    finally:
        if cur:
            cur.close()

# ===================== RUTAS DE LA APLICACIÓN =====================

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET'])
def login_page():
    """Página de login (GET)"""
    if 'username' in session:
        if session['rol'] == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('user_dashboard'))
    
    return render_template('login.html', error=None)

@app.route('/login', methods=['POST'])
def login_submit():
    """Procesamiento de login (POST)"""
    if 'username' in session:
        if session['rol'] == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('user_dashboard'))
    
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    
    if not username or not password:
        return render_template('login.html', error="Usuario y contraseña son requeridos")
    
    conn = get_db_connection()
    if conn is None:
        return render_template('login.html', error="Error de conexión a la base de datos")
    
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT id, username, password, rol, empresa_id 
            FROM users 
            WHERE LOWER(username) = LOWER(%s)
        """, (username,))
        user = cur.fetchone()
        
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['rol'] = user[3].lower()
            session['empresa_id'] = user[4]
            
            app.logger.info(f"Login exitoso: {user[1]}, Rol: {user[3]}")
            
            if session['rol'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            app.logger.warning(f"Intento fallido: {username}")
            return render_template('login.html', error="Usuario o contraseña incorrectos")
    except Exception as e:
        app.logger.error(f"Error en login: {str(e)}")
        return render_template('login.html', error="Error interno del servidor")
    finally:
        if cur:
            cur.close()

@app.route('/register', methods=['GET'])
def register_page():
    """Página de registro (GET)"""
    if 'username' in session:
        if session['rol'] == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('user_dashboard'))
    
    return render_template('register.html', error=None)

@app.route('/register', methods=['POST'])
def register_submit():
    """Procesamiento de registro (POST)"""
    if 'username' in session:
        if session['rol'] == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('user_dashboard'))
    
    # Recoger datos del formulario
    nombre_emp = request.form.get('nombre_empresa', '').strip()
    username = request.form.get('username', '').strip().lower()
    password = request.form.get('password', '')
    direccion = request.form.get('direccion', '').strip()
    telefono = request.form.get('telefono', '').strip()
    correo_emp = request.form.get('correo_empresa', '').strip().lower()

    # Validaciones básicas
    if not nombre_emp or not username or not password:
        return render_template('register.html', error="Los campos marcados con * son obligatorios.")
    
    if not es_correo_valido(username):
        return render_template('register.html', error="Formato de correo inválido.")
    
    if not es_contrasena_valida(password):
        return render_template('register.html', error="La contraseña debe tener 8+ caracteres, 1 minúscula, 1 mayúscula, 1 número y 1 símbolo.")
    
    conn = get_db_connection()
    if conn is None:
        return render_template('register.html', error="Error de conexión a la base de datos")
    
    try:
        cur = conn.cursor()
        
        # Verificar si la empresa ya existe
        cur.execute("SELECT id FROM empresas WHERE LOWER(nombre) = LOWER(%s)", (nombre_emp,))
        if cur.fetchone():
            return render_template('register.html', error=f"La empresa '{nombre_emp}' ya está registrada.")
        
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
        if send_verification_email(username, code):
            return redirect(url_for('verify', verif_id=verif_id))
        else:
            return render_template('register.html', error="Error enviando correo de verificación. Intente nuevamente.")
            
    except Exception as e:
        app.logger.error(f"Error en registro: {str(e)}")
        return render_template('register.html', error="Error interno del servidor")
    finally:
        if cur:
            cur.close()

@app.route('/verify/<int:verif_id>', methods=['GET'])
def verify_page(verif_id):
    """Página de verificación (GET)"""
    if 'username' in session:
        if session['rol'] == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('user_dashboard'))
    
    resent = request.args.get('resent')
    return render_template('verify.html', error=None, resent=resent, verif_id=verif_id)

@app.route('/verify/<int:verif_id>', methods=['POST'])
def verify_submit(verif_id):
    """Procesamiento de verificación (POST)"""
    if 'username' in session:
        if session['rol'] == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('user_dashboard'))
    
    code_input = request.form.get('code', '').strip()
    
    conn = get_db_connection()
    if conn is None:
        return render_template('verify.html', error="Error de conexión a la base de datos", verif_id=verif_id)
    
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT nombre_empresa, direccion, telefono, correo_empresa,
                   username, password, code, created_at
            FROM verifications 
            WHERE id = %s
        """, (verif_id,))
        row = cur.fetchone()
        
        if not row:
            return render_template('verify.html', error="Registro de verificación no encontrado.", verif_id=verif_id)
        
        nombre_emp, direccion, telefono, correo_emp, username, hashed, code_db, created_at = row
        
        # Validar código y tiempo
        if datetime.utcnow() - created_at > timedelta(minutes=15):
            return render_template('verify.html', error="El código ha caducado. Solicita uno nuevo.", verif_id=verif_id)
        
        if code_input != code_db:
            return render_template('verify.html', error="Código incorrecto. Intenta nuevamente.", verif_id=verif_id)
        
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
        
        flash('¡Registro completado con éxito! Ya puedes iniciar sesión', 'success')
        return redirect(url_for('login_page'))
        
    except Exception as e:
        app.logger.error(f"Error en verificación: {str(e)}")
        return render_template('verify.html', error="Error interno del servidor", verif_id=verif_id)
    finally:
        if cur:
            cur.close()

@app.route('/resend/<int:verif_id>')
def resend_code(verif_id):
    """Reenviar código de verificación"""
    conn = get_db_connection()
    if conn is None:
        return "Error de conexión a la base de datos", 500
    
    try:
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
        if send_verification_email(username, new_code):
            return redirect(url_for('verify_page', verif_id=verif_id, resent=1))
        else:
            return "Error enviando correo", 500
    except Exception as e:
        app.logger.error(f"Error reenviando código: {str(e)}")
        return "Error interno del servidor", 500
    finally:
        if cur:
            cur.close()

def get_dashboard_data(empresa_id):
    """Obtiene los datos comunes para ambos dashboards."""
    conn = get_db_connection()
    if conn is None:
        return None
    
    try:
        cur = conn.cursor()
        
        # Obtener información de la empresa
        cur.execute("""
            SELECT nombre, direccion, telefono, correo 
            FROM empresas 
            WHERE id = %s
        """, (empresa_id,))
        empresa = cur.fetchone()
        
        # Obtener usuarios de la empresa
        cur.execute("""
            SELECT id, username, rol 
            FROM users 
            WHERE empresa_id = %s
            ORDER BY username
        """, (empresa_id,))
        usuarios = cur.fetchall()
        
        # Obtener inventario
        cur.execute("""
            SELECT id, nombre, descripcion, cantidad, precio, ubicacion
            FROM inventario
            WHERE empresa_id = %s
            ORDER BY nombre
        """, (empresa_id,))
        inventario = cur.fetchall()
        
        # Obtener estadísticas
        cur.execute("SELECT COUNT(*) FROM inventario WHERE empresa_id = %s", (empresa_id,))
        total_articulos = cur.fetchone()[0]
        
        cur.execute("SELECT COUNT(*) FROM users WHERE empresa_id = %s", (empresa_id,))
        total_usuarios = cur.fetchone()[0]
        
        # Preparar datos
        empresa_data = {
            'nombre': empresa[0],
            'direccion': empresa[1] or 'No especificada',
            'telefono': empresa[2] or 'No especificado',
            'correo': empresa[3] or 'No especificado',
            'total_articulos': total_articulos,
            'total_usuarios': total_usuarios
        }
        
        return {
            'empresa': empresa_data,
            'usuarios': usuarios,
            'inventario': inventario
        }
    except Exception as e:
        app.logger.error(f"Error obteniendo datos dashboard: {str(e)}")
        return None
    finally:
        if cur:
            cur.close()

@app.route('/admin')
def admin_dashboard():
    if 'username' not in session:
        return redirect(url_for('login_page'))
    
    if session['rol'] != 'admin':
        flash('No tienes permisos para acceder a esta página', 'danger')
        return redirect(url_for('user_dashboard'))
    
    # Obtener sección actual
    section = request.args.get('section', 'compania')
    
    # Obtener datos
    data = get_dashboard_data(session['empresa_id'])
    if data is None:
        flash('Error cargando datos', 'danger')
        return render_template('admin.html', section=section)
    
    return render_template(
        'admin.html',
        section=section,
        empresa=data['empresa'],
        usuarios=data['usuarios'],
        inventario=data['inventario'],
        rol=session['rol']
    )

@app.route('/dashboard')
def user_dashboard():
    if 'username' not in session:
        return redirect(url_for('login_page'))
    
    # Obtener sección actual
    section = request.args.get('section', 'compania')
    
    # Obtener datos
    data = get_dashboard_data(session['empresa_id'])
    if data is None:
        flash('Error cargando datos', 'danger')
        return render_template('dashboard.html', section=section)
    
    return render_template(
        'dashboard.html',
        section=section,
        empresa=data['empresa'],
        usuarios=data['usuarios'],
        inventario=data['inventario'],
        rol=session['rol']
    )

# ... (las funciones restantes como editar_compania, agregar_usuario, etc. se mantienen iguales)
# Solo cambian las redirecciones para usar login_page en lugar de login

# Al final del archivo:
with app.app_context():
    if asegurar_esquema():
        app.logger.info("Esquema de base de datos verificado")
    else:
        app.logger.error("Error verificando esquema de base de datos")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
