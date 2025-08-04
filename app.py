import os
import re
import csv
import random
import smtplib
import logging
import urllib.parse
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.header import Header
from io import StringIO
from flask import (
    Flask, render_template, request, redirect,
    session, url_for, Response, g, flash
)
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
from psycopg2 import pool
from dotenv import load_dotenv

# Configuración básica
app = Flask(__name__)
load_dotenv('app.env')

# Configuración de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('inventario_app')
handler = logging.FileHandler('/var/www/inventario_app/app.log')
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

# Configuración de la aplicación
app.secret_key = os.getenv('SECRET_KEY')
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30)
)

# Manejo seguro de contraseñas con caracteres especiales
def get_db_password():
    password = os.getenv('DB_PASSWORD')
    # Escapar caracteres especiales para PostgreSQL
    return urllib.parse.quote_plus(password) if password else ''

# Configuración de la base de datos
DB_CONFIG = {
    'host': os.getenv('DB_HOST'),
    'port': os.getenv('DB_PORT', '5432'),
    'database': os.getenv('DB_NAME'),
    'user': os.getenv('DB_USER'),
    'password': get_db_password()  # Usar la contraseña manejada de forma segura
}

# Configuración de correo
EMAIL_CONFIG = {
    'user': os.getenv('EMAIL_USER'),
    'password': os.getenv('EMAIL_PASS'),
    'server': os.getenv('SMTP_SERVER', 'smtp.gmail.com'),
    'port': int(os.getenv('SMTP_PORT', 587))
}

# Pool de conexiones
def create_connection_pool():
    try:
        logger.info("Intentando crear pool de conexiones...")
        logger.info(f"DB Config: {DB_CONFIG['host']}, {DB_CONFIG['port']}, {DB_CONFIG['database']}, {DB_CONFIG['user']}")
        
        conn_pool = pool.SimpleConnectionPool(
            minconn=1,
            maxconn=10,
            **DB_CONFIG
        )
        logger.info("Pool de conexiones creado exitosamente")
        return conn_pool
    except Exception as e:
        logger.error(f"Error creando pool de conexiones: {str(e)}")
        return None

connection_pool = create_connection_pool()

# Funciones de utilidad
def get_db_connection():
    if not connection_pool:
        logger.error("No hay pool de conexiones disponible")
        return None
        
    if 'db_conn' not in g:
        try:
            g.db_conn = connection_pool.getconn()
            logger.info("Conexión obtenida del pool")
            return g.db_conn
        except Exception as e:
            logger.error(f"Error obteniendo conexión: {str(e)}")
            return None
    return g.db_conn

@app.teardown_appcontext
def close_conn(e=None):
    db_conn = g.pop('db_conn', None)
    if db_conn and connection_pool:
        try:
            connection_pool.putconn(db_conn)
            logger.info("Conexión devuelta al pool")
        except Exception as e:
            logger.error(f"Error devolviendo conexión: {str(e)}")

def es_correo_valido(correo):
    return re.match(r"[^@ \t\r\n]+@[^@ \t\r\n]+\.[^@ \t\r\n]+", correo)

def es_contrasena_valida(password):
    pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*\W).{8,}$'
    return re.match(pattern, password)

def send_verification_email(to_email, code):
    body = f"Tu código de verificación es: {code}"
    msg = MIMEText(body, 'plain', 'utf-8')
    msg['Subject'] = Header('Verificación de correo', 'utf-8')
    msg['From'] = EMAIL_CONFIG['user']
    msg['To'] = to_email

    try:
        with smtplib.SMTP(EMAIL_CONFIG['server'], EMAIL_CONFIG['port']) as server:
            server.starttls()
            server.login(EMAIL_CONFIG['user'], EMAIL_CONFIG['password'])
            server.send_message(msg)
        logger.info(f"Correo enviado a {to_email}")
        return True
    except Exception as e:
        logger.error(f"Error enviando correo: {str(e)}")
        return False

def init_db():
    conn = get_db_connection()
    if not conn:
        logger.error("No se pudo obtener conexión para inicializar DB")
        return False
        
    try:
        cur = conn.cursor()
        logger.info("Inicializando esquema de base de datos...")
        
        queries = [
            """
            CREATE TABLE IF NOT EXISTS empresas (
                id SERIAL PRIMARY KEY,
                nombre VARCHAR(100) UNIQUE NOT NULL,
                direccion VARCHAR(200),
                telefono VARCHAR(50),
                correo VARCHAR(100),
                fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(100) UNIQUE NOT NULL,
                password VARCHAR(200) NOT NULL,
                rol VARCHAR(20) NOT NULL DEFAULT 'editor',
                empresa_id INTEGER REFERENCES empresas(id) ON DELETE CASCADE,
                fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
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
            """,
            """
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
            """
        ]
        
        for query in queries:
            cur.execute(query)
        
        conn.commit()
        logger.info("Esquema de base de datos inicializado correctamente")
        return True
    except Exception as e:
        logger.error(f"Error inicializando DB: {str(e)}")
        return False
    finally:
        if cur:
            cur.close()

# Middleware para verificar sesión
@app.before_request
def check_session():
    # Permitir acceso a estas rutas sin sesión
    public_routes = ['login', 'register', 'verify', 'resend_code', 'static', 'index']
    
    if request.endpoint in public_routes:
        return
    
    if 'username' not in session:
        flash('Debe iniciar sesión para acceder a esta página', 'danger')
        return redirect(url_for('login'))
    
    # Verificar rol para rutas de admin
    admin_routes = ['admin_dashboard', 'agregar_usuario', 'eliminar_usuario']
    
    if request.endpoint in admin_routes:
        if session.get('rol') != 'admin':
            flash('Acceso no autorizado', 'danger')
            return redirect(url_for('user_dashboard'))

# Rutas de la aplicación
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Si ya está autenticado, redirigir al dashboard apropiado
    if 'username' in session:
        if session['rol'] == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('user_dashboard'))
    
    error = None
    
    # Manejo de POST (envío de formulario)
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            error = "Usuario y contraseña son requeridos"
        else:
            conn = get_db_connection()
            if not conn:
                error = 'Error de conexión a la base de datos'
            else:
                try:
                    cur = conn.cursor()
                    cur.execute("""
                        SELECT id, username, password, rol, empresa_id 
                        FROM users 
                        WHERE LOWER(username) = LOWER(%s)
                    """, (username,))
                    user = cur.fetchone()
                    
                    if user and check_password_hash(user[2], password):
                        # Configurar sesión
                        session['user_id'] = user[0]
                        session['username'] = user[1]
                        session['rol'] = user[3].lower()
                        session['empresa_id'] = user[4]
                        
                        logger.info(f"Login exitoso: {user[1]}")
                        
                        # Redirigir según rol
                        if session['rol'] == 'admin':
                            return redirect(url_for('admin_dashboard'))
                        return redirect(url_for('user_dashboard'))
                    else:
                        error = 'Usuario o contraseña incorrectos'
                except Exception as e:
                    logger.error(f"Error en login: {str(e)}")
                    error = 'Error interno del servidor'
                finally:
                    if cur:
                        cur.close()
    
    return render_template('login.html', error=error)

@app.route('/register', methods=['GET'])
def register_page():
    if 'username' in session:
        if session['rol'] == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('user_dashboard'))
    return render_template('register.html', error=None)

@app.route('/register', methods=['POST'])
def register_submit():
    if 'username' in session:
        if session['rol'] == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('user_dashboard'))
    
    # Recoger datos
    nombre_emp = request.form.get('nombre_empresa', '').strip()
    username = request.form.get('username', '').strip().lower()
    password = request.form.get('password', '')
    direccion = request.form.get('direccion', '').strip()
    telefono = request.form.get('telefono', '').strip()
    correo_emp = request.form.get('correo_empresa', '').strip().lower()

    # Validaciones
    error = None
    if not nombre_emp or not username or not password:
        error = "Los campos marcados con * son obligatorios."
    elif not es_correo_valido(username):
        error = "Formato de correo inválido."
    elif not es_contrasena_valida(password):
        error = "La contraseña debe tener 8+ caracteres, 1 minúscula, 1 mayúscula, 1 número y 1 símbolo."
    
    if error:
        return render_template('register.html', error=error)
    
    conn = get_db_connection()
    if not conn:
        return render_template('register.html', error="Error de conexión a la base de datos")
    
    try:
        cur = conn.cursor()
        
        # Verificar si la empresa ya existe
        cur.execute("SELECT id FROM empresas WHERE LOWER(nombre) = LOWER(%s)", (nombre_emp,))
        if cur.fetchone():
            error = f"La empresa '{nombre_emp}' ya está registrada."
            return render_template('register.html', error=error)
        
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
            error = "Error enviando correo de verificación. Intente nuevamente."
            return render_template('register.html', error=error)
            
    except Exception as e:
        logger.error(f"Error en registro: {str(e)}")
        error = "Error interno del servidor"
        return render_template('register.html', error=error)
    finally:
        if cur:
            cur.close()

@app.route('/verify/<int:verif_id>', methods=['GET', 'POST'])
def verify(verif_id):
    if 'username' in session:
        if session['rol'] == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('user_dashboard'))
    
    error = None
    resent = request.args.get('resent')
    
    if request.method == 'POST':
        code_input = request.form.get('code', '').strip()
        
        conn = get_db_connection()
        if not conn:
            error = "Error de conexión a la base de datos"
        else:
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
                        
                        flash('¡Registro completado con éxito! Ya puedes iniciar sesión', 'success')
                        return redirect(url_for('login'))
            except Exception as e:
                logger.error(f"Error en verificación: {str(e)}")
                error = "Error interno del servidor"
            finally:
                if cur:
                    cur.close()
    
    return render_template('verify.html', error=error, resent=resent, verif_id=verif_id)

@app.route('/resend/<int:verif_id>')
def resend_code(verif_id):
    conn = get_db_connection()
    if not conn:
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
            return redirect(url_for('verify', verif_id=verif_id, resent=1))
        else:
            return "Error enviando correo", 500
    except Exception as e:
        logger.error(f"Error reenviando código: {str(e)}")
        return "Error interno del servidor", 500
    finally:
        if cur:
            cur.close()

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'username' not in session or session.get('rol') != 'admin':
        flash('Acceso no autorizado', 'danger')
        return redirect(url_for('login'))
    
    # Obtener sección actual
    section = request.args.get('section', 'compania')
    
    # Obtener datos de la empresa
    conn = get_db_connection()
    if not conn:
        flash('Error de conexión a la base de datos', 'danger')
        return render_template('admin.html', section=section)
    
    try:
        cur = conn.cursor()
        
        # Información de la empresa
        cur.execute("""
            SELECT nombre, direccion, telefono, correo 
            FROM empresas 
            WHERE id = %s
        """, (session['empresa_id'],))
        empresa = cur.fetchone()
        
        # Usuarios de la empresa
        cur.execute("""
            SELECT id, username, rol 
            FROM users 
            WHERE empresa_id = %s
            ORDER BY username
        """, (session['empresa_id'],))
        usuarios = cur.fetchall()
        
        # Inventario
        cur.execute("""
            SELECT id, nombre, descripcion, cantidad, precio, ubicacion
            FROM inventario
            WHERE empresa_id = %s
            ORDER BY nombre
        """, (session['empresa_id'],))
        inventario = cur.fetchall()
        
        # Estadísticas
        cur.execute("SELECT COUNT(*) FROM inventario WHERE empresa_id = %s", (session['empresa_id'],))
        total_articulos = cur.fetchone()[0]
        
        cur.execute("SELECT COUNT(*) FROM users WHERE empresa_id = %s", (session['empresa_id'],))
        total_usuarios = cur.fetchone()[0]
        
        # Preparar datos
        empresa_data = {
            'nombre': empresa[0],
            'direccion': empresa[1] or 'No especificada',
            'telefono': empresa[2] or 'No especificado',
            'correo': empresa[3] or 'No especificado',
            'total_articulos': total_articulos,
            'total_usuarios': total_usuarios
        } if empresa else None
        
        return render_template(
            'admin.html',
            section=section,
            empresa=empresa_data,
            usuarios=usuarios,
            inventario=inventario,
            rol=session['rol']
        )
    except Exception as e:
        logger.error(f"Error en admin_dashboard: {str(e)}")
        flash('Error cargando datos', 'danger')
        return render_template('admin.html', section=section)
    finally:
        if cur:
            cur.close()

@app.route('/user/dashboard')
def user_dashboard():
    if 'username' not in session:
        flash('Debe iniciar sesión para acceder a esta página', 'danger')
        return redirect(url_for('login'))
    
    # Obtener sección actual
    section = request.args.get('section', 'compania')
    
    # Obtener datos de la empresa
    conn = get_db_connection()
    if not conn:
        flash('Error de conexión a la base de datos', 'danger')
        return render_template('dashboard.html', section=section)
    
    try:
        cur = conn.cursor()
        
        # Información de la empresa
        cur.execute("""
            SELECT nombre, direccion, telefono, correo 
            FROM empresas 
            WHERE id = %s
        """, (session['empresa_id'],))
        empresa = cur.fetchone()
        
        # Inventario (los usuarios normales no ven otros usuarios)
        cur.execute("""
            SELECT id, nombre, descripcion, cantidad, precio, ubicacion
            FROM inventario
            WHERE empresa_id = %s
            ORDER BY nombre
        """, (session['empresa_id'],))
        inventario = cur.fetchall()
        
        # Estadísticas
        cur.execute("SELECT COUNT(*) FROM inventario WHERE empresa_id = %s", (session['empresa_id'],))
        total_articulos = cur.fetchone()[0]
        
        # Preparar datos
        empresa_data = {
            'nombre': empresa[0],
            'direccion': empresa[1] or 'No especificada',
            'telefono': empresa[2] or 'No especificado',
            'correo': empresa[3] or 'No especificado',
            'total_articulos': total_articulos,
        } if empresa else None
        
        return render_template(
            'dashboard.html',
            section=section,
            empresa=empresa_data,
            inventario=inventario,
            rol=session['rol']
        )
    except Exception as e:
        logger.error(f"Error en user_dashboard: {str(e)}")
        flash('Error cargando datos', 'danger')
        return render_template('dashboard.html', section=section)
    finally:
        if cur:
            cur.close()

@app.route('/logout')
def logout():
    session.clear()
    flash('Sesión cerrada correctamente', 'info')
    return redirect(url_for('index'))

# Inicialización de la aplicación
with app.app_context():
    logger.info("Iniciando aplicación...")
    logger.info(f"Usuario DB: {DB_CONFIG['user']}")
    logger.info(f"DB: {DB_CONFIG['database']}@{DB_CONFIG['host']}:{DB_CONFIG['port']}")
    
    if init_db():
        logger.info("Base de datos inicializada correctamente")
    else:
        logger.error("Error inicializando la base de datos")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
