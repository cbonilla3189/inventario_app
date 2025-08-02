from flask import (
    Flask, render_template, request, redirect,
    session, url_for, Response
)
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
from psycopg2 import sql
import re
import csv
import random
import smtplib
from email.mime.text import MIMEText
from email.header import Header
from io import StringIO
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'reemplaza_con_una_clave_super_segura'

@app.context_processor
def inject_role_icons():
    role_icons = {
        'admin':  ('Admin',  'rol-admin'),
        'editor': ('Editor', 'rol-editor'),
        'viewer': ('Viewer','rol-viewer')
    }
    return dict(role_icons=role_icons)

DB_HOST     = "10.120.0.2"
DB_NAME     = "login_db"
DB_USER     = "cbonilla"
DB_PASSWORD = "Cb_2024!xR7mZq"

SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT   = 587
EMAIL_USER  = 'carlosbonillau3189@gmail.com'
EMAIL_PASS  = 'dfcnasnucoehrctj'

def get_db_connection():
    return psycopg2.connect(
        host=DB_HOST, database=DB_NAME,
        user=DB_USER, password=DB_PASSWORD
    )

def es_correo_valido(correo):
    return re.match(r"[^@ \t\r\n]+@[^@ \t\r\n]+\.[^@ \t\r\n]+", correo)

def es_contrasena_valida(password):
    pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*\W).{8,}$'
    return re.match(pattern, password)

def send_verification_email(to_email, code):
    body = f"Tu código de verificación es: {code}"
    msg = MIMEText(body, _subtype='plain', _charset='utf-8')
    msg['Subject'] = Header('Verificación de correo', 'utf-8')
    msg['From']    = EMAIL_USER
    msg['To']      = to_email

    server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
    server.starttls()
    server.login(EMAIL_USER, EMAIL_PASS)
    server.send_message(msg)
    server.quit()

def asegurar_esquema():
    conn = get_db_connection()
    cur  = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS empresas (
            id SERIAL PRIMARY KEY,
            nombre VARCHAR(100) UNIQUE,
            fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    for col, tipo in [
        ('direccion', 'VARCHAR(200)'),
        ('telefono',  'VARCHAR(50)'),
        ('correo',    'VARCHAR(100)')
    ]:
        cur.execute("""
            SELECT 1 FROM information_schema.columns
             WHERE table_name='empresas' AND column_name=%s
        """, (col,))
        if not cur.fetchone():
            cur.execute(f"ALTER TABLE empresas ADD COLUMN {col} {tipo}")

    cur.execute("""
        SELECT 1 FROM information_schema.columns
         WHERE table_name='users' AND column_name='empresa_id'
    """)
    if not cur.fetchone():
        cur.execute("ALTER TABLE users ADD COLUMN empresa_id INTEGER")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS verifications (
            id SERIAL PRIMARY KEY,
            nombre_empresa   VARCHAR(100),
            direccion        VARCHAR(200),
            telefono         VARCHAR(50),
            correo_empresa   VARCHAR(100),
            username         VARCHAR(100),
            password         VARCHAR(200),
            code             CHAR(6),
            created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS inventario (
            id SERIAL PRIMARY KEY,
            empresa_id INTEGER REFERENCES empresas(id) ON DELETE CASCADE,
            nombre VARCHAR(150),
            descripcion TEXT,
            cantidad INTEGER,
            fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    cur.close()
    conn.close()

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
        cur  = conn.cursor()
        cur.execute("SELECT password, rol FROM users WHERE username=%s", (username,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if user and check_password_hash(user[0], password):
            session['username'] = username
            session['rol']      = user[1]
            return redirect('/admin_panel' if user[1]=='admin' else '/dashboard')
        error = "Usuario o contraseña incorrectos"
    return render_template('login.html', error=error)

@app.route('/register', methods=['GET','POST'])
def register():
    error = None
    if request.method == 'POST':
        nombre_emp = request.form['nombre_empresa'].strip()
        direccion  = request.form.get('direccion','').strip()
        telefono   = request.form.get('telefono','').strip()
        correo_emp = request.form.get('correo_empresa','').strip().lower()
        username   = request.form['username'].strip().lower()
        password   = request.form['password']

        if not nombre_emp or not username or not password:
            error = "Los campos marcados con * son obligatorios."
        elif not es_correo_valido(username):
            error = "Correo de usuario inválido."
        elif not es_contrasena_valida(password):
            error = ("La contraseña debe tener 8+ caracteres, "
                     "1 minúsc. 1 mayúsc. 1 dígito y 1 especial.")
        else:
            conn = get_db_connection()
            cur  = conn.cursor()
            cur.execute("SELECT id FROM empresas WHERE LOWER(nombre)=LOWER(%s)", (nombre_emp,))
            if cur.fetchone():
                error = f"La compañía «{nombre_emp}» ya existe."
                cur.close()
                conn.close()
            else:
                code   = ''.join(random.choices('0123456789', k=6))
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

@app.route('/verify/<int:verif_id>', methods=['GET','POST'])
def verify(verif_id):
    error  = None
    resent = request.args.get('resent')
    if request.method == 'POST':
        code_input = request.form['code'].strip()
        conn = get_db_connection()
        cur  = conn.cursor()
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
    cur  = conn.cursor()
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
@login_required
def dashboard():
    # … código previo …

    # 1. Definimos qué nombres permitimos
    allowed = ["Compañía", "Usuarios", "Inventarios"]

    # 2. Filtramos en la propia query (SQLAlchemy)
    menus = (
        Menu.query
            .filter_by(company_id=current_user.company_id)
            .filter(Menu.name.in_(allowed))
            .all()
    )

    # … resto del código …
    return render_template(
        "dashboard.html",
        menus=menus,
        panels=panels,
        current_user=current_user
    )

@app.route('/exportar_inventario')
def exportar_inventario():
    if 'username' not in session or session['rol'] == 'admin':
        return redirect('/')
    conn = get_db_connection()
    cur  = conn.cursor()
    cur.execute("""
        SELECT e.nombre FROM users u
        JOIN empresas e ON u.empresa_id = e.id
        WHERE u.username = %s
    """, (session['username'],))
    nombre_empresa = cur.fetchone()[0]
    tabla_inv      = nombre_empresa.lower().replace(' ', '_')

    cur.execute(sql.SQL("SELECT * FROM {}").format(sql.Identifier(tabla_inv)))
    rows     = cur.fetchall()
    colnames = [d[0] for d in cur.description]
    cur.close()
    conn.close()

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(colnames)
    writer.writerows(rows)
    return output.getvalue(), 200, {
        'Content-Type': 'text/csv',
        'Content-Disposition': f'attachment; filename={tabla_inv}_inventario.csv'
    }

@app.route('/admin_panel', methods=['GET', 'POST'])
def admin_panel():
    if 'username' not in session or session['rol'] != 'admin':
        return redirect('/')

    section   = request.args.get('section', 'users')
    tabla_sel = request.args.get('tabla')

    conn = get_db_connection()
    cur  = conn.cursor()

    if request.method == 'POST':
        accion = request.form.get('accion')

        if accion == 'editar_usuario':
            target_user = request.form['target_user']
            nuevo_rol   = request.form['new_role']
            nueva_empid = request.form.get('empresa_id') or None
            cur.execute("""
                UPDATE users SET rol=%s, empresa_id=%s
                WHERE username=%s
            """, (nuevo_rol, nueva_empid, target_user))
            conn.commit()

        if accion == 'eliminar_usuario':
            user_to_delete = request.form['username']
            if user_to_delete != 'admin':
                cur.execute("DELETE FROM users WHERE username=%s",
                            (user_to_delete,))
                conn.commit()

        if accion == 'eliminar_compania':
            cid = request.form['id']
            cur.execute("SELECT nombre FROM empresas WHERE id=%s", (cid,))
            nombre = cur.fetchone()[0]
            tab_inv = nombre.lower().replace(' ', '_')
            cur.execute("DELETE FROM users WHERE empresa_id=%s", (cid,))
            cur.execute(sql.SQL("DROP TABLE IF EXISTS {}").format(
                sql.Identifier(tab_inv)
            ))
            cur.execute("DELETE FROM empresas WHERE id=%s", (cid,))
            conn.commit()

        if accion == 'crear_tabla':
            new_tab = request.form['nombre_tabla'].strip().lower()
            if new_tab and new_tab not in ['users','empresas','verifications']:
                cur.execute(sql.SQL(
                    "CREATE TABLE IF NOT EXISTS {} ("
                    "id SERIAL PRIMARY KEY,"
                    "nombre VARCHAR(100), cantidad INTEGER)"
                ).format(sql.Identifier(new_tab)))
                conn.commit()

        if accion == 'eliminar_tabla':
            drop_tab = request.form['tabla']
            if drop_tab not in ['users','empresas','verifications']:
                cur.execute(sql.SQL("DROP TABLE IF EXISTS {}").format(
                    sql.Identifier(drop_tab)))
                conn.commit()

        if accion == 'eliminar_campo_tabla':
            tbl = request.form['tabla']
            col = request.form['columna']
            cur.execute(
                sql.SQL("ALTER TABLE {} DROP COLUMN IF EXISTS {}")
                   .format(sql.Identifier(tbl),
                           sql.Identifier(col))
            )
            conn.commit()

        if accion == 'agregar_campo_tabla':
            tbl   = request.form['tabla']
            col   = request.form['nombre_campo'].strip()
            tipo  = request.form['tipo_dato']
            cur.execute(
                sql.SQL("ALTER TABLE {} ADD COLUMN {} {}")
                   .format(sql.Identifier(tbl),
                           sql.Identifier(col),
                           sql.SQL(tipo))
            )
            conn.commit()

    users = lista_empresas = companias = usuarios_por_empresa = []
    inventario = columnas_tabla = []

    if section == 'users':
        cur.execute("""
            SELECT u.username, u.rol, u.empresa_id, e.nombre
              FROM users u
         LEFT JOIN empresas e ON u.empresa_id=e.id
          ORDER BY u.username
        """)
        users = cur.fetchall()
        cur.execute("SELECT id, nombre FROM empresas ORDER BY nombre")
        lista_empresas = cur.fetchall()

    if section == 'companias':
        cur.execute("SELECT * FROM empresas ORDER BY fecha_registro DESC")
        companias = cur.fetchall()
        cur.execute("SELECT username, rol, empresa_id FROM users ORDER BY username")
        usuarios_por_empresa = cur.fetchall()

    if section == 'inventario':
        cur.execute("""
            SELECT table_name
              FROM information_schema.tables
             WHERE table_schema='public'
               AND table_type='BASE TABLE'
        """)
        inventario = [r[0] for r in cur.fetchall()]
        if tabla_sel:
            cur.execute("""
                SELECT column_name, data_type
                  FROM information_schema.columns
                 WHERE table_name=%s
              ORDER BY ordinal_position
            """, (tabla_sel,))
            columnas_tabla = cur.fetchall()

    if section == 'registro':
        cur.execute("SELECT id, nombre FROM empresas ORDER BY nombre")
        lista_empresas = cur.fetchall()

    cur.close()
    conn.close()

    return render_template(
        'admin.html',
        section=section,
        users=users,
        lista_empresas=lista_empresas,
        companias=companias,
        usuarios_por_empresa=usuarios_por_empresa,
        inventario=inventario,
        tabla_seleccionada=tabla_sel,
        columnas_tabla=columnas_tabla
    )

@app.route('/inventario/editar/<int:item_id>', methods=['GET', 'POST'])
def editar_articulo(item_id):
    if 'username' not in session or session['rol'] == 'admin':
        return redirect('/')

    conn = get_db_connection()
    cur  = conn.cursor()

    cur.execute("""
        SELECT e.nombre FROM users u
        JOIN empresas e ON u.empresa_id = e.id
        WHERE u.username = %s
    """, (session['username'],))
    nombre_empresa = cur.fetchone()[0]
    tabla_inv      = nombre_empresa.lower().replace(' ', '_')

    cur.execute("""
        SELECT column_name FROM information_schema.columns
        WHERE table_name = %s ORDER BY ordinal_position
    """, (tabla_inv,))
    columnas = [r[0] for r in cur.fetchall()]

    if request.method == 'POST':
        valores = []
        sets    = []
        for col in columnas:
            if col == 'id':
                continue
            val = request.form.get(col)
            valores.append(val)
            sets.append(sql.SQL("{} = %s").format(sql.Identifier(col)))

        query = sql.SQL("UPDATE {} SET {} WHERE id = %s").format(
            sql.Identifier(tabla_inv),
            sql.SQL(', ').join(sets)
        )
        cur.execute(query, valores + [item_id])
        conn.commit()
        cur.close()
        conn.close()
        return redirect(url_for('dashboard', section='inventario'))

    cur.execute(sql.SQL("SELECT * FROM {} WHERE id = %s").format(
        sql.Identifier(tabla_inv)
    ), (item_id,))
    fila = cur.fetchone()
    cur.close()
    conn.close()

    if not fila:
        return "Artículo no encontrado", 404

    datos = dict(zip(columnas, fila))
    return render_template(
        'editar_articulo.html',
        datos=datos,
        columnas=columnas,
        nombre_empresa=nombre_empresa
    )

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('rol', None)
    return redirect('/')

if __name__ == '__main__':
    asegurar_esquema()
    app.run(debug=True)



