# app.py (con tokens, correo y módulo de inventario funcional)

import secrets
import sqlite3
import os
import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
import re

app = Flask(__name__)
app.secret_key = "clave_secreta_para_sesiones"

# ------------------- CONFIGURACIÓN MAIL -------------------
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'carlosbonillau3189@gmail.com'
app.config['MAIL_PASSWORD'] = 'alas dzko vshu bhkh'  # contraseña de aplicación Gmail
mail = Mail(app)

DB_FILE = "usuarios.db"
RESET_DB = False


# ------------------- INICIALIZACIÓN DB -------------------
def init_db():
    if RESET_DB and os.path.exists(DB_FILE):
        os.remove(DB_FILE)
        print("⚠️ Base de datos eliminada para reinicio limpio.")

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Tabla de usuarios
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nombre TEXT NOT NULL,
        apellido TEXT NOT NULL,
        empresa TEXT,
        correo TEXT UNIQUE NOT NULL,
        ruc TEXT,
        dv TEXT,
        telefono TEXT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        verificado INTEGER DEFAULT 0
    )
    """)

    # Tokens de verificación
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS tokens_verificacion (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token TEXT UNIQUE NOT NULL,
        fecha_expiracion DATETIME NOT NULL,
        FOREIGN KEY (user_id) REFERENCES usuarios (id)
    )
    """)

    # Inventario
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS productos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        nombre TEXT NOT NULL,
        categoria TEXT,
        cantidad INTEGER DEFAULT 0,
        precio REAL DEFAULT 0,
        creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES usuarios (id)
    )
    """)

    # Crear admin si no existe
    cursor.execute("SELECT * FROM usuarios WHERE username = ?", ("carlos",))
    admin = cursor.fetchone()
    if not admin:
        cursor.execute("""
            INSERT INTO usuarios 
            (nombre, apellido, empresa, correo, username, password, verificado)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, ("Admin", "Principal", "MiEmpresa", "admin@example.com", "carlos", generate_password_hash("1234"), 1))
        print("✅ Usuario admin creado: carlos / 1234")

    conn.commit()
    conn.close()


def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


# ------------------- CONTEXTO GLOBAL -------------------
@app.context_processor
def inject_user():
    return {"usuario": session.get("username")}


# ------------------- RUTAS PRINCIPALES -------------------
@app.route("/")
def home():
    if "user_id" in session:
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM usuarios WHERE id = ?", (session["user_id"],)).fetchone()
        conn.close()
        if user and user["username"] == "carlos":
            return redirect(url_for("admin_panel"))
        return redirect(url_for("dashboard"))
    return render_template("index.html")


# ------------------- LOGIN -------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db_connection()
        user = conn.execute("SELECT * FROM usuarios WHERE username = ?", (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            if user["verificado"] == 0:
                return "⚠️ Tu cuenta no está verificada. Revisa tu correo."
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("home"))
        return "❌ Usuario o contraseña incorrectos"
    return render_template("login.html")


# ------------------- REGISTRO -------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        nombre = request.form["nombre"]
        apellido = request.form["apellido"]
        empresa = request.form["empresa"]
        correo = request.form["correo"]
        ruc = request.form["ruc"]
        dv = request.form["dv"]
        telefono = request.form["telefono"]
        username = request.form["username"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        if password != confirm_password:
            return "❌ Las contraseñas no coinciden"

        pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_\-+=]).{8,}$'
        if not re.match(pattern, password):
            return """❌ La contraseña debe cumplir con los siguientes requisitos:
                    <ul>
                        <li>Mínimo 8 caracteres</li>
                        <li>Al menos una letra mayúscula</li>
                        <li>Al menos una letra minúscula</li>
                        <li>Al menos un número</li>
                        <li>Al menos un carácter especial (!@#$%^&*()_-+=)</li>
                    </ul>"""

        password_hash = generate_password_hash(password)
        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO usuarios 
                (nombre, apellido, empresa, correo, ruc, dv, telefono, username, password)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (nombre, apellido, empresa, correo, ruc, dv, telefono, username, password_hash))
            conn.commit()
            user_id = cursor.lastrowid
        except sqlite3.IntegrityError:
            conn.close()
            return "⚠️ Usuario o correo ya registrado"

        token = secrets.token_urlsafe(16)
        expiracion = datetime.datetime.now() + datetime.timedelta(minutes=30)
        cursor.execute("INSERT INTO tokens_verificacion (user_id, token, fecha_expiracion) VALUES (?, ?, ?)",
                       (user_id, token, expiracion))
        conn.commit()
        conn.close()

        try:
            msg = Message("Verifica tu cuenta", sender=app.config['MAIL_USERNAME'], recipients=[correo])
            msg.body = f"""
            Hola {nombre},

            Gracias por registrarte.
            Haz clic en el siguiente enlace para verificar tu cuenta (expira en 30 minutos):

            http://127.0.0.1:5000/verify/{token}
            """
            mail.send(msg)
        except Exception as e:
            print("Error enviando correo:", e)

        return "✅ Registro exitoso. Revisa tu correo para verificar tu cuenta."
    return render_template("register.html")


# ------------------- VERIFICACIÓN -------------------
@app.route("/verify/<token>")
def verify(token):
    conn = get_db_connection()
    token_info = conn.execute("SELECT * FROM tokens_verificacion WHERE token = ?", (token,)).fetchone()

    if not token_info:
        conn.close()
        return "❌ Token inválido o expirado"

    expiracion = datetime.datetime.strptime(token_info["fecha_expiracion"], "%Y-%m-%d %H:%M:%S.%f")
    if datetime.datetime.now() > expiracion:
        conn.execute("DELETE FROM tokens_verificacion WHERE token = ?", (token,))
        conn.commit()
        conn.close()
        return "⚠️ El enlace ha expirado. Regístrate de nuevo o solicita reenvío."

    conn.execute("UPDATE usuarios SET verificado = 1 WHERE id = ?", (token_info["user_id"],))
    conn.execute("DELETE FROM tokens_verificacion WHERE token = ?", (token,))
    conn.commit()
    conn.close()
    return "✅ Cuenta verificada. Ya puedes iniciar sesión."


# ------------------- ADMIN -------------------
@app.route("/admin")
def admin_panel():
    if "user_id" not in session or session.get("username") != "carlos":
        return redirect(url_for("login"))

    conn = get_db_connection()
    empresas = conn.execute("SELECT DISTINCT empresa FROM usuarios WHERE empresa != ''").fetchall()
    usuarios = conn.execute("SELECT id, nombre, apellido, username, correo, empresa, verificado FROM usuarios").fetchall()
    conn.close()
    return render_template("admin.html", empresas=empresas, usuarios=usuarios)

# app.py (con tokens, correo y módulo de inventario funcional)

import secrets
import sqlite3
import os
import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
import re

app = Flask(__name__)
app.secret_key = "clave_secreta_para_sesiones"

# ------------------- CONFIGURACIÓN MAIL -------------------
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'carlosbonillau3189@gmail.com'
app.config['MAIL_PASSWORD'] = 'alas dzko vshu bhkh'  # contraseña de aplicación Gmail
mail = Mail(app)

DB_FILE = "usuarios.db"
RESET_DB = False


# ------------------- INICIALIZACIÓN DB -------------------
def init_db():
    if RESET_DB and os.path.exists(DB_FILE):
        os.remove(DB_FILE)
        print("⚠️ Base de datos eliminada para reinicio limpio.")

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Tabla de usuarios
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nombre TEXT NOT NULL,
        apellido TEXT NOT NULL,
        empresa TEXT,
        correo TEXT UNIQUE NOT NULL,
        ruc TEXT,
        dv TEXT,
        telefono TEXT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        verificado INTEGER DEFAULT 0
    )
    """)

    # Tokens de verificación
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS tokens_verificacion (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token TEXT UNIQUE NOT NULL,
        fecha_expiracion DATETIME NOT NULL,
        FOREIGN KEY (user_id) REFERENCES usuarios (id)
    )
    """)

    # Inventario
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS productos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        nombre TEXT NOT NULL,
        categoria TEXT,
        cantidad INTEGER DEFAULT 0,
        precio REAL DEFAULT 0,
        creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES usuarios (id)
    )
    """)

    # Crear admin si no existe
    cursor.execute("SELECT * FROM usuarios WHERE username = ?", ("carlos",))
    admin = cursor.fetchone()
    if not admin:
        cursor.execute("""
            INSERT INTO usuarios 
            (nombre, apellido, empresa, correo, username, password, verificado)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, ("Admin", "Principal", "MiEmpresa", "admin@example.com", "carlos", generate_password_hash("1234"), 1))
        print("✅ Usuario admin creado: carlos / 1234")

    conn.commit()
    conn.close()


def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


# ------------------- CONTEXTO GLOBAL -------------------
@app.context_processor
def inject_user():
    return {"usuario": session.get("username")}


# ------------------- RUTAS PRINCIPALES -------------------
@app.route("/")
def home():
    if "user_id" in session:
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM usuarios WHERE id = ?", (session["user_id"],)).fetchone()
        conn.close()
        if user and user["username"] == "carlos":
            return redirect(url_for("admin_panel"))
        return redirect(url_for("dashboard"))
    return render_template("index.html")


# ------------------- LOGIN -------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db_connection()
        user = conn.execute("SELECT * FROM usuarios WHERE username = ?", (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            if user["verificado"] == 0:
                return "⚠️ Tu cuenta no está verificada. Revisa tu correo."
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("home"))
        return "❌ Usuario o contraseña incorrectos"
    return render_template("login.html")


# ------------------- REGISTRO -------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        nombre = request.form["nombre"]
        apellido = request.form["apellido"]
        empresa = request.form["empresa"]
        correo = request.form["correo"]
        ruc = request.form["ruc"]
        dv = request.form["dv"]
        telefono = request.form["telefono"]
        username = request.form["username"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        if password != confirm_password:
            return "❌ Las contraseñas no coinciden"

        pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_\-+=]).{8,}$'
        if not re.match(pattern, password):
            return """❌ La contraseña debe cumplir con los siguientes requisitos:
                    <ul>
                        <li>Mínimo 8 caracteres</li>
                        <li>Al menos una letra mayúscula</li>
                        <li>Al menos una letra minúscula</li>
                        <li>Al menos un número</li>
                        <li>Al menos un carácter especial (!@#$%^&*()_-+=)</li>
                    </ul>"""

        password_hash = generate_password_hash(password)
        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO usuarios 
                (nombre, apellido, empresa, correo, ruc, dv, telefono, username, password)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (nombre, apellido, empresa, correo, ruc, dv, telefono, username, password_hash))
            conn.commit()
            user_id = cursor.lastrowid
        except sqlite3.IntegrityError:
            conn.close()
            return "⚠️ Usuario o correo ya registrado"

        token = secrets.token_urlsafe(16)
        expiracion = datetime.datetime.now() + datetime.timedelta(minutes=30)
        cursor.execute("INSERT INTO tokens_verificacion (user_id, token, fecha_expiracion) VALUES (?, ?, ?)",
                       (user_id, token, expiracion))
        conn.commit()
        conn.close()

        try:
            msg = Message("Verifica tu cuenta", sender=app.config['MAIL_USERNAME'], recipients=[correo])
            msg.body = f"""
            Hola {nombre},

            Gracias por registrarte.
            Haz clic en el siguiente enlace para verificar tu cuenta (expira en 30 minutos):

            http://127.0.0.1:5000/verify/{token}
            """
            mail.send(msg)
        except Exception as e:
            print("Error enviando correo:", e)

        return "✅ Registro exitoso. Revisa tu correo para verificar tu cuenta."
    return render_template("register.html")


# ------------------- VERIFICACIÓN -------------------
@app.route("/verify/<token>")
def verify(token):
    conn = get_db_connection()
    token_info = conn.execute("SELECT * FROM tokens_verificacion WHERE token = ?", (token,)).fetchone()

    if not token_info:
        conn.close()
        return "❌ Token inválido o expirado"

    expiracion = datetime.datetime.strptime(token_info["fecha_expiracion"], "%Y-%m-%d %H:%M:%S.%f")
    if datetime.datetime.now() > expiracion:
        conn.execute("DELETE FROM tokens_verificacion WHERE token = ?", (token,))
        conn.commit()
        conn.close()
        return "⚠️ El enlace ha expirado. Regístrate de nuevo o solicita reenvío."

    conn.execute("UPDATE usuarios SET verificado = 1 WHERE id = ?", (token_info["user_id"],))
    conn.execute("DELETE FROM tokens_verificacion WHERE token = ?", (token,))
    conn.commit()
    conn.close()
    return "✅ Cuenta verificada. Ya puedes iniciar sesión."


# ------------------- ADMIN -------------------
@app.route("/admin")
def admin_panel():
    if "user_id" not in session or session.get("username") != "carlos":
        return redirect(url_for("login"))

    conn = get_db_connection()
    empresas = conn.execute("SELECT DISTINCT empresa FROM usuarios WHERE empresa != ''").fetchall()
    usuarios = conn.execute("SELECT id, nombre, apellido, username, correo, empresa, verificado FROM usuarios").fetchall()
    conn.close()
    return render_template("admin.html", empresas=empresas, usuarios=usuarios)

@app.route("/admin/eliminar/<int:id>")
def eliminar_usuario(id):
    if "user_id" not in session or session.get("username") != "carlos":
        return redirect(url_for("login"))

    conn = get_db_connection()
    target = conn.execute("SELECT username FROM usuarios WHERE id = ?", (id,)).fetchone()

    if target and target["username"] == "carlos":
        conn.close()
        return "⚠️ No puedes eliminar al administrador principal."

    conn.execute("DELETE FROM usuarios WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    return redirect(url_for("admin_panel"))

# ------------------- DASHBOARD -------------------
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM productos WHERE user_id=?", (session["user_id"],))
    total_productos = cursor.fetchone()[0]
    cursor.execute("SELECT * FROM productos WHERE user_id=? ORDER BY creado_en DESC LIMIT 5", (session["user_id"],))
    ultimos = cursor.fetchall()
    conn.close()

    return render_template("dashboard.html", usuario=session.get("username"), total_productos=total_productos, ultimos=ultimos)


# ------------------- INVENTARIO -------------------
@app.route("/inventario", methods=["GET", "POST"])
def inventario():
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == "POST":
        nombre = request.form["nombre"]
        categoria = request.form["categoria"]
        cantidad = request.form["cantidad"]
        precio = request.form["precio"]

        if not nombre:
            flash("Debe ingresar un nombre de producto", "danger")
        else:
            cursor.execute("""
                INSERT INTO productos (user_id, nombre, categoria, cantidad, precio)
                VALUES (?, ?, ?, ?, ?)
            """, (session["user_id"], nombre, categoria, cantidad, precio))
            conn.commit()
            flash("✅ Producto agregado correctamente", "success")

    cursor.execute("SELECT * FROM productos WHERE user_id=? ORDER BY creado_en DESC", (session["user_id"],))
    productos = cursor.fetchall()
    conn.close()

    return render_template("inventario.html", productos=productos, usuario=session.get("username"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


# ------------------- MAIN -------------------
if __name__ == "__main__":
    init_db()
    app.run(debug=True)



# ------------------- DASHBOARD -------------------
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM productos WHERE user_id=?", (session["user_id"],))
    total_productos = cursor.fetchone()[0]
    cursor.execute("SELECT * FROM productos WHERE user_id=? ORDER BY creado_en DESC LIMIT 5", (session["user_id"],))
    ultimos = cursor.fetchall()
    conn.close()

    return render_template("dashboard.html", usuario=session.get("username"), total_productos=total_productos, ultimos=ultimos)


# ------------------- INVENTARIO -------------------
@app.route("/inventario", methods=["GET", "POST"])
def inventario():
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == "POST":
        nombre = request.form["nombre"]
        categoria = request.form["categoria"]
        cantidad = request.form["cantidad"]
        precio = request.form["precio"]

        if not nombre:
            flash("Debe ingresar un nombre de producto", "danger")
        else:
            cursor.execute("""
                INSERT INTO productos (user_id, nombre, categoria, cantidad, precio)
                VALUES (?, ?, ?, ?, ?)
            """, (session["user_id"], nombre, categoria, cantidad, precio))
            conn.commit()
            flash("✅ Producto agregado correctamente", "success")

    cursor.execute("SELECT * FROM productos WHERE user_id=? ORDER BY creado_en DESC", (session["user_id"],))
    productos = cursor.fetchall()
    conn.close()

    return render_template("inventario.html", productos=productos, usuario=session.get("username"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


# ------------------- MAIN -------------------
if __name__ == "__main__":
    init_db()
    app.run(debug=True)
