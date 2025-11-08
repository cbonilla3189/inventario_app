# app.py
import os
import secrets
import sqlite3
import datetime
import re
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message

# -----------------------------
# Configuración
# -----------------------------
app = Flask(__name__)
app.secret_key = "clave_secreta_para_sesiones"  # cámbiala en producción

# Mail (usa contraseña de aplicación para Gmail)
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME='carlosbonillau3189@gmail.com',
    MAIL_PASSWORD='alas dzko vshu bhkh'  # reemplaza por tu password app
)
mail = Mail(app)

DB_FILE = "usuarios.db"
RESET_DB = False  # pon True solo si quieres borrar la DB en cada inicio (dev)


# -----------------------------
# Helpers DB
# -----------------------------
def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Crea tablas si no existen y un admin por defecto."""
    if RESET_DB and os.path.exists(DB_FILE):
        os.remove(DB_FILE)
        print("⚠️ Base de datos eliminada (RESET_DB=True)")

    conn = get_db_connection()
    cur = conn.cursor()

    # usuarios
    cur.execute("""
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

    # tokens de verificación persistentes
    cur.execute("""
    CREATE TABLE IF NOT EXISTS tokens_verificacion (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token TEXT UNIQUE NOT NULL,
        fecha_expiracion DATETIME NOT NULL,
        FOREIGN KEY (user_id) REFERENCES usuarios(id)
    )
    """)

    # inventario (productos por usuario)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS productos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        nombre TEXT NOT NULL,
        categoria TEXT,
        cantidad INTEGER DEFAULT 0,
        precio REAL DEFAULT 0,
        creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES usuarios(id)
    )
    """)

    # crear admin 'carlos' si no existe
    cur.execute("SELECT id FROM usuarios WHERE username = ?", ("carlos",))
    if not cur.fetchone():
        cur.execute("""
            INSERT INTO usuarios (nombre, apellido, empresa, correo, username, password, verificado)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, ("Admin", "Principal", "MiEmpresa", "admin@example.com", "carlos", generate_password_hash("1234"), 1))
        print("✅ Usuario admin creado: carlos / 1234")

    conn.commit()
    conn.close()


# -----------------------------
# Context processor (plantillas)
# -----------------------------
@app.context_processor
def inject_user():
    return {"usuario": session.get("username")}


# -----------------------------
# Rutas públicas: home / login / register / verify
# -----------------------------
@app.route("/")
def home():
    if "user_id" in session:
        # redirige según rol/admin
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM usuarios WHERE id = ?", (session["user_id"],)).fetchone()
        conn.close()
        if user and user["username"] == "carlos":
            return redirect(url_for("admin_panel"))
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username_or_email = request.form.get("username")  # nombre de campo puede ser username o correo según tu form
        password = request.form.get("password")

        conn = get_db_connection()
        # intentamos buscar por username primero, si no por correo
        user = conn.execute("SELECT * FROM usuarios WHERE username = ? OR correo = ?", (username_or_email, username_or_email)).fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            if user["verificado"] == 0:
                return render_template("verify.html", mensaje="Tu cuenta no está verificada. Revisa tu correo.")
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            flash("Inicio de sesión correcto", "success")
            return redirect(url_for("home"))
        flash("Usuario o contraseña incorrectos", "danger")
    return render_template("login.html")


def password_valid(password: str) -> tuple[bool, str]:
    """Valida condiciones: longitud, mayúscula, minúscula, número, especial."""
    pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_\-+=]).{8,}$'
    if not re.match(pattern, password):
        msg = (
            "La contraseña debe tener: mínimo 8 caracteres, al menos 1 mayúscula, "
            "1 minúscula, 1 número y 1 carácter especial (!@#$%^&*()_-+=)."
        )
        return False, msg
    return True, ""


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        nombre = request.form.get("nombre", "").strip()
        apellido = request.form.get("apellido", "").strip()
        empresa = request.form.get("empresa", "").strip()
        correo = request.form.get("correo", "").strip().lower()
        ruc = request.form.get("ruc", "").strip()
        dv = request.form.get("dv", "").strip()
        telefono = request.form.get("telefono", "").strip()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # validaciones
        if not nombre or not apellido or not correo or not username or not password:
            flash("Por favor completa los campos obligatorios.", "warning")
            return render_template("register.html")

        if password != confirm_password:
            flash("Las contraseñas no coinciden.", "warning")
            return render_template("register.html")

        ok, msg = password_valid(password)
        if not ok:
            flash(msg, "warning")
            return render_template("register.html")

        password_hash = generate_password_hash(password)

        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute("""
                INSERT INTO usuarios
                (nombre, apellido, empresa, correo, ruc, dv, telefono, username, password)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (nombre, apellido, empresa, correo, ruc, dv, telefono, username, password_hash))
            conn.commit()
            user_id = cur.lastrowid
        except sqlite3.IntegrityError:
            conn.close()
            flash("Usuario o correo ya registrado.", "danger")
            return render_template("register.html")

        # crear token persistente con expiración (30 minutos)
        token = secrets.token_urlsafe(20)
        expiracion = datetime.datetime.now() + datetime.timedelta(minutes=30)
        cur.execute("INSERT INTO tokens_verificacion (user_id, token, fecha_expiracion) VALUES (?, ?, ?)",
                    (user_id, token, expiracion))
        conn.commit()
        conn.close()

        # enviar correo (puede ir a spam)
        try:
            msg = Message("Verifica tu cuenta - Inventario App",
                          sender=app.config['MAIL_USERNAME'],
                          recipients=[correo])
            link = url_for("verify", token=token, _external=True)
            msg.body = f"Hola {nombre},\n\nGracias por registrarte. Verifica tu cuenta con este enlace (expira en 30 minutos):\n\n{link}\n\nSi no pediste este registro, ignora este correo."
            mail.send(msg)
        except Exception as e:
            # en dev puede fallar: mostramos en consola y seguimos
            print("Error enviando correo:", e)
            flash("Registro creado, pero no fue posible enviar el correo (verifica configuración de Mail).", "warning")

        flash("Registro exitoso. Revisa tu correo para verificar la cuenta.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/verify/<token>")
def verify(token):
    conn = get_db_connection()
    cur = conn.cursor()
    token_row = cur.execute("SELECT * FROM tokens_verificacion WHERE token = ?", (token,)).fetchone()
    if not token_row:
        conn.close()
        return render_template("verify.html", mensaje="Token inválido o ya usado.")
    # comprobar expiración
    try:
        expiracion = datetime.datetime.strptime(token_row["fecha_expiracion"], "%Y-%m-%d %H:%M:%S.%f")
    except Exception:
        # sqlite puede guardar como string diferente; intentar parse flexible
        expiracion = datetime.datetime.fromisoformat(token_row["fecha_expiracion"])
    if datetime.datetime.now() > expiracion:
        cur.execute("DELETE FROM tokens_verificacion WHERE token = ?", (token,))
        conn.commit()
        conn.close()
        return render_template("verify.html", mensaje="El enlace ha expirado. Regístrate de nuevo.")
    # marcar verificado y eliminar token
    cur.execute("UPDATE usuarios SET verificado = 1 WHERE id = ?", (token_row["user_id"],))
    cur.execute("DELETE FROM tokens_verificacion WHERE token = ?", (token,))
    conn.commit()
    conn.close()
    return render_template("verify.html", mensaje="Cuenta verificada. Ya puedes iniciar sesión.")


# -----------------------------
# Logout
# -----------------------------
@app.route("/logout")
def logout():
    session.clear()
    flash("Sesión cerrada.", "info")
    return redirect(url_for("home"))


# -----------------------------
# ADMIN: panel, empresas, usuarios, editar, eliminar
# -----------------------------
@app.route("/admin")
def admin_panel():
    if "user_id" not in session or session.get("username") != "carlos":
        flash("Acceso restringido a administradores.", "warning")
        return redirect(url_for("login"))

    conn = get_db_connection()
    empresas = conn.execute("SELECT DISTINCT empresa FROM usuarios WHERE empresa != ''").fetchall()
    usuarios = conn.execute("SELECT id, nombre, apellido, username, correo, empresa, verificado FROM usuarios").fetchall()
    conn.close()
    return render_template("admin.html", empresas=empresas, usuarios=usuarios)


@app.route("/admin/empresas")
def admin_empresas():
    if "user_id" not in session or session.get("username") != "carlos":
        return redirect(url_for("login"))
    conn = get_db_connection()
    empresas = conn.execute("SELECT DISTINCT empresa FROM usuarios WHERE empresa != ''").fetchall()
    conn.close()
    return render_template("admin_empresas.html", empresas=empresas)


@app.route("/admin/usuarios")
def admin_usuarios():
    if "user_id" not in session or session.get("username") != "carlos":
        return redirect(url_for("login"))
    conn = get_db_connection()
    usuarios = conn.execute("SELECT id, nombre, apellido, username, correo, empresa, verificado FROM usuarios").fetchall()
    conn.close()
    return render_template("admin_usuarios.html", usuarios=usuarios)


@app.route("/admin/eliminar/<int:id>", methods=["POST", "GET"])
def eliminar_usuario(id):
    if "user_id" not in session or session.get("username") != "carlos":
        return redirect(url_for("login"))
    conn = get_db_connection()
    target = conn.execute("SELECT username FROM usuarios WHERE id = ?", (id,)).fetchone()
    if target and target["username"] == "carlos":
        conn.close()
        flash("No puedes eliminar al administrador principal.", "warning")
        return redirect(url_for("admin_panel"))
    conn.execute("DELETE FROM usuarios WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    flash("Usuario eliminado.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/editar/<int:id>", methods=["GET", "POST"])
def editar_usuario(id):
    if "user_id" not in session or session.get("username") != "carlos":
        return redirect(url_for("login"))
    conn = get_db_connection()
    cur = conn.cursor()
    user = cur.execute("SELECT * FROM usuarios WHERE id = ?", (id,)).fetchone()
    if not user:
        conn.close()
        flash("Usuario no encontrado.", "danger")
        return redirect(url_for("admin_panel"))
    if request.method == "POST":
        nombre = request.form.get("nombre", user["nombre"])
        apellido = request.form.get("apellido", user["apellido"])
        empresa = request.form.get("empresa", user["empresa"])
        correo = request.form.get("correo", user["correo"])
        telefono = request.form.get("telefono", user["telefono"])
        cur.execute("""
            UPDATE usuarios
            SET nombre = ?, apellido = ?, empresa = ?, correo = ?, telefono = ?
            WHERE id = ?
        """, (nombre, apellido, empresa, correo, telefono, id))
        conn.commit()
        conn.close()
        flash("Usuario actualizado.", "success")
        return redirect(url_for("admin_panel"))
    conn.close()
    return render_template("editar_usuario.html", usuario=user)


# -----------------------------
# DASHBOARD usuario normal
# -----------------------------
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    conn = get_db_connection()
    # datos rápidos para mostrar (cantidad de productos, últimos)
    total = conn.execute("SELECT COUNT(*) as c FROM productos WHERE user_id = ?", (session["user_id"],)).fetchone()["c"]
    ultimos = conn.execute("SELECT * FROM productos WHERE user_id = ? ORDER BY creado_en DESC LIMIT 5", (session["user_id"],)).fetchall()
    conn.close()
    return render_template("dashboard.html", usuario=session.get("username"), total_productos=total, ultimos=ultimos)


# -----------------------------
# Mi empresa y usuarios asociados
# -----------------------------
@app.route("/mi_empresa")
def mi_empresa():
    if "user_id" not in session:
        return redirect(url_for("login"))
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM usuarios WHERE id = ?", (session["user_id"],)).fetchone()
    conn.close()
    return render_template("mi_empresa.html", empresa=user["empresa"], usuario=user)


@app.route("/usuarios_empresa")
def usuarios_empresa():
    if "user_id" not in session:
        return redirect(url_for("login"))
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM usuarios WHERE id = ?", (session["user_id"],)).fetchone()
    usuarios = conn.execute("SELECT * FROM usuarios WHERE empresa = ?", (user["empresa"],)).fetchall()
    conn.close()
    return render_template("usuarios_empresa.html", usuarios=usuarios)


# -----------------------------
# INVENTARIO: CRUD básico
# -----------------------------
@app.route("/inventario", methods=["GET", "POST"])
def inventario():
    if "user_id" not in session:
        return redirect(url_for("login"))
    conn = get_db_connection()
    cur = conn.cursor()
    if request.method == "POST":
        # crear producto
        nombre = request.form.get("nombre", "").strip()
        categoria = request.form.get("categoria", "").strip()
        cantidad = int(request.form.get("cantidad", 0))
        precio = float(request.form.get("precio") or 0)
        if not nombre:
            flash("Debe ingresar un nombre para el producto.", "warning")
        else:
            cur.execute("""
                INSERT INTO productos (user_id, nombre, categoria, cantidad, precio)
                VALUES (?, ?, ?, ?, ?)
            """, (session["user_id"], nombre, categoria, cantidad, precio))
            conn.commit()
            flash("Producto agregado.", "success")
    productos = cur.execute("SELECT * FROM productos WHERE user_id = ? ORDER BY creado_en DESC", (session["user_id"],)).fetchall()
    conn.close()
    return render_template("inventario.html", productos=productos)


@app.route("/inventario/editar/<int:producto_id>", methods=["GET", "POST"])
def inventario_editar(producto_id):
    if "user_id" not in session:
        return redirect(url_for("login"))
    conn = get_db_connection()
    cur = conn.cursor()
    prod = cur.execute("SELECT * FROM productos WHERE id = ? AND user_id = ?", (producto_id, session["user_id"])).fetchone()
    if not prod:
        conn.close()
        flash("Producto no encontrado.", "danger")
        return redirect(url_for("inventario"))
    if request.method == "POST":
        nombre = request.form.get("nombre", prod["nombre"])
        categoria = request.form.get("categoria", prod["categoria"])
        cantidad = int(request.form.get("cantidad", prod["cantidad"]))
        precio = float(request.form.get("precio", prod["precio"]))
        cur.execute("""
            UPDATE productos SET nombre=?, categoria=?, cantidad=?, precio=? WHERE id=? AND user_id=?
        """, (nombre, categoria, cantidad, precio, producto_id, session["user_id"]))
        conn.commit()
        conn.close()
        flash("Producto actualizado.", "success")
        return redirect(url_for("inventario"))
    conn.close()
    return render_template("inventario_editar.html", producto=prod)


@app.route("/inventario/eliminar/<int:producto_id>", methods=["POST", "GET"])
def inventario_eliminar(producto_id):
    if "user_id" not in session:
        return redirect(url_for("login"))
    conn = get_db_connection()
    conn.execute("DELETE FROM productos WHERE id = ? AND user_id = ?", (producto_id, session["user_id"]))
    conn.commit()
    conn.close()
    flash("Producto eliminado.", "success")
    return redirect(url_for("inventario"))


# -----------------------------
# Run
# -----------------------------
if __name__ == "__main__":
    init_db()
    app.run(debug=True)
