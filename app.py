from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response
import os
import mysql.connector
from mysql.connector import Error
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from datetime import timedelta
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from io import BytesIO
import uuid


app = Flask(__name__)
app.secret_key = "reporte_urbano_2026"
app.permanent_session_lifetime = timedelta(minutes=30)

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# =========================
# CONFIGURACIÓN MYSQL
# =========================
DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "",
    "database": "reporte_urbano",
    "port": 3306
}

# =========================
# CONEXIÓN MYSQL
# =========================
def obtener_conexion():
    try:
        conexion = mysql.connector.connect(
            host=DB_CONFIG["host"],
            user=DB_CONFIG["user"],
            password=DB_CONFIG["password"],
            database=DB_CONFIG["database"],
            port=DB_CONFIG["port"]
        )
        return conexion
    except Error as e:
        print(f"Error al conectar con MySQL: {e}")
        return None
# =========================
# ARCHIVOS / IMÁGENES
# =========================
def archivo_permitido(nombre_archivo):
    return "." in nombre_archivo and nombre_archivo.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def guardar_imagen(archivo):
    if not archivo or archivo.filename == "":
        return ""

    if not archivo_permitido(archivo.filename):
        return None

    nombre_seguro = secure_filename(archivo.filename)
    extension = nombre_seguro.rsplit(".", 1)[1].lower()
    nombre_unico = f"{os.urandom(8).hex()}.{extension}"
    ruta_guardado = os.path.join(app.config["UPLOAD_FOLDER"], nombre_unico)

    archivo.save(ruta_guardado)

    return f"uploads/{nombre_unico}"    

# =========================
# INICIALIZAR BASE DE DATOS
# =========================
def inicializar_bd():
    conexion = obtener_conexion()
    if conexion is None:
        print("No se pudo conectar a MySQL para inicializar la base de datos.")
        return

    cursor = conexion.cursor(dictionary=True)

    # Tabla de usuarios
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id INT AUTO_INCREMENT PRIMARY KEY,
            nombre VARCHAR(150) NOT NULL,
            usuario VARCHAR(100) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL,
            rol VARCHAR(50) NOT NULL DEFAULT 'admin',
            activo TINYINT(1) NOT NULL DEFAULT 1,
            fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Tabla de reportes
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reportes (
            id INT AUTO_INCREMENT PRIMARY KEY,
            nombre VARCHAR(150) NOT NULL,
            telefono VARCHAR(30) NOT NULL,
            correo VARCHAR(150) NOT NULL,
            tipo VARCHAR(150) NOT NULL,
            descripcion TEXT NOT NULL,
            ubicacion VARCHAR(255) NOT NULL,
            mapa_url TEXT,
            foto_problema VARCHAR(255),
            foto_solucion VARCHAR(255),
            fecha DATE,
            hora TIME,
            prioridad VARCHAR(20) NOT NULL DEFAULT 'Media',
            estado VARCHAR(30) NOT NULL DEFAULT 'Pendiente',
            fecha_finalizacion DATE NULL,
            hora_finalizacion TIME NULL,
            observacion_admin TEXT
        )
    """)

    # Usuario admin inicial
    cursor.execute("SELECT * FROM usuarios WHERE usuario = %s LIMIT 1", ("admin",))
    admin_existente = cursor.fetchone()

    if not admin_existente:
        password_hash = generate_password_hash("12345")
        cursor.execute("""
            INSERT INTO usuarios (nombre, usuario, password, rol, activo)
            VALUES (%s, %s, %s, %s, %s)
        """, (
            "Administrador General",
            "admin",
            password_hash,
            "admin",
            1
        ))
        conexion.commit()

    cursor.close()
    conexion.close()

# =========================
# DECORADOR LOGIN
# =========================
def login_requerido(func):
    @wraps(func)
    def envoltura(*args, **kwargs):
        if not session.get("admin_logueado"):
            flash("Debe iniciar sesión para acceder al panel.", "error")
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return envoltura

# =========================
# FUNCIONES USUARIO
# =========================
def buscar_usuario_por_nombre(usuario):
    conexion = obtener_conexion()
    if conexion is None:
        return None

    cursor = conexion.cursor(dictionary=True)
    cursor.execute("SELECT * FROM usuarios WHERE usuario = %s LIMIT 1", (usuario,))
    resultado = cursor.fetchone()

    cursor.close()
    conexion.close()
    return resultado
def obtener_todos_los_usuarios():
    conexion = obtener_conexion()
    if conexion is None:
        return []

    cursor = conexion.cursor(dictionary=True)
    cursor.execute("""
        SELECT id, nombre, usuario, rol, activo, fecha_creacion
        FROM usuarios
        ORDER BY id DESC
    """)
    usuarios = cursor.fetchall()

    cursor.close()
    conexion.close()
    return usuarios


def crear_usuario_admin(nombre, usuario, password, rol="admin"):
    conexion = obtener_conexion()
    if conexion is None:
        return False, "No se pudo conectar con la base de datos."

    cursor = conexion.cursor(dictionary=True)

    cursor.execute("SELECT id FROM usuarios WHERE usuario = %s LIMIT 1", (usuario,))
    existe = cursor.fetchone()

    if existe:
        cursor.close()
        conexion.close()
        return False, "El nombre de usuario ya existe."

    password_hash = generate_password_hash(password)

    cursor.execute("""
        INSERT INTO usuarios (nombre, usuario, password, rol, activo)
        VALUES (%s, %s, %s, %s, %s)
    """, (
        nombre,
        usuario,
        password_hash,
        rol,
        1
    ))

    conexion.commit()
    cursor.close()
    conexion.close()

    return True, "Usuario creado correctamente."

# =========================
# FUNCIONES DASHBOARD
# =========================
def contar_total_reportes():
    conexion = obtener_conexion()
    if conexion is None:
        return 0

    cursor = conexion.cursor(dictionary=True)
    cursor.execute("SELECT COUNT(*) AS total FROM reportes")
    resultado = cursor.fetchone()
    total = resultado["total"] if resultado else 0

    cursor.close()
    conexion.close()
    return total

def contar_reportes_por_estado(estado):
    conexion = obtener_conexion()
    if conexion is None:
        return 0

    cursor = conexion.cursor(dictionary=True)
    cursor.execute("SELECT COUNT(*) AS total FROM reportes WHERE estado = %s", (estado,))
    resultado = cursor.fetchone()
    total = resultado["total"] if resultado else 0

    cursor.close()
    conexion.close()
    return total

def contar_total_usuarios():
    conexion = obtener_conexion()
    if conexion is None:
        return 0

    cursor = conexion.cursor(dictionary=True)
    cursor.execute("SELECT COUNT(*) AS total FROM usuarios")
    resultado = cursor.fetchone()
    total = resultado["total"] if resultado else 0

    cursor.close()
    conexion.close()
    return total

def obtener_reportes_recientes(limite=8):
    conexion = obtener_conexion()
    if conexion is None:
        return []

    cursor = conexion.cursor(dictionary=True)
    cursor.execute("""
        SELECT id, nombre, tipo, prioridad, estado, fecha
        FROM reportes
        ORDER BY id DESC
        LIMIT %s
    """, (limite,))
    reportes = cursor.fetchall()

    cursor.close()
    conexion.close()
    return reportes
# =========================
# FUNCIONES REPORTES
# =========================
def asignar_prioridad(tipo):
    tipo = tipo.strip().lower()

    if tipo in [
        "accidente",
        "accidentes",
        "acompañamiento fúnebre",
        "acompanamiento fúnebre",
        "acompañamiento funebre",
        "acompanamiento funebre"
    ]:
        return "Alta"

    elif tipo in [
        "quema de basura",
        "baches en lugares de importancia",
        "alumbrado público",
        "alumbrado publico",
        "basura acumulada"
    ]:
        return "Media"

    return "Baja"
def generar_codigo_reporte():
    return "REP-" + uuid.uuid4().hex[:8].upper()


def insertar_reporte(nombre, telefono, correo, tipo, descripcion, ubicacion, mapa_url="", foto_problema=""):
    conexion = obtener_conexion()
    if conexion is None:
        return False, "No se pudo conectar con la base de datos.", None

    cursor = conexion.cursor()

    prioridad = asignar_prioridad(tipo)
    codigo_reporte = generar_codigo_reporte()

    cursor.execute("""
        INSERT INTO reportes (
            nombre, telefono, correo, tipo, descripcion,
            ubicacion, mapa_url, prioridad, estado,
            fecha, hora, foto_problema, codigo_reporte
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, CURDATE(), CURTIME(), %s, %s)
    """, (
        nombre,
        telefono,
        correo,
        tipo,
        descripcion,
        ubicacion,
        mapa_url,
        prioridad,
        "Pendiente",
        foto_problema,
        codigo_reporte
    ))

    conexion.commit()
    reporte_id = cursor.lastrowid

    cursor.close()
    conexion.close()

    return True, "Reporte enviado correctamente.", reporte_id


def obtener_todos_los_reportes():
    conexion = obtener_conexion()
    if conexion is None:
        return []

    cursor = conexion.cursor(dictionary=True)
    cursor.execute("""
        SELECT *
        FROM reportes
        ORDER BY id DESC
    """)
    reportes = cursor.fetchall()

    cursor.close()
    conexion.close()
    return reportes


def obtener_reportes_pendientes():
    conexion = obtener_conexion()
    if conexion is None:
        return []

    cursor = conexion.cursor(dictionary=True)
    cursor.execute("""
        SELECT *
        FROM reportes
        WHERE estado = 'Pendiente'
        ORDER BY id DESC
    """)
    reportes = cursor.fetchall()

    cursor.close()
    conexion.close()
    return reportes


def obtener_reporte_por_id(reporte_id):
    conexion = obtener_conexion()
    if conexion is None:
        return None

    cursor = conexion.cursor(dictionary=True)
    cursor.execute("""
        SELECT *
        FROM reportes
        WHERE id = %s
        LIMIT 1
    """, (reporte_id,))
    reporte = cursor.fetchone()

    cursor.close()
    conexion.close()
    return reporte

# =========================
# RUTAS
# =========================
@app.route("/")
def index():
    if session.get("admin_logueado"):
        return redirect(url_for("admin"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("admin_logueado"):
        return redirect(url_for("admin"))

    if request.method == "POST":
        usuario_ingresado = request.form.get("usuario", "").strip()
        clave_ingresada = request.form.get("clave", "").strip()

        if not usuario_ingresado or not clave_ingresada:
            flash("Debe completar usuario y contraseña.", "error")
            return redirect(url_for("login"))

        usuario = buscar_usuario_por_nombre(usuario_ingresado)

        if not usuario:
            flash("Usuario o contraseña incorrectos.", "error")
            return redirect(url_for("login"))

        if int(usuario["activo"]) != 1:
            flash("La cuenta se encuentra inactiva.", "error")
            return redirect(url_for("login"))

        if not check_password_hash(usuario["password"], clave_ingresada):
            flash("Usuario o contraseña incorrectos.", "error")
            return redirect(url_for("login"))

        session.clear()
        session.permanent = True
        session["admin_logueado"] = True
        session["admin_id"] = usuario["id"]
        session["admin_usuario"] = usuario["usuario"]
        session["admin_nombre"] = usuario["nombre"]
        session["admin_rol"] = usuario["rol"]

        flash("Inicio de sesión correcto.", "success")
        return redirect(url_for("admin"))

    return render_template("login.html")

@app.route("/admin")
@login_requerido
def admin():
    total_reportes = contar_total_reportes()
    total_pendientes = contar_reportes_por_estado("Pendiente")
    total_realizados = contar_reportes_por_estado("Realizado")
    total_usuarios = contar_total_usuarios()
    reportes = obtener_reportes_recientes(8)

    return render_template(
        "admin.html",
        reportes=reportes,
        total_reportes=total_reportes,
        total_pendientes=total_pendientes,
        total_realizados=total_realizados,
        total_usuarios=total_usuarios
    )

@app.route("/logout")
def logout():
    session.clear()
    flash("Sesión cerrada correctamente.", "info")
    return redirect(url_for("login"))

@app.route("/usuarios_admin")
@login_requerido
def usuarios_admin():
    usuarios = obtener_todos_los_usuarios()

    return render_template(
        "usuarios_admin.html",
        usuarios=usuarios
    )


@app.route("/crear_usuario_admin", methods=["GET", "POST"])
@login_requerido
def crear_usuario_admin_route():
    if request.method == "POST":
        nombre = request.form.get("nombre", "").strip()
        usuario = request.form.get("usuario", "").strip()
        password = request.form.get("password", "").strip()
        confirmar_password = request.form.get("confirmar_password", "").strip()
        rol = request.form.get("rol", "admin").strip()

        if not nombre or not usuario or not password or not confirmar_password:
            flash("Todos los campos son obligatorios.", "error")
            return redirect(url_for("crear_usuario_admin_route"))

        if password != confirmar_password:
            flash("Las contraseñas no coinciden.", "error")
            return redirect(url_for("crear_usuario_admin_route"))

        if len(password) < 4:
            flash("La contraseña debe tener al menos 4 caracteres.", "error")
            return redirect(url_for("crear_usuario_admin_route"))

        ok, mensaje = crear_usuario_admin(nombre, usuario, password, rol)

        if ok:
            flash(mensaje, "success")
            return redirect(url_for("usuarios_admin"))
        else:
            flash(mensaje, "error")
            return redirect(url_for("crear_usuario_admin_route"))

    return render_template("crear_usuario.html")

@app.route("/editar_usuario_admin/<int:usuario_id>", methods=["GET", "POST"])
@login_requerido
def editar_usuario_admin(usuario_id):
    usuario_obj = obtener_usuario_por_id(usuario_id)

    if not usuario_obj:
        flash("No se encontró el usuario.", "error")
        return redirect(url_for("usuarios_admin"))

    if request.method == "POST":
        nombre = request.form.get("nombre", "").strip()
        usuario = request.form.get("usuario", "").strip()
        rol = request.form.get("rol", "admin").strip()
        activo = 1 if request.form.get("activo") == "1" else 0

        if not nombre or not usuario:
            flash("Nombre y usuario son obligatorios.", "error")
            return redirect(url_for("editar_usuario_admin", usuario_id=usuario_id))

        if int(usuario_obj["id"]) == int(session.get("admin_id")) and activo == 0:
            flash("No puedes desactivar el usuario con el que tienes la sesión iniciada.", "error")
            return redirect(url_for("editar_usuario_admin", usuario_id=usuario_id))

        ok, mensaje = actualizar_usuario_admin_db(
            usuario_id=usuario_id,
            nombre=nombre,
            usuario=usuario,
            rol=rol,
            activo=activo
        )

        if ok:
            if int(usuario_id) == int(session.get("admin_id")):
                session["admin_usuario"] = usuario
                session["admin_nombre"] = nombre
                session["admin_rol"] = rol

            flash(mensaje, "success")
            return redirect(url_for("usuarios_admin"))
        else:
            flash(mensaje, "error")
            return redirect(url_for("editar_usuario_admin", usuario_id=usuario_id))

    return render_template("editar_usuario.html", usuario=usuario_obj)

@app.route("/cambiar_clave", methods=["GET", "POST"])
@login_requerido
def cambiar_clave():
    usuario_id = session.get("admin_id")
    usuario_actual = obtener_usuario_por_id(usuario_id)

    if not usuario_actual:
        flash("No se encontró el usuario actual.", "error")
        return redirect(url_for("admin"))

    if request.method == "POST":
        clave_actual = request.form.get("clave_actual", "").strip()
        nueva_clave = request.form.get("nueva_clave", "").strip()
        confirmar_nueva = request.form.get("confirmar_nueva", "").strip()

        if not clave_actual or not nueva_clave or not confirmar_nueva:
            flash("Todos los campos son obligatorios.", "error")
            return redirect(url_for("cambiar_clave"))

        usuario_completo = buscar_usuario_por_nombre(session.get("admin_usuario"))

        if not usuario_completo:
            flash("No se pudo verificar el usuario actual.", "error")
            return redirect(url_for("cambiar_clave"))

        if not check_password_hash(usuario_completo["password"], clave_actual):
            flash("La contraseña actual no es correcta.", "error")
            return redirect(url_for("cambiar_clave"))

        if len(nueva_clave) < 6:
            flash("La nueva contraseña debe tener al menos 6 caracteres.", "error")
            return redirect(url_for("cambiar_clave"))

        if nueva_clave != confirmar_nueva:
            flash("La nueva contraseña y su confirmación no coinciden.", "error")
            return redirect(url_for("cambiar_clave"))

        if clave_actual == nueva_clave:
            flash("La nueva contraseña no puede ser igual a la actual.", "error")
            return redirect(url_for("cambiar_clave"))

        ok, mensaje = actualizar_password_usuario(usuario_id, nueva_clave)

        if ok:
            flash(mensaje, "success")
            return redirect(url_for("admin"))
        else:
            flash(mensaje, "error")
            return redirect(url_for("cambiar_clave"))

    return render_template("cambiar_clave.html", usuario=usuario_actual)

@app.route("/eliminar_usuario_admin/<int:usuario_id>", methods=["POST"])
@login_requerido
def eliminar_usuario_admin(usuario_id):
    usuario_obj = obtener_usuario_por_id(usuario_id)

    if not usuario_obj:
        flash("No se encontró el usuario.", "error")
        return redirect(url_for("usuarios_admin"))

    if int(usuario_id) == int(session.get("admin_id")):
        flash("No puedes eliminar el usuario con el que tienes la sesión iniciada.", "error")
        return redirect(url_for("usuarios_admin"))

    ok, mensaje = eliminar_usuario_admin_db(usuario_id)

    if ok:
        flash(mensaje, "success")
    else:
        flash(mensaje, "error")

    return redirect(url_for("usuarios_admin"))

def obtener_usuario_por_id(usuario_id):
    conexion = obtener_conexion()
    if conexion is None:
        return None

    cursor = conexion.cursor(dictionary=True)
    cursor.execute("""
        SELECT id, nombre, usuario, rol, activo, fecha_creacion
        FROM usuarios
        WHERE id = %s
        LIMIT 1
    """, (usuario_id,))
    usuario = cursor.fetchone()

    cursor.close()
    conexion.close()
    return usuario


def actualizar_usuario_admin_db(usuario_id, nombre, usuario, rol, activo):
    conexion = obtener_conexion()
    if conexion is None:
        return False, "No se pudo conectar con la base de datos."

    cursor = conexion.cursor(dictionary=True)

    cursor.execute("""
        SELECT id FROM usuarios
        WHERE usuario = %s AND id <> %s
        LIMIT 1
    """, (usuario, usuario_id))
    existe = cursor.fetchone()

    if existe:
        cursor.close()
        conexion.close()
        return False, "Ya existe otro usuario con ese nombre de acceso."

    cursor = conexion.cursor()
    cursor.execute("""
        UPDATE usuarios
        SET nombre = %s,
            usuario = %s,
            rol = %s,
            activo = %s
        WHERE id = %s
    """, (
        nombre,
        usuario,
        rol,
        activo,
        usuario_id
    ))

    conexion.commit()
    filas = cursor.rowcount

    cursor.close()
    conexion.close()

    if filas > 0:
        return True, "Usuario actualizado correctamente."
    return False, "No se pudo actualizar el usuario."

def actualizar_password_usuario(usuario_id, nueva_password):
    conexion = obtener_conexion()
    if conexion is None:
        return False, "No se pudo conectar con la base de datos."

    password_hash = generate_password_hash(nueva_password)

    cursor = conexion.cursor()
    cursor.execute("""
        UPDATE usuarios
        SET password = %s
        WHERE id = %s
    """, (password_hash, usuario_id))

    conexion.commit()
    filas = cursor.rowcount

    cursor.close()
    conexion.close()

    if filas > 0:
        return True, "Contraseña actualizada correctamente."
    return False, "No se pudo actualizar la contraseña."

def eliminar_usuario_admin_db(usuario_id):
    conexion = obtener_conexion()
    if conexion is None:
        return False, "No se pudo conectar con la base de datos."

    cursor = conexion.cursor()
    cursor.execute("DELETE FROM usuarios WHERE id = %s", (usuario_id,))
    conexion.commit()
    filas = cursor.rowcount

    cursor.close()
    conexion.close()

    if filas > 0:
        return True, "Usuario eliminado correctamente."
    return False, "No se pudo eliminar el usuario."

@app.route("/ciudadano")
def ciudadano():
    tipos = [
        "Accidente",
        "Acompañamiento fúnebre",
        "Quema de basura",
        "Baches en lugares de importancia",
        "Poda de árbol",
        "Alumbrado público",
        "Basura acumulada",
        "Otros problemas comunitarios"
    ]
    return render_template("ciudadano.html", tipos=tipos)


@app.route("/crear_reporte", methods=["POST"])
def crear_reporte():
    nombre = request.form.get("nombre", "").strip()
    telefono = request.form.get("telefono", "").strip()
    correo = request.form.get("correo", "").strip()
    tipo = request.form.get("tipo", "").strip()
    descripcion = request.form.get("descripcion", "").strip()
    ubicacion = request.form.get("ubicacion", "").strip()
    mapa_url = request.form.get("mapa_url", "").strip()
    foto_archivo = request.files.get("foto_problema")

    if not nombre or not telefono or not correo or not tipo or not descripcion or not ubicacion:
        flash("Todos los campos del reporte son obligatorios.", "error")
        return redirect(url_for("ciudadano"))

    ruta_foto = guardar_imagen(foto_archivo)

    if ruta_foto is None:
        flash("La imagen debe estar en formato JPG, JPEG, PNG o WEBP.", "error")
        return redirect(url_for("ciudadano"))

    ok, mensaje, reporte_id = insertar_reporte(
    nombre=nombre,
    telefono=telefono,
    correo=correo,
    tipo=tipo,
    descripcion=descripcion,
    ubicacion=ubicacion,
    mapa_url=mapa_url,
    foto_problema=ruta_foto
)

    if ok:
        return redirect(url_for("confirmacion_reporte", reporte_id=reporte_id))
    else:
        flash(mensaje, "error")
        return redirect(url_for("ciudadano"))
    

@app.route("/confirmacion/<int:reporte_id>")
def confirmacion_reporte(reporte_id):
    reporte = obtener_reporte_por_id(reporte_id)

    if not reporte:
        flash("No se encontró el reporte.", "error")
        return redirect(url_for("ciudadano"))

    return render_template("confirmacion.html", reporte=reporte)


@app.route("/descargar_comprobante/<int:reporte_id>")
def descargar_comprobante(reporte_id):
    reporte = obtener_reporte_por_id(reporte_id)

    if not reporte:
        flash("No se encontró el reporte.", "error")
        return redirect(url_for("ciudadano"))

    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    ancho, alto = A4

    y = alto - 50

    pdf.setTitle(f"Comprobante_Reporte_{reporte['id']}")

    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(50, y, "COMPROBANTE DE REPORTE CIUDADANO")
    y -= 28

    pdf.setFont("Helvetica", 11)
    pdf.drawString(50, y, "Sistema Web de Reporte Urbano")
    y -= 18
    pdf.drawString(50, y, "Constancia de recepción del reporte")
    y -= 30

    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(50, y, "Datos del reporte")
    y -= 24

    pdf.setFont("Helvetica", 11)

    lineas = [
        f"ID del reporte: {reporte['id']}",
        f"Nombre: {reporte['nombre']}",
        f"Teléfono: {reporte['telefono']}",
        f"Correo: {reporte['correo']}",
        f"Tipo de incidencia: {reporte['tipo']}",
        f"Ubicación: {reporte['ubicacion']}",
        f"Prioridad asignada: {reporte['prioridad']}",
        f"Estado actual: {reporte['estado']}",
        f"Fecha de registro: {reporte['fecha']}",
        f"Hora de registro: {reporte['hora']}",
        "Descripción:"
    ]

    for linea in lineas:
        pdf.drawString(50, y, linea)
        y -= 18

    descripcion = str(reporte["descripcion"])
    max_chars = 88

    for i in range(0, len(descripcion), max_chars):
        pdf.drawString(65, y, descripcion[i:i + max_chars])
        y -= 16

    y -= 12
    pdf.setFont("Helvetica-Oblique", 10)
    pdf.drawString(50, y, "Este documento sirve como constancia de recepción del reporte ciudadano.")

    pdf.showPage()
    pdf.save()

    buffer.seek(0)

    response = make_response(buffer.read())
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = f"attachment; filename=comprobante_reporte_{reporte['id']}.pdf"
    return response
   


@app.route("/reportes")
@login_requerido
def reportes():
    reportes = obtener_todos_los_reportes()
    return render_template("reportes.html", reportes=reportes)


@app.route("/reporte/<int:reporte_id>")
@login_requerido
def detalle_reporte(reporte_id):
    reporte = obtener_reporte_por_id(reporte_id)

    if not reporte:
        flash("No se encontró el reporte solicitado.", "error")
        return redirect(url_for("reportes"))

    mensaje_recibido = (
        f"Hola {reporte['nombre']}, le escribimos del Sistema de Reporte Urbano. "
        f"Su reporte {reporte.get('codigo_reporte', reporte['id'])} fue recibido correctamente."
    )

    mensaje_camino = (
        f"Hola {reporte['nombre']}, le escribimos del Sistema de Reporte Urbano. "
        f"Estamos cerca de su domicilio para dar atención al reporte "
        f"{reporte.get('codigo_reporte', reporte['id'])}."
    )

    mensaje_resuelto = (
        f"Hola {reporte['nombre']}, le informamos que su reporte "
        f"{reporte.get('codigo_reporte', reporte['id'])} fue marcado como realizado. "
        f"Gracias por utilizar el sistema."
    )

    whatsapp_recibido = generar_link_whatsapp(reporte.get("telefono", ""), mensaje_recibido)
    whatsapp_camino = generar_link_whatsapp(reporte.get("telefono", ""), mensaje_camino)
    whatsapp_resuelto = generar_link_whatsapp(reporte.get("telefono", ""), mensaje_resuelto)

    return render_template(
        "detalle_reporte.html",
        reporte=reporte,
        whatsapp_recibido=whatsapp_recibido,
        whatsapp_camino=whatsapp_camino,
        whatsapp_resuelto=whatsapp_resuelto
    )


def obtener_reportes_realizados():
    conexion = obtener_conexion()
    if conexion is None:
        return []

    cursor = conexion.cursor(dictionary=True)
    cursor.execute("""
        SELECT *
        FROM reportes
        WHERE estado = 'Realizado'
        ORDER BY id DESC
    """)
    reportes = cursor.fetchall()

    cursor.close()
    conexion.close()
    return reportes

@app.route("/reportes_pendientes")
@login_requerido
def reportes_pendientes():
    reportes = obtener_reportes_pendientes()
    return render_template("reportes_pendientes.html", reportes=reportes)


@app.route("/reportes_realizados")
@login_requerido
def reportes_realizados():
    reportes = obtener_reportes_realizados()
    return render_template("reportes_realizados.html", reportes=reportes)


@app.route("/cambiar_estado/<int:reporte_id>", methods=["POST"])
@login_requerido
def cambiar_estado(reporte_id):
    nuevo_estado = request.form.get("estado", "").strip()

    if nuevo_estado not in ["Pendiente", "Realizado"]:
        flash("Estado no válido.", "error")
        return redirect(url_for("detalle_reporte", reporte_id=reporte_id))

    ok, mensaje = actualizar_estado_reporte(reporte_id, nuevo_estado)

    if ok:
        flash(mensaje, "success")
    else:
        flash(mensaje, "error")

    return redirect(url_for("detalle_reporte", reporte_id=reporte_id))
def guardar_observacion_admin(reporte_id, observacion):
    conexion = obtener_conexion()
    if conexion is None:
        return False, "No se pudo conectar con la base de datos."

    cursor = conexion.cursor()
    cursor.execute("""
        UPDATE reportes
        SET observacion_admin = %s
        WHERE id = %s
    """, (observacion, reporte_id))

    conexion.commit()
    filas_afectadas = cursor.rowcount

    cursor.close()
    conexion.close()

    if filas_afectadas > 0:
        return True, "Observación guardada correctamente."
    return False, "No se encontró el reporte."

def guardar_foto_solucion(reporte_id, ruta_foto):
    conexion = obtener_conexion()
    if conexion is None:
        return False, "No se pudo conectar con la base de datos."

    cursor = conexion.cursor()
    cursor.execute("""
        UPDATE reportes
        SET foto_solucion = %s
        WHERE id = %s
    """, (ruta_foto, reporte_id))

    conexion.commit()
    filas_afectadas = cursor.rowcount

    cursor.close()
    conexion.close()

    if filas_afectadas > 0:
        return True, "Foto de solución guardada correctamente."
    return False, "No se encontró el reporte."

@app.route("/guardar_observacion/<int:reporte_id>", methods=["POST"])
@login_requerido
def guardar_observacion(reporte_id):
    observacion = request.form.get("observacion_admin", "").strip()

    ok, mensaje = guardar_observacion_admin(reporte_id, observacion)

    if ok:
        flash(mensaje, "success")
    else:
        flash(mensaje, "error")

    return redirect(url_for("detalle_reporte", reporte_id=reporte_id))
@app.route("/subir_foto_solucion/<int:reporte_id>", methods=["POST"])
@login_requerido
def subir_foto_solucion(reporte_id):
    foto_archivo = request.files.get("foto_solucion")

    ruta_foto = guardar_imagen(foto_archivo)

    if ruta_foto is None:
        flash("La imagen debe estar en formato JPG, JPEG, PNG o WEBP.", "error")
        return redirect(url_for("detalle_reporte", reporte_id=reporte_id))

    if ruta_foto == "":
        flash("Debe seleccionar una imagen.", "error")
        return redirect(url_for("detalle_reporte", reporte_id=reporte_id))

    ok, mensaje = guardar_foto_solucion(reporte_id, ruta_foto)

    if ok:
        flash(mensaje, "success")
    else:
        flash(mensaje, "error")

    return redirect(url_for("detalle_reporte", reporte_id=reporte_id))
import re
from urllib.parse import quote

def generar_link_whatsapp(telefono, mensaje=""):
    if not telefono:
        return ""

    numero = re.sub(r"\D", "", telefono)

    if not numero:
        return ""

    # Ajuste simple para Paraguay:
    # si escriben 0981..., se convierte a 595981...
    if numero.startswith("0"):
        numero = "595" + numero[1:]

    if mensaje:
        return f"https://wa.me/{numero}?text={quote(mensaje)}"

    return f"https://wa.me/{numero}"

@app.route("/estadisticas")
@login_requerido
def estadisticas():
    resumen = obtener_estadisticas_generales()
    por_tipo = obtener_estadisticas_por_tipo()

    return render_template(
        "estadisticas.html",
        resumen=resumen,
        por_tipo=por_tipo
    )


def obtener_estadisticas_generales():
    conexion = obtener_conexion()
    if conexion is None:
        return {
            "total_reportes": 0,
            "pendientes": 0,
            "realizados": 0,
            "alta": 0,
            "media": 0,
            "baja": 0
        }

    cursor = conexion.cursor(dictionary=True)

    cursor.execute("SELECT COUNT(*) AS total FROM reportes")
    total_reportes = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) AS total FROM reportes WHERE estado = 'Pendiente'")
    pendientes = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) AS total FROM reportes WHERE estado = 'Realizado'")
    realizados = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) AS total FROM reportes WHERE prioridad = 'Alta'")
    alta = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) AS total FROM reportes WHERE prioridad = 'Media'")
    media = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) AS total FROM reportes WHERE prioridad = 'Baja'")
    baja = cursor.fetchone()["total"]

    cursor.close()
    conexion.close()

    return {
        "total_reportes": total_reportes,
        "pendientes": pendientes,
        "realizados": realizados,
        "alta": alta,
        "media": media,
        "baja": baja
    }


def obtener_estadisticas_por_tipo():
    conexion = obtener_conexion()
    if conexion is None:
        return []

    cursor = conexion.cursor(dictionary=True)
    cursor.execute("""
        SELECT tipo, COUNT(*) AS total
        FROM reportes
        GROUP BY tipo
        ORDER BY total DESC, tipo ASC
    """)
    datos = cursor.fetchall()

    cursor.close()
    conexion.close()
    return datos


def actualizar_estado_reporte(reporte_id, nuevo_estado):
    conexion = obtener_conexion()
    if conexion is None:
        return False, "No se pudo conectar con la base de datos."

    cursor = conexion.cursor()

    if nuevo_estado == "Realizado":
        cursor.execute("""
            UPDATE reportes
            SET estado = %s,
                fecha_finalizacion = CURDATE(),
                hora_finalizacion = CURTIME()
            WHERE id = %s
        """, (nuevo_estado, reporte_id))
    else:
        cursor.execute("""
            UPDATE reportes
            SET estado = %s,
                fecha_finalizacion = NULL,
                hora_finalizacion = NULL
            WHERE id = %s
        """, (nuevo_estado, reporte_id))

    conexion.commit()
    filas_afectadas = cursor.rowcount

    cursor.close()
    conexion.close()

    if filas_afectadas > 0:
        return True, "Estado actualizado correctamente."
    return False, "No se encontró el reporte."

def limpiar_datos_prueba():
    conexion = obtener_conexion()
    cursor = conexion.cursor()

    cursor.execute("DELETE FROM reportes")
    cursor.execute("DELETE FROM logs_cambios")

    conexion.commit()
    conexion.close()

# =========================
# INICIO
# =========================
if __name__ == "__main__":
    inicializar_bd()
    app.run(debug=True)