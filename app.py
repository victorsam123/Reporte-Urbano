from dotenv import load_dotenv
load_dotenv()

from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response, jsonify
import os
import re
import json
import socket
import secrets
import uuid
import unicodedata
import psycopg2
from psycopg2.extras import RealDictCursor
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from datetime import timedelta
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from io import BytesIO
from urllib.parse import quote, urlencode


app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.permanent_session_lifetime = timedelta(minutes=30)

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("SESSION_COOKIE_SECURE", "0") == "1"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def generar_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


@app.context_processor
def inyectar_csrf_token():
    return {"csrf_token": generar_csrf_token}


@app.before_request
def validar_csrf_token():
    if request.method != "POST":
        return None

    token_form = request.form.get("csrf_token", "")
    token_sesion = session.get("csrf_token", "")

    if not token_form or not token_sesion or not secrets.compare_digest(token_form, token_sesion):
        return "Token CSRF inválido o ausente.", 400

    return None

# =========================
# CONFIGURACIÓN POSTGRESQL
# =========================
DB_CONFIG = {
    "host": os.environ.get("DB_HOST", ""),
    "user": os.environ.get("DB_USER", ""),
    "password": os.environ.get("DB_PASSWORD", ""),
    "database": os.environ.get("DB_NAME", ""),
    "port": int(os.environ.get("DB_PORT", "5432"))
}

# =========================
# CONEXIÓN POSTGRESQL
# =========================
def obtener_conexion():
    try:
        conexion = psycopg2.connect(
            host=DB_CONFIG["host"],
            user=DB_CONFIG["user"],
            password=DB_CONFIG["password"],
            dbname=DB_CONFIG["database"],
            port=DB_CONFIG["port"],
            cursor_factory=RealDictCursor
        )
        print("Conexión correcta con PostgreSQL")
        return conexion
    except Exception as e:
        print(f"Error al conectar con PostgreSQL: {e}")
        return None


# =========================
# ARCHIVOS / IMÁGENES
# =========================
def validar_email(email):
    """Validación básica de email"""
    patron = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(patron, email) is not None


def validar_telefono(telefono):
    """Validación básica de teléfono (solo números y símbolos de teléfono)"""
    patron = r"^[\d\s\+\-\(\)]{7,30}$"
    return re.match(patron, telefono) is not None


def normalizar_texto(texto):
    texto = unicodedata.normalize("NFKD", texto or "")
    texto = "".join(caracter for caracter in texto if not unicodedata.combining(caracter))
    texto = re.sub(r"\s+", " ", texto).strip().lower()
    return texto


# Replica la normalizacion de acentos y espacios dentro de filtros SQL.
SQL_TRANSLITERACION_ORIGEN = (
    "\u00e1\u00e9\u00ed\u00f3\u00fa\u00c1\u00c9\u00cd\u00d3\u00da"
    "\u00e4\u00eb\u00ef\u00f6\u00fc\u00c4\u00cb\u00cf\u00d6\u00dc"
    "\u00e0\u00e8\u00ec\u00f2\u00f9\u00c0\u00c8\u00cc\u00d2\u00d9"
    "\u00e2\u00ea\u00ee\u00f4\u00fb\u00c2\u00ca\u00ce\u00d4\u00db"
    "\u00e3\u00f5\u00c3\u00d5\u00f1\u00d1"
)
SQL_TRANSLITERACION_DESTINO = (
    "aeiouAEIOU"
    "aeiouAEIOU"
    "aeiouAEIOU"
    "aeiouAEIOU"
    "aoAOnN"
)


def sql_normalizar_texto(campo_sql):
    return (
        "trim(regexp_replace("
        f"lower(translate({campo_sql}, '{SQL_TRANSLITERACION_ORIGEN}', '{SQL_TRANSLITERACION_DESTINO}')),"
        " '\\s+', ' ', 'g'))"
    )


CATALOGO_TIPOS_POR_PRIORIDAD = [
    {
        "label": "Crítica (riesgo inmediato)",
        "opciones": [
            "Accidentes de tránsito",
            "Cableado eléctrico caído",
            "Incendios / humo",
            "Fugas de gas",
            "Derrumbes",
            "Inundaciones graves"
        ]
    },
    {
        "label": "Alta (impacto fuerte)",
        "opciones": [
            "Alumbrado público apagado",
            "Basura acumulada en gran cantidad",
            "Baches peligrosos",
            "Semáforos dañados",
            "Animales muertos en vía pública"
        ]
    },
    {
        "label": "Media",
        "opciones": [
            "Poda de árboles",
            "Limpieza de terrenos baldíos",
            "Ruido excesivo",
            "Problemas de señalización",
            "Calles en mal estado (no crítico)"
        ]
    },
    {
        "label": "Baja",
        "opciones": [
            "Sugerencias",
            "Reclamos administrativos",
            "Mejoras estéticas",
            "Consultas"
        ]
    }
]

TIPOS_OFICIALES = {
    normalizar_texto(tipo): tipo
    for grupo in CATALOGO_TIPOS_POR_PRIORIDAD
    for tipo in grupo["opciones"]
}

TIPOS_EQUIVALENTES = {
    "accidente": "Accidentes de tránsito",
    "accidentes": "Accidentes de tránsito",
    "accidente de transito": "Accidentes de tránsito",
    "basura acumulada": "Basura acumulada en gran cantidad",
    "poda de arbol": "Poda de árboles",
    "alumbrado publico": "Alumbrado público apagado",
    "quema de basura": "Incendios / humo",
    "acompanamiento funebre": "Reclamos administrativos",
    "otros problemas comunitarios": "Consultas"
}

ESTADOS_VALIDOS = [
    "Pendiente",
    "En revisión",
    "Asignado",
    "En proceso",
    "Realizado",
    "Rechazado / No corresponde"
]
ESTADOS_FINALES = {"Realizado", "Rechazado / No corresponde"}


def normalizar_tipo_incidencia(tipo):
    tipo_limpio = re.sub(r"\s+", " ", (tipo or "")).strip()
    tipo_normalizado = normalizar_texto(tipo_limpio)

    if tipo_normalizado in TIPOS_OFICIALES:
        return TIPOS_OFICIALES[tipo_normalizado]

    if tipo_normalizado in TIPOS_EQUIVALENTES:
        return TIPOS_EQUIVALENTES[tipo_normalizado]

    return tipo_limpio


def archivo_permitido(nombre_archivo):
    return "." in nombre_archivo and nombre_archivo.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def guardar_imagen(archivo):
    if not archivo or archivo.filename == "":
        return ""

    if not archivo_permitido(archivo.filename):
        return None

    try:
        nombre_seguro = secure_filename(archivo.filename)
        extension = nombre_seguro.rsplit(".", 1)[1].lower()
        nombre_unico = f"{os.urandom(8).hex()}.{extension}"
        ruta_guardado = os.path.join(app.config["UPLOAD_FOLDER"], nombre_unico)

        archivo.save(ruta_guardado)

        return f"uploads/{nombre_unico}"
    except Exception as e:
        print(f"Error al guardar imagen: {e}")
        return None


# =========================
# INICIALIZAR BASE DE DATOS
# =========================
def inicializar_bd():
    conexion = obtener_conexion()
    if conexion is None:
        print("No se pudo conectar a PostgreSQL para inicializar la base de datos.")
        return

    cursor = conexion.cursor()

    # Tabla de usuarios
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS usuarios (
        id SERIAL PRIMARY KEY,
        nombre VARCHAR(150) NOT NULL,
        usuario VARCHAR(100) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        rol VARCHAR(50) NOT NULL DEFAULT 'admin',
        activo BOOLEAN NOT NULL DEFAULT TRUE,
        fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Tabla de reportes
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS reportes (
        id SERIAL PRIMARY KEY,
        codigo_reporte VARCHAR(20) UNIQUE,
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
        fecha_finalizacion DATE,
        hora_finalizacion TIME,
        observacion_admin TEXT
    )
    """)

    # Tabla de logs de cambios
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS logs_cambios (
        id SERIAL PRIMARY KEY,
        reporte_id INTEGER,
        usuario_id INTEGER,
        accion VARCHAR(100),
        fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Migración: agregar columnas que pueden faltar en tablas ya existentes
    migraciones = [
        "ALTER TABLE reportes ADD COLUMN IF NOT EXISTS codigo_reporte VARCHAR(20) UNIQUE",
        "ALTER TABLE reportes ADD COLUMN IF NOT EXISTS foto_solucion VARCHAR(255)",
        "ALTER TABLE reportes ADD COLUMN IF NOT EXISTS fecha_finalizacion DATE",
        "ALTER TABLE reportes ADD COLUMN IF NOT EXISTS hora_finalizacion TIME",
        "ALTER TABLE reportes ADD COLUMN IF NOT EXISTS observacion_admin TEXT",
        "ALTER TABLE reportes ADD COLUMN IF NOT EXISTS mapa_url TEXT",
    ]
    for sql_migracion in migraciones:
        try:
            cursor.execute(sql_migracion)
        except Exception as e_mig:
            print(f"Migración omitida: {e_mig}")
    conexion.commit()

    # Usuario admin inicial
    cursor.execute("SELECT * FROM usuarios WHERE usuario = %s LIMIT 1", ("admin",))
    admin_existente = cursor.fetchone()

    if not admin_existente:
        password_inicial_admin = os.environ.get("ADMIN_PASSWORD", "Admin@2026!")
        password_hash = generate_password_hash(password_inicial_admin)
        cursor.execute("""
            INSERT INTO usuarios (nombre, usuario, password, rol, activo)
            VALUES (%s, %s, %s, %s, %s)
        """, (
            "Administrador General",
            "admin",
            password_hash,
            "admin",
            True
        ))
        conexion.commit()

    cursor.execute("SELECT id, tipo, prioridad FROM reportes")
    reportes_existentes = cursor.fetchall()

    for reporte in reportes_existentes:
        tipo_alineado = normalizar_tipo_incidencia(reporte["tipo"])
        prioridad_alineada = asignar_prioridad(tipo_alineado)

        if tipo_alineado != reporte["tipo"] or prioridad_alineada != reporte["prioridad"]:
            cursor.execute("""
                UPDATE reportes
                SET tipo = %s,
                    prioridad = %s
                WHERE id = %s
            """, (
                tipo_alineado,
                prioridad_alineada,
                reporte["id"]
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

    cursor = conexion.cursor()
    cursor.execute("SELECT * FROM usuarios WHERE usuario = %s LIMIT 1", (usuario,))
    resultado = cursor.fetchone()

    cursor.close()
    conexion.close()
    return resultado


def obtener_todos_los_usuarios():
    conexion = obtener_conexion()
    if conexion is None:
        return []

    cursor = conexion.cursor()
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

    # Validación básica
    if len(password) < 6:
        return False, "La contraseña debe tener al menos 6 caracteres."
    
    if rol not in ["admin", "operador", "editor"]:
        return False, "Rol no válido."

    cursor = conexion.cursor()

    try:
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
            True
        ))

        conexion.commit()
        cursor.close()
        conexion.close()

        return True, "Usuario creado correctamente."
    except Exception as e:
        cursor.close()
        conexion.close()
        print(f"Error al crear usuario: {e}")
        return False, "Error al crear el usuario."


def obtener_usuario_por_id(usuario_id):
    conexion = obtener_conexion()
    if conexion is None:
        return None

    cursor = conexion.cursor()
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

    if rol not in ["admin", "operador", "editor"]:
        return False, "Rol no válido."

    cursor = conexion.cursor()

    try:
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
    except Exception as e:
        cursor.close()
        conexion.close()
        print(f"Error al actualizar usuario: {e}")
        return False, "Error al actualizar el usuario."


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


# =========================
# FUNCIONES DASHBOARD
# =========================
def contar_total_reportes():
    conexion = obtener_conexion()
    if conexion is None:
        return 0

    cursor = conexion.cursor()
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

    cursor = conexion.cursor()
    cursor.execute("SELECT COUNT(*) AS total FROM reportes WHERE estado = %s", (estado,))
    resultado = cursor.fetchone()
    total = resultado["total"] if resultado else 0

    cursor.close()
    conexion.close()
    return total


def contar_reportes_activos():
    conexion = obtener_conexion()
    if conexion is None:
        return 0

    cursor = conexion.cursor()
    cursor.execute("""
        SELECT COUNT(*) AS total FROM reportes
        WHERE estado NOT IN ('Realizado', 'Rechazado / No corresponde')
    """)
    resultado = cursor.fetchone()
    total = resultado["total"] if resultado else 0

    cursor.close()
    conexion.close()
    return total


def obtener_kpis_admin():
    conexion = obtener_conexion()
    if conexion is None:
        return {"pct_resolucion": 0, "criticos_activos": 0, "con_ubicacion": 0, "con_foto": 0}

    cursor = conexion.cursor()

    cursor.execute("SELECT COUNT(*) AS total FROM reportes")
    total = cursor.fetchone()["total"] or 0

    cursor.execute("SELECT COUNT(*) AS total FROM reportes WHERE estado = 'Realizado'")
    realizados = cursor.fetchone()["total"] or 0

    cursor.execute("""
        SELECT COUNT(*) AS total FROM reportes
        WHERE prioridad = 'Critica'
        AND estado NOT IN ('Realizado', 'Rechazado / No corresponde')
    """)
    criticos_activos = cursor.fetchone()["total"] or 0

    cursor.execute("""
        SELECT COUNT(*) AS total FROM reportes
        WHERE mapa_url IS NOT NULL AND mapa_url != ''
    """)
    con_ubicacion = cursor.fetchone()["total"] or 0

    cursor.execute("""
        SELECT COUNT(*) AS total FROM reportes
        WHERE foto_problema IS NOT NULL AND foto_problema != ''
    """)
    con_foto = cursor.fetchone()["total"] or 0

    cursor.close()
    conexion.close()

    pct_resolucion = round((realizados / total * 100), 1) if total > 0 else 0

    return {
        "pct_resolucion": pct_resolucion,
        "criticos_activos": criticos_activos,
        "con_ubicacion": con_ubicacion,
        "con_foto": con_foto
    }


def contar_total_usuarios():
    conexion = obtener_conexion()
    if conexion is None:
        return 0

    cursor = conexion.cursor()
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

    cursor = conexion.cursor()
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
    tipo_normalizado = normalizar_texto(tipo)

    if tipo_normalizado in {
        "accidentes de transito",
        "cableado electrico caido",
        "incendios / humo",
        "fugas de gas",
        "derrumbes",
        "inundaciones graves"
    }:
        return "Critica"

    elif tipo_normalizado in {
        "alumbrado publico apagado",
        "basura acumulada en gran cantidad",
        "baches peligrosos",
        "semaforos danados",
        "animales muertos en via publica"
    }:
        return "Alta"

    elif tipo_normalizado in {
        "poda de arboles",
        "limpieza de terrenos baldios",
        "ruido excesivo",
        "problemas de senalizacion",
        "calles en mal estado (no critico)"
    }:
        return "Media"

    return "Baja"


def generar_codigo_reporte():
    return "REP-" + uuid.uuid4().hex[:8].upper()


def insertar_reporte(nombre, telefono, correo, tipo, descripcion, ubicacion, mapa_url="", foto_problema=""):
    conexion = obtener_conexion()
    if conexion is None:
        return False, "No se pudo conectar con la base de datos.", None

    # Validación de datos (email es opcional)
    if correo and not validar_email(correo):
        return False, "El correo electrónico no es válido.", None
    
    if not validar_telefono(telefono):
        return False, "El teléfono no es válido.", None
    
    if len(descripcion) > 2000:
        return False, "La descripción es demasiado larga (máximo 2000 caracteres).", None

    cursor = conexion.cursor()

    try:
        tipo = normalizar_tipo_incidencia(tipo)
        prioridad = asignar_prioridad(tipo)
        codigo_reporte = generar_codigo_reporte()

        cursor.execute("""
            INSERT INTO reportes (
                nombre, telefono, correo, tipo, descripcion,
                ubicacion, mapa_url, prioridad, estado,
                fecha, hora, foto_problema, codigo_reporte
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_DATE, CURRENT_TIME, %s, %s)
            RETURNING id
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

        fila = cursor.fetchone()
        reporte_id = fila["id"] if fila else None

        conexion.commit()
        cursor.close()
        conexion.close()

        return True, "Reporte enviado correctamente.", reporte_id
    except Exception as e:
        cursor.close()
        conexion.close()
        print(f"Error al insertar reporte: {e}")
        return False, "Error al procesar el reporte.", None


def obtener_todos_los_reportes():
    conexion = obtener_conexion()
    if conexion is None:
        return []

    cursor = conexion.cursor()
    cursor.execute("""
        SELECT *
        FROM reportes
        ORDER BY id DESC
    """)
    reportes = cursor.fetchall()

    cursor.close()
    conexion.close()
    return reportes


def obtener_reportes_filtrados(
    codigo=None,
    estado=None,
    prioridad=None,
    tipo=None,
    fecha=None,
    busqueda=None,
    ordenar_por="id",
    direccion="desc",
    pagina=1,
    por_pagina=20,
    aplicar_paginacion=True
):
    conexion = obtener_conexion()
    if conexion is None:
        return [], 0

    columnas_orden = {
        "id": "id",
        "nombre": "nombre",
        "tipo": "tipo",
        "prioridad": "prioridad",
        "estado": "estado",
        "fecha": "fecha",
    }
    columna_sql = columnas_orden.get(ordenar_por, "id")
    direccion_sql = "ASC" if str(direccion).lower() == "asc" else "DESC"

    condiciones = []
    params = []

    if codigo:
        condiciones.append("codigo_reporte ILIKE %s")
        params.append(f"%{codigo}%")

    if estado:
        condiciones.append("estado = %s")
        params.append(estado)

    if prioridad:
        condiciones.append("prioridad = %s")
        params.append(prioridad)

    if tipo:
        tipo_busqueda = normalizar_texto(normalizar_tipo_incidencia(tipo))
        if tipo_busqueda:
            condiciones.append(f"{sql_normalizar_texto('tipo')} ILIKE %s")
            params.append(f"%{tipo_busqueda}%")

    if fecha:
        condiciones.append("fecha::date = %s")
        params.append(fecha)

    if busqueda:
        condiciones_busqueda = ["nombre ILIKE %s"]
        params_busqueda = [f"%{busqueda}%"]
        telefono_busqueda = re.sub(r"\D", "", busqueda)

        if telefono_busqueda:
            condiciones_busqueda.append("regexp_replace(telefono, '\\D', '', 'g') LIKE %s")
            params_busqueda.append(f"%{telefono_busqueda}%")

        condiciones.append("(" + " OR ".join(condiciones_busqueda) + ")")
        params.extend(params_busqueda)

    where = ("WHERE " + " AND ".join(condiciones)) if condiciones else ""

    print(f"[FILTROS] WHERE={where!r} params={params}")

    try:
        cursor = conexion.cursor()
        cursor.execute(f"SELECT COUNT(*) AS total FROM reportes {where}", params)
        total = cursor.fetchone()["total"] or 0

        query = f"SELECT * FROM reportes {where} ORDER BY {columna_sql} {direccion_sql}, id DESC"
        query_params = list(params)

        if aplicar_paginacion:
            pagina = max(1, int(pagina))
            por_pagina = max(1, int(por_pagina))
            offset = (pagina - 1) * por_pagina
            query += " LIMIT %s OFFSET %s"
            query_params.extend([por_pagina, offset])

        cursor.execute(query, query_params)
        reportes = cursor.fetchall()

        cursor.close()
        conexion.close()
        return reportes, total

    except Exception as e:
        print(f"[FILTROS ERROR] {e}")
        try:
            conexion.rollback()
            cursor.close()
            conexion.close()
        except Exception:
            pass
        return [], 0


def obtener_reportes_pendientes():
    conexion = obtener_conexion()
    if conexion is None:
        return []

    cursor = conexion.cursor()
    cursor.execute("""
        SELECT *
        FROM reportes
        WHERE estado NOT IN ('Realizado', 'Rechazado / No corresponde')
        ORDER BY id DESC
    """)
    reportes = cursor.fetchall()

    cursor.close()
    conexion.close()
    return reportes


def obtener_reportes_realizados():
    conexion = obtener_conexion()
    if conexion is None:
        return []

    cursor = conexion.cursor()
    cursor.execute("""
        SELECT *
        FROM reportes
        WHERE estado IN ('Realizado', 'Rechazado / No corresponde')
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

    cursor = conexion.cursor()
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


def actualizar_estado_reporte(reporte_id, nuevo_estado):
    conexion = obtener_conexion()
    if conexion is None:
        return False, "No se pudo conectar con la base de datos."

    if nuevo_estado not in ESTADOS_VALIDOS:
        return False, "Estado no válido."

    cursor = conexion.cursor()

    try:
        if nuevo_estado in ESTADOS_FINALES:
            cursor.execute("""
                UPDATE reportes
                SET estado = %s,
                   fecha_finalizacion = CURRENT_DATE,
                   hora_finalizacion = CURRENT_TIME
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
    except Exception as e:
        cursor.close()
        conexion.close()
        print(f"Error al actualizar estado: {e}")
        return False, "Error al actualizar el estado."


def guardar_observacion_admin(reporte_id, observacion):
    conexion = obtener_conexion()
    if conexion is None:
        return False, "No se pudo conectar con la base de datos."

    if len(observacion) > 2000:
        return False, "La observación es demasiado larga (máximo 2000 caracteres)."

    cursor = conexion.cursor()

    try:
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
    except Exception as e:
        cursor.close()
        conexion.close()
        print(f"Error al guardar observación: {e}")
        return False, "Error al guardar la observación."


def guardar_foto_solucion(reporte_id, ruta_foto):
    conexion = obtener_conexion()
    if conexion is None:
        return False, "No se pudo conectar con la base de datos."

    cursor = conexion.cursor()

    try:
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
    except Exception as e:
        cursor.close()
        conexion.close()
        print(f"Error al guardar foto: {e}")
        return False, "Error al guardar la foto."


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


def obtener_estadisticas_generales():
    conexion = obtener_conexion()
    if conexion is None:
        return {
            "total_reportes": 0,
            "pendientes": 0,
            "en_revision": 0,
            "asignado": 0,
            "en_proceso": 0,
            "activos": 0,
            "realizados": 0,
            "rechazado": 0,
            "critica": 0,
            "alta": 0,
            "media": 0,
            "baja": 0,
            "con_ubicacion": 0,
            "con_foto": 0
        }

    cursor = conexion.cursor()

    cursor.execute("SELECT COUNT(*) AS total FROM reportes")
    total_reportes = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) AS total FROM reportes WHERE estado = 'Pendiente'")
    pendientes = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) AS total FROM reportes WHERE estado = 'En revisi\u00f3n'")
    en_revision = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) AS total FROM reportes WHERE estado = 'Asignado'")
    asignado = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) AS total FROM reportes WHERE estado = 'En proceso'")
    en_proceso = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) AS total FROM reportes WHERE estado = 'Realizado'")
    realizados = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) AS total FROM reportes WHERE estado = 'Rechazado / No corresponde'")
    rechazado = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) AS total FROM reportes WHERE prioridad = 'Critica'")
    critica = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) AS total FROM reportes WHERE prioridad = 'Alta'")
    alta = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) AS total FROM reportes WHERE prioridad = 'Media'")
    media = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) AS total FROM reportes WHERE prioridad = 'Baja'")
    baja = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) AS total FROM reportes WHERE mapa_url IS NOT NULL AND mapa_url != ''")
    con_ubicacion = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) AS total FROM reportes WHERE foto_problema IS NOT NULL AND foto_problema != ''")
    con_foto = cursor.fetchone()["total"]

    cursor.close()
    conexion.close()

    activos = pendientes + en_revision + asignado + en_proceso

    return {
        "total_reportes": total_reportes,
        "pendientes": pendientes,
        "en_revision": en_revision,
        "asignado": asignado,
        "en_proceso": en_proceso,
        "activos": activos,
        "realizados": realizados,
        "rechazado": rechazado,
        "critica": critica,
        "alta": alta,
        "media": media,
        "baja": baja,
        "con_ubicacion": con_ubicacion,
        "con_foto": con_foto
    }


def obtener_estadisticas_por_tipo():
    conexion = obtener_conexion()
    if conexion is None:
        return []

    cursor = conexion.cursor()
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


def obtener_puerto_local():
    puerto_env = os.environ.get("PORT")
    if puerto_env:
        return int(puerto_env)

    for puerto in (5000, 5001):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(("127.0.0.1", puerto))
                return puerto
            except OSError:
                continue

    return 5001


# =========================
# RUTAS
# =========================
@app.route("/")
def index():
    return redirect(url_for("ciudadano"))


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

        if not usuario["activo"]:
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
    total_pendientes = contar_reportes_activos()
    total_realizados = contar_reportes_por_estado("Realizado")
    total_usuarios = contar_total_usuarios()
    reportes = obtener_reportes_recientes(8)
    kpis = obtener_kpis_admin()

    return render_template(
        "admin.html",
        reportes=reportes,
        total_reportes=total_reportes,
        total_pendientes=total_pendientes,
        total_realizados=total_realizados,
        total_usuarios=total_usuarios,
        kpis=kpis
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

        if len(password) < 6:
            flash("La contraseña debe tener al menos 6 caracteres.", "error")
            return redirect(url_for("crear_usuario_admin_route"))
        
        if rol not in ["admin", "operador", "editor"]:
            flash("Rol no válido.", "error")
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
    if usuario_id <= 0:
        flash("ID de usuario inválido.", "error")
        return redirect(url_for("usuarios_admin"))

    usuario_obj = obtener_usuario_por_id(usuario_id)

    if not usuario_obj:
        flash("No se encontró el usuario.", "error")
        return redirect(url_for("usuarios_admin"))

    if request.method == "POST":
        nombre = request.form.get("nombre", "").strip()
        usuario = request.form.get("usuario", "").strip()
        rol = request.form.get("rol", "admin").strip()
        activo = True if request.form.get("activo") == "1" else False

        if not nombre or not usuario:
            flash("Nombre y usuario son obligatorios.", "error")
            return redirect(url_for("editar_usuario_admin", usuario_id=usuario_id))

        if int(usuario_obj["id"]) == int(session.get("admin_id")) and not activo:
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
    if usuario_id <= 0:
        flash("ID de usuario inválido.", "error")
        return redirect(url_for("usuarios_admin"))

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


@app.route("/ciudadano")
def ciudadano():
    return render_template("ciudadano.html", tipos_por_prioridad=CATALOGO_TIPOS_POR_PRIORIDAD)


# =========================
# API PARA BUSCAR ESTADO DE REPORTE (sin login requerido)
# =========================
@app.route("/api/buscar_reporte", methods=["GET"])
def api_buscar_reporte():
    """Endpoint público para que ciudadanos consulten estado por código de reporte."""
    reporte_codigo = request.args.get("id", "").strip().upper()
    
    if not reporte_codigo:
        return {"exito": False, "mensaje": "El código del reporte es requerido."}, 400

    if not re.match(r"^REP-[A-Z0-9]{8}$", reporte_codigo):
        return {"exito": False, "mensaje": "Código inválido. Use el formato REP-XXXXXXXX."}, 400
    
    try:
        conexion = obtener_conexion()
        if conexion is None:
            return {"exito": False, "mensaje": "Error de conexión con la base de datos."}, 500

        cursor = conexion.cursor()
        cursor.execute("""
            SELECT id, codigo_reporte, tipo, estado, prioridad, fecha, hora,
                   observacion_admin, fecha_finalizacion, hora_finalizacion
            FROM reportes
            WHERE codigo_reporte = %s
            LIMIT 1
        """, (reporte_codigo,))
        reporte = cursor.fetchone()
        cursor.close()
        conexion.close()
    except Exception as e:
        print(f"Error al buscar reporte: {e}")
        return {"exito": False, "mensaje": "Error en la búsqueda del reporte."}, 500
    
    if not reporte:
        return {"exito": False, "mensaje": "Reporte no encontrado."}, 404
    
    # Construir respuesta con información del reporte
    respuesta = {
        "exito": True,
        "reporte": {
            "id": reporte["id"],
            "codigo_reporte": reporte["codigo_reporte"],
            "tipo": reporte["tipo"],
            "estado": reporte["estado"],
            "prioridad": reporte["prioridad"],
            "fecha": str(reporte["fecha"]) if reporte["fecha"] else "",
            "hora": str(reporte["hora"]) if reporte["hora"] else "",
            "observacion_admin": reporte["observacion_admin"] or "Sin observaciones",
            "fecha_finalizacion": str(reporte["fecha_finalizacion"]) if reporte["fecha_finalizacion"] else "",
            "hora_finalizacion": str(reporte["hora_finalizacion"]) if reporte["hora_finalizacion"] else ""
        }
    }
    
    return respuesta, 200


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

    if not nombre or not telefono or not tipo or not descripcion or not ubicacion:
        flash("Todos los campos del reporte son obligatorios.", "error")
        return redirect(url_for("ciudadano"))

    # Validar email y teléfono antes de procesar (email es opcional)
    if correo and not validar_email(correo):
        flash("El correo electrónico no es válido.", "error")
        return redirect(url_for("ciudadano"))
    
    if not validar_telefono(telefono):
        flash("El teléfono no es válido.", "error")
        return redirect(url_for("ciudadano"))
    
    if len(descripcion) > 2000:
        flash("La descripción es demasiado larga (máximo 2000 caracteres).", "error")
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
    if reporte_id <= 0:
        flash("ID de reporte inválido.", "error")
        return redirect(url_for("ciudadano"))

    reporte = obtener_reporte_por_id(reporte_id)

    if not reporte:
        flash("No se encontró el reporte.", "error")
        return redirect(url_for("ciudadano"))

    return render_template("confirmacion.html", reporte=reporte)


@app.route("/descargar_comprobante/<int:reporte_id>")
def descargar_comprobante(reporte_id):
    if reporte_id <= 0:
        flash("ID de reporte inválido.", "error")
        return redirect(url_for("ciudadano"))

    reporte = obtener_reporte_por_id(reporte_id)

    if not reporte:
        flash("No se encontró el reporte.", "error")
        return redirect(url_for("ciudadano"))

    try:
        buffer = BytesIO()
        pdf = canvas.Canvas(buffer, pagesize=A4)
        ancho, alto = A4

        y = alto - 50

        pdf.setTitle(f"Comprobante_Reporte_{reporte.get('codigo_reporte', reporte['id'])}")

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
            f"Código del reporte: {reporte.get('codigo_reporte', reporte['id'])}",
            f"Nombre: {reporte['nombre']}",
            f"Teléfono: {reporte['telefono']}",
            f"Correo: {reporte['correo']}",
            f"Tipo de incidencia: {reporte['tipo']}",
            f"Ubicación: {reporte['ubicacion']}",
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
        response.headers["Content-Disposition"] = (
            f"attachment; filename=comprobante_reporte_{reporte.get('codigo_reporte', reporte['id'])}.pdf"
        )
        return response
    except Exception as e:
        print(f"Error al generar PDF: {e}")
        flash("Error al generar el comprobante.", "error")
        return redirect(url_for("ciudadano"))


# ---------------------------------------------------------------------------
# Exportación PDF — panel administrativo
# ---------------------------------------------------------------------------

def _pdf_tabla_reportes(titulo, subtitulo, lista_reportes):
    """Genera un PDF en memoria con una tabla de reportes y lo devuelve como Response."""
    from datetime import datetime

    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    ancho, alto = A4

    MARGEN_IZQ = 30
    MARGEN_DER = ancho - 30
    ALTO_FILA = 16
    COLS = [30, 70, 175, 300, 375, 455, 530]  # x de inicio de cada columna
    ENCABEZADOS = ["ID", "Fecha", "Nombre", "Tipo", "Prioridad", "Estado", ""]

    def nueva_pagina():
        pdf.showPage()
        y_nuevo = alto - 40
        pdf.setFont("Helvetica-Bold", 8)
        for i, enc in enumerate(ENCABEZADOS[:-1]):
            pdf.drawString(COLS[i], y_nuevo, enc)
        pdf.setLineWidth(0.5)
        pdf.line(MARGEN_IZQ, y_nuevo - 4, MARGEN_DER, y_nuevo - 4)
        return y_nuevo - ALTO_FILA - 4

    # Encabezado principal
    y = alto - 45
    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(MARGEN_IZQ, y, titulo)
    y -= 20
    pdf.setFont("Helvetica", 10)
    pdf.drawString(MARGEN_IZQ, y, subtitulo)
    y -= 14
    pdf.setFont("Helvetica-Oblique", 9)
    pdf.drawString(MARGEN_IZQ, y, f"Generado: {datetime.now().strftime('%d/%m/%Y %H:%M')}")
    y -= 18

    # Encabezados de tabla
    pdf.setLineWidth(0.5)
    pdf.line(MARGEN_IZQ, y, MARGEN_DER, y)
    y -= 12
    pdf.setFont("Helvetica-Bold", 8)
    for i, enc in enumerate(ENCABEZADOS[:-1]):
        pdf.drawString(COLS[i], y, enc)
    y -= 4
    pdf.line(MARGEN_IZQ, y, MARGEN_DER, y)
    y -= ALTO_FILA

    # Filas
    pdf.setFont("Helvetica", 8)
    for r in lista_reportes:
        if y < 50:
            y = nueva_pagina()

        def trunc(val, largo):
            s = str(val or "")
            return s[:largo] + "…" if len(s) > largo else s

        pdf.drawString(COLS[0], y, str(r.get("id", "")))
        fecha = str(r.get("fecha", ""))[:10]
        pdf.drawString(COLS[1], y, fecha)
        pdf.drawString(COLS[2], y, trunc(r.get("nombre", ""), 16))
        pdf.drawString(COLS[3], y, trunc(r.get("tipo", ""), 17))
        pdf.drawString(COLS[4], y, trunc(r.get("prioridad", ""), 10))
        pdf.drawString(COLS[5], y, trunc(r.get("estado", ""), 18))

        y -= ALTO_FILA
        if y > 50:
            pdf.setLineWidth(0.2)
            pdf.line(MARGEN_IZQ, y + ALTO_FILA - 2, MARGEN_DER, y + ALTO_FILA - 2)

    # Pie
    y -= 10
    pdf.setFont("Helvetica-Oblique", 8)
    pdf.drawString(MARGEN_IZQ, max(y, 30), f"Total de registros: {len(lista_reportes)}")

    pdf.showPage()
    pdf.save()
    buffer.seek(0)
    return buffer


@app.route("/admin/exportar/todos")
@login_requerido
def exportar_pdf_todos():
    lista = obtener_todos_los_reportes()
    buffer = _pdf_tabla_reportes(
        "Reporte General — Todos los reportes",
        "Sistema Web de Reporte Urbano — Municipalidad de Presidente Franco",
        lista
    )
    response = make_response(buffer.read())
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = "attachment; filename=reporte_general_todos.pdf"
    return response


@app.route("/admin/exportar/pendientes")
@login_requerido
def exportar_pdf_pendientes():
    lista = obtener_reportes_pendientes()
    buffer = _pdf_tabla_reportes(
        "Reporte General — Casos activos",
        "Reportes que aún no han sido finalizados",
        lista
    )
    response = make_response(buffer.read())
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = "attachment; filename=reporte_pendientes.pdf"
    return response


@app.route("/admin/exportar/realizados")
@login_requerido
def exportar_pdf_realizados():
    lista = obtener_reportes_realizados()
    buffer = _pdf_tabla_reportes(
        "Reporte General — Casos finalizados",
        "Reportes con estado Realizado o Rechazado / No corresponde",
        lista
    )
    response = make_response(buffer.read())
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = "attachment; filename=reporte_realizados.pdf"
    return response


@app.route("/admin/exportar/estadisticas")
@login_requerido
def exportar_pdf_estadisticas():
    from datetime import datetime

    est = obtener_estadisticas_generales()
    kpis = obtener_kpis_admin()

    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    ancho, alto = A4

    y = alto - 50
    MARGEN = 50

    def linea(texto, fuente="Helvetica", tam=11, extra=0):
        nonlocal y
        pdf.setFont(fuente, tam)
        pdf.drawString(MARGEN, y, texto)
        y -= (18 + extra)

    def separador():
        nonlocal y
        pdf.setLineWidth(0.5)
        pdf.line(MARGEN, y + 10, ancho - MARGEN, y + 10)
        y -= 6

    linea("INFORME DE ESTADÍSTICAS — REPORTE URBANO", "Helvetica-Bold", 14)
    linea("Municipalidad de Presidente Franco", "Helvetica", 10)
    linea(f"Generado: {datetime.now().strftime('%d/%m/%Y %H:%M')}", "Helvetica-Oblique", 9)
    separador()

    linea("RESUMEN GENERAL", "Helvetica-Bold", 12, extra=4)
    linea(f"Total de reportes registrados:   {est.get('total_reportes', 0)}")
    linea(f"Reportes activos (en gestión):   {est.get('activos', 0)}")
    linea(f"Realizados:                      {est.get('realizados', 0)}")
    linea(f"Rechazados / No corresponde:     {est.get('rechazado', 0)}")
    separador()

    linea("DESGLOSE POR ESTADO", "Helvetica-Bold", 12, extra=4)
    linea(f"Pendiente:    {est.get('pendientes', 0)}")
    linea(f"En revisión:  {est.get('en_revision', 0)}")
    linea(f"Asignado:     {est.get('asignado', 0)}")
    linea(f"En proceso:   {est.get('en_proceso', 0)}")
    separador()

    linea("DESGLOSE POR PRIORIDAD", "Helvetica-Bold", 12, extra=4)
    linea(f"Crítica: {est.get('critica', 0)}")
    linea(f"Alta:    {est.get('alta', 0)}")
    linea(f"Media:   {est.get('media', 0)}")
    linea(f"Baja:    {est.get('baja', 0)}")
    separador()

    linea("INDICADORES EJECUTIVOS", "Helvetica-Bold", 12, extra=4)
    linea(f"Tasa de resolución:              {kpis.get('pct_resolucion', 0)}%")
    linea(f"Críticos activos sin resolver:   {kpis.get('criticos_activos', 0)}")
    linea(f"Reportes con ubicación en mapa:  {kpis.get('con_ubicacion', 0)}")
    linea(f"Reportes con foto del problema:  {kpis.get('con_foto', 0)}")

    pdf.showPage()
    pdf.save()
    buffer.seek(0)

    response = make_response(buffer.read())
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = "attachment; filename=estadisticas_reporte_urbano.pdf"
    return response


# ---------------------------------------------------------------------------

@app.route("/reportes")
@login_requerido
def reportes():
    codigo = request.args.get("codigo", "").strip()
    estado = request.args.get("estado", "").strip()
    prioridad = request.args.get("prioridad", "").strip()
    tipo = request.args.get("tipo", "").strip()
    fecha = request.args.get("fecha", "").strip()
    busqueda = request.args.get("busqueda", "").strip()
    ordenar_por = request.args.get("ordenar_por", "id").strip().lower()
    direccion = request.args.get("direccion", "desc").strip().lower()

    try:
        pagina = int(request.args.get("pagina", 1))
    except (TypeError, ValueError):
        pagina = 1

    por_pagina = 20
    hay_filtros = any([codigo, estado, prioridad, tipo, fecha, busqueda])

    lista, total_resultados = obtener_reportes_filtrados(
        codigo=codigo or None,
        estado=estado or None,
        prioridad=prioridad or None,
        tipo=tipo or None,
        fecha=fecha or None,
        busqueda=busqueda or None,
        ordenar_por=ordenar_por,
        direccion=direccion,
        pagina=max(1, pagina),
        por_pagina=por_pagina,
        aplicar_paginacion=True,
    )

    total_paginas = max(1, (total_resultados + por_pagina - 1) // por_pagina)
    pagina_actual = min(max(1, pagina), total_paginas)

    if pagina_actual != pagina and total_resultados > 0:
        lista, _ = obtener_reportes_filtrados(
            codigo=codigo or None,
            estado=estado or None,
            prioridad=prioridad or None,
            tipo=tipo or None,
            fecha=fecha or None,
            busqueda=busqueda or None,
            ordenar_por=ordenar_por,
            direccion=direccion,
            pagina=pagina_actual,
            por_pagina=por_pagina,
            aplicar_paginacion=True,
        )

    filtros = {
        "codigo": codigo,
        "estado": estado,
        "prioridad": prioridad,
        "tipo": tipo,
        "fecha": fecha,
        "busqueda": busqueda,
    }

    base_params = {
        "codigo": codigo,
        "estado": estado,
        "prioridad": prioridad,
        "tipo": tipo,
        "fecha": fecha,
        "busqueda": busqueda,
        "ordenar_por": ordenar_por,
        "direccion": direccion,
    }

    def url_reportes_con(params_extra):
        merged = {**base_params, **params_extra}
        limpios = {k: v for k, v in merged.items() if v not in (None, "")}
        return url_for("reportes") + ("?" + urlencode(limpios) if limpios else "")

    columnas_sort = ["id", "nombre", "tipo", "prioridad", "estado", "fecha"]
    sort_urls = {}
    for col in columnas_sort:
        nueva_direccion = "asc" if (ordenar_por != col or direccion == "desc") else "desc"
        sort_urls[col] = url_reportes_con({"ordenar_por": col, "direccion": nueva_direccion, "pagina": 1})

    paginacion = []
    for p in range(1, total_paginas + 1):
        paginacion.append({
            "numero": p,
            "actual": p == pagina_actual,
            "url": url_reportes_con({"pagina": p}),
        })

    prev_url = url_reportes_con({"pagina": pagina_actual - 1}) if pagina_actual > 1 else None
    next_url = url_reportes_con({"pagina": pagina_actual + 1}) if pagina_actual < total_paginas else None
    exportar_url = url_for("exportar_pdf_reportes_filtrados") + ("?" + urlencode({k: v for k, v in base_params.items() if v not in (None, "")}) if any(base_params.values()) else "")

    return render_template(
        "reportes.html",
        reportes=lista,
        filtros=filtros,
        hay_filtros=hay_filtros,
        total_resultados=total_resultados,
        pagina_actual=pagina_actual,
        total_paginas=total_paginas,
        paginacion=paginacion,
        prev_url=prev_url,
        next_url=next_url,
        ordenar_por=ordenar_por,
        direccion=direccion,
        sort_urls=sort_urls,
        exportar_url=exportar_url,
    )


@app.route("/reportes/exportar/pdf")
@login_requerido
def exportar_pdf_reportes_filtrados():
    codigo = request.args.get("codigo", "").strip()
    estado = request.args.get("estado", "").strip()
    prioridad = request.args.get("prioridad", "").strip()
    tipo = request.args.get("tipo", "").strip()
    fecha = request.args.get("fecha", "").strip()
    busqueda = request.args.get("busqueda", "").strip()
    ordenar_por = request.args.get("ordenar_por", "id").strip().lower()
    direccion = request.args.get("direccion", "desc").strip().lower()

    lista, total = obtener_reportes_filtrados(
        codigo=codigo or None,
        estado=estado or None,
        prioridad=prioridad or None,
        tipo=tipo or None,
        fecha=fecha or None,
        busqueda=busqueda or None,
        ordenar_por=ordenar_por,
        direccion=direccion,
        aplicar_paginacion=False,
    )

    subtitulo = "Listado filtrado y ordenado desde el módulo de reportes"
    if total == 0:
        subtitulo = "Sin resultados para los filtros seleccionados"

    buffer = _pdf_tabla_reportes(
        "Reporte General — Vista actual de reportes",
        subtitulo,
        lista,
    )

    response = make_response(buffer.read())
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = "attachment; filename=reportes_filtrados.pdf"
    return response


@app.route("/reporte/<int:reporte_id>/pdf")
@login_requerido
def exportar_pdf_detalle_reporte(reporte_id):
    from datetime import datetime
    if reporte_id <= 0:
        flash("ID de reporte inválido.", "error")
        return redirect(url_for("reportes"))

    reporte = obtener_reporte_por_id(reporte_id)
    if not reporte:
        flash("No se encontró el reporte.", "error")
        return redirect(url_for("reportes"))

    try:
        buffer = BytesIO()
        pdf = canvas.Canvas(buffer, pagesize=A4)
        ancho, alto = A4
        MARGEN = 50

        y = alto - 50
        codigo = reporte.get("codigo_reporte") or str(reporte["id"])

        # Encabezado
        pdf.setFont("Helvetica-Bold", 16)
        pdf.drawString(MARGEN, y, "DETALLE DEL REPORTE")
        y -= 22
        pdf.setFont("Helvetica", 10)
        pdf.drawString(MARGEN, y, "Sistema Web de Reporte Urbano — Municipalidad de Presidente Franco")
        y -= 14
        pdf.setFont("Helvetica-Oblique", 9)
        pdf.drawString(MARGEN, y, f"Generado: {datetime.now().strftime('%d/%m/%Y %H:%M')}")
        y -= 6
        pdf.setLineWidth(1)
        pdf.line(MARGEN, y, ancho - MARGEN, y)
        y -= 20

        # Datos del reporte
        def fila(etiqueta, valor):
            nonlocal y
            if y < 60:
                pdf.showPage()
                y = alto - 50
            pdf.setFont("Helvetica-Bold", 10)
            pdf.drawString(MARGEN, y, f"{etiqueta}:")
            pdf.setFont("Helvetica", 10)
            pdf.drawString(MARGEN + 160, y, str(valor or "—"))
            y -= 18

        fila("Código", codigo)
        fila("Estado", reporte.get("estado", ""))
        fila("Prioridad", reporte.get("prioridad", ""))
        fila("Nombre del ciudadano", reporte.get("nombre", ""))
        fila("Teléfono", reporte.get("telefono", ""))
        fila("Correo", reporte.get("correo", ""))
        fila("Tipo de incidencia", reporte.get("tipo", ""))
        fila("Ubicación", reporte.get("ubicacion", ""))
        fila("Fecha de registro", reporte.get("fecha", ""))
        fila("Hora de registro", reporte.get("hora", ""))
        if reporte.get("fecha_finalizacion"):
            fila("Fecha de finalización", reporte.get("fecha_finalizacion", ""))
        if reporte.get("hora_finalizacion"):
            fila("Hora de finalización", reporte.get("hora_finalizacion", ""))

        # Descripción (puede ser larga)
        y -= 4
        pdf.setFont("Helvetica-Bold", 10)
        pdf.drawString(MARGEN, y, "Descripción:")
        y -= 16
        pdf.setFont("Helvetica", 10)
        descripcion = str(reporte.get("descripcion") or "")
        max_chars = 90
        for i in range(0, max(len(descripcion), 1), max_chars):
            if y < 60:
                pdf.showPage()
                y = alto - 50
            pdf.drawString(MARGEN + 10, y, descripcion[i:i + max_chars])
            y -= 15

        # Observación admin
        if reporte.get("observacion_admin"):
            y -= 6
            pdf.setFont("Helvetica-Bold", 10)
            pdf.drawString(MARGEN, y, "Observación administrativa:")
            y -= 16
            pdf.setFont("Helvetica", 10)
            obs = str(reporte["observacion_admin"])
            for i in range(0, len(obs), max_chars):
                if y < 60:
                    pdf.showPage()
                    y = alto - 50
                pdf.drawString(MARGEN + 10, y, obs[i:i + max_chars])
                y -= 15

        # Pie
        y -= 10
        pdf.setLineWidth(0.5)
        pdf.line(MARGEN, max(y, 40), ancho - MARGEN, max(y, 40))
        y -= 14
        pdf.setFont("Helvetica-Oblique", 8)
        pdf.drawString(MARGEN, max(y, 28), "Documento generado automáticamente por el Sistema de Reporte Urbano.")

        pdf.showPage()
        pdf.save()
        buffer.seek(0)

        response = make_response(buffer.read())
        response.headers["Content-Type"] = "application/pdf"
        response.headers["Content-Disposition"] = f"inline; filename=reporte_{codigo}.pdf"
        return response
    except Exception as e:
        print(f"Error al generar PDF de detalle: {e}")
        flash("Error al generar el PDF.", "error")
        return redirect(url_for("detalle_reporte", reporte_id=reporte_id))


@app.route("/reporte/<int:reporte_id>")
@login_requerido
def detalle_reporte(reporte_id):
    if reporte_id <= 0:
        flash("ID de reporte inválido.", "error")
        return redirect(url_for("reportes"))

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
    if reporte_id <= 0:
        flash("ID de reporte inválido.", "error")
        return redirect(url_for("reportes"))

    nuevo_estado = request.form.get("estado", "").strip()

    ok, mensaje = actualizar_estado_reporte(reporte_id, nuevo_estado)

    if ok:
        flash(mensaje, "success")
    else:
        flash(mensaje, "error")

    return redirect(url_for("detalle_reporte", reporte_id=reporte_id))


@app.route("/guardar_observacion/<int:reporte_id>", methods=["POST"])
@login_requerido
def guardar_observacion(reporte_id):
    if reporte_id <= 0:
        flash("ID de reporte inválido.", "error")
        return redirect(url_for("reportes"))

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
    if reporte_id <= 0:
        flash("ID de reporte inválido.", "error")
        return redirect(url_for("reportes"))

    reporte = obtener_reporte_por_id(reporte_id)
    if not reporte:
        flash("No se encontró el reporte.", "error")
        return redirect(url_for("reportes"))

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


# =========================
# RUTA DEBUG - SERVIR GEOJSON EXPLÍCITAMENTE
# =========================
@app.route("/api/geojson")
def api_geojson():
    """Ruta explícita para servir el GeoJSON con headers correctos"""
    try:
        geojson_path = os.path.join(BASE_DIR, "static", "presidente_franco_boundary.geojson")
        with open(geojson_path, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
        return jsonify(data)
    except Exception as e:
        print(f"Error al servir GeoJSON: {e}")
        return {"error": str(e)}, 500


# INICIALIZAR AL CARGAR LA APP
# =========================
inicializar_bd()

# =========================
# INICIO LOCAL
# =========================
if __name__ == "__main__":
    app.run(
        host=os.environ.get("FLASK_HOST", "127.0.0.1"),
        port=obtener_puerto_local(),
        debug=os.environ.get("FLASK_DEBUG", "0") == "1"
    )
