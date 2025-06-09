# ---------------------------------------------
# 🖋 APLICACIÓN DE FIRMA DIGITAL CON STREAMLIT
# Autores: [Tu nombre o equipo]
# Descripción: Firma y verifica archivos usando RSA y ECC, almacenando llaves en AWS S3.
# ---------------------------------------------

import streamlit as st
from dotenv import load_dotenv
import os
import hashlib
import pickle
import zipfile
from datetime import datetime
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
import boto3
from botocore.exceptions import NoCredentialsError, ClientError

# -------- CONFIGURACIÓN AWS --------
AWS_BUCKET_NAME = "directorio-efirmas"
s3_client = boto3.client(
    's3',
    aws_access_key_id=st.secrets["AWS_ACCESS_KEY_ID"],
    aws_secret_access_key=st.secrets["AWS_SECRET_ACCESS_KEY"],
    region_name=st.secrets["AWS_DEFAULT_REGION"]
)

# -------- UTILIDADES --------
def hash_bytes(data):
    """Calcula el hash SHA-256 de los datos."""
    h = hashlib.sha256()
    h.update(data)
    return h.digest()

def guardar_llaves_s3(username, algoritmo="RSA"):
    """Genera y guarda par de llaves en AWS S3 según el algoritmo elegido."""
    if algoritmo == "RSA":
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    elif algoritmo == "ECC":
        private_key = ec.generate_private_key(ec.SECP256R1())
    else:
        st.error("Algoritmo no soportado.")
        return False

    public_key = private_key.public_key()

    # Serializar llaves
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Guardar en S3
    try:
        s3_client.put_object(Bucket=AWS_BUCKET_NAME, Key=f"{username}_private.pem", Body=private_bytes)
        s3_client.put_object(Bucket=AWS_BUCKET_NAME, Key=f"{username}_public.pem", Body=public_bytes)
        s3_client.put_object(Bucket=AWS_BUCKET_NAME, Key=f"{username}_algoritmo.txt", Body=algoritmo.encode())
        return True
    except (NoCredentialsError, ClientError) as e:
        st.error("Error al guardar llaves en S3: " + str(e))
        return False

def obtener_algoritmo_usuario(username):
    """Obtiene el algoritmo usado por el usuario."""
    try:
        response = s3_client.get_object(Bucket=AWS_BUCKET_NAME, Key=f"{username}_algoritmo.txt")
        return response["Body"].read().decode()
    except:
        return "RSA"  # Valor por defecto

def cargar_llave_s3(username, tipo="private"):
    """Carga una llave privada o pública desde S3."""
    key_suffix = "private.pem" if tipo == "private" else "public.pem"
    try:
        response = s3_client.get_object(Bucket=AWS_BUCKET_NAME, Key=f"{username}_{key_suffix}")
        pem_data = response['Body'].read()
        if tipo == "private":
            return serialization.load_pem_private_key(pem_data, password=None)
        else:
            return serialization.load_pem_public_key(pem_data)
    except s3_client.exceptions.NoSuchKey:
        st.warning("⚠ No se encontró la llave en S3.")
        return None

# -------- FUNCIONES DE FIRMA --------
def firmar_documento(username, file):
    """Firma un archivo con la llave privada del usuario."""
    private_key = cargar_llave_s3(username, tipo="private")
    if not private_key:
        return None, None

    algoritmo = obtener_algoritmo_usuario(username)
    file_bytes = file.read()
    file_hash = hash_bytes(file_bytes)

    # Firmar hash del archivo
    try:
        if algoritmo == "RSA":
            firma = private_key.sign(
                file_hash,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
        elif algoritmo == "ECC":
            firma = private_key.sign(file_hash, ec.ECDSA(hashes.SHA256()))
        else:
            st.error("Algoritmo de firma no soportado.")
            return None, None
    except Exception as e:
        st.error(f"Error durante la firma: {e}")
        return None, None

    # Crear .zip con firma y metadatos
    sig_data = {'username': username, 'signature': firma, 'algoritmo': algoritmo}
    zip_name = f"{file.name}_firma.zip"
    with zipfile.ZipFile(zip_name, 'w') as zipf:
        zipf.writestr("firma.sig", pickle.dumps(sig_data))
        zipf.writestr("metadata.txt", f"Firmado por: {username}\nFecha: {datetime.now()}")

    return zip_name, file.name, file_bytes

# -------- FUNCIÓN DE VERIFICACIÓN --------
def verificar_documento(zip_file, original_file):
    """Verifica si una firma digital es válida."""
    if not zipfile.is_zipfile(zip_file):
        return "⚠ No es un archivo firmado válido."

    with zipfile.ZipFile(zip_file, 'r') as zipf:
        if 'firma.sig' not in zipf.namelist():
            return "⚠ No contiene firma válida."

        sig_data = pickle.loads(zipf.read('firma.sig'))
        username = sig_data['username']
        signature = sig_data['signature']
        algoritmo = sig_data.get('algoritmo', 'RSA')

        file_bytes = original_file.read()
        public_key = cargar_llave_s3(username, tipo="public")
        if not public_key:
            return "⚠ No se pudo recuperar la llave pública."

        try:
            if algoritmo == "RSA":
                public_key.verify(
                    signature,
                    hash_bytes(file_bytes),
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )
            elif algoritmo == "ECC":
                public_key.verify(signature, hash_bytes(file_bytes), ec.ECDSA(hashes.SHA256()))
            else:
                return "❌ Algoritmo de firma no reconocido."
            return f"✅ Documento firmado por: {username} usando {algoritmo}"
        except Exception:
            return "❌ Firma inválida o documento alterado."

# -------- INTERFAZ DE USUARIO CON STREAMLIT --------
st.set_page_config(page_title="Firma Digital", layout="centered")
st.title("🖋 Aplicación de Firma Digital")

with st.expander("ℹ️ ¿Qué es RSA y ECC?"):
    st.markdown("""
    **RSA (Rivest-Shamir-Adleman)** y **ECC (Elliptic Curve Cryptography)** son algoritmos criptográficos usados para firma digital.

    - 🔐 **RSA** se basa en la factorización de números primos grandes. Es ampliamente utilizado, pero sus llaves tienden a ser más grandes para mantener la seguridad.
    - 🧮 **ECC** se basa en matemáticas de curvas elípticas. Ofrece la misma seguridad que RSA pero con llaves más pequeñas, lo que mejora el rendimiento.
    """)

# -------- AUTENTICACIÓN --------
st.sidebar.header("🔐 Autenticación")
usuarios = []
try:
    lista_objetos = s3_client.list_objects_v2(Bucket=AWS_BUCKET_NAME)['Contents']
    usuarios = list(set(obj['Key'].split('_')[0] for obj in lista_objetos if obj['Key'].endswith('_private.pem')))
except Exception as e:
    st.sidebar.error("Error al cargar usuarios: " + str(e))

modo = st.sidebar.radio("¿Qué deseas hacer?", ["Iniciar sesión", "Crear cuenta"])

if modo == "Crear cuenta":
    nuevo_usuario = st.sidebar.text_input("Nombre de usuario nuevo")
    algoritmo = st.sidebar.selectbox("Algoritmo de firma", ["RSA", "ECC"])
    if st.sidebar.button("Crear cuenta"):
        if nuevo_usuario in usuarios:
            st.sidebar.warning("⚠ El usuario ya existe.")
        else:
            exito = guardar_llaves_s3(nuevo_usuario, algoritmo)
            if exito:
                st.sidebar.success("✅ Cuenta creada con éxito.")

elif modo == "Iniciar sesión":
    usuario = st.sidebar.selectbox("Selecciona tu usuario", usuarios)
    if st.sidebar.button("Iniciar sesión"):
        st.session_state["usuario"] = usuario

# -------- FUNCIONALIDAD PRINCIPAL --------
if "usuario" in st.session_state:
    st.success(f"Sesión iniciada como: {st.session_state['usuario']}")
    tab1, tab2 = st.tabs(["✍ Firmar documento", "🔍 Verificar documento"])

    with tab1:
        archivo = st.file_uploader("Sube un archivo para firmar")
        if archivo and st.button("Firmar archivo"):
            zip_path, original_filename, file_bytes = firmar_documento(st.session_state['usuario'], archivo)
            if zip_path:
                col1, col2 = st.columns(2)
                with open(zip_path, "rb") as f:
                    col1.download_button("Descargar .zip de firma", f.read(), file_name=zip_path)
                col2.download_button("Descargar archivo original", file_bytes, file_name=original_filename)

    with tab2:
        archivo_zip = st.file_uploader("Sube el archivo de firma (.zip)", type="zip")
        archivo_original = st.file_uploader("Sube el archivo original para verificar",
                                            type=["txt", "pdf", "docx", "csv", "jpg", "png", "jpeg", "json", "xml", "md", "xlsx"])
        if archivo_zip and archivo_original and st.button("Verificar documento"):
            resultado = verificar_documento(archivo_zip, archivo_original)
            st.info(resultado)
else:
    st.info("🔑 Inicia sesión o crea una cuenta para continuar.")
