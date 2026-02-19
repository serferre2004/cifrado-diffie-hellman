import os
import time
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# ==========================================
# FUNCIONES DE MANEJO DE ARCHIVOS
# ==========================================

def process_encrypt_file():
    """Maneja la lectura, cifrado y guardado de un archivo."""
    input_path = input(">> Ingrese la ruta del archivo a cifrar: ")
    if not os.path.exists(input_path):
        print("[-] Error: El archivo no existe.")
        return
    try:
        # Leemos en binario para soportar cualquier tipo de archivo (PDF, Imagen, etc.)
        with open(input_path, 'rb') as f:
            data = f.read()
        
        password_path = input(">> Ingrese la ruta de la contraseña para cifrar: ")
        with open(password_path, "rb") as f:
            key = f.read()

        # Ciframos
        aesgcm = AESGCM(key)

        nonce = os.urandom(12)

        with open(input_path, "rb") as f:
            datos = f.read()

        cifrado = aesgcm.encrypt(nonce, datos, None)

        # Guardamos con extensión .aes
        output_path = input_path + ".aes"
        with open(output_path, 'wb') as f:
            f.write(nonce + cifrado)
        
        print(f"[+] Archivo cifrado con éxito.")
        print(f"[+] Guardado en: {os.path.abspath(output_path)}")

    except Exception as e:
        print(f"[-] Error durante el proceso: {e}")

def process_decrypt_file():
    """Maneja la lectura, descifrado y guardado del archivo resultante."""
    input_path = input(">> Ingrese la ruta del archivo cifrado (.aes): ")
    if not os.path.exists(input_path):
        print("[-] Error: El archivo no existe.")
        return

    try:
        password_path = input(">> Ingrese la ruta de la contraseña para descifrar: ")
        with open(password_path, "rb") as f:
           key = f.read()
        # Desciframos
        aesgcm = AESGCM(key)

        with open(input_path, "rb") as f:
            datos = f.read()

        nonce = datos[:12]
        cifrado = datos[12:]

        plano = aesgcm.decrypt(nonce, cifrado, None)

        # Definir nombre de salida (quitando el .aes o pidiendo uno nuevo)
        output_path = input(">> Ingrese nombre/ruta del archivo de salida (ej: documento_restaurado.pdf): ")
        
        with open(output_path, 'wb') as f:
            f.write(plano)
            
        print(f"[+] Archivo descifrado con éxito.")
        print(f"[+] Guardado en: {os.path.abspath(output_path)}")

    except Exception as e:
        print(f"[-] Error: {e}")

# ==========================================
# MENÚ PRINCIPAL
# ==========================================

def main():
    while True:
        print("\n==============================================")
        print("   CIFRADO AES   ")
        print("==============================================")
        print("1. Cifrar archivo (Genera .aes)")
        print("2. Descifrar archivo (A partir de .aes)")
        print("3. Salir")
        print("----------------------------------------------")
        
        choice = input("Seleccione una opción: ").strip()

        if choice == '1':
            process_encrypt_file()
        elif choice == '2':
            process_decrypt_file()
        elif choice == '3':
            print("[*] Saliendo...")
            break
        else:
            print("[-] Opción no válida.")

if __name__ == "__main__":
    main()