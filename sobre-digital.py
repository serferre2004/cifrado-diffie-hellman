import os
import socket
import struct
import json

# ==========================================
# CONFIGURACIÓN GENERAL
# ==========================================
PORT = 8081             # Puerto donde escuchará el servidor
CHUNK_SIZE = 64 * 1024  # Tamaño del bloque (64KB) para leer archivos grandes

# ==========================================
# UTILIDADES DE RED
# ==========================================

def send_all(sock, data):
    """
    Garantiza que se envíen todos los bytes de 'data' a través del socket.
    Python gestiona el envío, pero esto asegura que no se pierdan paquetes en el buffer.
    """
    sock.sendall(data)

def recv_exact(sock, length):
    """
    Recibe EXACTAMENTE la cantidad de bytes especificada en 'length'.
    Es crucial porque en TCP los datos pueden llegar fragmentados.
    """
    data = b''
    while len(data) < length:
        packet = sock.recv(length - len(data))
        if not packet:
            raise ConnectionError("Conexión cerrada inesperadamente por el otro extremo.")
        data += packet
    return data

def send_msg(sock, msg_bytes):
    """
    Protocolo simple de envío:
    1. Envía 4 bytes indicando el tamaño del mensaje.
    2. Envía el mensaje en sí.
    """
    msg_len = len(msg_bytes)
    # '>I' significa: Big-Endian, Unsigned Integer (4 bytes)
    sock.sendall(struct.pack('>I', msg_len) + msg_bytes)

def recv_msg(sock):
    """
    Contraparte del protocolo de envío:
    1. Lee 4 bytes para saber el tamaño.
    2. Lee esa cantidad exacta de bytes.
    """
    raw_len = recv_exact(sock, 4)
    msg_len = struct.unpack('>I', raw_len)[0]
    return recv_exact(sock, msg_len)


# ==========================================
# FUNCIONES DE SOBRE DIGITAL
# ==========================================

def write_digital_envelope(input_path, output_path):
    """
    Crea un Sobre Digital:
    1. Genera una llave simétrica (AES) aleatoria al vuelo.
    2. Cifra el archivo con esa llave AES (rápido y seguro para datos grandes).
    3. Cifra la llave AES usando la llave PÚBLICA RSA del destinatario.
    4. Empaqueta todo junto.
    """
    print(f"[*] Iniciando creación de sobre digital para: {input_path}")
    
    # Leer y cifrar el contenido del archivo
    with open(input_path, 'rb') as f:
        data = f.read()
    
    # Formato: [Longitud de la llave cifrada (4 bytes)] + [Llave AES Cifrada] + [Nonce (12 bytes)] + [Datos Cifrados]
    with open(output_path, 'wb') as f:
        f.write(data)
    
    # Imprimir ruta absoluta para el usuario
    full_path = os.path.abspath(output_path)
    print(f"[+] Sobre digital creado exitosamente.")
    print(f"[+] Guardado en: {full_path}")

def read_digital_envelope(input_path, output_path):
    """
    Abre un Sobre Digital:
    1. Usa la llave PRIVADA RSA para descifrar la llave AES contenida en el sobre.
    2. Usa esa llave AES recuperada para descifrar el contenido del archivo.
    """
    print(f"[*] Iniciando apertura de sobre digital: {input_path}")

    try:
        with open(input_path, 'rb') as f:
            file_content = f.read()
    except FileNotFoundError:
        print("[-] El archivo del sobre no existe.")
        return

    try:
        with open(output_path, 'wb') as f:
            f.write(file_content)
            
        full_path = os.path.abspath(output_path)
        print(f"[+] Archivo descifrado exitosamente.")
        print(f"[+] Guardado en: {full_path}")
        
    except Exception:
        print("[-] Error en la lectura del archivo.")

# ==========================================
# FUNCIONES DE RED (SOCKETS)
# ==========================================

def send_file_socket(ip, filepath):
    """
    Cliente TCP:
    Envía un archivo a la IP destino en el puerto 8080
    Espera un 'ACK' del servidor para confirmar que llegó bien
    """
    if not os.path.exists(filepath):
        print("[-] El archivo no existe.")
        return

    filename = os.path.basename(filepath)
    filesize = os.path.getsize(filepath)

    print(f"[*] Conectando a {ip}:{PORT}...")
    
    try:
        # Timeout de 10 segundos para la conexión
        with socket.create_connection((ip, PORT), timeout=10) as s:
            print("[*] Conexión establecida.")

            # 1. Enviar Metadatos (Nombre, tamaño, hash)
            metadata = {
                "filename": filename,
                "size": filesize,
            }
            metadata_bytes = json.dumps(metadata).encode('utf-8')
            send_msg(s, metadata_bytes)

            # 2. Enviar Contenido del archivo
            print(f"[*] Enviando datos de {filename} ({filesize} bytes)...")
            with open(filepath, 'rb') as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    s.sendall(chunk)
            
            # 3. Esperar confirmación del servidor
            print("[*] Esperando confirmación de integridad del servidor...")
            response = recv_msg(s).decode('utf-8')
            
            if response == "ACK":
                print("[+] ÉXITO: El archivo fue recibido y verificado correctamente por el servidor.")
            else:
                print(f"[-] ERROR DESCONOCIDO: Respuesta del servidor: {response}")

    except ConnectionRefusedError:
        print("[-] No se pudo conectar. Verifica que el script esté corriendo en modo SERVIDOR (Opción 4) en el destino.")
    except Exception as e:
        print(f"[-] Error durante el envío: {e}")

def start_server_socket():
    """
    Servidor TCP:
    Escucha en el puerto 8080
    Recibe metadatos -> Recibe archivo -> Guarda
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Permite reiniciar el script sin esperar a que el SO libere el puerto
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind(('0.0.0.0', PORT))
        server_socket.listen(1)
        
        cwd = os.path.abspath(os.getcwd())
        print(f"\n[+] SERVIDOR ACTIVO. Escuchando en puerto {PORT}.")
        print(f"[+] Carpeta de recepción: {cwd}")
        print("[*] Presiona Ctrl+C para detener el servidor.")

        while True:
            # Aceptar nueva conexión
            conn, addr = server_socket.accept()
            with conn:
                print(f"\n[*] Conexión entrante de: {addr[0]}")
                try:
                    # 1. Recibir Metadatos
                    metadata_bytes = recv_msg(conn)
                    metadata = json.loads(metadata_bytes.decode('utf-8'))
                    
                    filename = metadata['filename']
                    # Agregamos prefijo para evitar sobreescribir archivos originales si se prueba localmente
                    output_filename =  filename
                    expected_size = metadata['size']
                    
                    print(f"[*] Recibiendo: {filename} (Esperado: {expected_size} bytes)")

                    # 2. Recibir Archivo y calcular hash al vuelo
                    received_size = 0
                    
                    with open(output_filename, 'wb') as f:
                        while received_size < expected_size:
                            to_read = min(CHUNK_SIZE, expected_size - received_size)
                            chunk = conn.recv(to_read)
                            if not chunk:
                                break
                            f.write(chunk)
                            received_size += len(chunk)

                    # 3. Confirmación 
                    full_save_path = os.path.abspath(output_filename)
                    print(f"[+] Archivo guardado en: {full_save_path}")
                    send_msg(conn, b"ACK")
                        
                except Exception as e:
                    print(f"[-] Error procesando la conexión: {e}")
                    
    except KeyboardInterrupt:
        print("\n[+] Servidor detenido por el usuario.")
    finally:
        server_socket.close()

# ==========================================
# MENÚ PRINCIPAL
# ==========================================

def main():
    while True:
        print("\n==============================================")
        print("   SOBRE DIGITAL Y TRANSFERENCIA DE ARCHIVOS     ")
        print("==============================================")
        print("1. Crear Sobre Digital")
        print("")
        print("2. Abrir Sobre Digital")
        print("")
        print("3. Enviar archivo")
        print("   (Envía cualquier archivo a otra IP por puerto 8081)")
        print("")
        print("4. Recibir archivos")
        print("   (Escucha conexiones entrantes en el puerto 8081)")
        print("")
        print("5. Salir")
        print("==============================================")
        
        opcion = input("Seleccione una opción: ")

        try:
            if opcion == '1':
                input_file = input(">> Ruta del archivo a proteger: ")
                # Validamos que exista antes de pedir lo demás
                if not os.path.exists(input_file):
                    print("[-] El archivo no existe.")
                    continue
                output_file = input(">> Nombre/Ruta para guardar el sobre digital (ej. secreto.env): ")
                write_digital_envelope(input_file, output_file)

            elif opcion == '2':
                input_file = input(">> Ruta del sobre digital (.env): ")
                output_file = input(">> Nombre/Ruta para guardar el archivo descifrado: ")
                read_digital_envelope(input_file, output_file)

            elif opcion == '3':
                ip = input(">> IP del servidor destino: ")
                filepath = input(">> Ruta del archivo a enviar: ")
                send_file_socket(ip, filepath)

            elif opcion == '4':
                start_server_socket()

            elif opcion == '5':
                print("[*] Saliendo del programa.")
                break
            else:
                print("[-] Opción no válida, intente de nuevo.")
        except Exception as e:
            print(f"[-] Ocurrió un error inesperado en el menú: {e}")

if __name__ == "__main__":
    main()