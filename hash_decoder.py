import hashlib
import bcrypt
import base64
import re
import argon2
from argon2 import PasswordHasher


def identify_hash_type(hash_string):
    """Identifica el tipo de hash basado en su formato y longitud."""
    # Verificar si es Base64
    try:
        # Si termina con =, es posible que sea Base64, asi que lo verificamos y tratamos de decodificarlo
        if hash_string.endswith('='):
            base64.b64decode(hash_string)
            return "Base64"
    except:
        pass
    
    # Verificar si es Bcrypt, con el formato $2a$, $2b$ o $2y$ seguido del costo y la sal+hash (regex)
    if re.match(r'^\$2[ayb]\$\d+\$[./A-Za-z0-9]{53}$', hash_string):
        return "Bcrypt"
    
    # Verificar si es MD5, con el formato de 32 caracteres hexadecimales
    elif len(hash_string) == 32 and re.match(r'^[0-9a-f]{32}$', hash_string):
        return "MD5"
    
    # Verificar si es SHA-512, con el formato de 128 caracteres hexadecimales
    elif len(hash_string) == 128 and re.match(r'^[0-9a-f]{128}$', hash_string):
        return "SHA-512"
    
    else:
        return "Desconocido"

def decode_base64(encoded_text):
    """Decodifica una cadena en Base64 y devuelve el texto en claro."""
    try:
        return base64.b64decode(encoded_text).decode('utf-8')
    except:
        return "Error al decodificar Base64"

def calculate_hashes(password):
    """Calcula diferentes hashes para una contraseña dada."""


    # Convertir la contraseña a bytes
    password_bytes = password.encode('utf-8')
    
    # Calcular MD5
    md5_hash = hashlib.md5(password_bytes).hexdigest()
    
    # Calcular SHA256
    sha256_hash = hashlib.sha256(password_bytes).hexdigest()
    
    # Calcular SHA-512
    sha512_hash = hashlib.sha512(password_bytes).hexdigest()
    
    # Calcular Bcrypt
    bcrypt_hash = bcrypt.hashpw(password_bytes, bcrypt.gensalt(12)).decode('utf-8')
    
    # Calcular Argon2i
    ph = PasswordHasher(
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=argon2.Type.I
    )
    argon2i_hash = ph.hash(password)
    
    return {
        'MD5': md5_hash,
        'SHA-256': sha256_hash,
        'SHA-512': sha512_hash,
        'Bcrypt': bcrypt_hash,
        'Argon2i': argon2i_hash
    }

def get_hash_characteristics(hash_type):
    """Devuelve características del tipo de hash."""
    characteristics = {
        "Base64": "Método de codificación que transforma datos binarios en texto ASCII",
        "MD5": "32 caracteres hexadecimales, algoritmo criptográfico que genera un resumen de un archivo o secuencia de datos",
        "SHA-256": "64 caracteres hexadecimales, algoritmo de hash seguro de 256 bits que se usa para la seguridad criptográfica",
        "SHA-512": "128 caracteres hexadecimales, algoritmo de hash criptográfico que genera una cadena de 512 bits para representar un archivo o texto",
        "Bcrypt": "Formato $2a$, $2b$ o $2y$ seguido del costo y la sal+hash, Se basa en el algoritmo de cifrado Blowfish. Diseñado específicamente para contraseñas",
        "Argon2i": "Algoritmo moderno de hashing de contraseñas, ganador del Password Hashing Competition, es una variante del algoritmo de hash Argon2, que se usa para generar claves seguras para contraseñas. Argon2i está optimizado para resistir ataques de canal lateral"
    }
    return characteristics.get(hash_type, "Características desconocidas")

def analyze_hash(hash_string):
    """Analiza un hash y muestra información sobre él."""
    hash_type = identify_hash_type(hash_string)
    print(f"\nHash: {hash_string}")
    print(f"Tipo detectado: {hash_type}")
    print(f"Características: {get_hash_characteristics(hash_type)}")
    
    if hash_type == "Base64":
        print(f"Texto decodificado: {decode_base64(hash_string)}")
    elif hash_type in ["MD5", "SHA-256", "SHA-512", "Bcrypt", "Argon2i"]:
        print("No es posible obtener el texto original debido a la naturaleza unidireccional del hash.")

def main():
    print("=" * 80)
    print("HERRAMIENTA DE ANÁLISIS Y CÁLCULO DE HASHES")
    print("=" * 80)
    
    print("\nEJERCICIO 1: IDENTIFICACIÓN DE MECANISMOS Y DECODIFICACIÓN")
    print("-" * 60)
    
    hashes_to_analyze = [
        "QmFzM182NF8zc19nM25pNEw=",
        "a5b6c33382f2f1cddbfbaba65f2b892b193fa6361d481d8a12229a2d6d95d9b792f6204ea96e706fe6d6914d7f083a213706972e5831e1c7e2cf3c33642a2df9",
        "9c87400128d408cdcda0e4b3ff0e66fa",
        "$2a$10$6e8f6.ubOs6kpuxaKwvSueeYwCtU4tDzC2oCAlhQgl.9XOl6IMjsi"
    ]
    
    for hash_string in hashes_to_analyze:
        analyze_hash(hash_string)
    
    print("\nEJERCICIO 2: CÁLCULO DE HASHES PARA 'Passw0rd!'")
    print("-" * 60)
    
    password = "Passw0rd!"
    print(f"Calculando hashes para la contraseña: {password}")
    
    hashes = calculate_hashes(password)
    
    for algo, hash_value in hashes.items():
        print(f"\n{algo}:")
        print(f"{hash_value}")
    
    print("\n" + "=" * 80)
    print("Menu")
    print("=" * 80)
    
    while True:
        print("\nOpciones:")
        print("1. Analizar un hash")
        print("2. Calcular hashes para una contraseña")
        print("3. Salir")
        
        choice = input("\nElija una opción (1-3): ")
        
        if choice == '1':
            hash_to_analyze = input("Ingrese el hash a analizar: ")
            analyze_hash(hash_to_analyze)
        
        elif choice == '2':
            password = input("Ingrese la contraseña para calcular sus hashes: ")
            hashes = calculate_hashes(password)
            
            for algo, hash_value in hashes.items():
                print(f"\n{algo}:")
                print(f"{hash_value}")
        
        elif choice == '3':
            print("Gracias por utilizar este programa. ¡Hasta luego!")
            break
        
        else:
            print("Opción no válida. Intente de nuevo.")

if __name__ == "__main__":
    main()
