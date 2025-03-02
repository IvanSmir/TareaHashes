# Hash Decoder Tool - README

This tool try to identify hash types and decode Base64 encoded strings. It also calculates multiple hash formats for passwords and provides an interactive command-line interface.

## Features

- Identifies hash types (MD5, SHA-512, Bcrypt, Base64)
- Decodes Base64 encoded strings to plain text
- Calculates multiple hash formats for passwords (MD5, SHA-1, SHA-256, SHA-512, Bcrypt, Argon2i)
- Interactive command-line interface (CLI)

## Requirements

- Python 3.6+
- Required packages:
  - bcrypt
  - argon2-cffi

## Installation

### Windows

1. run `.\setup.bat`

```bat
@echo off
REM
python -m venv venv

REM
call venv\Scripts\activate && (
    REM
    pip install -r requirements.txt

    REM
    python hash_decoder.py
)
```

### Linux/macOS

1. make the script executable

```bash
chmod +x setup.sh
```

2. run `./setup.sh`

```bash
#!/bin/bash

# Crear entorno virtual (si no existe)
python3 -m venv venv

# Activar entorno virtual y ejecutar todo en el mismo contexto
source venv/bin/activate && {
    # Instalar dependencias
    pip install -r requirements.txt

    # Ejecutar script
    python hash_decoder.py
}
```

## Usage

The tool has three main options:

1. **Analyze a hash** - Identify hash type and get information
2. **Calculate hashes** - Generate multiple hash formats for a password
3. **Exit** - Close the program

## Example

When you run the script, it will:

1. Analyze sample hashes
2. Calculate hashes for "Passw0rd!"
3. Enter interactive mode

## Limitations

- Hash identification is based on format and may not always be accurate
- Cryptographic hashes cannot be "decoded" as they are one-way functions Only Base64 encoded strings can be decoded directly
