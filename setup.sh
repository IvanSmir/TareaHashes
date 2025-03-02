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