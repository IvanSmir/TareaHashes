@echo off
REM Crear entorno virtual (si no existe)
python -m venv venv

REM Activar entorno virtual y ejecutar todo en el mismo contexto
call venv\Scripts\activate && (
    REM Instalar dependencias
    pip install -r requirements.txt
    
    REM Ejecutar script
    python hash_decoder.py
)