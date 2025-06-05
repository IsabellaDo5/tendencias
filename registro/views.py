import sqlite3
from django.views import View
from django.shortcuts import render, redirect
from django.contrib import messages
from django.conf import settings
import hashlib
import os
class InicioView(View):
    def get(self, request):
        return render(request,'registro/index.html')

class RegistroView(View):
    def get(self, request):
        return render(request, 'registro/registro.html')

    def post(self, request):
        email = request.POST['email']
        password = request.POST['password']
        confirmPassword = request.POST['confirmPassword']

        if password != confirmPassword:
            return render(request, 'registro/registro.html', {
                'error': 'Las contraseñas no coinciden.'
            })

        # Encriptar la contraseña usando PBKDF2
        salt = os.urandom(16)
        hashed_password = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000
        )
        # Guardar salt y hash juntos (hex)
        password_storage = salt.hex() + ':' + hashed_password.hex()

        # Ruta a la base de datos SQLite
        db_path = os.path.join(settings.BASE_DIR, 'db.sqlite3')
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            # Crear tabla si no existe
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS usuarios (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE,
                    password TEXT
                )
            ''')
            # Insertar usuario
            cursor.execute(
                'INSERT INTO usuarios (email, password) VALUES (?, ?)',
                (email, password_storage)
            )
            conn.commit()
            conn.close()
            return render(request, 'registro/index.html', {
                'success': '¡Registro exitoso!'
            })
        except sqlite3.IntegrityError:
            return render(request, 'registro/registro.html', {
                'error': 'Ya existe otra cuenta con este correo, por favor ingrese otro diferente.'
            })
        except Exception as e:
            return render(request, 'registro/registro.html', {
                'error': f'Ocurrió un error: {str(e)}'
            })