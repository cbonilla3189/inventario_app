import secrets
import sqlite3
import os
import datetime
from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
import re

app = Flask(__name__)

# Ruta principal
@app.route('/')
def home():
    return render_template('base_index.html')

# Ruta de login (puedes expandirla luego)
@app.route('/login')
def login():
    return '<h2>Página de login (en construcción)</h2>'

@app.route('/register')
def register():
    return '<h2>Página de login (en construcción)</h2>'

@app.route('/nosotros')
def nosotros():
    return '<h2>Página de login (en construcción)</h2>'

@app.route('/contacto')
def contacto():
    return '<h2>Página de login (en construcción)</h2>'

if __name__ == '__main__':
    # Usa 127.0.0.1 para evitar conflictos de red
    # Usa un puerto alto como 5050 para evitar restricciones
    app.run(debug=True, host='127.0.0.1', port=5050)