from flask import Flask, render_template, request, redirect, session, url_for,  flash
from config import DB, CURSOR
import bcrypt
import hashlib  # <-- Adicione esta linha aqui

app = Flask(__name__)
app.secret_key = 'supersecretkey'



app = Flask(__name__)
app.secret_key = 'supersecretkey'

@app.route('/')
def index():
    return render_template('index.html')

import base64

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')  # Codifica pra bytes

        CURSOR.execute("SELECT * FROM usuarios WHERE username = %s", (username,))
        user = CURSOR.fetchone()

        if user:
            stored_password = user[2].encode('utf-8')  # Garante codificação

            # Verifica a senha com bcrypt
            if bcrypt.checkpw(password, stored_password):
                session['loggedin'] = True
                session['id'] = user[0]
                session['username'] = user[1]
                session['role'] = user[3]

                if user[3] == 'admin':
                    return redirect(url_for('admin_area'))
                else:
                    return redirect(url_for('user_area'))

        return "Login falhou"

    return render_template('login.html')

@app.route('/user')
def user_area():
    if 'loggedin' in session and session['role'] == 'user':
        return render_template('user_area.html', username=session['username'])
    return redirect(url_for('login'))

@app.route('/admin')
def admin_area():
    if 'loggedin' in session and session['role'] == 'admin':
        return render_template('admin_area.html', username=session['username'])
    return redirect(url_for('login'))
# --- ROTA DE CADASTRO ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Validação simples
        if not username or not password or not confirm_password:
            flash("Todos os campos são obrigatórios.")
            return render_template('register.html')

        if password != confirm_password:
            flash("As senhas não coincidem.")
            return render_template('register.html')

        # Verifica se o usuário já existe
        CURSOR.execute("SELECT * FROM usuarios WHERE username = %s", (username,))
        existing_user = CURSOR.fetchone()

        if existing_user:
            flash("Nome de usuário já existe.")
            return render_template('register.html')

        # Gera hash da senha com bcrypt
        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Insere no banco
        CURSOR.execute(
            "INSERT INTO usuarios (username, password, role) VALUES (%s, %s, 'user')",
            (username, hashed_pw)
        )
        DB.commit()

        flash("Cadastro realizado com sucesso! Faça login.")
        return redirect(url_for('login'))

    return render_template('register.html')
if __name__ == '__main__':
    app.run(debug=True)