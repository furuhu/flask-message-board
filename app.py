# app.py (完整更新 - 準備 Part 12 部署)
import datetime
import sqlite3
import os # <--- 確保匯入 os 模組
# 從 flask 匯入 Flask, render_template, request, redirect, url_for, flash, session, g, abort
from flask import Flask, render_template, request, redirect, url_for, flash, session, g, abort
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# --- 修改：從環境變數讀取 SECRET_KEY ---
# os.environ.get('SECRET_KEY', '...') 會嘗試讀取名為 'SECRET_KEY' 的環境變數
# 如果環境變數不存在 (例如在本地開發時未設定)，則使用後面提供的預設字串
# 這個預設字串不應該在生產環境中使用！我們會在 Render 上設定真正的 SECRET_KEY 環境變數。
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a_very_secret_key_for_dev_only_change_me')
# --- SECRET_KEY 設定結束 ---


# --- 表單定義 (同 Part 11a) ---
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(message="請輸入使用者名稱。"), Length(min=4, max=25, message="長度需在 4 到 25 之間。")])
    password = PasswordField('Password', validators=[DataRequired(message="請輸入密碼。"), Length(min=6, message="密碼長度至少需 6 位。")])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(message="請再次輸入密碼。"),
                                                 EqualTo('password', message='兩次輸入的密碼必須相符。')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        conn = get_db_connection()
        user = conn.execute('SELECT id FROM users WHERE username = ?', (username.data,)).fetchone()
        conn.close()
        if user:
            raise ValidationError('這個使用者名稱已經有人用了，請選用其他名稱。')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(message="請輸入使用者名稱。")])
    password = PasswordField('Password', validators=[DataRequired(message="請輸入密碼。")])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class MessageForm(FlaskForm):
    content = StringField('Message:', validators=[DataRequired(message="訊息不能為空！")])
    submit = SubmitField('Submit Message')


# --- 資料庫函數 (同 Part 11b) ---
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.cli.command('init-db')
def init_db_command():
    """清除現有資料並根據 schema.sql 建立新表。"""
    conn = get_db_connection()
    with open('schema.sql') as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()
    print('Initialized the database.')

# --- 使用者載入 (同 Part 11a) ---
@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id')
    if user_id is None:
        g.user = None
    else:
        conn = get_db_connection()
        g.user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        conn.close()

# --- 路由 (同 Part 11b) ---
@app.route('/', methods=['GET', 'POST'])
def index():
    form = MessageForm()
    if g.user and form.validate_on_submit():
        message_content = form.content.data
        user_id = g.user['id']
        conn = get_db_connection()
        conn.execute('INSERT INTO messages (content, user_id) VALUES (?, ?)',
                   (message_content, user_id))
        conn.commit()
        conn.close()
        return redirect(url_for('index'))

    conn = get_db_connection()
    messages_from_db = conn.execute(
        'SELECT m.id, m.created, m.content, m.user_id, u.username '
        'FROM messages m JOIN users u ON m.user_id = u.id '
        'ORDER BY m.id DESC'
    ).fetchall()
    conn.close()

    now = datetime.datetime.now()
    current_time_str = now.strftime("%Y-%m-%d %H:%M:%S")
    page_title = "Flask 留言板 (準備部署)" # 更新標題
    # 更新功能列表
    features = ["Templates", "Static", "Routes", "Data", "Forms", "DB", "WTForms", "Layouts", "Delete", "Auth+Assoc", "準備部署!"]

    return render_template('index.html',
                           the_title=page_title,
                           current_time=current_time_str,
                           messages=messages_from_db,
                           form=form)

@app.route('/about')
def about():
    page_title = "關於我們"
    return render_template('about.html', the_title=page_title)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if g.user:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        hashed_password = generate_password_hash(form.password.data)
        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (username, password) VALUES (?, ?)',
                       (username, hashed_password))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            flash('Registration failed, username might already exist.', 'danger')
            return render_template('register.html', the_title='Register', form=form)
        except Exception as e:
             conn.close()
             flash(f'An error occurred during registration: {e}', 'danger')
             return render_template('register.html', the_title='Register', form=form)
        conn.close()
        flash('Account created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', the_title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if g.user:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        if user and check_password_hash(user['password'], password):
            session.clear()
            session['user_id'] = user['id']
            flash('Login successful!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Login unsuccessful. Please check username and password.', 'danger')
    return render_template('login.html', the_title='Login', form=form)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/delete/<int:message_id>', methods=['POST'])
def delete(message_id):
    if not g.user:
        abort(403)
    conn = get_db_connection()
    message = conn.execute('SELECT user_id FROM messages WHERE id = ?', (message_id,)).fetchone()
    if message is None:
        conn.close()
        abort(404)
    if message['user_id'] != g.user['id']:
        conn.close()
        abort(403)
    conn.execute('DELETE FROM messages WHERE id = ?', (message_id,))
    conn.commit()
    conn.close()
    flash('Message deleted successfully!', 'success')
    return redirect(url_for('index'))

# if __name__ == '__main__':
#    app.run(debug=True)