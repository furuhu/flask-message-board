# app.py (完整更新 Part 12 - PostgreSQL + SQLAlchemy)
import datetime
import os
# 移除 sqlite3 匯入
# 新增匯入 SQLAlchemy 和相關工具
from flask import Flask, render_template, request, redirect, url_for, flash, session, g, abort
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# --- SQLAlchemy 設定 ---
# 從環境變數讀取資料庫 URL
db_url = os.environ.get('DATABASE_URL')
if db_url and db_url.startswith("postgres://"):
    # Render 提供的 URL 可能以 postgres:// 開頭，SQLAlchemy 需要 postgresql://
    db_url = db_url.replace("postgres://", "postgresql://", 1)

# 設定資料庫 URI 和關閉追蹤修改 (節省資源)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url or 'sqlite:///database.db' # 提供本地 SQLite 作為備用
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'fallback-secret-key-for-dev-only-change-me')

# 初始化 SQLAlchemy
db = SQLAlchemy(app)

# --- 資料庫模型 (取代 schema.sql) ---
class User(db.Model):
    """使用者模型"""
    __tablename__ = 'users' # 可選：明確指定表名
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False) # 儲存雜湊後的密碼，需要足夠長度
    # 定義一對多關係：一個使用者可以有多條訊息
    # backref='author' 讓我們可以透過 Message 物件用 message.author 訪問其 User 物件
    # lazy=True 表示相關訊息只有在被訪問時才會從資料庫載入
    messages = db.relationship('Message', backref='author', lazy=True)

    def __repr__(self): # 可選：定義物件的字串表示
        return f'<User {self.username}>'

class Message(db.Model):
    """訊息模型"""
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow) # 使用 UTC 時間
    # 定義外鍵，關聯到 users 表的 id 欄位
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    def __repr__(self):
        return f'<Message {self.id}>'

# --- 使用 db.create_all() 自動建立資料表 ---
# 這個函數會檢查資料庫中是否存在模型對應的表，如果不存在則建立
# 注意：這不會處理後續的表格修改 (需要資料庫遷移工具如 Flask-Migrate)
def init_db_on_startup():
    """檢查並建立所有資料庫表格"""
    print("Attempting to initialize database tables...")
    try:
        # 需要在應用程式上下文中執行
        with app.app_context():
            db.create_all()
        print("Database tables checked/created.")
    except Exception as e:
        print(f"Error during db.create_all(): {e}")

# --- 移除舊的 init-db CLI 指令 ---

# --- 使用者載入 (使用 SQLAlchemy) ---
@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id')
    if user_id is None:
        g.user = None
    else:
        # 使用 SQLAlchemy 的 query.get() 來根據主鍵查詢使用者
        g.user = User.query.get(user_id)
        # 注意：這裡 g.user 是一個 User 物件，而不是之前的字典

# --- 表單 (同之前) ---
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(message="請輸入使用者名稱。"), Length(min=4, max=25, message="長度需在 4 到 25 之間。")])
    password = PasswordField('Password', validators=[DataRequired(message="請輸入密碼。"), Length(min=6, message="密碼長度至少需 6 位。")])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(message="請再次輸入密碼。"),
                                                 EqualTo('password', message='兩次輸入的密碼必須相符。')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        # 使用 SQLAlchemy 查詢使用者是否存在
        user = User.query.filter_by(username=username.data).first()
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

# --- 路由 (使用 SQLAlchemy) ---
@app.route('/', methods=['GET', 'POST'])
def index():
    form = MessageForm()
    if g.user and form.validate_on_submit():
        message_content = form.content.data
        user_id = g.user.id # 從 User 物件取得 ID
        # --- 使用 SQLAlchemy 新增訊息 ---
        new_message = Message(content=message_content, user_id=user_id) # 建立 Message 物件
        db.session.add(new_message) # 加入到 session
        try:
            db.session.commit() # 提交到資料庫
        except Exception as e:
            db.session.rollback() # 如果出錯，回滾變更
            flash(f"儲存訊息時發生錯誤: {e}", "danger")
        # --- 新增結束 ---
        return redirect(url_for('index'))

    # --- 使用 SQLAlchemy 查詢訊息 ---
    # Message.query 會回傳一個查詢物件
    # .order_by(Message.created.desc()) 依照建立時間降序排列
    # .all() 執行查詢並取得所有結果 (Message 物件的列表)
    # 注意：因為設定了 backref='author'，可以直接透過 message.author.username 取得使用者名稱
    messages_from_db = Message.query.order_by(Message.created.desc()).all()
    # --- 查詢結束 ---

    now = datetime.datetime.now()
    current_time_str = now.strftime("%Y-%m-%d %H:%M:%S")
    page_title = "Flask + PostgreSQL"

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
        # --- 使用 SQLAlchemy 新增使用者 ---
        new_user = User(username=username, password=hashed_password) # 建立 User 物件
        db.session.add(new_user)
        try:
            db.session.commit()
            flash('Account created! You can now log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e: # 更通用的錯誤處理，捕捉可能的 IntegrityError 等
            db.session.rollback()
            flash(f'Registration failed. Error: {e}', 'danger')
        # --- 新增結束 ---
    return render_template('register.html', the_title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if g.user:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        # --- 使用 SQLAlchemy 查詢使用者 ---
        user = User.query.filter_by(username=username).first() # 根據使用者名稱查詢
        # --- 查詢結束 ---
        if user and check_password_hash(user.password, password): # 從 User 物件取得雜湊密碼
            session.clear()
            session['user_id'] = user.id # 從 User 物件取得 ID
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
    # --- 使用 SQLAlchemy 查詢要刪除的訊息 ---
    # query.get_or_404(id) 如果找不到會自動回傳 404 錯誤
    message_to_delete = Message.query.get_or_404(message_id)
    # --- 查詢結束 ---

    # 檢查擁有權
    if message_to_delete.author != g.user: # 可以直接比較 User 物件
        abort(403)

    # --- 使用 SQLAlchemy 刪除訊息 ---
    db.session.delete(message_to_delete)
    try:
        db.session.commit()
        flash('Message deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting message: {e}', 'danger')
    # --- 刪除結束 ---
    return redirect(url_for('index'))

# --- 確保在應用程式啟動時檢查並建立資料表 ---
# 需要在 app context 中執行
with app.app_context():
    init_db_on_startup()

# if __name__ == '__main__':
#    # 本地開發時，如果沒有設定 DATABASE_URL 環境變數，會使用 sqlite:///database.db
#    app.run(debug=True)