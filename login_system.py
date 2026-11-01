"""Reusable SQLite email-code authentication; application profiles stay in the host app."""
import hashlib
import hmac
import re
import secrets
import uuid


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), expires_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS verification_codes (email TEXT PRIMARY KEY, code_hash TEXT NOT NULL, expires_at REAL NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, created_at REAL NOT NULL);
"""


class AuthError(Exception):
    def __init__(self, message, status=400, field=None):
        super().__init__(message)
        self.status, self.field = status, field


def digest(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


class EmailCodeAuth:
    def __init__(self, conn, now, domain, demo=False):
        self.conn, self.now, self.domain, self.demo = conn, now, domain.lower(), demo

    def email(self, data):
        value = data.get('email', '')
        if not isinstance(value, str) or not value.strip() or len(value) > 254:
            raise AuthError('请填写有效邮箱', field='email')
        email = value.strip().lower()
        local, separator, domain = email.rpartition('@')
        if not separator or domain != self.domain or '..' in local or not re.fullmatch(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+", local, re.ASCII):
            raise AuthError(f'仅支持 @{self.domain} 邮箱', field='email')
        return email

    def issue_code(self, data, send=None):
        email = self.email(data)
        previous = self.conn.execute('SELECT created_at FROM verification_codes WHERE email=?', (email,)).fetchone()
        if not self.demo and previous and self.now - previous['created_at'] < 60:
            raise AuthError('验证码已发送，请 60 秒后再试', 429)
        code = f'{secrets.randbelow(1000000):06d}'
        if not self.demo:
            if send is None:
                raise AuthError('邮件服务尚未配置', 503)
            send(email, code)
        self.conn.execute('INSERT INTO verification_codes (email,code_hash,expires_at,attempts,created_at) VALUES (?,?,?,0,?) ON CONFLICT(email) DO UPDATE SET code_hash=excluded.code_hash,expires_at=excluded.expires_at,attempts=0,created_at=excluded.created_at', (email, digest(email + ':' + code), self.now + 600, self.now))
        result = {'message': '演示验证码已生成（未发送邮件）' if self.demo else '验证码已发送，请检查校园邮箱'}
        if self.demo:
            result['demoCode'] = code
        return result

    def verify_code(self, data):
        email = self.email(data)
        code = data.get('code', '')
        if not isinstance(code, str) or not 0 < len(code.strip()) <= 12:
            raise AuthError('请填写验证码', field='code')
        code = code.strip()
        record = self.conn.execute('SELECT * FROM verification_codes WHERE email=?', (email,)).fetchone()
        if not record or self.now >= record['expires_at']:
            raise AuthError('验证码不存在或已过期，请重新获取', 400, 'code')
        if record['attempts'] >= 5:
            raise AuthError('验证码尝试次数过多，请重新获取', 429, 'code')
        if not hmac.compare_digest(record['code_hash'], digest(email + ':' + code)):
            self.conn.execute('UPDATE verification_codes SET attempts=attempts+1 WHERE email=?', (email,))
            # Failed attempts must survive the host request's error rollback.
            self.conn.commit()
            raise AuthError('验证码不正确，请重新输入', 400, 'code')
        self.conn.execute('DELETE FROM verification_codes WHERE email=?', (email,))
        user = self.conn.execute('SELECT id FROM users WHERE email=?', (email,)).fetchone()
        user_id = user['id'] if user else uuid.uuid4().hex
        if not user:
            self.conn.execute('INSERT INTO users (id,email) VALUES (?,?)', (user_id, email))
        return user_id

    def user_for_session(self, token):
        if not token:
            return None
        return self.conn.execute('SELECT u.* FROM users u JOIN sessions s ON s.user_id=u.id WHERE s.token_hash=? AND s.expires_at>?', (digest(token), self.now)).fetchone()

    def sign_in(self, user_id, previous_token=''):
        if previous_token:
            self.logout(previous_token)
        token = secrets.token_urlsafe(32)
        self.conn.execute('INSERT INTO sessions (token_hash,user_id,expires_at) VALUES (?,?,?)', (digest(token), user_id, self.now + 7 * 86400))
        return token

    def logout(self, token):
        if token:
            self.conn.execute('DELETE FROM sessions WHERE token_hash=?', (digest(token),))
