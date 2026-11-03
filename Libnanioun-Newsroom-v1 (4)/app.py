"""Libnanioun Newsroom: editorial drafts, official Facebook Pages publishing,
and manual preparation of WhatsApp Channel updates.
"""
import hmac
import os
import secrets
import sqlite3
import uuid
from datetime import datetime
from functools import wraps
from io import BytesIO
from pathlib import Path
from urllib.parse import urlparse
from zoneinfo import ZoneInfo

import requests
from flask import (
    Flask, abort, flash, redirect, render_template, request, send_from_directory,
    session, url_for,
)
from PIL import Image, ImageOps, UnidentifiedImageError

BASE = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get('DATA_DIR', str(BASE / 'data')))
UPLOAD_DIR = DATA_DIR / 'uploads'
DATA_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / 'newsroom.sqlite3'

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
app.config['MAX_CONTENT_LENGTH'] = 12 * 1024 * 1024
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.environ.get('RENDER', '').lower() == 'true',
)
AR_TZ = ZoneInfo('Asia/Beirut')


def now_str():
    return datetime.now(AR_TZ).strftime('%Y-%m-%d %H:%M:%S')


def db():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS articles (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          title TEXT NOT NULL,
          body TEXT NOT NULL DEFAULT '',
          source_name TEXT NOT NULL DEFAULT '',
          source_url TEXT NOT NULL DEFAULT '',
          breaking INTEGER NOT NULL DEFAULT 0,
          image_filename TEXT,
          status TEXT NOT NULL DEFAULT 'draft',
          facebook_post_id TEXT,
          facebook_error TEXT,
          whatsapp_done INTEGER NOT NULL DEFAULT 0,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          published_at TEXT
        )''')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_articles_created ON articles(created_at DESC)')


init_db()


def get_article(article_id):
    with db() as conn:
        result = conn.execute('SELECT * FROM articles WHERE id = ?', (article_id,)).fetchone()
    if result is None:
        abort(404)
    return result


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return fn(*args, **kwargs)
    return wrapper


def csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_urlsafe(32)
    return session['csrf_token']


app.jinja_env.globals['csrf_token'] = csrf_token


@app.before_request
def check_post_csrf():
    if request.method == 'POST':
        provided = request.form.get('csrf_token', '')
        expected = session.get('csrf_token', '')
        if not expected or not hmac.compare_digest(provided, expected):
            abort(400, 'انتهت الجلسة أو رمز التحقق غير صحيح. حدّث الصفحة وحاول مجدداً.')


@app.after_request
def harden_response(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Cache-Control'] = 'no-store'
    return response


@app.context_processor
def template_helpers():
    return {'channel_url': os.environ.get('WHATSAPP_CHANNEL_URL', '').strip(),
            'facebook_is_configured': bool(os.environ.get('FACEBOOK_PAGE_ID') and
                                           os.environ.get('FACEBOOK_PAGE_ACCESS_TOKEN'))}


@app.route('/healthz')
def healthz():
    return {'status': 'ok'}


@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('logged_in'):
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = os.environ.get('ADMIN_USERNAME', 'admin')
        password = os.environ.get('ADMIN_PASSWORD', '')
        given_username = request.form.get('username', '')
        given_password = request.form.get('password', '')
        if (password and hmac.compare_digest(username, given_username) and
                hmac.compare_digest(password, given_password)):
            session.clear()
            session['logged_in'] = True
            session['csrf_token'] = secrets.token_urlsafe(32)
            return redirect(url_for('index'))
        flash('اسم المستخدم أو كلمة المرور غير صحيحين، أو كلمة مرور الإدارة غير مضبوطة.', 'error')
    return render_template('login.html')


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/')
@login_required
def index():
    with db() as conn:
        articles = conn.execute('SELECT * FROM articles ORDER BY id DESC LIMIT 100').fetchall()
        counts = conn.execute('''SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN status = 'draft' THEN 1 ELSE 0 END) AS drafts,
            SUM(CASE WHEN status = 'published' THEN 1 ELSE 0 END) AS published,
            SUM(CASE WHEN status = 'published' AND whatsapp_done = 0 THEN 1 ELSE 0 END) AS pending_wa
            FROM articles''').fetchone()
    return render_template('index.html', articles=articles, counts=counts)


def valid_source_url(raw):
    if not raw:
        return ''
    parsed = urlparse(raw)
    if parsed.scheme not in ('https', 'http') or not parsed.netloc:
        raise ValueError('رابط المصدر لازم يبدأ بـ https:// أو http://')
    return raw


def save_image(file):
    if not file or not file.filename:
        return None
    data = file.read(12 * 1024 * 1024 + 1)
    if len(data) > 12 * 1024 * 1024:
        raise ValueError('حجم الصورة أكبر من 12 ميغابايت.')
    try:
        image = Image.open(BytesIO(data))
        image.verify()
        image = Image.open(BytesIO(data))
        image = ImageOps.exif_transpose(image)
        image.thumbnail((2400, 2400))
        if image.mode == 'RGBA':
            background = Image.new('RGB', image.size, 'white')
            background.paste(image, mask=image.getchannel('A'))
            image = background
        else:
            image = image.convert('RGB')
    except (UnidentifiedImageError, OSError, ValueError) as exc:
        raise ValueError('الملف المرفوع ليس صورة صالحة.') from exc
    filename = f'{uuid.uuid4().hex}.jpg'
    image.save(UPLOAD_DIR / filename, 'JPEG', quality=88, optimize=True)
    return filename


def article_from_form(old_image=None):
    title = request.form.get('title', '').strip()
    body = request.form.get('body', '').strip()
    source_name = request.form.get('source_name', '').strip()
    source_url = valid_source_url(request.form.get('source_url', '').strip())
    if not title or len(title) > 250:
        raise ValueError('اكتب عنوان الخبر (حتى 250 حرف).')
    if len(body) > 10000:
        raise ValueError('نص الخبر طويل جداً (الحد 10,000 حرف).')
    if len(source_name) > 250:
        raise ValueError('اسم المصدر طويل جداً.')
    if len(source_url) > 1200:
        raise ValueError('رابط المصدر طويل جداً.')
    image_filename = save_image(request.files.get('image')) or old_image
    return (title, body, source_name, source_url,
            int(request.form.get('breaking') == '1'), image_filename)


@app.route('/new', methods=['GET', 'POST'])
@login_required
def new_article():
    if request.method == 'POST':
        try:
            fields = article_from_form()
        except ValueError as exc:
            flash(str(exc), 'error')
            return render_template('editor.html', article=None), 400
        with db() as conn:
            cur = conn.execute('''INSERT INTO articles (
                 title,body,source_name,source_url,breaking,image_filename,created_at,updated_at)
                 VALUES (?,?,?,?,?,?,?,?)''', (*fields, now_str(), now_str()))
            article_id = cur.lastrowid
        flash('تم حفظ الخبر كمسودة. ما نُشر شيء بعد.', 'success')
        return redirect(url_for('article_detail', article_id=article_id))
    return render_template('editor.html', article=None)


@app.route('/news/<int:article_id>')
@login_required
def article_detail(article_id):
    return render_template('detail.html', article=get_article(article_id),
                           channel_text=format_channel_text(get_article(article_id)))


@app.route('/news/<int:article_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_article(article_id):
    article = get_article(article_id)
    if article['status'] != 'draft':
        flash('يمكن تعديل المسودات فقط. المنشور على فيسبوك لا يتغيّر تلقائياً.', 'error')
        return redirect(url_for('article_detail', article_id=article_id))
    if request.method == 'POST':
        try:
            fields = article_from_form(article['image_filename'])
        except ValueError as exc:
            flash(str(exc), 'error')
            return render_template('editor.html', article=article), 400
        with db() as conn:
            conn.execute('''UPDATE articles SET title=?,body=?,source_name=?,source_url=?,
                breaking=?,image_filename=?,updated_at=?,facebook_error=NULL
                WHERE id=? AND status='draft' ''', (*fields, now_str(), article_id))
        flash('تم تعديل المسودة.', 'success')
        return redirect(url_for('article_detail', article_id=article_id))
    return render_template('editor.html', article=article)


def format_channel_text(article):
    parts = []
    if article['breaking']:
        parts.append('🔴 عاجل | لبنانيون للأخبار العاجلة')
    parts.append(article['title'])
    if article['body']:
        parts.append(article['body'])
    if article['source_name']:
        parts.append('المصدر: ' + article['source_name'])
    if article['source_url']:
        parts.append(article['source_url'])
    parts.append('🇱🇧 لبنانيون للأخبار العاجلة')
    return '\n\n'.join(parts)


def publish_to_facebook(article):
    page_id = os.environ.get('FACEBOOK_PAGE_ID', '').strip()
    token = os.environ.get('FACEBOOK_PAGE_ACCESS_TOKEN', '').strip()
    version = os.environ.get('GRAPH_API_VERSION', 'v26.0').strip()
    if not page_id or not token:
        raise ValueError('ربط فيسبوك غير مكتمل. أضف FACEBOOK_PAGE_ID و FACEBOOK_PAGE_ACCESS_TOKEN بإعدادات Render.')
    if not version.startswith('v') or any(c not in 'v0123456789.' for c in version):
        raise ValueError('إصدار Graph API غير صالح.')
    base_url = f'https://graph.facebook.com/{version}/{page_id}'
    message = format_channel_text(article)
    headers = {'Authorization': f'Bearer {token}'}
    if article['image_filename']:
        image_path = UPLOAD_DIR / article['image_filename']
        if not image_path.is_file():
            raise ValueError('الصورة غير موجودة على الخادم. تأكد من مساحة التخزين الدائمة.')
        with image_path.open('rb') as image_file:
            response = requests.post(base_url + '/photos',
                headers=headers,
                data={'caption': message, 'published': 'true'},
                files={'source': ('news.jpg', image_file, 'image/jpeg')}, timeout=35)
    else:
        response = requests.post(base_url + '/feed',
            headers=headers, data={'message': message, 'published': 'true'}, timeout=35)
    try:
        result = response.json()
    except ValueError:
        result = {}
    if not response.ok:
        err = result.get('error', {})
        explanation = err.get('message', 'تعذر النشر على فيسبوك.')
        raise ValueError(f'رفض فيسبوك النشر: {explanation[:450]}')
    post_id = result.get('post_id') or result.get('id')
    if not post_id:
        raise RuntimeError('لم يرجع فيسبوك معرّف منشور. تحقق من الصفحة يدوياً قبل إعادة المحاولة.')
    return str(post_id)


@app.route('/news/<int:article_id>/publish', methods=['POST'])
@login_required
def publish_article(article_id):
    if request.form.get('editor_approved') != 'yes':
        flash('يجب تأكيد تدقيق الخبر والمصدر قبل النشر.', 'error')
        return redirect(url_for('article_detail', article_id=article_id))
    with db() as conn:
        conn.execute('BEGIN IMMEDIATE')
        article = conn.execute('SELECT * FROM articles WHERE id=?', (article_id,)).fetchone()
        if not article:
            abort(404)
        if article['status'] != 'draft':
            flash('الخبر لم يعد مسودة. لن ننشره مرتين.', 'error')
            return redirect(url_for('article_detail', article_id=article_id))
        conn.execute('UPDATE articles SET status=?,facebook_error=NULL WHERE id=?',
                     ('publishing', article_id))
    try:
        post_id = publish_to_facebook(article)
    except ValueError as exc:
        with db() as conn:
            conn.execute('UPDATE articles SET status=?,facebook_error=? WHERE id=?',
                         ('draft', str(exc), article_id))
        flash(str(exc), 'error')
    except requests.RequestException:
        with db() as conn:
            conn.execute('UPDATE articles SET status=?,facebook_error=? WHERE id=?',
                         ('check', 'الاتصال بفيسبوك انقطع أو انتهت مهلته. تحقق من الصفحة قبل أي إعادة نشر.', article_id))
        flash('الاتصال بفيسبوك انقطع. افحص الصفحة بنفسك قبل إعادة المحاولة لتفادي منشور مكرر.', 'error')
    except Exception:
        app.logger.exception('Facebook publish: unexpected failure')
        with db() as conn:
            conn.execute('UPDATE articles SET status=?,facebook_error=? WHERE id=?',
                         ('check', 'حالة النشر غير مؤكدة. تحقق من صفحة فيسبوك يدوياً.', article_id))
        flash('حالة النشر غير مؤكدة. تفقد صفحة فيسبوك قبل محاولة أخرى.', 'error')
    else:
        with db() as conn:
            conn.execute('''UPDATE articles SET status=?,facebook_post_id=?,facebook_error=NULL,
                    published_at=?,updated_at=? WHERE id=?''',
                    ('published', post_id, now_str(), now_str(), article_id))
        flash('نُشر الخبر على فيسبوك بنجاح. الآن انسخ النص وافتح قناة واتساب.', 'success')
    return redirect(url_for('article_detail', article_id=article_id))


@app.route('/news/<int:article_id>/mark-whatsapp', methods=['POST'])
@login_required
def mark_whatsapp(article_id):
    article = get_article(article_id)
    if article['status'] != 'published':
        flash('انشر الخبر على فيسبوك أولاً.', 'error')
    else:
        with db() as conn:
            conn.execute('UPDATE articles SET whatsapp_done=1,updated_at=? WHERE id=?',
                         (now_str(), article_id))
        flash('تم تسجيل أنك نشرت الخبر يدوياً بقناة واتساب.', 'success')
    return redirect(url_for('article_detail', article_id=article_id))


@app.route('/news/<int:article_id>/reset-whatsapp', methods=['POST'])
@login_required
def reset_whatsapp(article_id):
    get_article(article_id)
    with db() as conn:
        conn.execute('UPDATE articles SET whatsapp_done=0,updated_at=? WHERE id=?',
                     (now_str(), article_id))
    flash('أُعيد الخبر لقائمة انتظار واتساب.', 'success')
    return redirect(url_for('article_detail', article_id=article_id))


@app.route('/uploads/<path:filename>')
@login_required
def uploaded_image(filename):
    if '/' in filename or '\\' in filename or not filename.endswith('.jpg'):
        abort(404)
    return send_from_directory(UPLOAD_DIR, filename, mimetype='image/jpeg', as_attachment=False)


@app.errorhandler(413)
def too_large(_):
    flash('حجم الملف كبير. الحد الأقصى 12 ميغابايت.', 'error')
    return redirect(url_for('new_article'))


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=int(os.environ.get('PORT', 5000)), debug=False)
