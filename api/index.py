import re
import uuid
import pymongo
from bson import ObjectId
from flask import Flask, render_template, request, session, redirect, url_for, abort, send_from_directory
import cloudinary
import cloudinary.uploader
import bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from api.mail import send_confirmation_link

cloudinary.config(
    cloud_name="cloud_name",
    api_key="api_key",
    api_secret="api_secret"
)

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024
app.secret_key = "lwittr alpha ver"
mongo_url = "mongodb://localhost:27017"
client = pymongo.MongoClient(mongo_url)

db = client.get_database('lwittr')
users = db.users
verification = db.verification
allowed_image_mime_types = {'image/gif', 'image/jpeg', 'image/pjpeg', 'image/png'}

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "100 per hour"],
    storage_uri=mongo_url,
    strategy="fixed-window",
)

from flask import Flask
import requests
import json

app = Flask(__name__)


@app.errorhandler(404)
def page_forbidden(e):
    return send_from_directory('web', '404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    return send_from_directory('web', 'upgrading.html'), 500


@app.errorhandler(403)
def page_forbidden(e):
    return send_from_directory('web', 'upgrading.html'), 403


@app.errorhandler(400)
def bad_request(e):
    return send_from_directory('web', 'upgrading.html'), 400


@app.errorhandler(429)
def too_many_requests(e):
    return render_template('upgrading.html', subtitle="You're being rate limited!", description=str(e)), 429


@app.route('/confirm/<string:email>/<uuid:code>')
@limiter.limit("1/2 minutes")
@limiter.limit("3/day")
def confirm_email(email, code):
    user_found = verification.find_one({"email": email})
    if user_found and str(code) == user_found['code']:
        session["id"] = str(user_found['user_id'])
        if users.update_one(
                {"_id": user_found['user_id']},
                {"$set": {"verified_email": True,
                          "alpha": True}}
        ):
            result = verification.delete_one({"_id": user_found['_id']})
            if result:
                limiter.storage.clear('confirm_email')
                return redirect(url_for('root'))
    print('user not found!')
    abort(404)


def get_ip():
    headers_list = request.headers.getlist("HTTP_X_FORWARDED_FOR")
    http_x_real_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)

    ip_address = headers_list[0] if headers_list else http_x_real_ip
    return ip_address


@app.route('/')
def root():
    if "id" in session:
        my_user = users.find_one({"_id": ObjectId(session["id"])})
        if my_user:
            return render_template('home.html', user=my_user)
        session.pop('id')
        return redirect(url_for('root'))
    return render_template('index.html')


@app.route('/sign_out')
def sign_out():
    session.pop('id')
    return redirect(url_for('root'))


@app.route('/twitter')
def twitter():
    return redirect(url_for('profile', screen_name='lwittr'))


@app.route('/x')
def x():
    return redirect(url_for('profile', screen_name='lwittr'))


@app.route('/blog')
@limiter.exempt
def blog():
    return redirect("https://lwittr.blogspot.com/", code=302)


@app.route('/login', methods=['GET'])
@limiter.exempt
def login():
    return send_from_directory('web', 'login.html')


@app.route('/login', methods=['POST'])
@limiter.limit("3/1 minute")
@limiter.limit("20/hour")
def post_login():
    if request.form:
        username_or_email = request.form.get('username_or_email')
        password = request.form.get('password')
        if len(password) < 6 or len(username_or_email) < 1:
            return render_template('login.html', alert='Invalid login credentials!'), 400
        user_found = users.find_one({"email": username_or_email})

        if not user_found:
            user_found = users.find_one({"screen_name": username_or_email})

        if user_found:
            real_password = user_found['password']

            if bcrypt.checkpw(password.encode('utf-8'), real_password):
                session["id"] = str(user_found["_id"])
                return redirect(url_for('root'))
            else:
                return render_template('login.html', alert="Passwords don't match!"), 400

        return render_template('login.html', alert="Invalid login credentials!"), 400

    abort(400)


@app.route('/create', methods=['GET'])
@limiter.exempt
def create():
    return send_from_directory('web', 'create.html')


@app.route('/create', methods=['POST'])
@limiter.limit("3/2 minutes")
@limiter.limit("10/day")
def post_create():
    supported_languages = ["en", "pt-BR"]
    lang = request.accept_languages.best_match(supported_languages)

    if request.form:
        name = request.form.get('user[name]').strip()
        screen_name = request.form.get('user[screen_name]')
        password = request.form.get('user[password]')
        password_confirmation = request.form.get('password[password_confirmation]')
        protected = request.form.get('user[protected]') == "1"
        email = request.form.get('user[email]')
        timezone = request.form.get('user[time_zone]')

        alert = ''

        user_found = users.find_one({"screen_name": screen_name})

        email_found = users.find_one({"email": email})

        if user_found:
            alert += f'An account already exists with this username ({screen_name})<br>'
        if email_found:
            alert += f'An account already exists with this email ({email})<br>'

        if alert != '':
            return render_template('create.html', alert=alert), 400

        if (
                name and not name == '' and len(name) > 40
        ):
            alert += f'Name must be 40 characters maximum<br>'

        if (
                screen_name.strip() == '' or
                len(screen_name) > 20 or
                len(screen_name) < 1 or
                not re.match('^[a-zA-Z0-9_]+$', screen_name)
        ):
            alert += ('Username must be 20 characters maximum, no spaces and '
                      'only letters, numbers and underscores are allowed.<br>')

        if len(password) < 6:
            alert += 'Password must be at least six characters long<br>'

        if password != password_confirmation:
            alert += 'Passwords do not match<br>'

        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            alert += 'Invalid email address<br>'

        if alert != '':
            return render_template('create.html', alert=alert), 400

        profile_picture = False

        if 'user[profile_image]' in request.files and request.files.get('user[profile_image]').filename != '':
            user_profile_picture = request.files.get('user[profile_image]')
            if user_profile_picture.mimetype not in allowed_image_mime_types:
                return render_template(
                    'create.html',
                    alert='Minimum size for picture 48x48 pixels (jpg, gif, png)'
                ), 400
            upload_result = cloudinary.uploader.upload(user_profile_picture, width=48, height=48, crop="fill")
            if upload_result.get('url') is not None:
                profile_picture = upload_result.get('url')

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        user_data = {
            "name": name,
            "screen_name": screen_name,
            "password": hashed_password,
            "email": email,
            "timezone": timezone,
            "lang": lang,
            "protected": protected,
            "profile_picture": profile_picture
        }

        data = users.insert_one(user_data)
        code = str(uuid.uuid4())
        verify = verification.insert_one({
            "email": email,
            "user_id": data.inserted_id,
            "code": code
        })

        url = f"{request.url_root}{url_for('confirm_email', email=email, code=code)}"

        if data and verify and send_confirmation_link(
                username=screen_name,
                email=email,
                url=url
        ):
            return render_template(
                'upgrading.html',
                title="lwittr / verify",
                subtitle="Verify your email address",
                description=f"Check your email address ({email}) and follow the instructions "
                            f"there to have access to all the features on your account."
            )

        abort(500)
    else:
        return render_template('create.html', alert='You need to fill the form!')


@app.route('/<string:screen_name>/with_friends')
def with_friends(screen_name):
    user = users.find_one({"screen_name": screen_name})
    if not user:
        abort(404)
    return render_template('profile.html', user=user, tab_previous=False)


@app.route('/tos')
@limiter.exempt
def tos():
    return send_from_directory('web', 'tos.html')


@app.route('/help')
@limiter.exempt
def help():
    return send_from_directory('web', 'help.html')


@app.route('/<string:screen_name>')
def profile(screen_name):
    user = users.find_one({"screen_name": screen_name})
    if not user:
        abort(404)
    return render_template('profile.html', user=user, tab_previous=True)


@app.route('/<path:path>')
@limiter.exempt
def static_page(path):
    return send_from_directory('web', path + '.html')

