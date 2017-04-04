import os
import web
from jinja2 import Environment,FileSystemLoader
import datetime
import random
import memcache
import re
import hmac

SECRET = 'IAmS0S3cr3t'

urls = (
    '/signup', 'Signup',
    '/login', 'Login',
    '/logout', 'Logout',
    '/?([a-z]+)?', 'WikiPage',
    '/_edit/?([a-z]+)?', 'EditPage', 
)

def render_template(template_name, **context):
    extensions = context.pop('extensions', [])
    globals = context.pop('globals', {})

    jinja_env = Environment(
            loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')),
            extensions=extensions,
            autoescape=False
            )
    jinja_env.globals.update(globals)

    #jinja_env.update_template_context(context)
    return jinja_env.get_template(template_name).render(context)

# Database server ORM setup
db = web.database(dbn='mysql', db='fullstackpython', user='victor', pw='password', 
                  host='127.0.0.1', port=3306)

# Memcache server setup
mc = memcache.Client(['127.0.0.1'], debug=1)
mc.flush_all()

# Basic handler setup
class Handler():

    def write(self, string):
        return string

    def render(self, template, **kw):
        return render_template(template, **kw)

# Functions for Signup Handler
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")

def valid_username(username):
    return USER_RE.match(username)

def valid_password(password):
    return PASSWORD_RE.match(password)

def valid_email(email):
    return EMAIL_RE.match(email)

# Functions for hashing passwords
def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val

# Function for setting date
def now():
    f = '%Y-%m-%d %H:%M:%S'
    now = datetime.datetime.now().strftime(f)
    return now

# Function for generating user id
def new_user_id():
    numbers = '0123456789'
    random_id = int(''.join(random.choice(numbers) for i in range(0, 9)))

    while True:
        id_ = list(db.select('users', where="user_id=%s" % random_id))
        if not id_:
            return random_id
        else:
            random_id = ''.join(random.choice(numbers) for i in range(0, 11))

# Signup handler
class Signup(Handler):

    def GET(self):
        return self.render('signup.html')

    def POST(self):
        data = web.input()

        user_username = data.get('username')
        user_password = data.get('password')
        user_verify = data.get('verify')
        user_email = data.get('email')
        error_username = ""
        error_password = ""
        error_verify = ""
        error_email = ""

        re_submit = False

        username = list(db.select('users', where="user_name='%s'" % user_username))
        if username:
            error_username = "That user already exists."
            re_submit = True
        elif not valid_username(user_username):
            error_username = "That's not a valid username."
            re_submit = True

        if not valid_password(user_password):
            error_password = "That wasn't a valid password."
            re_submit = True
        if user_password != user_verify:
            error_verify = "Your passwords didn't match."
            re_submit = True
        if user_email:
            if not valid_email(user_email):
                error_email = "That's not a valid email."
                re_submit = True
            else:
                email = list(db.select('users', where="user_email='%s'" % user_email))
                if email:
                    error_email = "That's not a valid email."
                    re_submit = True

        if re_submit:
            return self.render('signup.html', user_username=user_username, 
                               error_username=error_username, 
                               error_password=error_password, error_verify=error_verify, 
                               user_email=user_email, error_email=error_email)
        else:
            password_hash = hash_str(user_password)
            user_id = new_user_id()
            a = db.insert('users', user_id=user_id, user_name=user_username, 
                          password_hash=password_hash, signup_date=now(), user_email=user_email)
            new_cookie_val = make_secure_val(str(user_id))
            web.setcookie('user_id', new_cookie_val)  
            raise web.seeother('/welcome')

class Login(Handler):

    def GET(self):

        return self.render('login.html')

    def POST(self):

        data = web.input()
        user_username = data.get('username')
        user_password = data.get('password')
        
        account = list(db.select('users', where="user_name='%s'" % user_username))

        if account[0].get('password_hash') == hash_str(user_password):
            user_id = account[0].get('user_id')
            new_cookie_val = make_secure_val(str(user_id))
            web.setcookie('user_id', new_cookie_val)
            raise web.seeother('/welcome')
        else:
            error = 'Invalid Login'
            return self.render('login.html', error=error)

class Logout(Handler):

    def GET(self):
        web.setcookie('user_id', "")
        raise web.seeother('/signup')

class WikiPage(Handler):

    def GET(self, page_name):
        path = web.ctx.env.get('PATH_INFO')
        user_id_str = web.cookies().get('user_id')
        if user_id_str:
            cookie_val = check_secure_val(user_id_str)
            if cookie_val:
                user_id = cookie_val.split('|')[0]
                account = list(db.select('users', where="user_id='%s'" % user_id))
                username = account[0].get('user_name')

                #Logged in user
                wiki = list(db.select('wiki', where="name='%s'" % path))
                if wiki:
                    content = wiki[0].get('content')
                    return self.render('wiki.html', username=username, content=content, 
                                       name=path, edit="edit")
                else:
                    raise web.seeother('/_edit%s' % path)
            else:
                return self.render('wiki.html')

class EditPage(Handler):

    def GET(self, page_name):
        user_id_str = web.cookies().get('user_id')
        if user_id_str:
            cookie_val = check_secure_val(user_id_str)
            if cookie_val:
                user_id = cookie_val.split('|')[0]
                account = list(db.select('users', where="user_id='%s'" % user_id))
                username = account[0].get('user_name')

                #Logged in user
                content=""
                if page_name:
                    wiki = list(db.select('wiki', where="name='/%s'" % page_name))
                else:
                    wiki = list(db.select('wiki', where="name='/'"))
                if wiki:
                    content = wiki[0].get('content')
                return self.render('edit.html', username=username, content=content)
            else:
                raise web.seeother('/login')

    def POST(self, page_name):
        user_id_str = web.cookies().get('user_id')
        if user_id_str:
            cookie_val = check_secure_val(user_id_str)
            if cookie_val:
                # user_id = cookie_val.split('|')[0]
                # account = list(db.select('users', where="user_id='%s'" % user_id))
                # username = account[0].get('user_name')
                data = web.input()
                name = '/'
                if page_name:
                    name += page_name
                content = data.get('content')
                a = db.insert('wiki', name=name, content=content)
                raise web.seeother(name)

if __name__ == "__main__":
    app = web.application(urls, globals())
    app.run()