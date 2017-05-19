import os,random, hashlib
import webapp2
import jinja2
import re
import hmac
import string
from google.appengine.ext import db
# =======================================================================================
SECRET= '7Y4p70GUQ91CJyDwTXLv'

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
autoescape = True)
# =======================================================================================
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

# Functions for sekuring and hashing
def make_secure_val(s):
   return  "{}|{}".format(s, hmac.new(SECRET,s).hexdigest())

def check_secure_val(h):
    s = h.split('|')[0]
    if make_secure_val(s) == h:
        return s
# salts
def make_salt(length = 5):
    return ''.join(random.choice(string.letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return "{}|{}".format(salt,h)

def valid_pw(name, password, h):
    salt = h.split('|')[0]
    return h == make_pw_hash(name,password,salt)


# Func for validating inputs
def valid_entry(userinput, reg_ex):
    USER_RE = re.compile(reg_ex)
    return USER_RE.match(userinput)
# =======================================================================================

# Main Handler
class Handler(webapp2.RequestHandler):
    """class with some basic functions from most handlers will inherit"""
    def write(self, *a, **kw):
        self.response.out.write(*a,**kw)


    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template,**kw))

    def set_sec_cookie(self,name,val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie', '{}={}; Path=/'.format(name,cookie_val))

    def read_sec_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_sec_cookie('user-id', str(user.key().id()))

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_sec_cookie('user-id')
        self.user = uid and User.by_id(int(uid))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user-id=; Path=/')

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)
# =======================================================================================

# PARENT class for databases (for consistency purposes, read doc.)
def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)
# =======================================================================================

# Database Classes
class User(db.Model):
    """class for a USER instances in a databases"""
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name ).get()
        return u

    @classmethod
    def register(cls,name,pw,email = None):
        pw_hash = make_pw_hash(name,pw)
        return User(parent=users_key(), name = name, pw_hash = pw_hash, email = email)

    @classmethod
    def login(cls, name, pw):
        user = cls.by_name(name)
        if user and valid_pw(name,pw, user.pw_hash):
            return user


class Post(db.Model):
    """class for particular POSTS in a database"""
    subject = db.StringProperty( required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    author = db.ReferenceProperty(User, collection_name ='post_author')
    likes = db.IntegerProperty()
    voters = db.StringListProperty()
    # last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_content = self.content.replace('\n', '<br>')
        # The names of the attributes are used as the names of the corresponding
        # properties on an entity. Model instance attributes whose names
            # begin with an underscore (_) are ignored,
        # so your application can use such attributes to store data on a model
            # instance that isn't saved to the Datastore.
        return render_str("/post.html", post = self)

# =======================================================================================

class SimpleBlog(Handler):
    """class for rendering the front page of a blog website"""
    def get(self):
        blog_posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC LIMIT 10")
        posts_comments = db.GqlQuery("SELECT * FROM Comment ORDER BY created DESC")
        self.render("blog_front.html", blog_posts=blog_posts, posts_comments = posts_comments)
# =======================================================================================
# Post related handlers
class NewPost(Handler):
    """class for adding a new post to the blogsite"""
    def get(self):
        if self.user:
            self.render('blog_new_post.html')
        else:
            self.redirect("/blog/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')
        post_author = self.user

        if content and subject:
            post = Post(parent = blog_key(),
            author = post_author,
            subject = subject,
            content = content,
            likes = 0
            )
            #This stores the object into a database
            post.put()
            # To get the ID of an entity you just created: obj.key().id()
            # To look up an object by ID, you can use the get_by_id() functionself.
            self.redirect('/blog/{}'.format(post.key().id()))
        else:
            error = "We need both, a valid subject (min. 3 characters) and a Blog!"
            self.render("blog_new_post.html", error=error, content=content, subject=subject)

class PostPage(Handler):
    """Class that will lead to each post"""
    def get(self, post_id):
        post = Post.get_by_id(int(post_id), parent = blog_key())

        if not post:
            self.error(404)
            return
        self.render('permalink.html', post = post)

class EditPost(Handler):
    """class for editing a post by its user"""
    def get(self, post_id):
        post = Post.get_by_id(int(post_id), parent = blog_key())

        if not post:
            self.error(404)
            return

        if post.author.name == self.user.name:
            self.render("edit_post.html", post=post, subject=post.subject, content=post.content)
        else:
            error = "You need to be logged in to edit your post!"
            return self.render('login.html', error=error)

    def post(self, post_id):
        post = Post.get_by_id(int(post_id), parent = blog_key())

        subject = self.request.get("subject")
        content = self.request.get("content")

        if self.user and self.user.name == post.author.name:
            if subject and content:
                post.subject = subject
                post.content = content
                post.put()
                self.redirect("/blog/{}".format(str(p.key().id())) )
            else:
                error = "Oops, please fill out both input fields!"
                self.render("edit_post.html", post=post, subject=subject, content=content,
                             error=error)
        else:
            error = "Oops, please log in for editing posts!"
            return self.render('login.html', error=error)

# Making specific handlers for disliking/liking and redirects the url is probably not the best method
class LikingPost(Handler):
    def post(self, post_id):
        post = Post.get_by_id(int(post_id), parent = blog_key())

        post.likes += 1
        # Is user name unique in the code or is appending ID better idea?
        post.voters.append(self.user.name)
        # This checks if the user is not the author so the change actually changes the instance in DB
        if self.user.name != post.author.name:
            post.put()
            self.redirect("/blog")

class DislikingPost(Handler):
    def post(self, post_id):
        post = Post.get_by_id(int(post_id), parent = blog_key())

        post.likes -= 1
        # Is user name unique in the code or is appending ID better idea?
        post.voters.append(self.user.name)
        # This checks if the user is not the author so the change actually changes the instance in DB
        if self.user.name != post.author.name:
            post.put()
            self.redirect("/blog")

class DeletePost(Handler):
    """class for deleting a blog post"""
    def get(self, post_id):
        post = Post.get_by_id(int(post_id), parent = blog_key())

        if self.user.name == post.author.name:
            post.delete()
            message = "Your post has been removed!"
            self.render("blog.html", post=post, message=message)
        else:
            error = "You can only delete your own posts!"
            return self.render("login.html", error=error)
# =======================================================================================
# Comment related DB
class Comment(db.Model):
    comment = db.TextProperty(required=True)
    comment_author = db.StringProperty(required=True)
    comment_id = db.IntegerProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

# =======================================================================================
# Comment related handlers
class AddComment(Handler):
    """class that handles a new comment"""
    def get(self, post_id):
        post = Post.get_by_id(int(post_id), parent = blog_key())

        if self.user:
            self.render("add_comment.html", post=post, subject=post.subject,
                        content=post.content)
        else:
            error = "You need to be logged in to comment posts!"
            return self.render('login.html', error=error)

    def post(self, post_id):
        post = Post.get_by_id(int(post_id), parent = blog_key())

        comment_content = self.request.get("comment")
        # Same as with post breaks must be preserved
        comment = comment_content.replace('\n', '<br>')

        comment_author = self.user.name
        comment_id = int(post.key().id())

        if self.user:
            if comment_author and comment and comment_id:
                comment = Comment(parent = blog_key(),
                comment=comment,
                comment_author=comment_author,
                comment_id = comment_id)

                comment.put()

                self.redirect("/blog")
            else:
                error = "You have to enter text in the comment field!"
                return self.render("add_comment.html", post=post, subject=post.subject,
                             content=p.content, error=error)


class EditComment(Handler):
    """class that allows an user to edit his or her own comment"""
    def get(self, comment_id):
        com = Comment.get_by_id(int(comment_id), parent = blog_key())

        if not com:
            self.error(404)
            return

        commented = com.comment.replace('<br>', '')

        if self.user:
            self.render("edit_comment.html", com=com, commented=commented)
        else:
            error = "Please log in to be able to edit comments!"
            return self.render('login.html', error=error)

    def post(self, comment_id):
        com = Comment.get_by_id(int(comment_id), parent = blog_key())

        commentin = self.request.get("comment")
        comment = commentin.replace('\n', '<br>')
        commentid = com.comment_id
        comment_author = com.comment_author

        if self.user:
            if comment_author and comment and comment_id:
                com.comment = comment
                com.comment_author = comment_author
                com.put()
                self.redirect("/blog")
            else:
                error = "You have to enter text in the comment field!"
                return self.render("edit_comment.html", comment=comment, commented=com.comment)


class RemoveComment(Handler):
    """class for removing a comment"""
    def get(self, comment_id):
        com = Comment.get_by_id(int(comment_id), parent = blog_key())

        if self.user.name == com.comment_author:
            com.delete()
            message = "Your comment has been removed!"
            self.render("blog_front.html",com=com, message = message)
        else:
            error = "You can only remove your own posts!"
            return self.render("login.html", error=error)

#-------------------------------------------------------------------
# SignUp Form + Welcome Handler
class Signup(Handler):
    def get(self):
        self.render("signup_form.html")

    def post(self):
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        valid_name = valid_entry(self.username, r"^[a-zA-Z0-9_-]{3,20}$")
        valid_pass = valid_entry(self.password, r"^.{3,20}$")
        valid_email = valid_entry(self.email, r"^[\S]+@[\S]+.[\S]+$")

        if valid_name:
            if valid_pass:
                if (self.password == self.verify):
                    self.done()
                else:
                    self.render("signup_form.html",
                    username = self.username,
                    verify = 'Your passwords do not match!')
            else:
                self.render("signup_form.html",
                    username = self.username,
                    pass_error = 'Your password is not valid!')
        else:
            self.render("signup_form.html",
                name_error = "This is not a valid name.",
                username = self.username
            )
    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):
    def done(self):
        # Make sure the user does not exist already
        u = User.by_name(self.username)
        if u:
            message = "This user already exists."
            self.render("signup_form.html", name_error = message)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()
            #this sets the cookie
            self.login(u)
            self.redirect("/blog")

class WelcomeHandler(Handler):
    def get(self):
        if self.user:
            self.render("welcome.html", username = self.user.name)
        else:
            self.redirect('/blog/signup')

class Login(Handler):
    def get(self):
        self.render('login_form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        user = User.login(username, password)

        if user:
            self.login(user)
            self.redirect("/blog/welcome")
        else:
            msg = 'Invalid Login'
            self.render('login_form.html', error = msg)

class Logout(Handler):
    def get(self):
        # empties the cookie
        self.logout()
        self.redirect('/blog')


app = webapp2.WSGIApplication([
    ('/blog/signup', Register),
    ("/blog/welcome", WelcomeHandler),
    ('/', SimpleBlog),
    ('/blog/?', SimpleBlog),
    ('/blog/login', Login),
    ('/blog/logout', Logout),
    ('/blog/([0-9]+)', PostPage),
    ('/blog/edit_post/([0-9]+)', EditPost),
    ('/blog/newpost', NewPost),
    ('/blog/upvote/([0-9]+)', LikingPost),
    ('/blog/downvote/([0-9]+)', DislikingPost),
    ('/blog/deleted/([0-9]+)', DeletePost),
    ('/blog/add_comment/([0-9]+)', AddComment),
    ('/blog/edit_comment/([0-9]+)',EditComment),
    ('/blog/remove_comment/([0-9]+)', RemoveComment),
    ], debug=True)
