import os
import re
import random
import hashlib
import hmac
import webapp2
import jinja2
from string import letters
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'fart'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

# Represents a Post
class Post(db.Model):
    author = db.StringProperty(required = True)
    subject = db.StringProperty(required = True)
    comments = db.IntegerProperty()
    likes = db.IntegerProperty()
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    @classmethod
    def by_author(cls, author):
        p = Post.all().filter('author =', author).get()
        return p

    @classmethod
    def by_subject(cls, subject):
        p = Post.all().filter('subject =', subject).get()
        return p

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)


def like_key(post = 'default'):
    return db.Key.from_path('like', post)

# Represents a Like
class Like(db.Model):
    post = db.StringProperty(required = True)
    user = db.StringProperty(required = True)

def comment_key(post = 'default'):
    return db.Key.from_path('comment', post)

# Represents a Comment
class Comment(db.Model):
    post = db.StringProperty(required = True)
    author = db.StringProperty(required = True)
    avatar = db.StringProperty(default = "https://www.gravatar.com/avatar/0")
    comment = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

    @classmethod
    def by_post(cls, post):
        c = Comment.all().filter('post =', post).get()
        return c

# User functions

# Random string for making passwords
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

# Creates the password hash
def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

# Compares the input password to the one in the datastore
def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

# Represents a User
class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()
    avatar = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None, avatar = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email,
                    avatar = avatar)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

# Handler class to make it simpler for rendering each page
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

# Sign Up Page
class SignUp(Handler):
    def get(self):
        if not self.user:
            self.render('register.html')
        else:
            self.redirect('/')

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')
        params = dict(username = self.username,
                      email = self.email)
        u = User.by_name(self.username)
        if u:
            params['error_username'] = "That user already exists."
            have_error = True
        elif not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            # Shows the errors if not filled out properly
            self.render('register.html', **params)
        else:
            self.avatar = ("http://www.gravatar.com/avatar/" +
                hashlib.md5(self.email).hexdigest())
            u = User.register(self.username, self.password, self.email,
                self.avatar)
            u.put()
            self.login(u)
            self.redirect('/')

# Like Post Page
class LikePost(Handler):
    def get(self):
        # Gets the post ID from the get query
        self.post = self.request.get('post')
        if self.user:
            # Verifies if the user has liked a post
            like = db.GqlQuery(
                "select * from Like where user = '%s' and post = '%s'"
                % (self.user.name, self.post))
            post_key = db.Key.from_path('Post',
                int(self.post), parent=blog_key())
            post = db.get(post_key)
            if like.get():
                # If the user has liked it, they are redirected to the
                # permalink
                self.redirect('/view-post?id=%s' % self.post)
            elif self.user.name != post.author:
                # Likes the post, and increases the like counter
                like = Like(user = self.user.name, post = self.post)
                like.put()
                post.likes += 1
                post.put()
                # Redirects to the permalink page
                self.redirect('/view-post?id=%s' % self.post)
        else:
            self.redirect('/login')

# Unlike Post Page
class UnlikePost(Handler):
    def get(self):
        # Gets the post ID from the get query
        self.post = self.request.get('post')
        if self.user:
            # Verifies if the user has liked a post
            likes = db.GqlQuery(
                "select * from Like where user = '%s' and post = '%s'"
                % (self.user.name, self.post))
            like = likes[0]
            post_key = db.Key.from_path('Post',
                int(self.post), parent=blog_key())
            post = db.get(post_key)
            # Unlikes the post and decreases the like counter
            if likes.get():
                like.delete()
                post.likes -= 1
                post.put()
                # Redirects to the permalink page
                self.redirect('/view-post?id=%s' % self.post)
            elif self.user.name == post.author:
                # Redirects to the permalink page
                self.redirect('/view-post?id=%s' % self.post)
        else:
            self.redirect('/login')

# Login Page
class Login(Handler):
    def get(self):
        if not self.user:
            self.render('login.html')
        else:
            self.redirect('/')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/')
        else:
            msg = 'Invalid login'
            self.render('login.html', error = msg)

#  Log Out Page
class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect('/')

# Front Page
class MainPage(Handler):
    def get(self):
        # Renders the 10 latest posts
        posts = db.GqlQuery("select * from Post order by created desc limit 10")
        self.render('front.html', posts = posts)

# Edit Post Page
class EditPost(Handler):
    def get(self):
        # Gets the post ID from the get query
        post_id = self.request.get('id')
        # Checks if there's a logged in user
        if self.user:
            # Looks up the post
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if not post:
                self.error(404)
                return
            # Verifies that the user is the post's author
            elif self.user.name == post.author:
                params = dict(id = int(post_id))
                params['post'] = post
                # Renders the page
                self.render('edit-post.html', **params)
            else:
                # If it's not the post author, redrects to the permalink
                self.redirect('/view-post?id=%s' % post_id)
        else:
            self.redirect('/login')

    def post(self):
        # Gets the post ID from the hidden input field
        self.id = self.request.get('id')
        # Looks up the post
        key = db.Key.from_path('Post', int(self.id), parent=blog_key())
        post = db.get(key)
        # Gets the post and subject from the input boxes
        self.blog = self.request.get('blog')
        self.subject = self.request.get('subject')
        # Saves the input field in case something goes wrong
        params = dict(blog = self.blog,
                    subject = self.subject,
                    id = self.id,
                    post = post)
        # Verifies both visible fields are filled in
        if self.subject and self.blog:
            # If so, saves the changes
            post.subject = self.subject
            post.content = self.blog
            post.put()
            # Redirects to the permalink
            self.redirect('/view-post?id=%s' % str(post.key().id()))
        else:
            # If not, renders the page with the error
            params['error'] = 'Post must contain both a subject and content.'
            self.render('edit-post.html', **params)

# Edit Comment Page
class EditComment(Handler):
    def get(self):
        # Gets the comment ID from the get query
        comment_id = self.request.get('id')
        # Makes sure if the user is logged in
        if self.user:
            # Looks up the comment
            key = db.Key.from_path('Comment',
                int(comment_id), parent=comment_key())
            comment = db.get(key)
            # Saves the comment id and comment contents for rendering the page
            params = dict(id = int(comment_id), comment = comment)
            # Verifies that there is a comment
            if not comment:
                self.error(404)
                return
            elif self.user.name == comment.author:
                # Looks up the post
                post_key = db.Key.from_path('Post',
                    int(comment.post), parent=blog_key())
                post = db.get(post_key)
                # Posts the post in the dictionary for rendering the page
                params['post'] = post
                self.render('edit-comment.html', **params)
            else:
                self.redirect('/view-post?id=%s' % post.key().id())
        else:
            self.redirect('/login')

    def post(self):
        # Gets the ID from the hidden input
        self.id = self.request.get('id')
        # Gets the new comment in the input field
        self.comment = self.request.get('comment')
        key = db.Key.from_path('Comment', int(self.id), parent=comment_key())
        comment = db.get(key)
        # Changes the comment to the one typed in the input field
        comment.comment = self.comment
        comment.put()
        # Redirects back to the post where the comment was made
        self.redirect('/view-post?id=%s' % comment.post)

# Delete Comment Page
class DeleteComment(Handler):
    def get(self):
        # Gets the comment ID from the get query
        comment_id = self.request.get('id')
        # Makes sure if the user is logged in
        if self.user:
            # Looks up the comment
            key = db.Key.from_path('Comment',
                int(comment_id), parent=comment_key())
            comment = db.get(key)
            # Saves the comment's id and content for rendering the page
            params = dict(id = int(comment_id), comment = comment)
            if not comment:
                self.error(404)
                return
            # Checks if the logged in user is the comment's author
            elif self.user.name == comment.author:
                # Looks up the post
                post_key = db.Key.from_path('Post',
                    int(comment.post), parent=blog_key())
                post = db.get(post_key)
                # Saves the post for rendering the page
                params['post'] = post
                # Renders the delete page
                self.render('delete-comment.html', **params)
            else:
                # If not the comment's author, redirects to the post
                self.redirect('/view-post?id=%s' % post.key().id())
        else:
            # If not logged in, redirects to the login page
            self.redirect('/login')

    def post(self):
        # Gets the ID from the hidden input
        self.id = self.request.get('id')
        # Looks up the comment
        key = db.Key.from_path('Comment', int(self.id), parent=comment_key())
        comment = db.get(key)
        # Looks up the post
        post_key = db.Key.from_path('Post', int(comment.post), parent=blog_key())
        post = db.get(post_key)
        # Deletes the comment
        comment.delete()
        # Decreases the posts comment counter
        post.comments -= 1
        post.put()
        # Redirects back to the post where the comment was made
        self.redirect('/view-post?id=%s' % post.key().id())

# Delete Post Page
class DeletePost(Handler):
    def get(self):
        # Gets the post ID from the get query
        post_id = self.request.get('id')
        # Checks if there's a user logged in
        if self.user:
            # Looks up the Post from the datastore
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

            # Checks if the logged in user is the post's author
            if self.user.name == post.author:
                params = dict(id = int(post_id))
                # Throws an error if the post is not found
                if not post:
                    self.error(404)
                    return
                # If it is found its parameter is set
                params['post'] = post
                # Renders the page with the post information
                self.render('delete-post.html', **params)
            else:
                # Redirects to the Permalink Page if the logged in user is not
                # the post's author.
                self.redirect('/view-post?id='+post_id)
        else:
            # Redirects to the login page if there's no user logged in
            self.redirect('/login')

    def post(self):
        # Gets the post ID from a hidden input
        self.id = self.request.get('id')
        # Looks up the post
        key = db.Key.from_path('Post', int(self.id), parent=blog_key())
        post = db.get(key)
        # Deletes the post, then redirects to the front page
        post.delete()
        self.redirect('/')

# New Post Page
class NewPost(Handler):
    def get(self):
        if self.user:
            # If there's a user logged in, renders the page
            self.render('new-post.html')
        else:
            # Otherwise, redirects to the login page
            self.redirect('/login')

    def post(self):
        # Gets the blog post and subject from the text boxes
        self.blog = self.request.get('blog')
        self.subject = self.request.get('subject')
        params = dict(blog = self.blog,
                    subject = self.subject)
        # Checks if both fields were filled out
        if self.subject and self.blog:
            # Creates a new Post entry
            p = Post(parent = blog_key(), subject = self.subject,
                    content = self.blog, author = self.user.name,
					comments = 0, likes = 0)
            p.put()
            # Redirects to the Permalink Page
            self.redirect('/view-post?id=%s' % str(p.key().id()))
        else:
            # Shows an error if both fields weren't filled out
            params['error'] = 'Post must contain both a subject and content.'
            self.render('new-post.html', **params)

# Permalink Page
class SinglePost(Handler):
    def get(self):
        # Gets the post based on the id in the get query
        post_id = self.request.get('id')
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        params = dict(post = post, id = int(post_id))
        # Queries information from the datastore
        posts = db.GqlQuery("select * from Post order by created desc limit 5")
        likes = db.GqlQuery("select * from Like where post = '%s'"
			% int(post_id))
        comments = db.GqlQuery(
			"select * from Comment WHERE post = '%s' order by created desc"
			% int(post_id))

        # Makes sure if there are comments
        if comments.get():
            params['comments'] = comments
        # Checks if the current user has liked this specific post
        if likes.get():
            for like in likes:
                if self.user:
                    if like.user == self.user.name:
                        params['like'] = like
        # Checks if the ID provided is a valid post ID
        if not post:
            self.error(404)
            return
        elif posts.get():
            params['posts'] = posts
        # Renders the page with the parameters that were set
        self.render("permalink.html", **params)

    def post(self):
        # Gets the comment from the text box
        self.comment = self.request.get('comment')
        # Gets the post ID from the hidden input
        self.id = self.request.get('id')
        params = dict(id = self.id)
        # Looks up the Post
        key = db.Key.from_path('Post', int(self.id), parent=blog_key())
        post = db.get(key)
        # Checks if the comments input box was empty when submitted
        if self.comment:
            # Inserts the new entry into the Comment entity
            c = Comment(comment = self.comment, author = self.user.name,
                        post = self.id, avatar = self.user.avatar,
                        parent = comment_key())
            c.put()
            # Increment the number of comments in the post's entry
            post.comments += 1
            post.put()
            # Redirects to the permalink
            self.redirect('/view-post?id=%s' % self.id)
        else:
            # Saves the error rending the page
            params['error'] = 'Comment must contain content.'
            # Queries information from the datastore
            posts = db.GqlQuery("select * from Post order by created desc limit 5")
            likes = db.GqlQuery("select * from Like where post = '%s'"
    			% int(self.id))
            comments = db.GqlQuery(
    			"select * from Comment WHERE post = '%s' order by created desc"
    			% int(self.id))
            # Makes sure if there are comments
            if comments.get():
                params['comments'] = comments
            # Checks if the current user has liked this specific post
            if likes.get():
                for like in likes:
                    if self.user:
                        if like.user == self.user.name:
                            params['like'] = like
            # Checks if the ID provided is a valid post ID
            if post:
                # Saves the post for rendering the page
                params['post'] = post
            if posts.get():
                params['posts'] = posts
            # Renders the page with the parameters that were set
            self.render("permalink.html", **params)

# Maps all the pages to their respective classes
app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/like/', LikePost),
    ('/unlike/', UnlikePost),
    ('/register', SignUp),
    ('/login', Login),
    ('/logout', Logout),
    ('/edit-post', EditPost),
    ('/delete-post', DeletePost),
    ('/edit-comment', EditComment),
    ('/delete-comment', DeleteComment),
    ('/new', NewPost),
    ('/view-post', SinglePost)
], debug=True)
