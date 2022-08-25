from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date, datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
from flask import abort
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
import os

Base = declarative_base()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

gravatar = Gravatar(app,
                    size=200,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return db.session.query(User).get(user_id)


# CONFIGURE TABLES
class BlogPost(db.Model, Base):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, ForeignKey('users.id'))
    author = relationship("User", back_populates="posts")
    comments = relationship("Comments", back_populates="parent_post")


class User(UserMixin, db.Model, Base):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), unique=True, nullable=False)
    name = db.Column(db.String(250), nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comments", back_populates="author")


class Comments(db.Model, Base):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    parent_post = relationship("BlogPost", back_populates="comments")
    post_id = db.Column(db.Integer, ForeignKey('blog_posts.id'))
    author_id = db.Column(db.Integer, ForeignKey('users.id'))
    author = relationship("User", back_populates="comments")
    date = db.Column(db.String(250), nullable=False)


db.create_all()

def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if int(current_user.get_id()) != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["GET", "POST"])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        email = register_form.email.data

        if User.query.filter_by(email=email).first():
            # User already exists
            flash("Looks like you already have an account. Sign in here!")
            return redirect(url_for('login'))

        password = generate_password_hash(register_form.password.data, method='pbkdf2:sha256', salt_length=8)
        name = register_form.name.data
        new_user = User(email=email, password=password, name=name)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=register_form)


@app.route('/login', methods=["POST", "GET"])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        email = login_form.email.data
        typed_password = login_form.password.data
        account = User.query.filter_by(email=email).first()
        if not account:
            flash("That email does not exist. Please try again.")
            return redirect(url_for("login"))
        elif not check_password_hash(account.password, typed_password):
            flash("Incorrect password. Please try again.")
            return redirect(url_for("login"))
        else:
            login_user(account)
            return redirect(url_for("get_all_posts"))
    return render_template("login.html", form=login_form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comment_form = CommentForm()
    if comment_form.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = Comments(text=comment_form.body.data, post_id=post_id, author_id=current_user.get_id(), date=datetime.now().strftime("%c"))
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for("show_post", post_id=post_id))
        else:
            flash("You need to log in to comment")
            return redirect(url_for("login"))

    return render_template("post.html", post=requested_post, form=comment_form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["POST", "GET"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))

@app.route("/delete_comment/<int:comment_id>")
def delete_comment(comment_id):
    post_id = request.args.get('post_id')
    comment_to_delete = Comments.query.get(comment_id)
    db.session.delete(comment_to_delete)
    db.session.commit()
    return redirect(url_for('show_post', post_id=post_id))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
