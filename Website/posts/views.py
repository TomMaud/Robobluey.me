import base64
from hashlib import scrypt

from cryptography.fernet import Fernet
from flask import Blueprint, render_template, flash, url_for, redirect, request
from flask_login import current_user
from sqlalchemy import desc

from config import db, Post, load_user, logger
from posts.forms import PostForm

posts_bp = Blueprint('posts', __name__, template_folder='templates')


@posts_bp.route('/create', methods=('GET', 'POST'))
def create():
    try:
        user = load_user(current_user.get_id())
        if user.role != "end_user":
            logger.info("{} with role {} unsuccessfully attempted to access {} from {}".format(user.email, user.role,
                                                                                               request.url,
                                                                                               request.remote_addr))
            return redirect(url_for('errors.adminerror'))
    except:
        flash("You must be logged in to create a post", category="warning")
        return redirect(url_for('accounts.login'))

    form = PostForm()

    if form.validate_on_submit():
        key = scrypt(password=user.password.encode(), salt=user.salt.encode(), n=2048, r=8, p=1, dklen=32)
        encoded_key = base64.b64encode(key)
        cipher = Fernet(encoded_key)
        title = cipher.encrypt(form.title.data.encode())
        body = cipher.encrypt(form.body.data.encode())
        new_post = Post(title=title, body=body, userid=user.id, user=user)

        db.session.add(new_post)
        db.session.commit()

        flash('Post created', category='success')
        logger.info("{} with role {} successfully created post {} from {}".format(user.email, user.role, new_post.id,
                                                                                  request.remote_addr))
        return redirect(url_for('posts.posts'))

    return render_template('posts/create.html', form=form)


@posts_bp.route('/posts')
def posts():
    try:
        print(1)
        user = load_user(current_user.get_id())
        print(user.role)
        if user.role != "end_user":
            logger.info("{} with role {} unsuccessfully attempted to access {} from {}".format(user.email, user.role,
                                                                                               request.url,
                                                                                               request.remote_addr))
            return redirect(url_for('errors.adminerror'))
    except Exception as e:
        print(e)
        flash("You must be logged in to view posts", category="warning")
        return redirect(url_for('accounts.login'))
    all_posts = Post.query.order_by(desc('id')).all()
    for i in all_posts:
        key = scrypt(password=i.user.password.encode(), salt=i.user.salt.encode(), n=2048, r=8, p=1, dklen=32)
        encoded_key = base64.b64encode(key)
        cipher = Fernet(encoded_key)
        i.title = cipher.decrypt(i.title).decode()
        i.body = cipher.decrypt(i.body).decode()
    return render_template('posts/posts.html', posts=all_posts)


@posts_bp.route('/<int:id>/update', methods=('GET', 'POST'))
def update(id):
    try:
        user = load_user(current_user.get_id())
        if user.role != "end_user":
            logger.info("{} with role {} unsuccessfully attempted to access {} from {}".format(user.email, user.role,
                                                                                               request.url,
                                                                                               request.remote_addr))
            return redirect(url_for('errors.adminerror'))
    except:
        flash("You must be logged in to edit posts", category="warning")
        return redirect(url_for('accounts.login'))
    post_to_update = Post.query.filter_by(id=id).first()

    if not post_to_update:
        return redirect(url_for('posts.posts'))

    if post_to_update.userid == user.id:
        form = PostForm()
        key = scrypt(password=user.password.encode(), salt=user.salt.encode(), n=2048, r=8, p=1, dklen=32)
        encoded_key = base64.b64encode(key)
        cipher = Fernet(encoded_key)
        if form.validate_on_submit():
            post_to_update.update(title=cipher.encrypt(form.title.data.encode()),
                                  body=cipher.encrypt(form.body.data.encode()))
            flash('Post updated', category='success')
            logger.info("{} with role {} successfully updated post {} from {}".format(user.email, user.role, id,
                                                                                      request.remote_addr))
            return redirect(url_for('posts.posts'))

        form.title.data = cipher.decrypt(post_to_update.title).decode()
        form.body.data = cipher.decrypt(post_to_update.body).decode()

        return render_template('posts/update.html', form=form)
    else:
        flash("You cannot edit a post not attributed to you", category="danger no-register")
        return redirect(url_for('posts.posts'))


@posts_bp.route('/<int:id>/delete')
def delete(id):
    try:
        user = load_user(current_user.get_id())
        if user.role != "end_user":
            logger.info("{} with role {} unsuccessfully attempted to access {} from {}".format(user.email, user.role,
                                                                                               request.url,
                                                                                               request.remote_addr))
            return redirect(url_for('errors.adminerror'))
    except:
        flash("You must be logged in to delete posts", category="warning")
        return redirect(url_for('accounts.login'))

    post = Post.query.filter_by(id=id).first()
    if user.id == post.userid:
        Post.query.filter_by(id=id).delete()
        db.session.commit()
        flash('Post deleted', category='success')
        logger.info("{} with role {} successfully deleted post {} from {}".format(user.email, user.role, id,
                                                                                  request.remote_addr))
    else:
        flash("You cannot delete a post not attributed to you", category="danger")
    return redirect(url_for('posts.posts'))
