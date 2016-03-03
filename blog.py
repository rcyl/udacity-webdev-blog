
import os

import jinja2
import  webapp2
import time
import json
from datetime import datetime, timedelta
import math
import logging
import hashlib
import hmac
import string 
import random
import re
import utils

from google.appengine.api import memcache
from google.appengine.ext import db


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = utils.jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def render_Json(self, d):
        json_txt = json.dumps(d);
        self.response.headers['Content-Type'] = 'application/json; charset:UTF-8'
        self.write(json_txt)

    def get_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and utils.check_secure_val(cookie_val)

    def set_secure_cookie(self, name, val):
        cookie_val = utils.make_secure_val(val)
        self.response.headers.add_header('Set-Cookie', '%s=%s;Path:=/' % (name,cookie_val))
      
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        if self.request.url.endswith('.json'):
            self.format = "json"
        else:
            self.format = "html"
        #checking whether uid in cookie
        uid = self.get_secure_cookie('User-id')
        self.user = uid and Users.by_id(int(uid))



class Blog(db.Model):
    title = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_mod = db.DateTimeProperty(auto_now = True)

    #converts data time into string format for json dumps
    def as_dict(self):
        time_fmt = "%c"
        d = { "title": self.title, 
            "content": self.content,
            "created": self.created.strftime(time_fmt),
            "last_mod": self.last_mod.strftime(time_fmt)
            }
        return d;

def top_blogs(update= False):
    key = 'top'
    blogs, age = utils.age_get(key)
    if update or blogs is None:
        blogs = db.GqlQuery("SELECT * FROM Blog ORDER BY created DESC")
        utils.age_set(key, blogs)
    return blogs, age


class Users(db.Model):
    username = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty

    @classmethod
    def by_name(cls, name):
        u = db.GqlQuery("SELECT * FROM Users WHERE username=:name", name=name).get()
        return u

    @classmethod  
    def by_id(cls, uid):
        #give id, return entity
        return cls.get_by_id(uid)

    @classmethod    
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and utils.verify_pw(name, pw, u.pw_hash):
            return u
    @classmethod        
    def create(cls, name, pw, email):
        return Users(username = name, 
                    pw_hash = utils.make_pw_salt(name, pw), 
                    email = email)

class BlogHandler(Handler):
    def render_main(self):
        blogs, age = top_blogs()
        if self.format == "html":
            self.render("main.html", query = utils.age_str(age), blogs = blogs, user = self.user)
        else:
            self.render_Json([b.as_dict() for b in blogs])
         
    def get(self):
        self.render_main()

class loginHandler(Handler):
    def get(self):
        self.render("login.html")
    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")

        #verify username and password
        u = Users.login(username, password)
        if u: 
            self.set_secure_cookie('User-id',str(u.key().id()))
          # can choose between setting username in cookie or user id
           # storing user id allows quicker access to entities in database (i think)
            self.redirect("/blog")
        else:
            error_msg = "Invalid login/password. Please try again"
            self.render("login.html", error = error_msg)

class logoutHandler(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'User-id=;Path:=/')
        self.redirect("/blog")

class newPostHandler(Handler):
    def render_new(self, title="", content="", error=""):
        self.render("newpost.html",title = title, content = content, error = error)

    def get(self):
        #if not logged in, cannot post, redirect to login page
        if self.user:
            self.render_new()
        else:
            self.redirect("/blog/login") 

    def post(self):
        title = self.request.get("title")
        content = self.request.get("content")

        if title and content:
            b = Blog(title=title, content = content)
            b.put()
            top_blogs(update=True) #updating cache
            self.redirect("/blog/%s" % b.key().id())
        else:
            error = "we need both the title and some content"
            self.render_new(title, content, error)

class singlePostHandler(Handler):
    def get(self, entity_id):
        key = "%s" % entity_id
        blog, age = utils.age_get(key)

        if blog is None:
           blog = Blog.get_by_id(int(entity_id)) 
           utils.age_set(key, blog)
           age=0
        if self.format=="html":
            self.render("singlepost.html", query = utils.age_str(age), blog=blog)
        else: 
            self.render_Json([blog.as_dict()])


class signupHandler(Handler):
    def get(self):
        self.render("signup.html")
    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        vpass = self.request.get("vpass")
        email = self.request.get("email")

        have_error = False;
        words={"username": username, "email":email}

        if not utils.valid_username(username):
            words["error_msg_user"] = "That is not a valid user name"
            have_error = True
        if not utils.valid_password(password):
            words["error_msg_pass"] = "That is not a valid password"
            have_error = True
        if password!=vpass:
            words["error_msg_vpass"] = "Your passwords did not match"
            have_error = True
        if not utils.valid_email(email):
            words["error_msg_email"] = "That is not a valid email address"
            have_error=True

        if have_error:
            self.render("signup.html", **words)
        else:
            # check if users already exist
            if Users.by_name(username):
                words["error_msg_user"] = "That username is already taken"
                self.render("signup.html", **words)
            else:
                u = Users.create(username, password, email)
                u.put()
                self.set_secure_cookie('User-id', str(u.key().id()))
                self.redirect("/blog")  

class flushHandler(Handler):
    def get(self):
        memcache.flush_all();
        self.redirect("/blog")


app = webapp2.WSGIApplication([('/blog/?(?:.json)?',BlogHandler)
                               ,('/blog/newPost', newPostHandler)
                               ,('/blog/(\d+)(?:.json)?', singlePostHandler)
                               ,('/blog/signup', signupHandler)
                               ,('/blog/login/?', loginHandler)
                               ,('/blog/logout/?', logoutHandler)
                               ,('/blog/flush/?', flushHandler)]
                               ,debug=True)