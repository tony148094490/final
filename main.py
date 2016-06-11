import os
import datetime
import jinja2
import webapp2
import re
import random
import string
import hashlib
import logging
import time

from google.appengine.api import memcache
from google.appengine.ext import ndb


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                                autoescape = False)
class UserAccount(ndb.Model):
    username = ndb.StringProperty(required = True)
    hashedPassword = ndb.StringProperty(required = True)
    email = ndb.StringProperty(required = False)

class Entry(ndb.Model):
    url = ndb.StringProperty(required = True)
    content = ndb.TextProperty(required = True)
    version = ndb.IntegerProperty(required = True)
    creationDate = ndb.DateProperty(auto_now_add = True)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def makeSalt(self):
        result = ''
        for x in range(5):
            result += random.choice(string.ascii_letters)
        return result

    def makeHash(self, username, salt = None):
        if not salt:
            salt = self.makeSalt()
        saltedUsername = username + salt
        return '%s|%s' % (salt, hashlib.sha256(saltedUsername).hexdigest())

class WikiPageHandler(Handler):
    def get(self, url):

        userCookie = self.request.cookies.get('user_id')

        version = self.request.get('v')

        if version:
            #Get the specified version
            version = int(version)
            entry = ndb.gql(
                "SELECT * FROM Entry WHERE url ='%s' AND version = %s" % (url, version)).fetch()
        else :
            #Get the latest version
            entry = ndb.gql(
                "SELECT * FROM Entry WHERE url='%s' ORDER BY version DESC LIMIT 1" % url).fetch()

        if entry:
            entry = entry[0]
            self.render('Entry.html', content=entry.content, url=url, cookie=userCookie, version=version)
        elif version:
            self.response.write('Ther version %s does not exit!' % version)
        elif userCookie:
            self.redirect('/wiki/_edit%s' % url)
        else:
            self.response.write('Please log in for creating new entries!')

class WikiEditHandler(Handler):
    def get(self, url):
        cookie = self.request.cookies.get('user_id')
        if cookie is None:
            self.response.write('Please log in for creating/editing new entries!')

        version = self.request.get('v')

        if version:
            #Get the specified version
            entry = ndb.gql(
                "SELECT * FROM Entry WHERE url ='%s' AND version = %s" % (url, version)).fetch()
        else :
            #Get the latest version
            entry = ndb.gql(
                "SELECT * FROM Entry WHERE url='%s' ORDER BY version DESC LIMIT 1" % url).fetch()

        self.render('newWiki.html',
                     content=entry[0].content if entry else "",
                     version=version,
                     url=url,
                     contentError="")

    def post(self, url):
        content = self.request.get("content")
        version = self.request.get('v')
        entryList = ndb.gql(
                 "SELECT * FROM Entry WHERE url='%s' ORDER BY version DESC LIMIT 1" % url).fetch()

        if content:
            if version:
                version = int(version)
                entry = ndb.gql(
                    "SELECT * FROM Entry WHERE url='%s' AND version=%s" %(url, version)).fetch()
                if entry[0]:
                    entry[0].content = content
                    if entryList:
                        entry[0].version = entryList[0].version + 1
                    entry[0].put()
                    time.sleep(2)
                    self.redirect('/wiki%s' % url)
                    return
            elif entryList:
                version = entryList[0].version + 1
            else:
                version = 1

            newEntry = Entry(url=url,content=content,version=version)
            

            newEntry.put()
            time.sleep(2)
            self.redirect('/wiki%s' % url)
        else:
            self.render('newWiki.html',
                        content=content,
                        contentError="Content cannot be empty"
                        )

class WikiSignupHandler(Handler):
    def get(self):
        self.render("wikiSignup.html",
                    username="",
                    password="",
                    verify="",
                    email="",
                    usernameError="",
                    passwordError="",
                    verifyError="",
                    emailError="")

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")

        usernameError = ""
        passwordError = ""
        verifyError = ""
        emailError = ""
        if ( (self.validUserName(username)) and self.newUser(username) and self.validPassword(password) 
            and self.validVerification(password, verify) and self.validEmail(email) ):

            # make a hashed cookie! 
            hashedUsername = self.makeHash(username)
            self.response.headers.add_header('Set-Cookie', 'user_id=%s;Path=/wiki/' % str(username))

            # persist an entity
            hashedPassword = self.makeHash(password)
            userAccount = UserAccount(username = username, hashedPassword = hashedPassword, email = email, id = username)
            userAccount.put()

            self.redirect("/wiki/")

        else: 
            if(not self.newUser(username)):
                usernameError = "This username already exists."
            if(not self.validUserName(username)):
                usernameError = "That's not a valid username."
            if(not self.validPassword(password)):
                passwordError = "That wasn't a valid password."
                password = ""
                verify = ""
            if(self.validPassword(password) and not self.validVerification(password, verify)):
                verifyError = "Your passwords didn't match."
                password = ""
                verify = ""
            if(not self.validEmail(email)):
                emailError = "That's not a valid email."

            self.render("wikiSignup.html",
                        username = username,
                        password = password,
                        verify = verify,
                        email = email,
                        usernameError = usernameError,
                        passwordError = passwordError,
                        verifyError = verifyError,
                        emailError = emailError)

    def newUser(self, username):
        userKey = ndb.Key(UserAccount, username)
        user = userKey.get()
        if (user):
            return False
        else:
            return True

    def validUserName(self, user_name):
        USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        return USER_RE.match(user_name)

    def validPassword(self, pswd):
        PSWD_RE = re.compile(r"^.{3,20}$")
        return PSWD_RE.match(pswd)

    def validVerification(self, first, second):
        return first == second

    def validEmail(self, email):
        if email == "":
            return True
        EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
        return EMAIL_RE.match(email)        

class WikiLoginHandler(Handler):
    def get(self):
        self.render("wikiLogin.html",
                    username="",
                    password="",
                    loginError="")
    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")

        if(self.validLogin(username, password)):
            hashedUsername = self.makeHash(username)
            self.response.headers.add_header('Set-Cookie', 'user_id=%s;Path=/wiki/' % str(username))
            self.redirect("/wiki/")

        else:
            loginError = "Invalid login"
            self.render("wikiLogin.html",username=username,password=password,loginError=loginError)

    def validLogin(self, username, password):
        userKey = ndb.Key(UserAccount, username)
        user = userKey.get()
        if (user):
            hashedPassword = user.hashedPassword
            salt = hashedPassword.split('|')[0]
            return hashedPassword == self.makeHash(password,salt)
        else:
            return False

class WikiLogoutHandler(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=;Path=/wiki/')

        self.redirect('/wiki/')

class WikiHistoryHandler(Handler):
    def get(self, url):
        cookie = self.request.cookies.get('user_id')
        if cookie is None:
            self.response.write('Please log in for viewing histories!')

        entries = ndb.gql(
            "SELECT * FROM Entry WHERE url='%s' ORDER BY version DESC" % url).fetch()
        self.render('wikiHistory.html',entries=entries,url=url,cookie=cookie)

PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([                
                               ('/wiki/_edit' + PAGE_RE, WikiEditHandler),
                               ('/wiki/signup', WikiSignupHandler),
                               ('/wiki/login', WikiLoginHandler),
                               ('/wiki/logout', WikiLogoutHandler),
                               ('/wiki/_history' + PAGE_RE, WikiHistoryHandler),
                               ('/wiki' + PAGE_RE, WikiPageHandler),

                                ],
                                debug=True)








