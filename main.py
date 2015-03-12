#
#   Author: Sebastian Horoszkiewicz
#   Created on 22 Feb 2015
#   E-mail: sebahoroszko@gmail.com
#
#   10% of final grade.
#   Due Wed. 4th March 2015 - end of the day.
#   All code in Python, GAE, and webapp2.
#   Deploy on GAE.

import os
import jinja2
import string
import random
import webapp2
import os.path
import logging
from webapp2_extras import sessions
from google.appengine.ext import ndb
from google.appengine.api import mail
from google.appengine.ext.webapp import util

JINJA = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
    extensions=['jinja2.ext.autoescape'],
    autoescape=True,
)

user_detail_key = ndb.Key('UserDetail', 'user_details_key')
class Index():
    title = 'Registration System'
    pswdRetTitle = 'Reset Password'
    regTitle = 'Welcome to the Registration Page'
    page1_title = 'Page 1' 
    page2_title = 'Page 2' 
    page3_title = 'Page 3' 
    loginTitle = 'Welcome to the Login Page'
    verificationErr = 'Invalid Link'
    ressetinPswTitle = 'Reset Your Password'
    pswdTitle = 'Resetting Password'
    
class BaseHandler(webapp2.RequestHandler):
    def dispatch(self):
        # Get a session store for this request.
        self.session_store = sessions.get_store(request=self.request)
        try:
            # Dispatch the request.
            webapp2.RequestHandler.dispatch(self)       # dispatch the main handler
        finally:
            # Save all sessions.
            self.session_store.save_sessions(self.response)
            
    @webapp2.cached_property
    def session(self):
        # Returns a session using the default cookie key.
        return self.session_store.get_session()
        
class UserDetail(ndb.Model):
    userid = ndb.StringProperty()
    email = ndb.StringProperty()
    passwd = ndb.StringProperty()
    mailConfirmed = ndb.BooleanProperty()
    pending = ndb.BooleanProperty()
    secretLink = ndb.StringProperty()
    resetKey = ndb.StringProperty()
    
# We need to provide for LOGOUT.
class LogoutHandler(BaseHandler):
    def post(self):
        self.session.clear()
        self.redirect('/')
    
class Page1Handler(BaseHandler):
    def get(self):
        username = self.session.get('loggedUserId')
        if username is None:
            self.redirect('/login')
        else:
            template = JINJA.get_template('html/page1.html')
            self.response.write(template.render(
                { 'the_title': Index.page1_title } 
            ))
            
class Page2Handler(BaseHandler):
    def get(self):
        username = self.session.get('loggedUserId')
        if username is None:
            self.redirect('/login')
        else:
            template = JINJA.get_template('html/page2.html')
            self.response.write(template.render(
                { 'the_title': Index.page2_title } 
            ))
            
class Page3Handler(BaseHandler):
    def get(self):
        username = self.session.get('loggedUserId')
        if username is None:
            self.redirect('/login')
        else:
            template = JINJA.get_template('html/page3.html')
            self.response.write(template.render(
                { 'the_title': Index.page3_title } 
            ))
            
class PasswordRetrievalHandler(webapp2.RequestHandler):
    def get(self):
        # What if the user has forgotten their password?  Provide a password-reset facility/form.
        template = JINJA.get_template('html/retrievePassword.html')
        self.response.write(template.render(
            { 'the_title': Index.pswdRetTitle } 
        ))
    def post(self):
        err_messages=[]
        uUsername = self.request.get('user-id')
        uEmail = self.request.get('userEmail')
        uEmail = uEmail.upper()
        if self.request.get('user-id') == "":
            err_messages.append('Please enter valid user-id')
        if self.request.get('userEmail') == "":
            err_messages.append('Please enter valid email address.')
        ret = []
        qry = ndb.gql("SELECT * FROM UserDetail WHERE email = :email AND userid = :uUsername", email=uEmail, uUsername=uUsername)
        ret = qry.fetch()
        if ret == []:
            err_messages.append('Make sure you inputted correct user-id and email address.')
        else:
            for q in ret:
                if not q.mailConfirmed:
                    err_messages.append('Please confirm your email first.')
                    
        if len(err_messages) is not 0:
            template = JINJA.get_template('html/retrievePassword.html')
            self.response.write(template.render(
                { 'the_title': Index.pswdRetTitle,
                    'error_messeg': err_messages }
            ))
        else:
            resetPasKey = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))
            for q in qry:
                # set reset key for user
                q.resetKey = resetPasKey
                q.put()

            mail.send_mail(sender="Reg-Sys Support <sebahoroszko@gmail.com>",
            to= uEmail,
            subject="Resetting Password",
            body="""
Hi """+uUsername+""",

To reset your password visit http://reg-sys.appspot.com/resetPassword and enter code below:

"""+resetPasKey+"""


Notice: If you requested resetting your password more than once only code from latest email will work.

Please let us know if you have any questions.


The Reg-Sys Team
            """)
            template = JINJA.get_template('html/login.html')
            self.response.write(template.render(
                { 'the_title': Index.loginTitle,
                    'success_messeg': 'Please check your mail and follow the insturctions in it.' }
            ))
            
class ResetPasswordHandler(webapp2.RequestHandler):
    def get(self):
        # Display the LOGIN form.
        template = JINJA.get_template('html/resetPassword.html')
        self.response.write(template.render(
            { 'the_title': Index.ressetinPswTitle } 
        ))
    def post(self):
        err_messages = []
        username = self.request.get('user-id')
        emailAddrE = self.request.get('email')
        emailAddrE = emailAddrE.upper()
        codeE = self.request.get('code')
        passwrdE = self.request.get('passwd')
        passwrd2E = self.request.get('passwd2')
        sendThisID = ""
        secCodeFDB = ""
        mailFDB = ""
        codeE=codeE.upper()
        qry = ndb.gql("SELECT * FROM UserDetail WHERE userid = :username", username=username)
        if qry.fetch() is not []:
            for q in qry:
                sendThisID = q.userid
                secCodeFDB = q.resetKey
                mailFDB = q.email
        else:
            err_messages.append('Sorry, details entered are incorrect.')
        
        if len(err_messages) is 0 and sendThisID != username:
            err_messages.append('Please enter valid user-id.')
        if len(err_messages) is 0 and mailFDB != emailAddrE:
            err_messages.append('Please enter valid email address.')
        if len(err_messages) is 0 and secCodeFDB != codeE:
            err_messages.append('Please enter valid reset code.')
        if passwrdE != passwrd2E:
            err_messages.append("Your passwords does not match.")
        if passwrdE == username:
            err_messages.append("Your new password cannot be the same as your user-id.")
        passValidat=PasswordValidation()
        if len(err_messages) is 0 and passValidat.validatePassword(passwrdE , passwrd2E):
            err_messages.append('Your new password is not safe enough.')
            
        if len(err_messages) is 0:
            for q in qry:
                if q.userid == username:
                    q.resetKey = ""
                    q.passwd = passwrdE
                    q.put()
            template = JINJA.get_template('html/login.html')
            self.response.write(template.render(
                { 'the_title': Index.loginTitle,
                    'success_messeg': 'Your password has been successfully changed.' }
            ))
        else:
            # Display the LOGIN form.
            template = JINJA.get_template('html/resetPassword.html')
            self.response.write(template.render(
                { 'the_title': Index.ressetinPswTitle,
                   'error_messeg' : err_messages 
                   } 
            ))
            
class LoginHandler(BaseHandler):
    def get(self):
        # Display the LOGIN form.
        template = JINJA.get_template('html/login.html')
        self.response.write(template.render(
            { 'the_title': Index.loginTitle } 
        ))

    def post(self):
        err_messages = []
        self.session.clear()
        username = self.request.get('userid')
        passwd = self.request.get('passwd')
        
        # Check that a login and password arrived from the FORM.
        if self.request.get('userid') == "":
            err_messages.append("Please Enter Valid User-id")
        if self.request.get('passwd') == "":    
            err_messages.append("Please Enter Valid Password")
        invalid=True
        # Lookup login ID in "confirmed" datastore.
        qry = ndb.gql("SELECT * FROM UserDetail WHERE userid = :username", username=username)
        for q in qry:
            # Check for password match.
            if q.mailConfirmed and q.passwd == passwd and q.userid == username:
                invalid=False
            if not q.mailConfirmed and q.passwd == passwd and q.userid == username:
                err_messages.append("Please confirm your registration first.")
                
        if invalid:
            err_messages.append("Your login details are Invalid!")
        if len(err_messages) is 0:
            # Set the user as logged in and let them have access to /page1, /page2, and /page3.  SESSIONs.
            self.session['loggedUserId'] = username
            self.redirect('/page1')
        else:
            template = JINJA.get_template('html/login.html')
            self.response.write(template.render(
                { 'the_title': Index.loginTitle,
                    'error_messeg' : err_messages }
            ))

class PasswordValidation():
    def validatePassword(self, password1, password2):
        invalidPAssword=False
        # Is the password too simple?
        #    # check is it an english word.
        allwords=[]
        folder = os.path.dirname(os.path.realpath(__file__))
        file_path = os.path.join(folder, 'words.txt')
        for words in open(file_path, 'r').readlines():
            allwords.append(words.strip())
            
        #    # upper/lower case, nubers, special chars..
        count=0
        chars = set('0123456789!#$%^&*()_-=+@".,|><{}')
        for c in password1:
            if c in chars:
                count=count+1
        # Check if password1 == password2.
        #    # ETC.
        if (password1.lower() in allwords or 
                    len(password1)<5 or
                    password1.isalpha() or
                    count < 2 or
                    password1 != password2 ):
            invalidPAssword = True
        
        return invalidPAssword
        
class RegisterHandler(BaseHandler):
    def get(self):
        template = JINJA.get_template('html/reg.html')
        self.response.write(template.render(
            { 'the_title': Index.regTitle } 
        ))

    def post(self):
        invalid=False
        username = self.request.get('userid')
        email = self.request.get('email')
        email = email.upper()
        passwd = self.request.get('passwd')
        passwd2 = self.request.get('passwd2')
        validateData = [username, email, passwd, passwd2]
        invalidList=[]
        # Check if the data items from the POST are empty.
        for value in validateData:
            if value == "":
                invalidList.append("Please fill in all fields.")
                invalid = True
                break
                
        passValidat=PasswordValidation()
        if passValidat.validatePassword(passwd, passwd2):
            invalidList.append("Your password is not safe enough.")
            invalid=True
        
        if ' ' in username:
            invalidList.append("User-id can not contain spaces.")
            invalid = True
        
        if passwd == username:
            invalidList.append("Your password cannot be the same as your user-id.")
            invalid = True
        
        # Does the userid already exist in the "confirmed" datastore or in "pending"?
        qry = ndb.gql("SELECT userid FROM UserDetail")
        for q in qry:
            if q.userid == username:
                invalidList.append("This user-id is already taken.")
                invalid=True
        
        if invalid:
            template = JINJA.get_template('html/reg.html')
            self.response.write(template.render(
                { 'the_title': Index.regTitle,
                    'errorList' : invalidList } 
            ))
            
        else:
            # Add registration details to "pending" datastore.
            # This code needs to move to the email confirmation handler.
            secretThing = ''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(32))
            user = UserDetail(parent=user_detail_key)
            user = UserDetail()
            user.userid = username
            user.email = email
            user.passwd = passwd
            user.mailConfirmed = False
            user.pending = True
            user.secretLink=secretThing
            user.resetKey = ""
            user.put()
            toEmail=username+" <"+email+">"
            link="http://reg-sys.appspot.com/verify?param="+username+secretThing
            # Can GAE send email? - yes
            # Send confirmation email.
            mail.send_mail(sender="Reg-Sys Support <sebahoroszko@gmail.com>",
                to= toEmail,
                subject="Your account has been approved",
                body="""
Hi """+username+""",

Thanks for signing up for Reg-Sys application!

Please click on following link to confirm your registration;

"""+link+"""

Please let us know if you have any questions.


The Reg-Sys Team
            """)
            # Can my GAE app receive email? - yes
            self.session.clear()
            template = JINJA.get_template('html/login.html')
            self.response.write(template.render(
                { 'the_title': Index.loginTitle,
                    'success_messeg' : 'You have successfully registered! Check your email to login.'
                }
            ))

class VerificationHandler(webapp2.RequestHandler):
    def get(self):
        valid=False
        err_messages = []
        parameter = self.request.get('param')
        count=0
        username=""
        qry = ndb.gql("SELECT * FROM UserDetail")
        if qry.fetch() is not []:
            for q in qry:
                if q.mailConfirmed and q.userid + q.secretLink == self.request.get('param'):
                    err_messages.append('Your email has been confirmed already.')
                elif not q.mailConfirmed and q.userid + q.secretLink == self.request.get('param'):
                    valid=True
                    username = q.userid
                    
        if len(err_messages) is 0 and not valid:
            err_messages.append('WTF? What are you trying to do?')
        if len(err_messages) is 0 and valid:
            qry = ndb.gql("SELECT * FROM UserDetail WHERE userid = :username",username=username)
            if qry.fetch() is not []:
                for q in qry:
                    # Update
                    if q.userid == username:
                        q.pending=False
                        q.mailConfirmed=True
                        q.put()
            template = JINJA.get_template('html/login.html')
            self.response.write(template.render(
                { 'the_title': Index.loginTitle,
                    'success_messeg' : 'Your email has been confirmed! Now you can login and ejoy our content!'
                }
            ))
        else:
            template = JINJA.get_template('html/login.html')
            self.response.write(template.render(
                { 'the_title': Index.loginTitle,
                    'error_messeg' : err_messages
                }
            ))
            
            
config = {}
config['webapp2_extras.sessions'] = {
    'secret_key': 'mysuopersecreatkeythatissupersec',
}

app = webapp2.WSGIApplication([
    # Login
    ('/', LoginHandler),('/login', LoginHandler),
    ('/processlogin', LoginHandler),
    # Register
    ('/register', RegisterHandler),
    ('/processreg', RegisterHandler),
    ('/verify', VerificationHandler),
    # Resetting Password
    ('/passwordRetrieval', PasswordRetrievalHandler),
    ('/procesRetrieval', PasswordRetrievalHandler),
    # The only way to access link below is to either type address or get it through email
    ('/resetPassword', ResetPasswordHandler),
    ('/processreset', ResetPasswordHandler),
    # Logout
    ('/logout', LogoutHandler),
    # Next three URLs are only available to logged-in users.
    ('/page1', Page1Handler),
    ('/page2', Page2Handler),
    ('/page3', Page3Handler),
], debug=True, config=config)
