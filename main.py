import wsgiref.handlers
import datetime, time, hashlib, urllib, urllib2, re, os
from google.appengine.ext import db
from google.appengine.ext import webapp
from google.appengine.api import urlfetch, mail, memcache, users, taskqueue
from google.appengine.ext.webapp import template
from django.utils import simplejson
from pprint import pprint
from datetime import datetime, date, time
import logging
import spreedly
import keymaster
import base64
import sys

APP_NAME = 'hd-signup'
EMAIL_FROM = "Dojo Signup <no-reply@%s.appspotmail.com>" % APP_NAME
DAYS_FOR_KEY = 30

try:
    is_dev = os.environ['SERVER_SOFTWARE'].startswith('Dev')
except:
    is_dev = False

if is_dev:
    SPREEDLY_ACCOUNT = 'hackerdojotest'
    SPREEDLY_APIKEY = keymaster.get('spreedly:hackerdojotest')
    PLAN_IDS = {'full': '1957'}
else:
    SPREEDLY_ACCOUNT = 'hackerdojo'
    SPREEDLY_APIKEY = keymaster.get('spreedly:hackerdojo')
    PLAN_IDS = {'full': '1987', 'hardship': '2537', 'supporter': '1988', 'family': '3659', 'minor': '3660', 'full-check': '6479', 'hardship-check': '6480', 'worktrade': '6608' }

is_prod = not is_dev

def fetch_usernames(use_cache=True):
    usernames = memcache.get('usernames')
    if usernames and use_cache:
        return usernames
    else:
        resp = urlfetch.fetch('http://domain.hackerdojo.com/users', deadline=10)
        if resp.status_code == 200:
            usernames = [m.lower() for m in simplejson.loads(resp.content)]
            if not memcache.set('usernames', usernames, 3600*24):
                logging.error("Memcache set failed.")
            return usernames

class Membership(db.Model):
    hash = db.StringProperty()
    first_name = db.StringProperty(required=True)
    last_name = db.StringProperty(required=True)
    email = db.StringProperty(required=True)
    plan  = db.StringProperty(required=True)
    status  = db.StringProperty() # None, active, suspended
    referrer  = db.StringProperty()
    username = db.StringProperty()
    rfid_tag = db.StringProperty()
    auto_signin = db.StringProperty()
    
    spreedly_token = db.StringProperty()
    
    created = db.DateTimeProperty(auto_now_add=True)
    updated = db.DateTimeProperty(auto_now=True)
    
    def full_name(self):
        return '%s %s' % (self.first_name, self.last_name)
    
    def spreedly_url(self):
        return "https://spreedly.com/%s/subscriber_accounts/%s" % (SPREEDLY_ACCOUNT, self.spreedly_token)
    
    @classmethod
    def get_by_email(cls, email):
        return cls.all().filter('email =', email).get()
    
    @classmethod
    def get_by_hash(cls, hash):
        return cls.all().filter('hash =', hash).get()

class MainHandler(webapp.RequestHandler):
    def get(self):
        self.response.out.write(template.render('templates/main.html', {
            'is_prod': is_prod, 
            'plan': self.request.get('plan', 'full'),
            'paypal': self.request.get('paypal')}))
    
    def post(self):
        first_name = self.request.get('first_name')
        last_name = self.request.get('last_name')
        email = self.request.get('email').lower()
        plan = self.request.get('plan', 'full')
        
        if not first_name or not last_name or not email:
            self.response.out.write(template.render('templates/main.html', {
                'is_prod': is_prod, 'plan': plan, 'message': "Sorry, we need all three fields."}))
        else:
            
            # this just runs a check twice. (there is no OR in GQL)
            # first name, last name
            existing_member = db.GqlQuery("SELECT * FROM Membership WHERE first_name = '%s' AND last_name = '%s'" % (first_name, last_name)).get()
            if existing_member:
                membership = existing_member
            # email
            existing_member = db.GqlQuery("SELECT * FROM Membership WHERE email = '%s'" % email).get()
            if existing_member:
                membership = existing_member

            first_part = re.compile(r'[^\w]').sub('', first_name.split(' ')[0])
            last_part = re.compile(r'[^\w]').sub('', last_name)
            if len(first_part)+len(last_part) >= 15:
                last_part = last_part[0]
            username = '.'.join([first_part, last_part]).lower()
            if username in fetch_usernames():
                username = email.split('@')[0].lower()
            
            # username@hackerdojo.com
            existing_member = db.GqlQuery("SELECT * FROM Membership WHERE email = '%s@hackerdojo.com'" % username).get()
            if existing_member:
                membership = existing_member
            
            try:
                membership
            except NameError:
                membership = None
                
            # old code below
            #existing_member = Membership.get_by_email(email)
            #if existing_member and existing_member.status in [None, 'paypal']:
            #    existing_member.delete()
            if membership is None:
                membership = Membership(
                    first_name=first_name, last_name=last_name, email=email, plan=plan)
                if self.request.get('paypal') == '1':
                    membership.status = 'paypal'
                membership.hash = hashlib.md5(membership.email).hexdigest()
                membership.referrer = self.request.get('referrer')
                membership.put()
            
            self.redirect('/account/%s' % membership.hash)

class AccountHandler(webapp.RequestHandler):
    def get(self, hash):
        membership = Membership.get_by_hash(hash)
        # steal this part to detect if they registered with hacker dojo email above
        first_part = re.compile(r'[^\w]').sub('', membership.first_name.split(' ')[0]) # First word of first name
        last_part = re.compile(r'[^\w]').sub('', membership.last_name)
        if len(first_part)+len(last_part) >= 15:
            last_part = last_part[0] # Just last initial
        username = '.'.join([first_part, last_part]).lower()
        if username in fetch_usernames():
            username = membership.email.split('@')[0].lower()
        if self.request.get('u'):
            pick_username = True
        message = self.request.get('message')
        self.response.out.write(template.render('templates/account.html', locals()))
    
    def post(self, hash):
        username = self.request.get('username')
        password = self.request.get('password')
        if password != self.request.get('password_confirm'):
            self.redirect(self.request.path + "?message=Passwords don't match")
        elif len(password) < 6:
            self.redirect(self.request.path + "?message=Password must be 6 characters or longer")
        else:
            membership = Membership.get_by_hash(hash)
            membership.put()
            
            # Yes, storing their username and password temporarily so we can make their account later
            memcache.set(hashlib.sha1(membership.hash+SPREEDLY_APIKEY).hexdigest(), 
                '%s:%s' % (username, password), time=3600)
            
            customer_id = membership.key().id()

            # This code is weird...
            if "maker00000" in membership.referrer.lower():
                headers = {'Authorization': "Basic %s" % base64.b64encode('%s:X' % SPREEDLY_APIKEY),
                    'Content-Type':'application/xml'}
                # Create subscriber
                data = "<subscriber><customer-id>%s</customer-id><email>%s</email></subscriber>" % (customer_id, membership.email)
                resp = urlfetch.fetch("https://spreedly.com/api/v4/%s/subscribers.xml" % (SPREEDLY_ACCOUNT), 
                        method='POST', payload=data, headers = headers, deadline=5)
                # Credit
                data = "<credit><amount>30.00</amount></credit>"
                resp = urlfetch.fetch("https://spreedly.com/api/v4/%s/subscribers/%s/credits.xml" % (SPREEDLY_ACCOUNT, customer_id), 
                        method='POST', payload=data, headers=headers, deadline=5)
            
            query_str = urllib.urlencode({'first_name': membership.first_name, 'last_name': membership.last_name, 
                'email': membership.email, 'return_url': 'http://%s/success/%s' % (self.request.host, membership.hash)})
            # check if they are active already since we didn't create a new member above
            # apparently the URL will be different
            if membership.status != "active":
              self.redirect("https://spreedly.com/%s/subscribers/%s/subscribe/%s/%s?%s" % 
                (SPREEDLY_ACCOUNT, customer_id, PLAN_IDS[membership.plan], username, query_str))
            else:
              self.redirect("https://www.spreedly.com/%s/subscriber_accounts/%s" % (SPREEDLY_ACCOUNT, membership.spreedly_token))
            
            
class CreateUserTask(webapp.RequestHandler):
    def post(self):
        def fail(what, details):
            mail.send_mail(sender=EMAIL_FROM,
                to="Internal Dev <internal-dev@hackerdojo.com>",
                subject="[hd-signup] CreateUserTask failure",
                body=details)
        def retry(countdown=None):
            retries = int(self.request.get('retries', 0)) + 1
            if retries <= 5:
                taskqueue.add(url='/tasks/create_user', method='POST', countdown=countdown,
                    params={'hash': self.request.get('hash'), 'retries': retries})
            else:
                fail("Too many retries")
        
        membership = Membership.get_by_hash(self.request.get('hash'))
        if membership is None or membership.username:
            return
        if not membership.spreedly_token:
            return retry(300)
            
        try:
            username, password = memcache.get(hashlib.sha1(membership.hash+SPREEDLY_APIKEY).hexdigest()).split(':')
        except (AttributeError, ValueError):
            return fail("Account information expired")
            
        try:
            resp = urlfetch.fetch('http://domain.hackerdojo.com/users', method='POST', payload=urllib.urlencode({
                'username': username,
                'password': password,
                'first_name': membership.first_name,
                'last_name': membership.last_name,
                'secret': keymaster.get('api@hackerdojo.com'),
            }), deadline=10)
        except urlfetch.DownloadError, e:
            return retry()
        except Exception, e:
            return fail(e)
        
        usernames = fetch_usernames(False)
        if username in usernames:
            membership.username = username
            membership.put()
        else:
            return retry()

class SuccessHandler(webapp.RequestHandler):
    def get(self, hash):
        member = Membership.all().filter('hash =', hash).get()
        if member:
            if self.request.query_string == 'email':
                spreedly_url = member.spreedly_url()
                mail.send_mail(sender=EMAIL_FROM,
                    to="%s <%s>" % (member.full_name(), member.email),
                    subject="Welcome to Hacker Dojo, %s!" % member.first_name,
                    body=template.render('templates/welcome.txt', locals()))
                self.redirect(self.request.path)
            else:
                success_html = urlfetch.fetch("http://hackerdojo.pbworks.com/api_v2/op/GetPage/page/SubscriptionSuccess/_type/html").content
                success_html = success_html.replace('joining!', 'joining, %s!' % member.first_name)
                is_prod = not is_dev
                self.response.out.write(template.render('templates/success.html', locals()))

class NeedAccountHandler(webapp.RequestHandler):
    def get(self):
        message = self.request.get('message')
        self.response.out.write(template.render('templates/needaccount.html', locals()))
    
    def post(self):
        email = self.request.get('email').lower()
        if not email:
            self.redirect(self.request.path)
        else:
            member = Membership.all().filter('email =', email).filter('status =', 'active').get()
            if not member:
                self.redirect(self.request.path + '?message=There is no active record of that email.')
            else:
                mail.send_mail(sender=EMAIL_FROM,
                    to="%s <%s>" % (member.full_name(), member.email),
                    subject="Create your Hacker Dojo account",
                    body="""Hello,\n\nHere's a link to create your Hacker Dojo account:\n\nhttp://%s/account/%s""" % (self.request.host, member.hash))
                sent = True
                self.response.out.write(template.render('templates/needaccount.html', locals()))

class UpdateHandler(webapp.RequestHandler):
    def get(self):
        pass
    
    def post(self, ids=None):
        subscriber_ids = self.request.get('subscriber_ids').split(',')
        s = spreedly.Spreedly(SPREEDLY_ACCOUNT, token=SPREEDLY_APIKEY)
        for id in subscriber_ids:
            subscriber = s.subscriber_details(sub_id=int(id))
            member = Membership.get_by_id(int(subscriber['customer-id']))
            if member:
                if member.status == 'paypal':
                    mail.send_mail(sender=EMAIL_FROM,
                        to="PayPal <paypal@hackerdojo.com>",
                        subject="Please cancel PayPal subscription for %s" % member.full_name(),
                        body=member.email)
                member.status = 'active' if subscriber['active'] == 'true' else 'suspended'
                if member.status == 'active' and not member.username:
                    taskqueue.add(url='/tasks/create_user', method='POST', params={'hash': member.hash})
                member.spreedly_token = subscriber['token']
                member.plan = subscriber['feature-level'] or member.plan
                member.email = subscriber['email']
                member.put()

        self.response.out.write("ok")
            
class LinkedHandler(webapp.RequestHandler):
    def get(self):
        self.response.out.write(simplejson.dumps([m.username for m in Membership.all().filter('username !=', None)]))

class SuspendedHandler(webapp.RequestHandler):
    def get(self):
        self.response.out.write(simplejson.dumps([[m.fullname(), m.username] for m in Membership.all().filter('status =', 'suspended')]))

class MemberListHandler(webapp.RequestHandler):
    def get(self):
      user = users.get_current_user()
      if not user:
        self.redirect(users.create_login_url('/memberlist'))
      signup_users = Membership.all().order("last_name").fetch(1000);
      self.response.out.write(template.render('templates/memberlist.html', locals()))
		
class AllHandler(webapp.RequestHandler):
    def get(self):
      user = users.get_current_user()
      if not user:
        self.redirect(users.create_login_url('/userlist'))
      if users.is_current_user_admin():
        signup_users = Membership.all().fetch(1000)
        signup_usernames = [m.username for m in signup_users]
        domain_usernames = fetch_usernames()
        signup_usernames = set(signup_usernames) - set([None])
        signup_usernames = [m.lower() for m in signup_usernames]
        users_not_on_domain = set(signup_usernames) - set(domain_usernames)
        users_not_on_signup = set(domain_usernames) - set(signup_usernames)
        self.response.out.write(template.render('templates/users.html', locals()))
      else:
        self.response.out.write("Need admin access")
      
class CleanupHandler(webapp.RequestHandler):
    def get(self):
        self.post()
        
    def post(self):
        deleted_emails = []
        for membership in Membership.all().filter('status =', None):
            if (datetime.date.today() - membership.created.date()).days > 5:
                deleted_emails.append(membership.email)
                membership.delete()
        if deleted_emails:
            mail.send_mail(sender=EMAIL_FROM,
                to="Jeff Lindsay <progrium@gmail.com>",
                subject="Recent almost members",
                body='\n'.join(deleted_emails))

class ProfileHandler(webapp.RequestHandler):
    def get(self):
      user = users.get_current_user()
      if not user:
          self.redirect(users.create_login_url('/profile'))
          return
      else:
          account = Membership.all().filter('username =', user.nickname()).get()
          email = account.username + "@hackerdojo.com"
          gravatar_url = "http://www.gravatar.com/avatar/" + hashlib.md5(email.lower()).hexdigest()          
          self.response.out.write(template.render('templates/profile.html', locals()))

class PrefHandler(webapp.RequestHandler):
   def get(self):
      user = users.get_current_user()
      if not user:
          self.redirect(users.create_login_url('/pref'))
          return
      else:
          account = Membership.all().filter('username =', user.nickname()).get()
          if not account:
            error = "<p>Error - couldn't find your account.</p>"
            error += "<pre>Nick: "+str(user.nickname())
            error += "<pre>Email: "+str(user.email())
            error += "<pre>Account: "+str(account)
            if account:
              error += "<pre>Token: "+str(account.spreedly_token)
            self.response.out.write(template.render('templates/error.html', locals()))
            return
          auto_signin = account.auto_signin
          self.response.out.write(template.render('templates/pref.html', locals()))

   def post(self):
      user = users.get_current_user()
      if not user:
          self.redirect(users.create_login_url('/pref'))
          return
      account = Membership.all().filter('username =', user.nickname()).get()
      if not account:
            error = "<p>Error #1983, which should never happen."
            self.response.out.write(template.render('templates/error.html', locals()))
            return
      auto_signin = self.request.get('auto').strip()
      account.auto_signin = auto_signin
      account.put()
      self.response.out.write(template.render('templates/prefsaved.html', locals()))
 
            

class KeyHandler(webapp.RequestHandler):
    def get(self):
      user = users.get_current_user()
      if not user:
          self.redirect(users.create_login_url('/key'))
          return
      else:
          account = Membership.all().filter('username =', user.nickname()).get()
          if not account or not account.spreedly_token:
            error = "<p>It appears that you have an account on @hackerdojo.com, but you do not have a corresponding account in the signup application.</p><p>How to remedy:</p><ol><li>If you <b>are not</b> in the Spreedly system yet, <a href=\"/\">sign up</a> now.</li><li>If you <b>are</b> in Spreedly already, please contact <a href=\"mailto:signupops@hackerdojo.com?Subject=Spreedly+account+not+linked+to+hackerdojo+account\">signupops@hackerdojo.com</a>.</li></ol>"
            error += "<pre>Nick: "+str(user.nickname())
            error += "<pre>Email: "+str(user.email())
            error += "<pre>Account: "+str(account)
            if account:
              error += "<pre>Token: "+str(account.spreedly_token)
            
            self.response.out.write(template.render('templates/error.html', locals()))
            return
          if account.status != "active":
            url = "https://spreedly.com/"+SPREEDLY_ACCOUNT+"/subscriber_accounts/"+account.spreedly_token
            error = "<p>Your Spreedly account status does not appear to me marked as active.  This might be a mistake, in which case we apologize. <p>To investigate your account, you may go here: <a href=\""+url+"\">"+url+"</a> <p>If you believe this message is in error, please contact <a href=\"mailto:signupops@hackerdojo.com?Subject=Spreedly+account+not+linked+to+hackerdojo+account\">signupops@hackerdojo.com</a></p>";
            self.response.out.write(template.render('templates/error.html', locals()))
            return
          delta = datetime.utcnow() - account.created
          if delta.days < DAYS_FOR_KEY:
            error = "<p>You have been a member for "+str(delta.days)+" days.  After "+str(DAYS_FOR_KEY)+" days you qualify for a key.  Check back in "+str(DAYS_FOR_KEY-delta.days)+" days!</p><p>If you believe this message is in error, please contact <a href=\"mailto:signupops@hackerdojo.com?Subject=Membership+create+date+not+correct\">signupops@hackerdojo.com</a>.</p>";
            self.response.out.write(template.render('templates/error.html', locals()))
            return    
          bc = BadgeChange.all().filter('username =', account.username).fetch(100)
          self.response.out.write(template.render('templates/key.html', locals()))

    def post(self):
      user = users.get_current_user()
      if not user:
          self.redirect(users.create_login_url('/key'))
          return
      account = Membership.all().filter('username =', user.nickname()).get()
      if not account or not account.spreedly_token or account.status != "active":
            error = "<p>Error #1982, which should never happen."
            self.response.out.write(template.render('templates/error.html', locals()))
            return
      rfid_tag = self.request.get('rfid_tag').strip()
      description = self.request.get('description').strip()
      if rfid_tag.isdigit():
        if Membership.all().filter('rfid_tag =', rfid_tag).get():
          error = "<p>That RFID tag is in use by someone else.</p>"
          self.response.out.write(template.render('templates/error.html', locals()))
          return
        if not description:
          error = "<p>Please enter a reason why you are associating a replacement RFID key.  Please hit BACK and try again.</p>"
          self.response.out.write(template.render('templates/error.html', locals()))
          return
        account.rfid_tag = rfid_tag
        account.put()
        bc = BadgeChange(rfid_tag = rfid_tag, username=account.username, description=description)
        bc.put()
        self.response.out.write(template.render('templates/key_ok.html', locals()))
        return
      else:
        error = "<p>That RFID ID seemed invalid. Hit back and try again.</p>"
        self.response.out.write(template.render('templates/error.html', locals()))
        return

class RFIDHandler(webapp.RequestHandler):
    def get(self):
      if self.request.get('id'):
        m = Membership.all().filter('rfid_tag ==', self.request.get('id')).filter('status =', 'active').get()
        if self.request.get('callback'): # jsonp callback support
          self.response.out.write(self.request.get('callback')+"(");
        if m:
          email = m.username + "@hackerdojo.com"
          gravatar_url = "http://www.gravatar.com/avatar/" + hashlib.md5(email.lower()).hexdigest()
          self.response.out.write(simplejson.dumps({"gravatar": gravatar_url,"auto_signin":m.auto_signin, "status" : m.status, "name" : m.first_name + " " + m.last_name, "rfid_tag" : m.rfid_tag, "username" : m.username }))
        else:
          self.response.out.write(simplejson.dumps({}))
        if self.request.get('callback'):
          self.response.out.write(")");
      else:
        if self.request.get('maglock:key') == keymaster.get('maglock:key'):
          self.response.out.write(simplejson.dumps([ {"rfid_tag" : m.rfid_tag, "username" : m.username } for m in Membership.all().filter('rfid_tag !=', None).filter('status =', 'active')]))
        else:
          self.response.out.write("Access denied")

class ModifyHandler(webapp.RequestHandler):
    def get(self):
      Membership.all().filter('email =', user.email()).get()
      if not user:
          self.redirect(users.create_login_url('/modify'))
          return
      else:
          account = Membership.all().filter('username =', user.nickname()).get()
          if not account or not account.spreedly_token:
            error = "<p>Sorry, your hackerdojo account does not appear to be linked to a Spreedly account.  Please contact <a href=\"mailto:treasurer@hackerdojo.com\">treasurer@hackerdojo.com</a> so they can manually update your account."
            self.response.out.write(template.render('templates/error.html', locals()))
            return
          url = "https://spreedly.com/"+SPREEDLY_ACCOUNT+"/subscriber_accounts/"+account.spreedly_token
          self.redirect(url)
          
class BadgeChange(db.Model):
    created = db.DateTimeProperty(auto_now_add=True)
    rfid_tag = db.StringProperty()    
    username = db.StringProperty()
    description = db.StringProperty()

def main():
    application = webapp.WSGIApplication([
        ('/', MainHandler),
        ('/api/rfid', RFIDHandler),
        ('/userlist', AllHandler),
        ('/api/linked', LinkedHandler),
        ('/api/suspended', SuspendedHandler),
        ('/cleanup', CleanupHandler),
        ('/profile', ProfileHandler),
        ('/key', KeyHandler),
        ('/pref', PrefHandler),
        ('/modify', ModifyHandler),
        ('/account/(.+)', AccountHandler),
        ('/upgrade/needaccount', NeedAccountHandler),
        ('/success/(.+)', SuccessHandler),
        ('/memberlist', MemberListHandler),
        ('/update', UpdateHandler),
        ('/tasks/create_user', CreateUserTask),
        ], debug=True)
    wsgiref.handlers.CGIHandler().run(application)

if __name__ == '__main__':
    main()
