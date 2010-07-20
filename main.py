import wsgiref.handlers
import datetime, time, hashlib, urllib, urllib2, re, os
from google.appengine.ext import db
from google.appengine.ext import webapp
from google.appengine.api import urlfetch, mail, memcache, users
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
DAYS_FOR_KEY = 60

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
    PLAN_IDS = {'full': '1987', 'hardship': '2537', 'supporter': '1988', 'family': '3659', 'minor': '3660', 'full-check': '6479', 'hardship-check': '6480' }

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
    
    spreedly_token = db.StringProperty()
    
    created = db.DateTimeProperty(auto_now_add=True)
    updated = db.DateTimeProperty(auto_now=True)
    
    def full_name(self):
        return '%s %s' % (self.first_name, self.last_name)
    
    def spreedly_url(self):
        return "https://spreedly.com/%s/subscriber_accounts/%s" % (SPREEDLY_ACCOUNT, self.spreedly_token)

class MainHandler(webapp.RequestHandler):
    def get(self):
        self.response.out.write(template.render('templates/main.html', {
            'is_prod': is_prod, 
            'plan': self.request.get('plan', 'full'),
            'paypal': self.request.get('paypal')}))
    
    def post(self):
        first_name = self.request.get('first_name')
        last_name = self.request.get('last_name')
        email = self.request.get('email')
        plan = self.request.get('plan', 'full')
        
        if not first_name or not last_name or not email:
            self.response.out.write(template.render('templates/main.html', {'is_prod': is_prod, 'plan': plan, 'message': "Sorry, we need all three fields."}))
        else:
            existing_member = Membership.all().filter('email =', email).get()
            if existing_member:
                if existing_member.status in [None, 'paypal']:
                    existing_member.delete()
                else:
                    self.response.out.write(template.render('templates/main.html', {'is_prod': is_prod, 'plan': plan, 'message': "You're already in our system!"}))
                    return
            m = Membership(first_name=first_name, last_name=last_name, email=email, plan=plan)
            if self.request.get('paypal') == '1':
                m.status = 'paypal'
            m.hash = hashlib.md5(m.email).hexdigest()
            m.referrer = self.request.get('referrer')
            m.put()
            id = str(m.key().id())
            username = "%s-%s-%s" % (m.first_name.lower(), m.last_name.lower(), id)
            query_str = urllib.urlencode({'first_name': m.first_name, 'last_name': m.last_name, 'email': m.email, 'return_url': 'http://%s/account/%s' % (self.request.host, m.hash)})

            if "maker00000" in m.referrer.lower():
              key = SPREEDLY_APIKEY
              encoded = base64.b64encode( key+':X')
              authstr = "Basic "+encoded
              mheaders = {'Authorization':authstr,'Content-Type':'application/xml'}
              # Create subscriber
              data = "<subscriber><customer-id>%s</customer-id><email>%s</email></subscriber>" % (id,email)
              resp = urlfetch.fetch("https://spreedly.com/api/v4/%s/subscribers.xml" % (SPREEDLY_ACCOUNT), method='POST',  payload=data, headers = mheaders, deadline=10)
              # Credit
              data = "<credit><amount>30.00</amount></credit>"
              resp = urlfetch.fetch("https://spreedly.com/api/v4/%s/subscribers/%s/credits.xml" % (SPREEDLY_ACCOUNT, id), method='POST',  payload=data, headers = mheaders, deadline=10)

                        
            self.redirect("https://spreedly.com/%s/subscribers/%s/subscribe/%s/%s?%s" % (SPREEDLY_ACCOUNT, id, PLAN_IDS[m.plan], username, query_str))

class AccountHandler(webapp.RequestHandler):
    def get(self, hash):
        m = Membership.all().filter('hash =', hash).get()
        if m.username:
            self.redirect('/success/%s' % hash)
        else:
            s = spreedly.Spreedly(SPREEDLY_ACCOUNT, token=SPREEDLY_APIKEY)
            valid_acct = False
            try:
                subscriber = s.subscriber_details(sub_id=int(m.key().id()))
                valid_acct = subscriber['active'] == 'true'
            except spreedly.SpreedlyResponseError:
                pass
            if valid_acct:
                user = users.get_current_user()
                if user:
                    m.username = user.nickname().split('@')[0]
                    m.put()
                    self.redirect(users.create_logout_url('/success/%s' % hash))
                else:
                    message = self.request.get('message')
                    p = re.compile(r'[^\w]')
                    username = '.'.join([p.sub('', m.first_name), p.sub('', m.last_name)]).lower()
                    if username in fetch_usernames():
                        username = m.email.split('@')[0]
                    if self.request.get('u'):
                        pick_username = True
                    login_url = users.create_login_url(self.request.path)
                    self.response.out.write(template.render('templates/account.html', locals()))
            else:
                self.redirect("/")
    
    def post(self, hash):
        username = self.request.get('username')
        password = self.request.get('password')
        if password != self.request.get('password_confirm'):
            self.redirect(self.request.path + "?message=Passwords don't match")
        elif len(password) < 6:
            self.redirect(self.request.path + "?message=Password must be 6 characters or longer")
        else:
            m = Membership.all().filter('hash =', hash).get()
            
            if m and m.spreedly_token:
                try:
                    resp = urlfetch.fetch('http://domain.hackerdojo.com/users', method='POST', payload=urllib.urlencode({
                        'username': username,
                        'password': password,
                        'first_name': m.first_name,
                        'last_name': m.last_name,
                        'secret': keymaster.get('api@hackerdojo.com'),
                    }), deadline=10)
                    out = resp.content
                except urlfetch.DownloadError, e:
                    out = str(e)
            
            usernames = fetch_usernames(False)
            if username in usernames:
                m.username = username
                m.put()
                self.redirect('/success/%s?email' % hash)
            else:
                mail.send_mail(sender=EMAIL_FROM,
                    to="Jeff Lindsay <progrium@gmail.com>",
                    subject="Error creating account for %s" % username,
                    body=out if m.spreedly_token else "Attempt to make user without paying: " + self.request.remote_addr)
                self.redirect(self.request.path + "?message=There was a problem creating your account. Please contact an admin.")
            

class SuccessHandler(webapp.RequestHandler):
    def get(self, hash):
        member = Membership.all().filter('hash =', hash).get()
        if member:
            if self.request.query_string == 'email':
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
        email = self.request.get('email')
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

class KeyHandler(webapp.RequestHandler):
    def get(self):
      user = users.get_current_user()
      if not user:
          self.redirect(users.create_login_url('/key'))
          return
      else:
          account = Membership.all().filter('email =', user.email()).get()
          if not account or not account.spreedly_token:
            error = "<p>It appears that you have an account on @hackerdojo.com, but you do not have a corresponding account in the signup application.</p><p>How to remedy:</p><ol><li>If you <b>are not</b> in the Spreedly system yet, <a href=\"/\">sign up</a> now.</li><li>If you <b>are</b> in Spreedly already, please contact <a href=\"mailto:signupops@hackerdojo.com?Subject=Spreedly+account+not+linked+to+hackerdojo+account\">signupops@hackerdojo.com</a>.</li></ol>"
            self.response.out.write(template.render('templates/error.html', locals()))
            return
          if account.status != "active":
            url = "https://spreedly.com/"+SPREEDLY_ACCOUNT+"/subscriber_accounts/"+account.spreedly_token
            error = "<p>Your Spreedly account status does not appear to me marked as active.  This might be a mistake, in which case we apologize. <p>To investigate your account, you may go here: <a href=\""+url+"\">"+url+"</a> <p>If you believe this message is in error, please contact <a href=\"mailto:signupops@hackerdojo.com?Subject=Spreedly+account+not+linked+to+hackerdojo+account\">signupops@hackerdojo.com</a></p>";
            self.response.out.write(template.render('templates/error.html', locals()))
            return
          delta = datetime.utcnow() - account.created
          if delta.days < DAYS_FOR_KEY:
            error = "<p>You have been a member for "+str(delta.days)+" days.  After "+str(DAYS_FOR_KEY)+" days you qualify for a key.  Check back in "+str(DAYS_FOR_KEY-delta.days)+" days!</p>";
            self.response.out.write(template.render('templates/error.html', locals()))
            return    
          bc = BadgeChange.all().filter('username =', account.username).fetch(100)
          self.response.out.write(template.render('templates/key.html', locals()))

    def post(self):
      user = users.get_current_user()
      if not user:
          self.redirect(users.create_login_url('/key'))
          return
      account = Membership.all().filter('email =', user.email()).get()    
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
     
class BadgeChange(db.Model):
    created = db.DateTimeProperty(auto_now_add=True)
    rfid_tag = db.StringProperty()    
    username = db.StringProperty()
    description = db.StringProperty()

def main():
    application = webapp.WSGIApplication([
        ('/', MainHandler),
        ('/api/linked', LinkedHandler),
        ('/api/suspended', SuspendedHandler),
        ('/cleanup', CleanupHandler),
        ('/key', KeyHandler),
        ('/account/(.+)', AccountHandler),
        ('/upgrade/needaccount', NeedAccountHandler),
        ('/success/(.+)', SuccessHandler),
        ('/update', UpdateHandler),
        ], debug=True)
    wsgiref.handlers.CGIHandler().run(application)

if __name__ == '__main__':
    main()
