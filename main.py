import wsgiref.handlers
import datetime, time, hashlib, urllib, urllib2, re, os
from google.appengine.ext import db
from google.appengine.ext import webapp
from google.appengine.api import urlfetch, mail
from google.appengine.ext.webapp import template
import spreedly

try:
    is_dev = os.environ['SERVER_SOFTWARE'].startswith('Dev')
except:
    is_dev = False

import keys
if is_dev:
    SPREEDLY_ACCOUNT = 'hackerdojotest'
    SPREEDLY_APIKEY = keys.hackerdojotest
    PLAN_IDS = {'full': '1957'}
else:
    SPREEDLY_ACCOUNT = 'hackerdojo'
    SPREEDLY_APIKEY = keys.hackerdojo
    PLAN_IDS = {'full': '1987', 'hardship': '2537', 'supporter': '1988', 'family': '3659', 'minor': '3660'}

is_prod = not is_dev

def build_subscriber_url(account):
    return "https://spreedly.com/%s/subscriber_accounts/%s" % (SPREEDLY_ACCOUNT, account.token)

class Membership(db.Model):
    hash = db.StringProperty()
    first_name = db.StringProperty(required=True)
    last_name = db.StringProperty(required=True)
    email = db.StringProperty(required=True)
    plan  = db.StringProperty(required=True)
    status  = db.StringProperty() # None, active, suspended
    referrer  = db.StringProperty()
    username = db.StringProperty()
    
    spreedly_token = db.StringProperty()
    
    created = db.DateTimeProperty(auto_now_add=True)
    updated = db.DateTimeProperty(auto_now=True)

class MainHandler(webapp.RequestHandler):
    def get(self):
        self.response.out.write(template.render('templates/main.html', {'is_prod': is_prod, 'plan': self.request.get('plan', 'full')}))
    
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
                if existing_member.status == 'unpaid':
                    existing_member.delete()
                else:
                    self.response.out.write(template.render('templates/main.html', {'is_prod': is_prod, 'plan': plan, 'message': "You're already in our system!"}))
                    return
            m = Membership(first_name=first_name, last_name=last_name, email=email, plan=plan)
            m.hash = hashlib.md5(m.email).hexdigest()
            m.referrer = self.request.get('referrer')
            m.put()
            id = str(m.key().id())
            username = "%s-%s-%s" % (m.first_name.lower(), m.last_name.lower(), id)
            query_str = urllib.urlencode({'first_name': m.first_name, 'last_name': m.last_name, 'email': m.email, 'return_url': 'http://%s/success/%s' % (self.request.host, m.hash)})
            self.redirect("https://spreedly.com/%s/subscribers/%s/subscribe/%s/%s?%s" % (SPREEDLY_ACCOUNT, id, PLAN_IDS[m.plan], username, query_str))

class SuccessHandler(webapp.RequestHandler):
    def get(self):
        success_html = urlfetch.fetch("http://hackerdojo.pbworks.com/api_v2/op/GetPage/page/SubscriptionSuccess/_type/html").content
        member = Membership.all().filter('hash =', self.request.path.split('/')[-1]).get()
        if member:
            success_html = success_html.replace('joining!', 'joining, %s!' % member.first_name)
        is_prod = not is_dev
        self.response.out.write(template.render('templates/success.html', locals()))

class UpdateHandler(webapp.RequestHandler):
    def get(self):
        pass
    
    def post(self, ids=None):
        subscriber_ids = self.request.get('subscriber_ids').split(',')
        s = spreedly.Spreedly(SPREEDLY_ACCOUNT, token=SPREEDLY_APIKEY)
        for id in subscriber_ids:
            subscriber = s.subscriber_details(sub_id=int(id))
            member = Membership.get_by_id(int(subscriber['customer-id']))
            #old_status = member.status
            member.status = 'active' if subscriber['active'] == 'true' else 'suspended'
            member.spreedly_token = subscriber['token']
            member.plan = subscriber['feature-level'] or member.plan
            member.email = subscriber['email']
            member.put()
        self.response.out.write("ok")
            
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
            mail.send_mail(sender="Signup <no-reply@hackerdojo-signup.appspotmail.com>",
                to="Jeff Lindsay <progrium@gmail.com>",
                subject="Recent almost members",
                body='\n'.join(deleted_emails))

def main():
    application = webapp.WSGIApplication([
        ('/', MainHandler),
        ('/cleanup', CleanupHandler),
        ('/success.*', SuccessHandler),
        ('/update', UpdateHandler),], debug=True)
    wsgiref.handlers.CGIHandler().run(application)

if __name__ == '__main__':
    main()
