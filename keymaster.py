from google.appengine.api import urlfetch, memcache
from google.appengine.ext import webapp
import urllib

## Example usage
#
# def needs_key():
#     key = keymaster.get('my-key')
#     if key:
#         # Do something with key
#     else:
#         keymaster.request('my-key')
# 
# def main():
#     application = webapp.WSGIApplication([
#         ('/key/(.+)', keymaster.Handler({
#             'my-key': ('6f7e21711e29e6d4b4e64daceb2a7348', '2isy046g', needs_key),
#             'another-key': ('keymaster-hash', 'keymaster-secret', optional_key_arrival_callback),
#             })),
#         ], debug=True)

_keys = {}

def get(keyname):
    return memcache.get(keyname, namespace='keymaster')
    
def request(keyname):
    urlfetch.fetch('http://www.thekeymaster.org/%s' % _keys[keyname][0], method='POST', payload=urllib.urlencode({'secret': _keys[keyname][1]}), deadline=10)
    
class _Handler(webapp.RequestHandler):
    def get(self, keyname):
        request(keyname)
    
    def post(self, keyname):
        key = self.request.get('key')
        if key:
            memcache.set(keyname, key, namespace='keymaster')
            if len(_keys[keyname]) > 2:
                _keys[keyname][2]()

def Handler(keys):
    global _keys
    _keys = keys
    return _Handler
