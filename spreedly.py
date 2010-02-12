import urllib, xml.dom.minidom

__version__ = '0.1'

SITE_NAME = 'your-site'
SPREEDLY_BASE_URL = 'https://spreedly.com/api/v4/%(site)s/'
SPREEDLY_TOKEN = 'your-token'

def remove_whitespace_nodes(node, unlink=True):
    remove_list = set()

    for child in node.childNodes:
        if child.nodeType == child.TEXT_NODE and not child.data.strip():
            remove_list.add(child)
        elif child.hasChildNodes():
            remove_whitespace_nodes(child, unlink)

    for node in remove_list:
        node.parentNode.removeChild(node)
        node.unlink()

def get_code(response):
    if hasattr(response, 'code'):
        return response.code # py 2.6
    
    return int(response.headers['status'][0:3])

class UAOpener(urllib.FancyURLopener):
    def __init__(self, token, *args, **kwargs):
        self.token = token
        urllib.FancyURLopener.__init__(self, *args, **kwargs)

    def prompt_user_passwd(self, host, realm):
        return (self.token, 'X')

    version = 'pyspreedly/%s' % __version__

class XMLReply(object):
    def __init__(self, payload):
        self.raw_payload = payload
        self.data = payload.read()
        self.xml = None
        
        dom = self.to_xml()
        self.dict = self.to_dict(dom.documentElement)
        
    def to_xml(self):
        if self.xml is None:
            self.xml = xml.dom.minidom.parseString(self.data)
            remove_whitespace_nodes(self.xml.documentElement)
        return self.xml

    def to_dict(self, parent):
        child = parent.firstChild
    
        if not child:
            return None
        elif child.nodeType == child.TEXT_NODE:
            return child.nodeValue
    
        block = dict()
    
        while child is not None:
            if child.nodeType == child.ELEMENT_NODE:
                block[child.tagName] = self.to_dict(child)
    
            child = child.nextSibling
    
        return block

    # -- 

    def __repr__(self):
        return '<XMLReply: data=%d bytes>' % len(self.data)

class SpreedlyResponseError(Exception):
    def __init__(self, response):
        self.code = get_code(response)
        self.headers = response.headers
        self.url = self.safe_url(response.url)
        self.body = response.read()
    
    def safe_url(self, url):
        if not '@' in url:
            return url
            
        return url[:url.index('//')+2]+url[url.index('@')+1:]
    
    def __str__(self):
        return '<SpreedlyResponseError: code=%d, url=%s>' % (self.code, self.url)

class Spreedly(object):
    """
    Stupid-simple Python library for talking
    to spreedly.com.
    """
    def __init__(self, site=SITE_NAME, base_url=SPREEDLY_BASE_URL, token=SPREEDLY_TOKEN):
        self.site = site
        self.base_url = base_url
        self.token = token
        
    def url(self, rel_url):
        return self.base_url % { 'site': self.site }+rel_url
        
    def request(self, url, data=None):
        opener = UAOpener(self.token)
        return self.to_reply(opener.open(self.url(url), data))
        
    def to_reply(self, response):
        if not get_code(response) == 200:
            raise SpreedlyResponseError(response)
        
        return XMLReply(response).dict
    
    # -- 
    
    def url_factory(url):
        def wrapped_request(self, data=None, **kwargs):
            return self.request(url % kwargs, data)
        return wrapped_request
        
    subscribers = url_factory('subscribers.xml')
    subscription_plans = url_factory('subscription_plans.xml')
    subscriber_details = url_factory('subscribers/%(sub_id)d.xml')
    
    def __repr__(self):
        return '<Spreedly: site=%s, token=%s>' % (self.site, self.token)
        
if __name__ == "__main__":
    sp = Spreedly()
    
    print sp.subscription_plans()
    print sp.subscriber_details(sub_id=1)
    print sp.subscribers()
