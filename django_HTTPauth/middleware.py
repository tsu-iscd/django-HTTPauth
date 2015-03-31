"""
Cross Site Request Forgery Middleware.

This module provides a middleware that implements protection
against request forgeries from other sites.
"""
from __future__ import unicode_literals

import logging
import itertools
import re
import copy
import hmac

from datetime import datetime, timedelta
from copy import copy

from django.http import HttpResponse
from django_HTTPauth import token_validate
from django.conf import settings
from django.core.urlresolvers import get_callable
from django.utils.cache import patch_vary_headers
from django.utils.encoding import force_text
from django.utils.http import same_origin
from django.utils.crypto import constant_time_compare, get_random_string
from django.utils.safestring import mark_safe


logger = logging.getLogger('django.request')

REASON_NO_REFERER = "Referer checking failed - no Referer."
REASON_BAD_REFERER = "Referer checking failed - %s does not match %s."
REASON_NO_CSRF_COOKIE = "CSRF cookie not set."
REASON_BAD_TOKEN = "CSRF token missing or incorrect."

CSRF_KEY_LENGTH=16

def _get_failure_view():
    return get_callable(settings.CSRF_FAILURE_VIEW)


def _get_new_csrf_key():
    return get_random_string(CSRF_KEY_LENGTH)


def validate_auth_token(request,auth_token):

    dic_all = {} 
    for x in request.POST:
        if x!='auth_token' and x!='auth_policy':
            dic_all[x]=request.POST[x]

    if token_validate(request,auth_token,dic_all) == False:
        return False
    return True
 
def _sanitize_token(token):
    token = re.sub('[^a-zA-Z0-9+/=;]+', '', force_text(token))
    if token == '':
        return None
    return token

class HttpAuthMiddleware(object):
    def _accept(self, request):
        return None

    def _reject(self, request, reason):
        logger.warning('Forbidden (%s): %s',
                       reason, request.path,
            extra={
                'status_code': 403,
                'request': request,
            }
        )
        return _get_failure_view()(request, reason=reason)

    def process_view(self, request, callback, callback_args, callback_kwargs):

        if getattr(request, 'auth_processing_done', False):
            return None

        if request.method == 'POST':
            auth_token = _sanitize_token(request.POST.get('auth_token',''))
            
            if auth_token is None:
                try:
                    csrf_token = _sanitize_token(request.COOKIES[settings.CSRF_COOKIE_NAME])
                    request_csrf_token = request.POST.get('csrfmiddlewaretoken', '')
                    if not constant_time_compare(request_csrf_token, csrf_token):
                        return self._reject(request, REASON_BAD_TOKEN)
                except KeyError:
                    return self._reject(request, REASON_BAD_TOKEN)

            if not validate_auth_token(request,auth_token):
                return self._reject(request, REASON_BAD_TOKEN)

        return self._accept(request)

class CookieMiddleware(object):
    hmac_secret_key     = settings.COOKIE_MIDDLEWARE['secret_key']
    controlled_cookies  = settings.COOKIE_MIDDLEWARE['controlled_cookies']
    logout_page         = settings.LOGOUT_PAGE

    def process_request(self, request):
        if not self.is_request_valid(request):
            self.create_logout_request(request)
            request.__forbidden = True

        for c in request.unwanted_cookies:
            del request.COOKIES[c]

    def process_response(self, request, response):
        try:    is_forbidden = request.__forbidden
        except: is_forbidden = False
        if is_forbidden: 
            return self.unset_unnecessary_cookies(response, request.__COOKIES_FOR_DELETION)
        
        try:
            WAF_ALPHA = self.load_dump(request.COOKIES['~WAF~ALPHA'][33:])
        except:
            WAF_ALPHA = {}
        #get copy of response cookie names
        setted_cookies = dict(response.cookies)

        for cookie_name in setted_cookies:
            if cookie_name not in self.controlled_cookies:
                continue
            c = copy(response.cookies[cookie_name])

            #create WAF cookie
            c_waf = self.create_waf_cookie(c)
            self.set_cookie(response, c_waf)

            #register setted cookie
            c = response.cookies[cookie_name]
            WAF_ALPHA[c.key] = {}
            WAF_ALPHA[c.key]['path']   = c['path']
            WAF_ALPHA[c.key]['domain'] = c['domain']
            WAF_ALPHA[c.key]['secure'] = c['secure']

        if bool(WAF_ALPHA):
            self.set_WAF_ALPHA_value(response, self.dump(WAF_ALPHA))
        return response

    def create_logout_request(self, request):
        request.path = self.logout_page
        request.__COOKIES_FOR_DELETION = [{"key":"~WAF~ALPHA","path":"/","domain": None}]

    def unset_unnecessary_cookies(self, response, unnecessary_cookies):
        for i in unnecessary_cookies:
            response.delete_cookie(i['key'],i['path'],i['domain'])
        return response

    def get_controlled_cookies(self,request):
        contolled_cookies = {}
        for x in request.COOKIES:
            if x in self.controlled_cookies:
                contolled_cookies[x] = request.COOKIES[x]
        return contolled_cookies

    def is_request_valid(self,request):
        contolled_cookies = self.get_controlled_cookies(request)
        request.unwanted_cookies = {}

        #pass the request if it dont contain any controlled cookie
        if not bool(contolled_cookies):
            return True

        #if it contains controoled cookies but not ~WAF~ALPHA
        if '~WAF~ALPHA' not in request.COOKIES:
            request.unwanted_cookies = contolled_cookies
            return True
        
        #check for ~WAF~ALPHA integrity
        if not self.check_hmac(request.COOKIES['~WAF~ALPHA']):
            return False
        
        WAF_ALPHA = self.load_dump(request.COOKIES['~WAF~ALPHA'][33:])
        
        for c in contolled_cookies:
            if c not in WAF_ALPHA:
                request.unwanted_cookies[c] = request.COOKIES[c]
                continue
            if not self.is_cookie_valid(request, WAF_ALPHA, c):
                return False
        return True
        
    def is_path_invalid(self, cookie_path, request_path):
        return not(re.match(cookie_path, request_path))

    def is_domain_invalid(self, cookie_domain, request_domain):
        return not(re.search(cookie_domain+'$', '.'+request_domain))

    def is_connection_insecure(self, is_cookie_secure, is_connection_secure):
        return is_cookie_secure and not is_cookie_secure

    def is_cookie_valid(self, request, WAF_ALPHA, key):    
        #check path, domain and secure cookie on unsecure connection
        if (  self.is_path_invalid( WAF_ALPHA[key]['path'], request.path ) or
              self.is_domain_invalid( WAF_ALPHA[key]['domain'], request.META['SERVER_NAME'] ) or
              self.is_connection_insecure( WAF_ALPHA[key]['secure'], request.is_secure() ) ):
            return False
        
        #look for ~WAF pair
        if key+"~WAF" in request.COOKIES:
            waf_cookie = request.COOKIES[key+"~WAF"]
        else: 
            return False
        
        p = {}
        try:
            p['value'],p['expires'] = (waf_cookie[33:].split('|'))
        except:
            return False
        
        #check for ~WAF cookie integrity
        if not self.check_hmac(waf_cookie):
            return False
        #check for cookie value integrity
        if p['value'] != request.COOKIES[key]:
            return False
        #check whether expires was extended
        if p['expires'] != 's':
            if datetime.fromtimestamp(float(p['expires'])) < datetime.now():
                return False
        return True

    def check_hmac(self, cookie):
        if str(cookie[:32]) != str(hmac.new(self.hmac_secret_key, msg=cookie[33:]).hexdigest()):
            return False
        return True
    
    def create_waf_cookie(self,cookie):
        cookie.key = cookie.key + '~WAF'
        try:    expires =  int((datetime.strptime(cookie['expires'], "%a, %d-%b-%Y %H:%M:%S %Z") - datetime(1970,1,1)).total_seconds()) 
        except: expires = "session"
        cookie.value = hmac.new(self.hmac_secret_key, msg=cookie.value+"|"+str(expires)).hexdigest()+ "|"+ cookie.value  +"|"+ str(expires)
        return cookie

    def set_WAF_ALPHA_value(self, response, value):
        hmac_value  = hmac.new(self.hmac_secret_key, msg=value).hexdigest()
        response.set_cookie('~WAF~ALPHA',hmac_value+"|"+value)

    #set and unset Cookie.Morsel objects
    def set_cookie(self,response, cookie):
        response.set_cookie( cookie.key, cookie.value,
                             path=cookie['path'],
                             domain=cookie['domain'],
                             secure=cookie['secure'],
                             httponly=cookie['httponly'])

    def unset_cookie(self,response, cookie):
        response.delete_cookie( cookie.key, 
                                path=cookie['path'],
                                domain=cookie['domain'])

    #dump and load_dump for WAS~ALPHA
    def dump(self, lst):
        s = ''
        for v in lst:
            s += "{}|{}|{}|{}|".format(v, lst[v]['path'], lst[v]['domain'], lst[v]['secure'])
        return s

    def load_dump(self, s):
        l = s.split('|')[:-1]
        undumped = {}
        for i in range(0,len(l),4):
            undumped[l[i]] = {
                    'key'    : l[i],
                    'path'   : l[i+1],
                    'domain' : l[i+2],
                    'secure' : l[i+3]
                }
        return undumped


