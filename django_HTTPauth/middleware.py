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
    token = re.sub('[^a-zA-Z0-9+/=]+', '', force_text(token))
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




