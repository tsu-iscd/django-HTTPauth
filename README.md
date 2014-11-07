django-HTTPauth
===============

##Brief description

HTTP messages authentication mechanism for Django based on HMAC and attribute based access control (ABAC)

##Main features:
* Strict protection against CSRF attack
* CSRF-tokens protection based on the following properties
  * token time-to-live - protection against replay attacks
  * token randomization - protection against BREACH-like attacks
  * token scope - protection against token leakage
* Integrity control of parameter names and values
* Validation of client-side generated data
* Basic authorization
* Support sessionless and sessionful modes
* Can be employed in configurations without sharing or persistent session support
* Reducing attacks surface

##Installation
1. Download and unpack django-HTTPauth to your django project.
2. Replace 'django.middleware.csrf.CsrfViewMiddleware' line by 'signed\_csrf.middleware.HttpAuthMiddleware' in MIDDLEWARE\_CLASSES tuple of settings.py.

##Configuration
There are a few ways to configure policy of the protected form:
* Use dictionary
* Use decorators

###Using dictionary
Add a dictionary with a name policy to the protected form. There are several options which can be used in the policy:

1. **object** - required - identificator of the form. Regexp of form action URL.
2. **subject** - required - identificator of the client. If this option is not set then the settings.SESSION\_COOKIE\_NAME will be used. Session will be created if it's not exist.
3. **name_protection** - optional - protection against such attack as HTTP parameter pollution. If this options is set to True then request from a client will be accepted only if total amount and all names of the form fields will be the same as were send by the server to the client.
4. **replay_protection** - optional - protection against replay attack. Includes 'enable' and 'interval' options. First option enables protection. Second one set the expiration period (in seconds).
5. **parameter_protection** - optional - section which includes subsections which are names of the protected parameters and their options. Options are 'action' and 'value'. If 'action' is 'validate' then 'value' includes regexp of the correct form field value. If 'action' is 'control' then the form field value will be accepted only if it was not modified by client.

If policy is not configured then the random number will be generated to protect the form against CSRF attack.

Example:
```python
class ClientForm(forms.Form):
    first\_name = forms.CharField(max_length=40)
    last\_name = forms.CharField(max_length=40)
    code = forms.IntegerField()
    policy = {
              'object': 'http://127.0.0.1:8000/[a-z]+/',
              'replay_protection': {
                   'enable':False, 
                   'interval':60
              }, 
              'name_protection':True,
               'parameter_protection':
              {
               'first\_name': 
              {
                  'action':'validate',
                  'value':'[a-z]+'
               },
                'code': 
              {
                  'action':'control',
               },
              }
             }
```

###Using decorators
Decorators can be used as an alternative mechanism of form configuration. There are the following decorators:

1. **name\_protection** - optional - policy\_name_protection(True|False).
2. **replay\_protection** - optional -  policy\_replay\_protection(INTERVAL). Interval (positive integer value) - expiration period of the form token (in seconds).
3. **parameter\_protection** - optional - policy(PARAMETER\_FIELD\_NAME=(ACTION,VALUE| )). 

Example:
```python
@policy\_name_protection(True)
@policy\_replay\_protection(30)
@policy(code=('control',))
class ClientForm(forms.Form):
    first\_name = forms.CharField(max_length=40)
    last\_name = forms.CharField(max_length=40)
    code = forms.IntegerField()
    policy = {
              'object': 'http://127.0.0.1:8000/[a-z]+/',
             }
```

##Bibliography
* [Vladimir Kochetkov. How to Develop a Secure Web Application and Stay in Mind?] (http://www.slideshare.net/kochetkov.vladimir/how-to-develop-a-secure-web-application-and-stay-in-mind-phdays-3)
* [Jim Monico, Eoin Keary. Form Processing and Workflows](http://secappdev.org/handouts/2014/Jim%20Manico/HTML%20Forms%20and%20Workflows%20v3.pdf)
* [TrustWave’s SpiderLabs. HMAC Token Protection](http://blog.spiderlabs.com/2014/01/modsecurity-advanced-topic-of-the-week-hmac-token-protection.html)
* [TrustWave’s SpiderLabs. Reducing web application attack surface](http://blog.spiderlabs.com/2012/07/reducing-web-apps-attack-surface.html)
