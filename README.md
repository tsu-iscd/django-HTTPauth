django-HTTPauth
===============

##Brief description

HTTP messages authentication mechanism for Django based on HMAC and attribute based access control (ABAC)

##Main features:
* Strict protection against CSRF attack
* CSRF-tokens protection based on the following
  * token time-to-live - protection against replay attacks
  * token randomization - protection against BREACH-like attacks
  * token scope - protection against token leakage
* Integrity control of parameter names and values
* Validation of client-side generated data
* Basic authorization
* Can be employed in configurations without sharing or persistent session support
* Reducing attacks surface

##Bibliography
*[Jim Monico, Eoin Keary. Form Processing and Workflows](http://secappdev.org/handouts/2014/Jim%20Manico/HTML%20Forms%20and%20Workflows%20v3.pdf)
*[TrustWave’s SpiderLabs. HMAC Token Protection](http://blog.spiderlabs.com/2014/01/modsecurity-advanced-topic-of-the-week-hmac-token-protection.html)
*[TrustWave’s SpiderLabs. Reducing web application attack surface](http://blog.spiderlabs.com/2012/07/reducing-web-apps-attack-surface.html)
