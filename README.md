# 1click

#With 1click OWASP secure headers and many other low hanging fruits can be found for any given url.

Following are the low-hanging fruits can be identified with the 1click,
#x-contenttype_options
# HSTS 
#X-frame_Options
#Content-Secuirty_policy
#cache-control 
#Referrer-policy - Inprogress 
#Server Info Leak 
#Feature_policy 
#CORS_Headers 
#Cross_origin_resource_Policy
#Cross-Origin-Embedder-Policy
#X-Permitted-Cross-Domain-Policies

**Steps:**
1. Create a file('target.txt') with list of url's which you want to scan
2. Enter 'python 1lick.py'

**
Below is the sample report generated after running scan for 'ctflearn.com':**

Testing for : https://ctflearn.com
Here is the Report:
*******************************************************************
----------Checking for server infoleak------------

Server informatoin:		cloudflare
X-powered-by is not generated

-------------checking for xframe issues----------

Clickjacking: Application is vulnerable to clickjacking

-------------Checking for caching----------------

Caching: Application is vulnerable to caching

Application supports follwing caching headers:

-------------Checking for feature policy----------------

feature policy is not supporting

-------------Checking for X-Xss-Protection---------------

X-XSS-Protection not set, There is a possibility of having xss

--------------Checking for CORS-------------------

cors has not been configured properly

----------------checking for Cross Origin Resource_policy(different from CORS)--------------

cross-origin resource policy has not configured properly
----------------checking for Cross-Origin-Embedder-Policy----------------------

Cross-Origin-Embedder-Policy has not been configured properly
--------------------Checking for Cross-Domain_policies------------------

X-Permitted-Cross-Domain-Policies has not been configured properly
--------------------Checking for X-Content-type options------------
X-Content-Type-Options not set

---------------Checking for HSTS headers-----------
HSTS: HSTS header not set properly, Man in the middle attacks is possible

Content-Security-Policy is not present

**************End of the report***************
