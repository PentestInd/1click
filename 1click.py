import requests
urls=open("zenq.com", "r")

for url in urls:
	url=url.strip()
	req=requests.get(url)
	print( 'Testing for :',url)
	print('Here is the summery:')
	print('*******************************************************************')
	
#x-contenttype_options -> Yes
# HSTS -> Yes
#X-frame_Options --> Yes
#Content-Secuirty_policy --> Yes
#cache-control --> Yes
#Referrer-policy --> Inprogress
#Server Info Leak -->Yes
#Feature_policy -> yes
#CORS_Headers --> Yes
#Cross_origin_resource_Policy --> Yes

#Server Info Leak
	print('----------Checking for server infoleak------------\n')
	try:
		server_info_leak = req.headers['Server']
		print('Server informatoin:\t\t' +server_info_leak)
		xpoweredby = req.headers['X-Powered-By']
		print('Additional server information through X-powered by:'+xpoweredby)
	except:
		print('X-powered-by is not generated\n')	
#	ref = req.headers['Referrer-Policy']
#	print('This is test')
#	if ((ref == 'no-referrer')|(ref == 'strict-origin-when-cross-origin')):
#			print('Application is not vulnerabile to Referrer policy issue')
#	else:
#		print('Referrer policy is not set configured properly')

#	try:

# X-Frame options header
	print('-------------checking for xframe issues----------\n')
	try:
		xframe=req.headers['X-Frame-Options']
		if ((xframe == 'DENY') and (xframe == 'SAMEORIGIN')):
			print('Clickjacking: Application is not Vulnerable to clickjacking\n')
			print('X-frame-options:' +xframe) 
	except:
		print('Clickjacking: Application is vulnerable to clickjacking\n')
# For Caching 
	print('-------------Checking for caching----------------\n')
	try:
		coaching = req.headers['Cache-Control']
		substring1 = "max-age"
		substring2 = "no-store"
		substring3 = "must-revalidate"
		substring4 = "no-cache"
		if (((substring1 in coaching) and (substring2 in coaching) and (substring3 in coaching)) or ((substring2 in coaching) and (substring3 in coaching)) or ((substring4 in coaching) and (substring2 in coaching) and (substring3 in coaching))):
			print ('Caching: Applicatoin is not vulnerable to caching\n')
			print('Application supports follwing caching headers:' +coaching+ '\n')
	except:
		print('Caching: Application is vulnerable to caching\n') 

# Feature policy
	print('-------------Checking for feature policy----------------\n')

	try:
		feature = req.headers['Feature-Policy']
		print('Feature-poicy contains:' +feature+'\n')
	except:
		print('feature policy is not supporting\n')

# X-XSS-Protection check 
	print('-------------Checking for X-Xss-Protection---------------\n')

	try:
		browser_protection__for_xss = req.headers['X-XSS-Protection']
		if browser_protection_for_xss != '1; mode = block':
			print ('X-XSS-Protection not set properly, There is a possibility of having xss:' +browser_protection_xss+'\n')
	except:
		print ('X-XSS-Protection not set, There is a possibility of having xss\n')
	
#CORS checking
	print('--------------Checking for CORS-------------------\n')
	try:
		cors_check = req.headers['Access-Control-Allow-Origin']
		if cors_check =='*':
			print('Cors misconfiguration exists as application is allowing ', +cors_check+'\n')
		elif cors_check !='*':
			print('Application allows following cors configuration :' +cors_check+'\n')
	except:
		print('cors has not been configured properly\n')

#Cross Origin Resource_policy(different from CORS)
	print('----------------checking for Cross Origin Resource_policy(different from CORS)--------------\n')
	try:
		corp=req.headers['Cross-Origin-Resource-Policy']
		if corp == 'same-origin':
			print('cross-origin resource policy is configured properly with allowing following origin:' +corp+'\n')
		else:
			print('cross-origin resource policy has not been configured properly\n')

	except:
		print('cross-origin resource policy has not configured properly')

#Cross-Origin-Embedder-Policy - This prevents a document from loading any cross-origin resources that don’t explicitly grant the document permission
	print('----------------checking for Cross-Origin-Embedder-Policy----------------------\n')
	try:
		coep_check=req.headers['Cross-Origin-Embedder-Policy']
		if coep_check == 'require-corp':
			print('Cross-Origin-Embedder-Policy has been configured properly with following configuration:' +coep_check+'\n')
		else:
			print('Cross-Origin-Embedder-Policy has not been configured properly')
	except:
		print('Cross-Origin-Embedder-Policy has not been configured properly')

#X-Permitted-Cross-Domain-Policies - A cross-domain policy file is an XML document that grants a web client, such as Adobe Flash Player or Adobe Acrobat (though not necessarily limited to these), permission to handle data across domains.
	print('--------------------Checking for Cross-Domain_policies------------------\n')
	try:
		cross_domain_policy=req.headers['X-Permitted-Cross-Domain-Policies']
		if cross_domain_policy == 'master-only':
			print('Cross_domain_Policy says:' +cross_domain_policy+'\n')
		elif cross_domain_policy == 'by-content-type':
			print('Only policy files served with Content-Type: text/x-cross-domain-policy are allowed. Cross domain policy says:' +cross_domain_policy)
		elif cross_domain_policy == 'by-ftp-filename':
			print('Only policy files whose file names are crossdomain.xml (i.e. URLs ending in /crossdomain.xml) are allowed.Cross Domain policy says:' +cross_domain_policy)
		elif cross_domain_policy == 'all':
			print('All policy files on this target domain are allowed. cross domain policy says:' +cross_domain_policy)
		else:
			print('X-Permitted-Cross-Domain-Policy is configured properly')
	except:
		print('X-Permitted-Cross-Domain-Policies has not been configured properly')

# X-Content_Type_options
	print('--------------------Checking for X-Content-type options------------')
	try:
      		options_content_type = req.headers['X-Content-Type-Options']
      		if options_content_type != 'nosniff':
      			print ('X-Content-Type-Options not set properly:', options_content_type)
#			print('\n')
	except:
      		print ('X-Content-Type-Options not set\n')
      
# HSTS 
	print('---------------Checking for HSTS headers-----------')
	try:
		transport_security = req.headers['Strict-Transport-Security']
		substring = "max-age"
		if substring in transport_security:
			print('HSTS : Strict Tranport-Security header has been configured properly\n') 
	except:
      		print ('HSTS: HSTS header not set properly, Man in the middle attacks is possible\n')
      
#CSP configuration
	try:
      		content_security = req.headers['Content-Security-Policy']
      		print ('Content-Security-Policy is set with following configurations:' +content_security+'\n')
#		substring9 = "script"
#		substring10 = "default"
#		substring11 = "base-uri"
#		if substring9 in content_security:
#			print('CSP: CSP is configured for scripts\n')
#		if substring10 in content_security:
#                       print('CSP: CSP is configured with default src's\n')
#		if substring11 in content_security:
#			print('CSP: CSP is configured with base-URI\n')
	except:
      		print ('Content-Security-Policy is not present\n')

	print('**************End of the report***************')
