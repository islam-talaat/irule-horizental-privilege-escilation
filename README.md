Do you know how to prevent horizontal privilege escalation using F5?





that's what we already did for one of our customers, F5 WAF can protect the web application from unauthenticated attacks or even vertical privilege escalation, but by default, we couldn't find a way to prevent the attacker from accessing pages that he doesn't have access to after login.



and here we decided to use iRule!



depending on a sessionID cookie and another unencrypted cookie that defines the user role we made it!



the web application now can validate if the user is allowed to access the page or not before giving him access.






#security #cybersecurity #BIGIP #F5 #web #Patching
