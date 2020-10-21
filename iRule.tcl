when CLIENT_ACCEPTED {
# Global Variables
  set cookiename "F5_Role_Cookie"
  set encryption_passphrase "Encryption Key, that should be long and complex"
}


when HTTP_RESPONSE {
	if { $uri equals "/" } {
		set uRole [HTTP::cookie "DEV-Cookie"]  
		#log local0. "LogIdentifier uRole: $uRole"
		set roleCookie $uRole
		append roleCookie #sessionID and also part of string
		#log local0. "LogIdentifier uRole: $uRole"
		#log local0. "LogIdentifier uRole: $roleCookie"

		HTTP::cookie remove "DEV-Cookie"
		HTTP::cookie insert name "F5_Role_Cookie" value $roleCookie path "/"
		HTTP::cookie encrypt $cookiename $encryption_passphrase
		log local0. "LogIdentifier EncryptedCookie: [HTTP::cookie "F5_Role_Cookie"]"
	}
}

	switch [HTML::tag name] {
		"form" {
	if { [HTML::tag attribute "action"] equals "./home.aspx" } {
	HTML::tag attribute replace "action" "./"
}
}
}
}


when HTTP_REQUEST {
	#lowercase URI to avoid case sensitive manipulation
	set uri [string tolower [HTTP::uri]] 
	set sessionID [HTTP::cookie "ASP.NET_SessionId"]
	#log local0. "LogIdentifier sessionID: $sessionID"
	#decrypt the cookie
	set decrypted [HTTP::cookie decrypt $cookiename $encryption_passphrase]
	log local0. "Log1 LogIdentifier DecryptedCookie: $decrypted"
	log local0. "Log2 LogIdentifier URI is: $uri"
	if { [matchclass $uri equals URI-List-AnyAccess] } {
		log local0. "Log3 LogIdentifier class AnyAccess $uri"
		return
	} elseif { $uri starts_with "/font" } {
		log local0. "Log3 LogIdentifier Font $uri "
		return
	} elseif { $uri contains "/scripts/" } {
		log local0. "Log3 LogIdentifier Font $uri "
		return
	} elseif { $uri contains "/images/" } {
		log local0. "Log3 LogIdentifier Images $uri "
		return
	} elseif { $uri contains "/css/" } {
		log local0. "Log3 LogIdentifier class CSS $uri "
		return
	} elseif { ( [matchclass $uri equals URI-Role1] ) && #condition to compare session ID and Role1 } {
		return	
	} elseif { ( [matchclass $uri equals URI-Role2] ) && #condition to compare session ID and Role2 } {
		return
	} elseif { ( [matchclass $uri equals URI-Role3] ) && #condition to compare session ID and Role3 } {
		return
	} elseif { ( [matchclass $uri equals URI-Role4] ) && #condition to compare session ID and Role4 } {
		return

	} elseif { ( [matchclass $uri equals URI-Role5] ) && #condition to compare session ID and Role5 } {
		return	
	} elseif { ( [matchclass $uri equals URI-Role6] ) && #condition to compare session ID and Role6 } {
		return
	} elseif { ( [matchclass $uri equals URI-Role7] ) && #condition to compare session ID and Role7 } {
		return
	} elseif { ( [matchclass $uri equals URI-Role8] ) && #condition to compare session ID and Role8 } {
		return
	} else {
  		log local0. "Log3 LogIdentifier 403 AccessDenied $uri "
		HTTP::redirect "https://site.com/accessdenied"
	}



}
