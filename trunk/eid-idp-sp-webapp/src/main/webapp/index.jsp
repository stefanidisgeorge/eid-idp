<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html>
<head>
<title>eID Identity Provider (IdP) - Test Service Provider (SP)</title>
</head>
<body>
<h1>eID Identity Provider (IdP) - Test Service Provider (SP)</h1>
<p>This test Service Provider (SP) demos the different
identification/authentication protocols towards the eID IdP.</p>
<ul>
	<li><a
		href="https://<%=request.getServerName()%>:<%=request.getServerPort()%>/eid-idp/protocol/foobar">
		Unsupported Protocol</a></li>

	<li><a
		href="saml-request?IdPDestination=https://<%=request.getServerName()%>:<%=request.getServerPort()%>/eid-idp/protocol/saml2-ident&SPDestination=https://<%=request.getServerName()%>:<%=request.getServerPort()%>/eid-idp-sp/saml2-landing">
		SAML2 eID IdP Request: Identification</a></li>
	<li><a
		href="saml-request?IdPDestination=https://<%=request.getServerName()%>:<%=request.getServerPort()%>/eid-idp/protocol/saml2-auth&SPDestination=https://<%=request.getServerName()%>:<%=request.getServerPort()%>/eid-idp-sp/saml2-landing">
		SAML2 eID IdP Request: Authentication</a></li>
	<li><a
		href="saml-request?IdPDestination=https://<%=request.getServerName()%>:<%=request.getServerPort()%>/eid-idp/protocol/saml2-auth-ident&SPDestinationPage=/saml2-landing">
		SAML2 eID IdP Request: Authentication + Identification (using SPDestinationPage)</a></li>

	<li><a
		href="openid-request?UserIdentifier=https://<%=request.getServerName()%>:<%=request.getServerPort()%>/eid-idp/endpoints/openid-identity&SPDestination=https://<%=request.getServerName()%>:<%=request.getServerPort()%>/eid-idp-sp/openid-landing">
		OpenID eID IdP Request: Identification</a></li>

	<li><a
		href="openid-request?UserIdentifier=https://<%=request.getServerName()%>:<%=request.getServerPort()%>/eid-idp/endpoints/openid-auth&SPDestination=https://<%=request.getServerName()%>:<%=request.getServerPort()%>/eid-idp-sp/openid-landing">
		OpenID eID IdP Request: Authentication</a></li>

	<li><a
		href="openid-request?UserIdentifier=https://<%=request.getServerName()%>:<%=request.getServerPort()%>/eid-idp/endpoints/openid-auth-identity&SPDestination=https://<%=request.getServerName()%>:<%=request.getServerPort()%>/eid-idp-sp/openid-landing">
		OpenID eID IdP Request: Authentication + Identification</a></li>
</ul>
</body>
</html>