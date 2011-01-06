<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<%@ page contentType="text/html; charset=UTF-8" %>

<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>

<html>
<head>
<title>eID Identity Provider (IdP) - Test Service Provider (SP)</title>
</head>
<body>

<jsp:useBean id="attributes" scope="request" class="be.fedict.eid.idp.sp.AttributeBean"/>

<jsp:setProperty name="attributes" property="session" value="<%= request.getSession() %>"  />

<h1>Authentication Results</h1>
<p>Results should be displayed here.</p>
<img src="photo" />
<table>
	<tr>
		<th>Identifier</th>
		<td><%=session.getAttribute("Identifier")%></td>
	</tr>
	<c:forEach var="entry" items="${attributes.attributeMap}">
	    <tr>
	        <th>${entry.key}</th>
	        <td>${entry.value}</td>
	    </tr>
    </c:forEach>
</table>
<a href="index.jsp">Back</a>
</body>
</html>