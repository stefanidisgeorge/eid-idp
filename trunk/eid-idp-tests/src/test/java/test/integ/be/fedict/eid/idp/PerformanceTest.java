/*
 * eID Identity Provider Project.
 * Copyright (C) 2011 FedICT.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version
 * 3.0 as published by the Free Software Foundation.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, see 
 * http://www.gnu.org/licenses/.
 */

package test.integ.be.fedict.eid.idp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.awt.Component;
import java.io.IOException;
import java.io.StringWriter;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.security.cert.X509Certificate;
import javax.servlet.http.HttpServletResponse;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.httpclient.ConnectTimeoutException;
import org.apache.commons.httpclient.Cookie;
import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HostConfiguration;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.methods.ByteArrayRequestEntity;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.methods.RequestEntity;
import org.apache.commons.httpclient.params.HttpConnectionParams;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;
import org.apache.commons.httpclient.protocol.SSLProtocolSocketFactory;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.junit.Test;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import be.fedict.eid.applet.DiagnosticTests;
import be.fedict.eid.applet.Messages;
import be.fedict.eid.applet.Messages.MESSAGE_ID;
import be.fedict.eid.applet.Status;
import be.fedict.eid.applet.View;
import be.fedict.eid.applet.sc.PcscEid;
import be.fedict.eid.applet.shared.AppletProtocolMessageCatalog;
import be.fedict.eid.applet.shared.AuthenticationContract;
import be.fedict.eid.applet.shared.AuthenticationDataMessage;
import be.fedict.eid.applet.shared.AuthenticationRequestMessage;
import be.fedict.eid.applet.shared.FinishedMessage;
import be.fedict.eid.applet.shared.HelloMessage;
import be.fedict.eid.applet.shared.protocol.HttpReceiver;
import be.fedict.eid.applet.shared.protocol.HttpTransmitter;
import be.fedict.eid.applet.shared.protocol.ProtocolMessageCatalog;
import be.fedict.eid.applet.shared.protocol.Transport;
import be.fedict.eid.applet.shared.protocol.Unmarshaller;

public class PerformanceTest {

	// private static final String PROXY_HOST = null;

	private static final String PROXY_HOST = "proxy2.yourict.net";

	private static final int PROXY_PORT = 8080;

	//private static final String EID_IDP_HOST = "idp.services.belgium.be";

	// private static final String EID_IDP_HOST = "localhost";

	private static final String EID_IDP_HOST = "www.e-contract.be";

	private static final String EID_IDP_SAML_BROWSER_POST_URL = "https://"
			+ EID_IDP_HOST + "/eid-idp/protocol/saml2/post/auth-ident";

	private static final String EID_IDP_APPLET_URL = "https://" + EID_IDP_HOST
			+ "/eid-idp/applet-authentication-service";

	private static final String EID_IDP_EXIT_URL = "https://" + EID_IDP_HOST
			+ "/eid-idp/protocol-exit";

	private static final Log LOG = LogFactory.getLog(PerformanceTest.class);

	@Test
	public void testPerformance() throws Exception {
		DefaultBootstrap.bootstrap();

		Messages messages = new Messages(Locale.getDefault());
		PcscEid pcscEid = new PcscEid(new TestView(), messages);
		if (false == pcscEid.isEidPresent()) {
			LOG.info("insert eID card");
			pcscEid.waitForEidPresent();
		}
		LOG.info("reading out eID card...");
		byte[] identityData = pcscEid.readFile(PcscEid.IDENTITY_FILE_ID);
		byte[] addressData = pcscEid.readFile(PcscEid.ADDRESS_FILE_ID);
		byte[] photoData = pcscEid.readFile(PcscEid.PHOTO_FILE_ID);
		byte[] rrnCertData = pcscEid.readFile(PcscEid.RRN_CERT_FILE_ID);
		List<java.security.cert.X509Certificate> authnCertChain = pcscEid
				.getAuthnCertificateChain();
		byte[] identitySignatureData = pcscEid
				.readFile(PcscEid.IDENTITY_SIGN_FILE_ID);
		byte[] addressSignatureData = pcscEid
				.readFile(PcscEid.ADDRESS_SIGN_FILE_ID);

		XMLObjectBuilderFactory builderFactory = Configuration
				.getBuilderFactory();
		String spDestination = "http://localhost/eid-idp-performance-sp";

		boolean running = true;
		long t0 = System.currentTimeMillis();
		long authnCount = 0;
		while (running) {
			SAMLObjectBuilder<AuthnRequest> requestBuilder = (SAMLObjectBuilder<AuthnRequest>) builderFactory
					.getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
			AuthnRequest authnRequest = requestBuilder.buildObject();
			authnRequest.setID("authn-request-" + UUID.randomUUID().toString());
			authnRequest.setVersion(SAMLVersion.VERSION_20);
			authnRequest.setIssueInstant(new DateTime());
			authnRequest.setDestination(EID_IDP_SAML_BROWSER_POST_URL);
			authnRequest.setAssertionConsumerServiceURL(spDestination);
			authnRequest.setForceAuthn(true);
			authnRequest
					.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);

			SAMLObjectBuilder<Issuer> issuerBuilder = (SAMLObjectBuilder<Issuer>) builderFactory
					.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
			Issuer issuer = issuerBuilder.buildObject();
			issuer.setValue("eID IdP Performance Test");
			authnRequest.setIssuer(issuer);

			MarshallerFactory marshallerFactory = Configuration
					.getMarshallerFactory();
			Marshaller marshaller = marshallerFactory
					.getMarshaller(authnRequest);
			Element authnRequestElement = marshaller.marshall(authnRequest);
			String authnRequestString = xmlToString(authnRequestElement);
			LOG.debug("authn request: " + authnRequestString);
			String authnRequestBase64 = Base64
					.encodeBase64String(authnRequestString.getBytes());

			HttpClient httpClient = new HttpClient();
			HostConfiguration hostConfiguration = httpClient
					.getHostConfiguration();
			if (null != PROXY_HOST) {
				hostConfiguration.setProxy(PROXY_HOST, PROXY_PORT);
			}

			MySSLProtocolSocketFactory protocolSocketFactory = new MySSLProtocolSocketFactory();
			Protocol protocol = new Protocol("https",
					(ProtocolSocketFactory) protocolSocketFactory, 443);
			Protocol.registerProtocol("https", protocol);

			PostMethod postMethod = new PostMethod(
					EID_IDP_SAML_BROWSER_POST_URL);
			postMethod.addParameter("SAMLRequest", authnRequestBase64);
			int protocolRequestResult = httpClient.executeMethod(postMethod);
			LOG.debug("protocol request result: " + protocolRequestResult);
			LOG.debug("result body: " + postMethod.getResponseBodyAsString());
			assertEquals(HttpServletResponse.SC_MOVED_TEMPORARILY,
					protocolRequestResult);
			String idpLocation = postMethod.getResponseHeader("Location")
					.getValue();
			LOG.debug("IdP location: " + idpLocation);
			Cookie[] cookies = httpClient.getState().getCookies();
			LOG.debug("# cookies: " + cookies.length);
			for (Cookie cookie : cookies) {
				String cookieName = cookie.getName();
				String cookieValue = cookie.getValue();
				LOG.debug("cookie: " + cookieName + "=" + cookieValue);
			}

			HttpClientHttpTransceiver httpTransceiver = new HttpClientHttpTransceiver(
					httpClient, EID_IDP_APPLET_URL);
			HelloMessage helloMessage = new HelloMessage();
			Transport.transfer(helloMessage, httpTransceiver);
			postMethod = httpTransceiver.getPostMethod();
			LOG.debug("eID Applet HelloMessage result: "
					+ httpTransceiver.getResult());

			ProtocolMessageCatalog protocolMessageCatalog = new AppletProtocolMessageCatalog();
			Unmarshaller unmarshaller = new Unmarshaller(protocolMessageCatalog);
			Object resultObject = unmarshaller.receive(httpTransceiver);
			LOG.debug("result object type: "
					+ resultObject.getClass().getName());

			AuthenticationRequestMessage authenticationRequestMessage = (AuthenticationRequestMessage) resultObject;

			byte[] salt = "salt".getBytes();
			SSLSession sslSession = protocolSocketFactory.getSSLSession();
			X509Certificate[] peerCertificateChain = sslSession
					.getPeerCertificateChain();
			LOG.debug("server cert: " + peerCertificateChain[0]);
			byte[] encodedServerCertificate = peerCertificateChain[0]
					.getEncoded();
			AuthenticationContract authenticationContract = new AuthenticationContract(
					salt, null, null, null, encodedServerCertificate,
					authenticationRequestMessage.challenge);

			byte[] toBeSigned = authenticationContract.calculateToBeSigned();

			byte[] signature = pcscEid.signAuthn(toBeSigned);

			AuthenticationDataMessage authenticationDataMessage = new AuthenticationDataMessage(
					salt, null, signature, authnCertChain, null, identityData,
					addressData, photoData, identitySignatureData,
					addressSignatureData, rrnCertData, encodedServerCertificate);
			httpTransceiver.reset();
			Transport.transfer(authenticationDataMessage, httpTransceiver);
			LOG.debug("eID Applet HelloMessage result: "
					+ httpTransceiver.getResult());
			resultObject = unmarshaller.receive(httpTransceiver);
			LOG.debug("result object type: "
					+ resultObject.getClass().getName());
			assertEquals(FinishedMessage.class, resultObject.getClass());

			GetMethod getMethod = new GetMethod(EID_IDP_EXIT_URL);
			protocolRequestResult = httpClient.executeMethod(getMethod);
			LOG.debug("protocol-exit status: " + protocolRequestResult);
			String responseHtmlMessage = getMethod.getResponseBodyAsString();
			LOG.debug("response HTML: " + responseHtmlMessage);
			assertTrue(responseHtmlMessage.indexOf("SAMLResponse") != -1);

			authnCount++;
			LOG.info("authentication count: " + authnCount);
			long t = System.currentTimeMillis();
			double averageAuthn = ((double) (t - t0) / 1000)
					/ (double) (authnCount);
			LOG.info("average # authn / sec: " + averageAuthn);
		}
	}

	private String xmlToString(Node node) throws TransformerException {
		Source source = new DOMSource(node);
		StringWriter stringWriter = new StringWriter();
		Result result = new StreamResult(stringWriter);
		TransformerFactory factory = TransformerFactory.newInstance();
		Transformer transformer = factory.newTransformer();
		transformer.transform(source, result);
		return stringWriter.getBuffer().toString();
	}

	private static class MySSLProtocolSocketFactory extends
			SSLProtocolSocketFactory {

		private static final Log LOG = LogFactory
				.getLog(MySSLProtocolSocketFactory.class);

		private final SSLContext sslContext;

		private SSLSession sslSession;

		public MySSLProtocolSocketFactory() throws NoSuchAlgorithmException,
				KeyManagementException {
			this.sslContext = SSLContext.getInstance("SSL");
			TrustManager trustManager = new MyTrustManager();
			TrustManager[] trustManagers = { trustManager };
			this.sslContext.init(null, trustManagers, null);
		}

		public SSLSession getSSLSession() {
			return this.sslSession;
		}

		@Override
		public Socket createSocket(String host, int port,
				InetAddress clientHost, int clientPort) throws IOException,
				UnknownHostException {
			LOG.debug("create socket(host,port,clientHost,clientPort): " + host
					+ ":" + port);
			return super.createSocket(host, port, clientHost, clientPort);
		}

		@Override
		public Socket createSocket(Socket socket, String host, int port,
				boolean autoClose) throws IOException, UnknownHostException {
			LOG.debug("create socket (socket, host, port, autoClose): " + host
					+ ":" + port);
			Socket resultSocket = this.sslContext.getSocketFactory()
					.createSocket(socket, host, port, autoClose);
			LOG.debug("result socket type: "
					+ resultSocket.getClass().getName());
			SSLSocket sslSocket = (SSLSocket) resultSocket;
			this.sslSession = sslSocket.getSession();
			return resultSocket;
		}

		@Override
		public Socket createSocket(String host, int port,
				InetAddress clientHost, int clientPort,
				HttpConnectionParams params) throws IOException,
				UnknownHostException, ConnectTimeoutException {
			LOG.debug("create socket");
			Socket resultSocket = this.sslContext.getSocketFactory()
					.createSocket(host, port, clientHost, clientPort);
			SSLSocket sslSocket = (SSLSocket) resultSocket;
			this.sslSession = sslSocket.getSession();
			return resultSocket;
		}

		@Override
		public Socket createSocket(String host, int port) throws IOException,
				UnknownHostException {
			LOG.debug("create socket (host, port): " + host + ":" + port);
			return super.createSocket(host, port);
		}

	}

	private static class HttpClientHttpTransceiver implements HttpTransmitter,
			HttpReceiver {

		private static final Log LOG = LogFactory
				.getLog(HttpClientHttpTransceiver.class);

		private final HttpClient httpClient;

		private PostMethod postMethod;

		private final String url;

		public HttpClientHttpTransceiver(HttpClient httpClient, String url) {
			this.httpClient = httpClient;
			this.url = url;
			reset();
		}

		public PostMethod getPostMethod() {
			return this.postMethod;
		}

		public int getResult() {
			try {
				return this.httpClient.executeMethod(this.postMethod);
			} catch (HttpException e) {
				LOG.error("HTTP error: " + e.getMessage());
			} catch (IOException e) {
				LOG.error("IO error: " + e.getMessage());
			}
			return 0;
		}

		public void reset() {
			this.postMethod = new PostMethod(this.url);
		}

		@Override
		public boolean isSecure() {
			return true;
		}

		@Override
		public void addHeader(String headerName, String headerValue) {
			this.postMethod.addRequestHeader(headerName, headerValue);
		}

		@Override
		public void setBody(byte[] bodyValue) {
			RequestEntity requestEntity = new ByteArrayRequestEntity(bodyValue);
			this.postMethod.setRequestEntity(requestEntity);
		}

		@Override
		public List<String> getHeaderNames() {
			Header[] headers = this.postMethod.getResponseHeaders();
			List<String> headerNames = new LinkedList<String>();
			for (Header header : headers) {
				headerNames.add(header.getName());
			}
			return headerNames;
		}

		@Override
		public String getHeaderValue(String headerName) {
			Header header = this.postMethod.getResponseHeader(headerName);
			return header.getValue();
		}

		@Override
		public byte[] getBody() {
			try {
				return this.postMethod.getResponseBody();
			} catch (IOException e) {
				LOG.error("IO error: " + e.getMessage());
			}
			return null;
		}
	}

	public static class TestView implements View {

		private static final Log LOG = LogFactory.getLog(TestView.class);

		public void addDetailMessage(String detailMessage) {
			LOG.debug("detail: " + detailMessage);
		}

		public Component getParentComponent() {
			return null;
		}

		public boolean privacyQuestion(boolean includeAddress,
				boolean includePhoto, String identityDataUsage) {
			return false;
		}

		public void setStatusMessage(Status status, String statusMessage) {
			LOG.debug("status: [" + status + "]: " + statusMessage);
		}

		public void progressIndication(int max, int current) {
		}

		@Override
		public void addTestResult(DiagnosticTests diagnosticTest,
				boolean success, String description) {
		}

		@Override
		public void increaseProgress() {
		}

		@Override
		public void resetProgress(int max) {
		}

		@Override
		public void setProgressIndeterminate() {
		}

		@Override
		public void setStatusMessage(Status status, MESSAGE_ID messageId) {
		}
	}

	private static class MyTrustManager implements X509TrustManager {

		private static final Log LOG = LogFactory.getLog(MyTrustManager.class);

		public void checkClientTrusted(
				java.security.cert.X509Certificate[] chain, String authType)
				throws CertificateException {
			LOG.error("checkClientTrusted");
			throw new UnsupportedOperationException();
		}

		public void checkServerTrusted(
				java.security.cert.X509Certificate[] chain, String authType)
				throws CertificateException {
			LOG.debug("check server trusted");
			LOG.debug("auth type: " + authType);
		}

		public java.security.cert.X509Certificate[] getAcceptedIssuers() {
			LOG.error("getAcceptedIssuers");
			throw new UnsupportedOperationException();
		}
	}
}
