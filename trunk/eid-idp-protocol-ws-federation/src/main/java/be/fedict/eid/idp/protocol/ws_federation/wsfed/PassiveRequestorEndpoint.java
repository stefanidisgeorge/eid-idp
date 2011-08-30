package be.fedict.eid.idp.protocol.ws_federation.wsfed;

import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.ws.wsaddressing.EndpointReference;

import javax.xml.namespace.QName;

public interface PassiveRequestorEndpoint extends Endpoint {

	/**
	 * Element local name.
	 */
	public static final String DEFAULT_ELEMENT_LOCAL_NAME = "PassiveRequestorEndpoint";

	/**
	 * Default element name.
	 */
	public static final QName DEFAULT_ELEMENT_NAME = new QName(
			WSFedConstants.WSFED_NS, DEFAULT_ELEMENT_LOCAL_NAME,
			WSFedConstants.WSFED_PREFIX);

	/**
	 * Local name of the XSI type.
	 */
	public static final String TYPE_LOCAL_NAME = "PassiveRequestorEndpointType";

	/**
	 * QName of the XSI type.
	 */
	public static final QName TYPE_NAME = new QName(WSFedConstants.WSFED_NS,
			TYPE_LOCAL_NAME, WSFedConstants.WSFED_PREFIX);

	public EndpointReference getEndpointReference();

	public void setEndpointReference(EndpointReference endpointReference);
}
