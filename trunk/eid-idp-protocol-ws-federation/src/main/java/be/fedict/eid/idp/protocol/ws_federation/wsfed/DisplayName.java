package be.fedict.eid.idp.protocol.ws_federation.wsfed;

import org.opensaml.ws.wstrust.WSTrustObject;
import org.opensaml.xml.schema.XSURI;

import javax.xml.namespace.QName;

public interface DisplayName extends XSURI, WSTrustObject {

	/**
	 * Element local name.
	 */
	public static final String DEFAULT_ELEMENT_LOCAL_NAME = "DisplayName";

	/**
	 * Default element name.
	 */
	public static final QName DEFAULT_ELEMENT_NAME = new QName(
			WSFedConstants.WSFED_AUTH_NS, DEFAULT_ELEMENT_LOCAL_NAME,
			WSFedConstants.WSFED_AUTH_PREFIX);

	/**
	 * Local name of the XSI type.
	 */
	public static final String TYPE_LOCAL_NAME = "DisplayNameType";

	/**
	 * QName of the XSI type.
	 */
	public static final QName TYPE_NAME = new QName(
			WSFedConstants.WSFED_AUTH_NS, TYPE_LOCAL_NAME,
			WSFedConstants.WSFED_AUTH_PREFIX);
}
