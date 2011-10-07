package be.fedict.eid.idp.protocol.ws_federation.wsfed;

import org.opensaml.xml.schema.impl.XSURIImpl;

public class DisplayNameImpl extends XSURIImpl implements DisplayName {

	/**
	 * Constructor.
	 * 
	 * @param namespaceURI
	 *            the namespace the element is in
	 * @param elementLocalName
	 *            the local name of the XML element this Object represents
	 * @param namespacePrefix
	 *            the prefix for the given namespace
	 */
	public DisplayNameImpl(String namespaceURI, String elementLocalName,
			String namespacePrefix) {
		super(namespaceURI, elementLocalName, namespacePrefix);
	}
}
