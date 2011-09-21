package be.fedict.eid.idp.protocol.ws_federation.wsfed;

import org.opensaml.ws.wstrust.impl.AbstractWSTrustObjectBuilder;

public class DescriptionBuilder extends
		AbstractWSTrustObjectBuilder<Description> {

	@Override
	public Description buildObject() {
		return buildObject(Description.DEFAULT_ELEMENT_NAME);

	}

	@Override
	public Description buildObject(String namespaceURI, String localName,
			String namespacePrefix) {
		return new DescriptionImpl(namespaceURI, localName, namespacePrefix);
	}
}
