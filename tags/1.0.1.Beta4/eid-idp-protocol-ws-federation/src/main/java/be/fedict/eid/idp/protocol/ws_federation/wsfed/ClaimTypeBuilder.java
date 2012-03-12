package be.fedict.eid.idp.protocol.ws_federation.wsfed;

import org.opensaml.common.impl.AbstractSAMLObjectBuilder;

public class ClaimTypeBuilder extends AbstractSAMLObjectBuilder<ClaimType> {

	@Override
	public ClaimType buildObject() {
		return buildObject(ClaimType.DEFAULT_ELEMENT_NAME);

	}

	@Override
	public ClaimType buildObject(String namespaceURI, String localName,
			String namespacePrefix) {
		return new ClaimTypeImpl(namespaceURI, localName, namespacePrefix);
	}
}
