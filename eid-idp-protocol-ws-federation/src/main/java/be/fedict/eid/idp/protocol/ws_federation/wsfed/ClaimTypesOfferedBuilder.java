package be.fedict.eid.idp.protocol.ws_federation.wsfed;

import org.opensaml.common.impl.AbstractSAMLObjectBuilder;

public class ClaimTypesOfferedBuilder extends
		AbstractSAMLObjectBuilder<ClaimTypesOffered> {

	@Override
	public ClaimTypesOffered buildObject() {
		return buildObject(ClaimTypesOffered.DEFAULT_ELEMENT_NAME);

	}

	@Override
	public ClaimTypesOffered buildObject(String namespaceURI, String localName,
			String namespacePrefix) {
		return new ClaimTypesOfferedImpl(namespaceURI, localName,
				namespacePrefix);
	}
}
