package be.fedict.eid.idp.protocol.ws_federation.wsfed;

import org.opensaml.common.impl.AbstractSAMLObjectBuilder;

public class PassiveRequestorEndpointBuilder extends
		AbstractSAMLObjectBuilder<PassiveRequestorEndpoint> {

	@Override
	public PassiveRequestorEndpoint buildObject() {
		return buildObject(PassiveRequestorEndpoint.DEFAULT_ELEMENT_NAME);

	}

	@Override
	public PassiveRequestorEndpoint buildObject(String namespaceURI,
			String localName, String namespacePrefix) {
		return new PassiveRequestorEndpointImpl(namespaceURI, localName,
				namespacePrefix);
	}
}
