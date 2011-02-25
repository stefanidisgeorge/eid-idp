package be.fedict.eid.idp.protocol.ws_federation.wsfed;

import org.opensaml.common.impl.AbstractSAMLObjectBuilder;

public class SecurityTokenServiceBuilder extends AbstractSAMLObjectBuilder<SecurityTokenService> {

    @Override
    public SecurityTokenService buildObject() {
        return buildObject(SecurityTokenService.DEFAULT_ELEMENT_NAME);

    }

    @Override
    public SecurityTokenService buildObject(String namespaceURI, String localName, String namespacePrefix) {
        return new SecurityTokenServiceImpl(namespaceURI, localName, namespacePrefix);
    }
}
