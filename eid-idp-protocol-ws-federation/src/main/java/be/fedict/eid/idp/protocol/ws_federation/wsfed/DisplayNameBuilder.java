package be.fedict.eid.idp.protocol.ws_federation.wsfed;

import org.opensaml.ws.wstrust.impl.AbstractWSTrustObjectBuilder;

public class DisplayNameBuilder extends AbstractWSTrustObjectBuilder<DisplayName> {

    @Override
    public DisplayName buildObject() {
        return buildObject(DisplayName.DEFAULT_ELEMENT_NAME);

    }

    @Override
    public DisplayName buildObject(String namespaceURI, String localName, String namespacePrefix) {
        return new DisplayNameImpl(namespaceURI, localName, namespacePrefix);
    }
}
