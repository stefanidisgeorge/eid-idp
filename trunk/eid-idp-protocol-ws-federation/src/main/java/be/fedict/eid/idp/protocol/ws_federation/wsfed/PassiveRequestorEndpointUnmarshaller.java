package be.fedict.eid.idp.protocol.ws_federation.wsfed;

import org.opensaml.saml2.metadata.impl.EndpointUnmarshaller;
import org.opensaml.ws.wsaddressing.EndpointReference;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.UnmarshallingException;

public class PassiveRequestorEndpointUnmarshaller extends EndpointUnmarshaller {

    /**
     * {@inheritDoc}
     */
    protected void processChildElement(XMLObject parentSAMLObject, XMLObject childSAMLObject)
            throws UnmarshallingException {

        PassiveRequestorEndpoint passiveRequestorEndpoint =
                (PassiveRequestorEndpoint) parentSAMLObject;

        if (childSAMLObject instanceof EndpointReference) {
            passiveRequestorEndpoint.setEndpointReference((EndpointReference) childSAMLObject);
        } else {
            super.processChildElement(parentSAMLObject, childSAMLObject);
        }
    }
}
