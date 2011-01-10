package be.fedict.eid.idp.protocol.ws_federation.wsfed;

import org.opensaml.saml2.metadata.impl.RoleDescriptorUnmarshaller;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.UnmarshallingException;

public class SecurityTokenServiceUnmarshaller extends RoleDescriptorUnmarshaller {

    /**
     * {@inheritDoc}
     */
    protected void processChildElement(XMLObject parentSAMLObject, XMLObject childSAMLObject)
            throws UnmarshallingException {

        SecurityTokenService securityTokenService = (SecurityTokenService) parentSAMLObject;

        if (childSAMLObject instanceof PassiveRequestorEndpoint) {
            securityTokenService.getPassiveRequestorEndpoints().add((PassiveRequestorEndpoint) childSAMLObject);
        } else if (childSAMLObject instanceof ClaimTypesOffered) {
            securityTokenService.setClaimTypesOffered((ClaimTypesOffered) childSAMLObject);
        } else {
            super.processChildElement(parentSAMLObject, childSAMLObject);
        }
    }
}
