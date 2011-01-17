package be.fedict.eid.idp.protocol.ws_federation.wsfed;

import org.opensaml.common.impl.AbstractSAMLObjectMarshaller;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.MarshallingException;
import org.w3c.dom.Element;

public class ClaimTypeMarshaller extends AbstractSAMLObjectMarshaller {

    /**
     * {@inheritDoc}
     */
    protected void marshallAttributes(XMLObject samlObject, Element domElement) throws MarshallingException {

        ClaimType claimType = (ClaimType) samlObject;

        if (claimType.isOptionalXSBoolean() != null) {
            domElement.setAttributeNS(null, ClaimType.OPTIONAL_ATTRIB_NAME,
                    claimType.isOptionalXSBoolean().toString());
        }

        if (claimType.getUri() != null) {
            domElement.setAttributeNS(null, ClaimType.URI_ATTRIB_NAME,
                    claimType.getUri());
        }

        super.marshallAttributes(samlObject, domElement);
    }
}
