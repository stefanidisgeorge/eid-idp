package be.fedict.eid.idp.protocol.ws_federation.wsfed;

import org.opensaml.common.impl.AbstractSAMLObjectUnmarshaller;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.UnmarshallingException;

public class ClaimTypesOfferedUnmarshaller extends
		AbstractSAMLObjectUnmarshaller {

	/**
	 * {@inheritDoc}
	 */
	protected void processChildElement(XMLObject parentSAMLObject,
			XMLObject childSAMLObject) throws UnmarshallingException {

		ClaimTypesOffered claimTypesOffered = (ClaimTypesOffered) parentSAMLObject;

		if (childSAMLObject instanceof ClaimType) {
			claimTypesOffered.getClaimTypes().add((ClaimType) childSAMLObject);
		} else {
			super.processChildElement(parentSAMLObject, childSAMLObject);
		}
	}
}
