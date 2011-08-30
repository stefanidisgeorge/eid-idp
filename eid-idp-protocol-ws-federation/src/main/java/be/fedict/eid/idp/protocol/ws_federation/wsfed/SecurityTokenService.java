package be.fedict.eid.idp.protocol.ws_federation.wsfed;

import org.opensaml.saml2.metadata.RoleDescriptor;

import javax.xml.namespace.QName;
import java.util.List;

public interface SecurityTokenService extends RoleDescriptor {

	/**
	 * Element local name.
	 */
	public static final String DEFAULT_ELEMENT_LOCAL_NAME = "SecurityTokenService";

	/**
	 * Default element name.
	 */
	public static final QName DEFAULT_ELEMENT_NAME = new QName(
			WSFedConstants.WSFED_NS, DEFAULT_ELEMENT_LOCAL_NAME,
			WSFedConstants.WSFED_PREFIX);

	/**
	 * Local name of the XSI type.
	 */
	public static final String TYPE_LOCAL_NAME = "SecurityTokenServiceType";

	/**
	 * QName of the XSI type.
	 */
	public static final QName TYPE_NAME = new QName(WSFedConstants.WSFED_NS,
			TYPE_LOCAL_NAME, WSFedConstants.WSFED_PREFIX);

	public List<PassiveRequestorEndpoint> getPassiveRequestorEndpoints();

	public ClaimTypesOffered getClaimTypesOffered();

	public void setClaimTypesOffered(ClaimTypesOffered claimTypesOffered);

}
