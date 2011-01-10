package be.fedict.eid.idp.protocol.ws_federation.wsfed;

import org.opensaml.common.SAMLObject;

import javax.xml.namespace.QName;
import java.util.List;

public interface ClaimTypesOffered extends SAMLObject {

    /**
     * Element local name.
     */
    public static final String DEFAULT_ELEMENT_LOCAL_NAME = "ClaimTypesOffered";

    /**
     * Default element name.
     */
    public static final QName DEFAULT_ELEMENT_NAME =
            new QName(WSFedConstants.WSFED_NS, DEFAULT_ELEMENT_LOCAL_NAME,
                    WSFedConstants.WSFED_PREFIX);

    /**
     * Local name of the XSI type.
     */
    public static final String TYPE_LOCAL_NAME = "ClaimTypesOfferedType";

    /**
     * QName of the XSI type.
     */
    public static final QName TYPE_NAME = new QName(WSFedConstants.WSFED_NS,
            TYPE_LOCAL_NAME, WSFedConstants.WSFED_PREFIX);

    public List<ClaimType> getClaimTypes();

}
