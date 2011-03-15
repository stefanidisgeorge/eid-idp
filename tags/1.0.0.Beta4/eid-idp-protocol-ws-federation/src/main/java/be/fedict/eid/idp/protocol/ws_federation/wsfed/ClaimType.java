package be.fedict.eid.idp.protocol.ws_federation.wsfed;

import org.opensaml.common.SAMLObject;
import org.opensaml.xml.schema.XSBooleanValue;

import javax.xml.namespace.QName;

public interface ClaimType extends SAMLObject {

    /**
     * Element local name.
     */
    public static final String DEFAULT_ELEMENT_LOCAL_NAME = "ClaimType";

    /**
     * Default element name.
     */
    public static final QName DEFAULT_ELEMENT_NAME =
            new QName(WSFedConstants.WSFED_AUTH_NS, DEFAULT_ELEMENT_LOCAL_NAME,
                    WSFedConstants.WSFED_AUTH_PREFIX);

    /**
     * Local name of the XSI type.
     */
    public static final String TYPE_LOCAL_NAME = "ClaimTypeType";

    /**
     * QName of the XSI type.
     */
    public static final QName TYPE_NAME = new QName(WSFedConstants.WSFED_AUTH_NS,
            TYPE_LOCAL_NAME, WSFedConstants.WSFED_AUTH_PREFIX);

    /** Optional attribute name. */
    public static final String OPTIONAL_ATTRIB_NAME = "Optional";

    /** URI attribute name. */
    public static final String URI_ATTRIB_NAME = "Uri";


    public DisplayName getDisplayName();

    public void setDisplayName(DisplayName displayName);

    public Description getDescription();

    public void setDescription(Description description);

    public String getUri();

    public void setUri(String uri);

    public Boolean isOptional();

    public XSBooleanValue isOptionalXSBoolean();

    public void setOptional(Boolean optional);

    public void setOptional(XSBooleanValue optional);
}
