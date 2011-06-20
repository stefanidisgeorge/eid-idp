package be.fedict.eid.idp.protocol.ws_federation.wsfed;

import org.opensaml.common.impl.AbstractSAMLObject;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSBooleanValue;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class ClaimTypeImpl extends AbstractSAMLObject implements ClaimType {

    private DisplayName displayName;
    private Description description;
    private String uri;
    private XSBooleanValue optional;

    /**
     * Constructor.
     *
     * @param namespaceURI     the namespace the element is in
     * @param elementLocalName the local name of the XML element this Object represents
     * @param namespacePrefix  the prefix for the given namespace
     */
    public ClaimTypeImpl(String namespaceURI, String elementLocalName, String namespacePrefix) {
        super(namespaceURI, elementLocalName, namespacePrefix);
    }

    public DisplayName getDisplayName() {
        return this.displayName;
    }

    public void setDisplayName(DisplayName displayName) {
        this.displayName = prepareForAssignment(this.displayName, displayName);
    }

    public Description getDescription() {
        return this.description;
    }

    public void setDescription(Description description) {
        this.description = prepareForAssignment(this.description, description);
    }

    public String getUri() {
        return this.uri;
    }

    public void setUri(String uri) {
        this.uri = prepareForAssignment(this.uri, uri);
    }

    public Boolean isOptional() {
        if (this.optional != null) {
            return optional.getValue();
        }

        return Boolean.FALSE;
    }

    public XSBooleanValue isOptionalXSBoolean() {
        return this.optional;
    }

    public void setOptional(Boolean optional) {
        if (optional != null) {
            this.optional = prepareForAssignment(this.optional,
                    new XSBooleanValue(optional, false));
        } else {
            this.optional = prepareForAssignment(this.optional, null);
        }
    }

    public void setOptional(XSBooleanValue optional) {
        this.optional = prepareForAssignment(this.optional, optional);
    }

    public List<XMLObject> getOrderedChildren() {
        ArrayList<XMLObject> children = new ArrayList<XMLObject>();

        if (this.displayName != null) {
            children.add(this.displayName);
        }

        if (this.description != null) {
            children.add(this.description);
        }

        if (children.size() == 0) {
            return null;
        }

        return Collections.unmodifiableList(children);
    }
}
