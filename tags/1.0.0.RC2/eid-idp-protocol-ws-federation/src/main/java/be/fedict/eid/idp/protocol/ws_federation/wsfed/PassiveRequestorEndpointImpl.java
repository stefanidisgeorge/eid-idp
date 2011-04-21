package be.fedict.eid.idp.protocol.ws_federation.wsfed;

import org.opensaml.saml2.metadata.impl.EndpointImpl;
import org.opensaml.ws.wsaddressing.EndpointReference;
import org.opensaml.xml.XMLObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class PassiveRequestorEndpointImpl extends EndpointImpl implements PassiveRequestorEndpoint {

    private EndpointReference endpointReference;

    /**
     * Constructor.
     *
     * @param namespaceURI     the namespace the element is in
     * @param elementLocalName the local name of the XML element this Object represents
     * @param namespacePrefix  the prefix for the given namespace
     */
    public PassiveRequestorEndpointImpl(String namespaceURI, String elementLocalName, String namespacePrefix) {
        super(namespaceURI, elementLocalName, namespacePrefix);
    }

    public EndpointReference getEndpointReference() {
        return this.endpointReference;
    }

    public void setEndpointReference(EndpointReference endpointReference) {
        this.endpointReference = prepareForAssignment(this.endpointReference, endpointReference);
    }

    public List<XMLObject> getOrderedChildren() {
        ArrayList<XMLObject> children = new ArrayList<XMLObject>();

        if (super.getOrderedChildren() != null) {
            children.addAll(super.getOrderedChildren());
        }

        if (this.endpointReference != null) {
            children.add(this.endpointReference);
        }

        if (children.size() == 0) {
            return null;
        }

        return Collections.unmodifiableList(children);
    }
}
