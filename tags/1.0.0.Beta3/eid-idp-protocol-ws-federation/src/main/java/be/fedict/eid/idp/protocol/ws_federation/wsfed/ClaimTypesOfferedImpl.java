package be.fedict.eid.idp.protocol.ws_federation.wsfed;

import org.opensaml.common.impl.AbstractSAMLObject;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.util.IndexedXMLObjectChildrenList;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class ClaimTypesOfferedImpl extends AbstractSAMLObject implements ClaimTypesOffered {

    private final IndexedXMLObjectChildrenList<ClaimType> claimTypes;

    /**
     * Constructor.
     *
     * @param namespaceURI     the namespace the element is in
     * @param elementLocalName the local name of the XML element this Object represents
     * @param namespacePrefix  the prefix for the given namespace
     */
    public ClaimTypesOfferedImpl(String namespaceURI, String elementLocalName, String namespacePrefix) {
        super(namespaceURI, elementLocalName, namespacePrefix);
        this.claimTypes = new IndexedXMLObjectChildrenList<ClaimType>(this);
    }


    public List<ClaimType> getClaimTypes() {
        return this.claimTypes;
    }

    public List<XMLObject> getOrderedChildren() {
        ArrayList<XMLObject> children = new ArrayList<XMLObject>();

        children.addAll(this.claimTypes);

        return Collections.unmodifiableList(children);
    }
}
