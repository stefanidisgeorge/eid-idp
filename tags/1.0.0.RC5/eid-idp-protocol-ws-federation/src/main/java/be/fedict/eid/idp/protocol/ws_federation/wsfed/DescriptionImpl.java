package be.fedict.eid.idp.protocol.ws_federation.wsfed;

import org.opensaml.xml.schema.impl.XSURIImpl;

public class DescriptionImpl extends XSURIImpl implements Description {

    /**
     * Constructor.
     *
     * @param namespaceURI     the namespace the element is in
     * @param elementLocalName the local name of the XML element this Object represents
     * @param namespacePrefix  the prefix for the given namespace
     */
    public DescriptionImpl(String namespaceURI, String elementLocalName, String namespacePrefix) {
        super(namespaceURI, elementLocalName, namespacePrefix);
    }
}
