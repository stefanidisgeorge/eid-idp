package be.fedict.eid.idp.sp;

import be.fedict.eid.idp.common.AttributeConstants;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.servlet.http.HttpSession;
import java.util.Map;

public class AttributeBean {

    private static final Log LOG = LogFactory.getLog(AttributeBean.class);

    private HttpSession session;

    public HttpSession getSession() {
        return session;
    }

    public void setSession(HttpSession session) {
        this.session = session;
    }

    @SuppressWarnings("unchecked")
    public Map getAttributeMap() {

        Map<String, Object> attributeMap =
                (Map<String, Object>) session.getAttribute("AttributeMap");

        for (Map.Entry<String, Object> entry : attributeMap.entrySet()) {
            LOG.debug("attribute: " + entry.getKey() + " value=" + entry.getValue());
        }

        return attributeMap;
    }

    public void setAttributeMap(Map value) {
        // empty
    }

}
