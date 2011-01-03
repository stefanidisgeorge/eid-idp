package be.fedict.eid.idp.sp;

import javax.servlet.http.HttpSession;
import java.util.Map;

public class AttributeBean {

    private HttpSession session;

    public HttpSession getSession() {
        return session;
    }

    public void setSession(HttpSession session) {
        this.session = session;
    }

    public Map getAttributeMap() {
        return (Map) session.getAttribute("AttributeMap");
    }

    public void setAttributeMap(Map value) {
        // empty
    }

}
