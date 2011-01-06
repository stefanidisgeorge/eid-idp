/*
 * eID Identity Provider Project.
 * Copyright (C) 2010 FedICT.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version
 * 3.0 as published by the Free Software Foundation.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, see
 * http://www.gnu.org/licenses/.
 */

package be.fedict.eid.idp.sp;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.servlet.http.HttpSession;
import java.util.Map;

public class AttributeBean {

    private static final Log LOG = LogFactory.getLog(AttributeBean.class);

    private HttpSession session;
    private Map<String, Object> attributeMap;

    public HttpSession getSession() {
        return this.session;
    }

    @SuppressWarnings("unchecked")
    public void setSession(HttpSession session) {

        this.session = session;
        this.attributeMap = (Map<String, Object>) session.getAttribute("AttributeMap");

        for (Map.Entry<String, Object> entry : this.attributeMap.entrySet()) {
            LOG.debug("attribute: " + entry.getKey() + " value=" + entry.getValue());
        }
    }

    public Map getAttributeMap() {

        return this.attributeMap;
    }

    public void setAttributeMap(Map value) {
        // empty
    }

}
