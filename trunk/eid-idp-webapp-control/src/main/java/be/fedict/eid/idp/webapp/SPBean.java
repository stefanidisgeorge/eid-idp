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

package be.fedict.eid.idp.webapp;

import be.fedict.eid.idp.entity.RPAttributeEntity;
import be.fedict.eid.idp.entity.RPEntity;
import be.fedict.eid.idp.model.Constants;
import org.jboss.ejb3.annotation.LocalBinding;
import org.jboss.seam.annotations.*;
import org.jboss.seam.annotations.datamodel.DataModel;
import org.jboss.seam.contexts.SessionContext;
import org.jboss.seam.faces.FacesMessages;
import org.jboss.seam.log.Log;

import javax.ejb.Remove;
import javax.ejb.Stateful;
import java.util.List;

@Stateful
@Name("idpSP")
@LocalBinding(jndiBinding = Constants.IDP_JNDI_CONTEXT + "webapp/SPBean")
public class SPBean implements SP {

        private static final String ATTRIBUTE_LIST_NAME = "idpRPAttributes";

        @Logger
        private Log log;

        @In(create = true)
        private SessionContext sessionContext;

        @In(create = true)
        FacesMessages facesMessages;

        @SuppressWarnings("unused")
        @DataModel(ATTRIBUTE_LIST_NAME)
        private List<RPAttributeEntity> attributeList;

        @Remove
        @Destroy
        public void destroy() {
                this.log.debug("destroy");

        }

        @Override
        public String getRp() {

                RPEntity rp = (RPEntity)
                        this.sessionContext.get(Constants.RP_SESSION_ATTRIBUTE);
                if (null != rp) {
                        return rp.getName();
                }
                return null;
        }

        @Override
        @Factory(ATTRIBUTE_LIST_NAME)
        public void attributeFactory() {

                RPEntity rp = (RPEntity)
                        this.sessionContext.get(Constants.RP_SESSION_ATTRIBUTE);
                if (null != rp) {
                        this.attributeList = rp.getAttributes();
                }
        }

}
