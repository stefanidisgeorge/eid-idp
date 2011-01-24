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

import be.fedict.eid.idp.entity.RPEntity;
import be.fedict.eid.idp.model.Constants;
import org.jboss.ejb3.annotation.LocalBinding;
import org.jboss.seam.annotations.Destroy;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Logger;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.contexts.SessionContext;
import org.jboss.seam.faces.FacesMessages;
import org.jboss.seam.log.Log;

import javax.ejb.Remove;
import javax.ejb.Stateful;

@Stateful
@Name("idpSP")
@LocalBinding(jndiBinding = Constants.IDP_JNDI_CONTEXT + "webapp/SPBean")
public class SPBean implements SP {

        @Logger
        private Log log;

        @In(create = true)
        private SessionContext sessionContext;

        @In(create = true)
        FacesMessages facesMessages;

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
}
