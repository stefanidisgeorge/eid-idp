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

package be.fedict.eid.idp.model.applet;

import be.fedict.eid.applet.service.spi.IdentityRequest;
import be.fedict.eid.idp.model.Constants;
import be.fedict.eid.idp.spi.IdentityProviderFlow;
import org.jboss.ejb3.annotation.LocalBinding;

import javax.ejb.Local;
import javax.ejb.Stateless;

@Stateless
@Local(be.fedict.eid.applet.service.spi.IdentityService.class)
@LocalBinding(jndiBinding = Constants.IDP_JNDI_CONTEXT + "AppletIdentityServiceBean")
public class AppletIdentityServiceBean implements be.fedict.eid.applet.service.spi.IdentityService {

        @Override
        public IdentityRequest getIdentityRequest() {

                boolean includeIdentity = false;
                boolean includeAddress = false;
                boolean includePhoto = false;
                boolean includeCertificates = true;
                IdentityProviderFlow idpFlow = AppletUtil
                        .getSessionAttribute(Constants.IDP_FLOW_SESSION_ATTRIBUTE);
                switch (idpFlow) {


                        case IDENTIFICATION:
                        case AUTHENTICATION_WITH_IDENTIFICATION:
                                includeIdentity = true;
                                includeAddress = true;
                                includePhoto = true;
                                break;
                        case AUTHENTICATION:
                                includeIdentity = false;
                                includeAddress = false;
                                includePhoto = false;
                }

                return new IdentityRequest(includeIdentity, includeAddress,
                        includePhoto, includeCertificates);
        }
}
