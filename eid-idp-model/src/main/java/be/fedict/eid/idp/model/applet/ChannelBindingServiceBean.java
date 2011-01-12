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

import be.fedict.eid.applet.service.spi.ChannelBindingService;
import be.fedict.eid.idp.model.Configuration;
import be.fedict.eid.idp.model.Constants;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jboss.ejb3.annotation.LocalBinding;

import javax.ejb.EJB;
import javax.ejb.Local;
import javax.ejb.Stateless;
import java.security.cert.X509Certificate;

/**
 * eID Applet Channel Binding Service implementation.
 *
 * @author Wim Vandenhaute
 */
@Stateless
@Local(ChannelBindingService.class)
@LocalBinding(jndiBinding = Constants.IDP_JNDI_CONTEXT + "ChannelBindingServiceBean")
public class ChannelBindingServiceBean implements ChannelBindingService {

        private static final Log LOG = LogFactory
                .getLog(ChannelBindingServiceBean.class);

        @EJB
        private Configuration configuration;

        @Override
        public X509Certificate getServerCertificate() {

                return this.configuration.getAppletConfig().getServerCertificate();
        }
}
