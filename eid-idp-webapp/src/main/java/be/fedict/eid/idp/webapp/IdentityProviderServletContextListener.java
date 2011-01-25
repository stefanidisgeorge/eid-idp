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

import be.fedict.eid.idp.model.AttributeService;
import be.fedict.eid.idp.model.DefaultAttribute;
import be.fedict.eid.idp.model.IdentityService;
import be.fedict.eid.idp.model.ProtocolServiceManager;
import be.fedict.eid.idp.model.exception.KeyStoreLoadException;
import be.fedict.eid.idp.spi.IdentityProviderConfigurationFactory;
import be.fedict.eid.idp.spi.protocol.EndpointType;
import be.fedict.eid.idp.spi.protocol.EndpointsType;
import be.fedict.eid.idp.spi.protocol.IdentityProviderProtocolType;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.ejb.EJB;
import javax.servlet.Servlet;
import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.ServletRegistration.Dynamic;
import java.util.List;

public class IdentityProviderServletContextListener implements
        ServletContextListener {

        @EJB
        private ProtocolServiceManager protocolServiceManager;

        @EJB
        private IdentityService identityService;

        @EJB
        private AttributeService attributeService;

        private static final Log LOG = LogFactory
                .getLog(IdentityProviderServletContextListener.class);

        public void contextInitialized(ServletContextEvent event) {
                LOG.debug("contextInitialized");

                initProtocolServices(event);

                initIdentity();

                initIdentityProviderConfiguration(event);

                initAttributes();
        }

        /**
         * Initialize the default eID Attributes
         */
        private void initAttributes() {

                for (DefaultAttribute defaultAttribute : DefaultAttribute.values()) {
                        this.attributeService.saveAttribute(defaultAttribute.getName());
                }
        }

        private void initIdentity() {

                if (this.identityService.isIdentityConfigured()) {
                        try {
                                this.identityService.reloadIdentity();
                        } catch (KeyStoreLoadException e) {
                                throw new RuntimeException(e);
                        }
                }

        }

        private void initIdentityProviderConfiguration(ServletContextEvent event) {
                ServletContext servletContext = event.getServletContext();
                servletContext
                        .setAttribute(
                                IdentityProviderConfigurationFactory.IDENTITY_PROVIDER_CONFIGURATION_CONTEXT_ATTRIBUTE,
                                this.identityService);
        }

        private void initProtocolServices(ServletContextEvent event) {
                ServletContext servletContext = event.getServletContext();
                ClassLoader classLoader = Thread.currentThread()
                        .getContextClassLoader();
                List<IdentityProviderProtocolType> protocolServices = this.protocolServiceManager
                        .getProtocolServices();
                for (IdentityProviderProtocolType protocolService : protocolServices) {
                        String name = protocolService.getName();
                        LOG.debug("initializing protocol service: " + name);
                        EndpointsType endpoints = protocolService.getEndpoints();
                        if (null == endpoints) {
                                continue;
                        }
                        List<EndpointType> endpointList = endpoints.getEndpoint();
                        for (EndpointType endpoint : endpointList) {
                                String contextPath = endpoint.getContextPath();
                                String servletClassName = endpoint.getServletClass();
                                LOG.debug("initializing on context path: " + contextPath
                                        + " servlet " + servletClassName);
                                Class<?> servletClass;
                                try {
                                        servletClass = classLoader.loadClass(servletClassName);
                                } catch (ClassNotFoundException e) {
                                        throw new RuntimeException(
                                                "could not load the servlet class: "
                                                        + servletClassName);
                                }
                                if (!Servlet.class.isAssignableFrom(servletClass)) {
                                        throw new RuntimeException("not a servlet class: "
                                                + servletClassName);
                                }
                                String servletName = name + contextPath;
                                LOG.debug("servlet name: " + servletName);
                                @SuppressWarnings("unchecked")
                                Dynamic dynamic = servletContext.addServlet(servletName,
                                        (Class<? extends Servlet>) servletClass);
                                String urlPattern = "/endpoints" + contextPath;
                                dynamic.addMapping(urlPattern);
                        }
                }
        }

        public void contextDestroyed(ServletContextEvent event) {
                LOG.debug("contextDestroy");
        }
}
