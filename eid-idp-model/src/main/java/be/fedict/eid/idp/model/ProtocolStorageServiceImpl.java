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

package be.fedict.eid.idp.model;

import be.fedict.eid.idp.spi.ProtocolStorage;
import be.fedict.eid.idp.spi.ProtocolStorageService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.servlet.ServletContext;

/**
 * Protocol storage service implementation
 *
 * @author Wim Vandenhaute
 */
public class ProtocolStorageServiceImpl implements ProtocolStorageService {

        private static final Log LOG = LogFactory.getLog(ProtocolStorageServiceImpl.class);

        private final String protocolId;

        public ProtocolStorageServiceImpl(String protocolId) {
                this.protocolId = protocolId;
        }

        @Override
        public void setValue(ServletContext servletContext, String name,
                             Object value, int validity) {

                LOG.debug("Set value name=" + name);

                ProtocolStorage storage =
                        new ProtocolStorage(protocolId, name, value, validity);

                servletContext.setAttribute(getKey(protocolId, name), storage);
        }

        @SuppressWarnings("unchecked")
        @Override
        public <T> T findValue(ServletContext servletContext, String name, Class<T> type) {

                LOG.debug("Get value:  name=" + name);

                ProtocolStorage storage =
                        (ProtocolStorage) servletContext.getAttribute(
                                getKey(protocolId, name));

                if (null == storage) {
                        LOG.debug("Value not found!");
                        return null;
                }
                return (T) storage.getValue();
        }

        @Override
        public void removeValue(ServletContext servletContext, String name) {

                LOG.debug("Remove value: name=" + name);
                servletContext.removeAttribute(getKey(protocolId, name));
        }

        private String getKey(String protocolId, String name) {

                return protocolId + "-" + name;
        }
}
