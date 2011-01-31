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

package be.fedict.eid.idp.spi;

import java.util.Date;

/**
 * Protocol storage.
 *
 * @author Wim Vandenhaute
 */
public class ProtocolStorage {

        private final String protocolId;
        private final String name;
        private final Object value;

        private final Date created;
        // validity in seconds
        private final int validity;

        public ProtocolStorage(String protocolId, String name, Object value,
                               int validity) {

                this.protocolId = protocolId;
                this.name = name;
                this.value = value;
                this.validity = validity;
                this.created = new Date();
        }

        public String getProtocolId() {
                return protocolId;
        }

        public String getName() {
                return name;
        }

        public Object getValue() {
                return value;
        }

        public Date getCreated() {
                return created;
        }

        public int getValidity() {
                return validity;
        }
}


