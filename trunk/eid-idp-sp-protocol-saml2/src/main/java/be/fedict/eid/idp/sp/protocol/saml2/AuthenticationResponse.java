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

package be.fedict.eid.idp.sp.protocol.saml2;

import java.io.Serializable;
import java.util.Map;

/**
 * SAML2 Authentication Response DO.
 */
public class AuthenticationResponse implements Serializable {

        private final String identifier;
        private final Map<String, Object> attributeMap;
        private final String relayState;

        public AuthenticationResponse(String identifier,
                                      Map<String, Object> attributeMap,
                                      String relayState) {
                this.identifier = identifier;
                this.attributeMap = attributeMap;
                this.relayState = relayState;
        }

        public String getIdentifier() {
                return identifier;
        }

        public Map<String, Object> getAttributeMap() {
                return attributeMap;
        }

        public String getRelayState() {
                return relayState;
        }
}
