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

package be.fedict.eid.idp.sp.protocol.openid;

import java.io.Serializable;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * OpenID Authentication Response DO.
 */
public class OpenIDAuthenticationResponse implements Serializable {

        private static final long serialVersionUID = 1L;

        private final Date authenticationTime;
        private final String identifier;
        private final List<String> authenticationPolicies;
        private final Map<String, Object> attributeMap;

        public OpenIDAuthenticationResponse(Date authenticationTime,
                                            String identifier,
                                            List<String> authenticationPolicies,
                                            Map<String, Object> attributeMap) {
                this.authenticationTime = authenticationTime;
                this.identifier = identifier;
                this.authenticationPolicies = authenticationPolicies;
                this.attributeMap = attributeMap;
        }

        public Date getAuthenticationTime() {
                return authenticationTime;
        }

        public String getIdentifier() {
                return identifier;
        }

        public Map<String, Object> getAttributeMap() {
                return attributeMap;
        }

        public List<String> getAuthenticationPolicies() {
                return authenticationPolicies;
        }
}
