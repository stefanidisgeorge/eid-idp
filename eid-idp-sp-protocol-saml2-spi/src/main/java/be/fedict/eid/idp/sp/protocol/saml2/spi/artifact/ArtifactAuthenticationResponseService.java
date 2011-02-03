/*
 * eID Identity Provider Project.
 * Copyright (C) 2011 FedICT.
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

package be.fedict.eid.idp.sp.protocol.saml2.spi.artifact;

import be.fedict.eid.idp.sp.protocol.saml2.spi.AuthenticationResponseService;

/**
 * SPI for authentication response services for SAML v2.0 HTTP Artifact Binding.
 *
 * @author Wim Vandenhaute.
 */
public interface ArtifactAuthenticationResponseService extends AuthenticationResponseService {

        /**
         * Gives back the location of the eID IdP SAML v2.0 Artifact service.
         *
         * @return eID IdP SAML v2.0 Artifact Service Location.
         */
        String getArtifactServiceLocation();

}
