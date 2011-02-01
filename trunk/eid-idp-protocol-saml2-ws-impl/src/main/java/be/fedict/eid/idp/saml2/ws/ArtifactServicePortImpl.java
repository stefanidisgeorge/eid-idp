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

package be.fedict.eid.idp.saml2.ws;

import oasis.names.tc.saml._2_0.protocol.ArtifactResolveType;
import oasis.names.tc.saml._2_0.protocol.ArtifactResponseType;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.jws.WebService;

@WebService(endpointInterface = "be.fedict.eid.idp.saml2.ws.ArtifactServicePortType")
public class ArtifactServicePortImpl implements ArtifactServicePortType {

        private static final Log LOG = LogFactory
                .getLog(ArtifactServicePortImpl.class);

        @Override
        public ArtifactResponseType resolve(ArtifactResolveType artifactResolve) {

                LOG.debug("Resolve: " + artifactResolve.getArtifact());
                return null;  //To change body of implemented methods use File | Settings | File Templates.
        }
}
