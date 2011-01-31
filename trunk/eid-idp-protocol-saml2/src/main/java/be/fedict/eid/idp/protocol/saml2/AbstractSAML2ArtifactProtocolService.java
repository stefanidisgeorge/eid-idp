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

package be.fedict.eid.idp.protocol.saml2;

import be.fedict.eid.idp.spi.ReturnResponse;
import org.opensaml.saml2.core.Response;

import javax.servlet.ServletContext;
import java.util.UUID;

public abstract class AbstractSAML2ArtifactProtocolService extends AbstractSAML2ProtocolService {

        @SuppressWarnings("unchecked")
        @Override
        protected ReturnResponse handleSamlResponse(ServletContext servletContext,
                                                    String targetUrl,
                                                    Response samlResponse,
                                                    String relayState)
                throws Exception {

                ReturnResponse returnResponse = new ReturnResponse(targetUrl);

                // generate artifact ID: TODO: do so properly ...
                String artifactId = UUID.randomUUID().toString();
                returnResponse.addAttribute("SAMLart", artifactId);

                // temp store SAML response
                this.protocolStorageService.setValue(servletContext,
                        artifactId, samlResponse, 5 * 60); // TODO: configurable, see SAML2Util

                if (null != relayState) {
                        returnResponse.addAttribute("RelayState", relayState);
                }
                return returnResponse;
        }
}
