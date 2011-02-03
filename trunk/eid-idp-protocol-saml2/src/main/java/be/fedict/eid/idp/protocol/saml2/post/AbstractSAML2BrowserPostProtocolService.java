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

package be.fedict.eid.idp.protocol.saml2.post;

import be.fedict.eid.idp.protocol.saml2.AbstractSAML2ProtocolService;
import be.fedict.eid.idp.protocol.saml2.HTTPOutTransport;
import be.fedict.eid.idp.spi.ReturnResponse;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.core.Response;
import org.opensaml.ws.transport.OutTransport;

import javax.servlet.http.HttpServletRequest;

public abstract class AbstractSAML2BrowserPostProtocolService extends AbstractSAML2ProtocolService {

        @SuppressWarnings("unchecked")
        @Override
        protected ReturnResponse handleSamlResponse(HttpServletRequest request,
                                                    String targetUrl,
                                                    Response samlResponse,
                                                    String relayState)
                throws Exception {

                ReturnResponse returnResponse = new ReturnResponse(targetUrl);

                HTTPPostEncoder messageEncoder = new HTTPPostEncoder();
                BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();
                messageContext.setOutboundSAMLMessage(samlResponse);
                messageContext.setRelayState(relayState);

                OutTransport outTransport = new HTTPOutTransport(returnResponse);
                messageContext.setOutboundMessageTransport(outTransport);

                messageEncoder.encode(messageContext);
                return returnResponse;
        }
}
