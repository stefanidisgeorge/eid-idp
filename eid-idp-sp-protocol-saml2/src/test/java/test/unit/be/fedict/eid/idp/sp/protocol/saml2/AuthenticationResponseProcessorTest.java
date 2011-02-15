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

package test.unit.be.fedict.eid.idp.sp.protocol.saml2;

import be.fedict.eid.idp.common.Attribute;
import be.fedict.eid.idp.common.AttributeType;
import be.fedict.eid.idp.common.SamlAuthenticationPolicy;
import be.fedict.eid.idp.common.saml2.AuthenticationResponse;
import be.fedict.eid.idp.common.saml2.Saml2Util;
import be.fedict.eid.idp.sp.protocol.saml2.post.AuthenticationResponseProcessor;
import be.fedict.eid.idp.sp.protocol.saml2.spi.AuthenticationResponseService;
import org.apache.xml.security.utils.Base64;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.w3c.dom.Element;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class AuthenticationResponseProcessorTest {

        private AuthenticationResponseService mockAuthenticationResponseService;
        private HttpServletRequest mockHttpServletRequest;


        @Before
        public void setUp() throws Exception {

                this.mockAuthenticationResponseService =
                        createMock(AuthenticationResponseService.class);
                this.mockHttpServletRequest = createMock(HttpServletRequest.class);
        }

        @After
        public void tearDown() throws Exception {
        }

        @Test
        public void testPostSamlResponse() throws Exception {

                // Setup
                String userId = UUID.randomUUID().toString();
                String attributeName = "urn:test:attribute";
                Attribute attribute = new Attribute(attributeName,
                        AttributeType.STRING, UUID.randomUUID().toString());
                Map<String, Attribute> attributes = new HashMap<String, Attribute>();
                attributes.put(attributeName, attribute);

                String issuerName = "test-issuer";

                String requestId = UUID.randomUUID().toString();
                String recipient = "http://www.testsp.com/saml";
                String relayState = "test-relay-state";

                Response samlResponse = Saml2Util.getResponse(requestId,
                        recipient, issuerName);

                Assertion assertion = Saml2Util.getAssertion(issuerName,
                        requestId, recipient, 5, samlResponse.getIssueInstant(),
                        SamlAuthenticationPolicy.IDENTIFICATION, userId,
                        attributes, null, null);
                samlResponse.getAssertions().add(assertion);

                Element samlResponseElement = Saml2Util.marshall(samlResponse);
                String encodedSamlResponse =
                        Base64.encode(Saml2Util.domToString(samlResponseElement, true).getBytes());

                AuthenticationResponseProcessor responseProcessor =
                        new AuthenticationResponseProcessor(mockAuthenticationResponseService);

                // Expectations
                expect(mockHttpServletRequest.getMethod()).andReturn("POST");
                expect(mockHttpServletRequest.getParameter("SAMLRequest"))
                        .andReturn(null);
                expect(mockHttpServletRequest.getParameter("SAMLResponse"))
                        .andReturn(encodedSamlResponse);
                expect(mockHttpServletRequest.getParameter("RelayState"))
                        .andReturn(relayState).times(2);
                expect(mockHttpServletRequest.getRequestURL()).
                        andReturn(new StringBuffer(recipient));

                expect(mockAuthenticationResponseService.getMaximumTimeOffset())
                        .andReturn(5);
                expect(mockAuthenticationResponseService.getAttributeSecretKey())
                        .andReturn(null);
                expect(mockAuthenticationResponseService.getAttributePrivateKey())
                        .andReturn(null);

                replay(mockAuthenticationResponseService, mockHttpServletRequest);

                // Operate
                AuthenticationResponse authenticationResponse =
                        responseProcessor.process(requestId, recipient, relayState,
                                mockHttpServletRequest);

                // Verify
                verify(mockAuthenticationResponseService, mockHttpServletRequest);

                assertNotNull(authenticationResponse);
                assertEquals(userId, authenticationResponse.getIdentifier());
                assertEquals(relayState, authenticationResponse.getRelayState());
                assertEquals(SamlAuthenticationPolicy.IDENTIFICATION,
                        authenticationResponse.getAuthenticationPolicy());
                assertNotNull(authenticationResponse.getAssertion());
                assertNotNull(authenticationResponse.getAuthenticationTime());
                assertNotNull(authenticationResponse.getAttributeMap());
                assertEquals(1, authenticationResponse.getAttributeMap().size());
                assertEquals(attribute.getValue(),
                        authenticationResponse.getAttributeMap().get(attributeName));
        }

}
