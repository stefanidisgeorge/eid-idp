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

package be.fedict.eid.idp.protocol.ws_federation;

import java.io.IOException;
import java.io.OutputStream;
import java.security.cert.CertificateEncodingException;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;

import oasis.names.tc.saml._2_0.metadata.EntityDescriptorType;
import oasis.names.tc.saml._2_0.metadata.KeyDescriptorType;
import oasis.names.tc.saml._2_0.metadata.KeyTypes;
import oasis.names.tc.saml._2_0.metadata.ObjectFactory;
import oasis.names.tc.saml._2_0.metadata.RoleDescriptorType;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.oasis_open.docs.wsfed.authorization._200706.ClaimType;
import org.oasis_open.docs.wsfed.authorization._200706.DescriptionType;
import org.oasis_open.docs.wsfed.authorization._200706.DisplayNameType;
import org.oasis_open.docs.wsfed.federation._200706.ClaimTypesOfferedType;
import org.oasis_open.docs.wsfed.federation._200706.EndpointType;
import org.oasis_open.docs.wsfed.federation._200706.SecurityTokenServiceType;
import org.w3._2000._09.xmldsig_.KeyInfoType;
import org.w3._2000._09.xmldsig_.X509DataType;
import org.w3._2005._08.addressing.AttributedURIType;
import org.w3._2005._08.addressing.EndpointReferenceType;

import be.fedict.eid.idp.spi.IdentityProviderConfiguration;
import be.fedict.eid.idp.spi.IdentityProviderConfigurationFactory;

public class WSFederationMetadataHttpServlet extends HttpServlet {

	private static final long serialVersionUID = 1L;

	private static final Log LOG = LogFactory
			.getLog(WSFederationMetadataHttpServlet.class);

	@Override
	protected void doGet(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		LOG.debug("doGet");
		response.setContentType("application/samlmetadata+xml");

		IdentityProviderConfiguration configuration = IdentityProviderConfigurationFactory
				.getInstance(request);

		OutputStream outputStream = response.getOutputStream();
		try {
			writeMetadata(request, configuration, outputStream);
		} catch (JAXBException e) {
			throw new ServletException("JAXB error: " + e.getMessage(), e);
		}
	}

	private void writeMetadata(HttpServletRequest request,
			IdentityProviderConfiguration configuration,
			OutputStream outputStream) throws JAXBException, ServletException {
		ObjectFactory objectFactory = new ObjectFactory();
		EntityDescriptorType entityDescriptor = objectFactory
				.createEntityDescriptorType();

		String location = "https://" + request.getServerName() + ":"
				+ request.getServerPort() + request.getContextPath()
				+ "/protocol/ws-federation";
		LOG.debug("location: " + location);
		entityDescriptor.setEntityID(location);

		org.oasis_open.docs.wsfed.federation._200706.ObjectFactory fedObjectFactory = new org.oasis_open.docs.wsfed.federation._200706.ObjectFactory();
		SecurityTokenServiceType securityTokenService = fedObjectFactory
				.createSecurityTokenServiceType();
		List<RoleDescriptorType> roleDescriptors = entityDescriptor
				.getRoleDescriptorOrIDPSSODescriptorOrSPSSODescriptor();
		roleDescriptors.add(securityTokenService);
		securityTokenService.getProtocolSupportEnumeration().add(
				"http://docs.oasis-open.org/wsfed/federation/200706");

		List<EndpointType> passiveRequestorEndpoints = securityTokenService
				.getPassiveRequestorEndpoint();
		EndpointType endpoint = fedObjectFactory.createEndpointType();
		passiveRequestorEndpoints.add(endpoint);

		org.w3._2005._08.addressing.ObjectFactory addrObjectFactory = new org.w3._2005._08.addressing.ObjectFactory();

		EndpointReferenceType endpointReference = addrObjectFactory
				.createEndpointReferenceType();
		endpoint.getEndpointReference().add(endpointReference);
		AttributedURIType address = addrObjectFactory.createAttributedURIType();
		endpointReference.setAddress(address);

		address.setValue(location);

		List<KeyDescriptorType> keyDescriptors = securityTokenService
				.getKeyDescriptor();
		KeyDescriptorType keyDescriptor = objectFactory
				.createKeyDescriptorType();
		keyDescriptors.add(keyDescriptor);
		keyDescriptor.setUse(KeyTypes.SIGNING);
		org.w3._2000._09.xmldsig_.ObjectFactory dsObjectFactory = new org.w3._2000._09.xmldsig_.ObjectFactory();
		KeyInfoType keyInfo = dsObjectFactory.createKeyInfoType();
		keyDescriptor.setKeyInfo(keyInfo);
		List<Object> keyInfoObjects = keyInfo.getContent();
		X509DataType x509Data = dsObjectFactory.createX509DataType();
		keyInfoObjects.add(dsObjectFactory.createX509Data(x509Data));

		try {
			x509Data.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(
					dsObjectFactory
							.createX509DataTypeX509Certificate(configuration
									.getIdentity().getEncoded()));
		} catch (CertificateEncodingException e) {
			throw new ServletException("could not get the identity");
		}

		ClaimTypesOfferedType claimTypesOffered = fedObjectFactory
				.createClaimTypesOfferedType();
		securityTokenService.setClaimTypesOffered(claimTypesOffered);
		List<ClaimType> claimTypes = claimTypesOffered.getClaimType();
		org.oasis_open.docs.wsfed.authorization._200706.ObjectFactory authObjectFactory = new org.oasis_open.docs.wsfed.authorization._200706.ObjectFactory();
		ClaimType nameClaimType = authObjectFactory.createClaimType();
		claimTypes.add(nameClaimType);
		nameClaimType
				.setUri("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name");
		nameClaimType.setOptional(true);
		DisplayNameType nameDisplayName = authObjectFactory
				.createDisplayNameType();
		nameDisplayName.setValue("Name");
		nameClaimType.setDisplayName(nameDisplayName);
		DescriptionType nameDescription = authObjectFactory
				.createDescriptionType();
		nameDescription.setValue("The name of the subject.");
		nameClaimType.setDescription(nameDescription);

		JAXBContext context = JAXBContext
				.newInstance(
						ObjectFactory.class,
						org.oasis_open.docs.wsfed.federation._200706.ObjectFactory.class);
		Marshaller marshaller = context.createMarshaller();
		marshaller.setProperty("com.sun.xml.bind.namespacePrefixMapper",
				new WSFederationNamespacePrefixMapper());
		marshaller.marshal(objectFactory
				.createEntityDescriptor(entityDescriptor), outputStream);
	}
}
