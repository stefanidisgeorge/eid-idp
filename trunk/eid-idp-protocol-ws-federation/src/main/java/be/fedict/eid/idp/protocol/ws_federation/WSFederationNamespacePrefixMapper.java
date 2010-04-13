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

import java.util.HashMap;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.sun.xml.bind.marshaller.NamespacePrefixMapper;

public class WSFederationNamespacePrefixMapper extends NamespacePrefixMapper {
	private static final Log LOG = LogFactory
			.getLog(WSFederationNamespacePrefixMapper.class);

	private static final Map<String, String> prefixes = new HashMap<String, String>();

	static {
		prefixes.put("http://www.w3.org/2000/09/xmldsig#", "ds");
		prefixes.put("urn:oasis:names:tc:SAML:2.0:metadata", "md");
		prefixes.put("http://www.w3.org/2001/04/xmlenc#", "xenc");
		prefixes.put("urn:oasis:names:tc:SAML:2.0:assertion", "saml");
		prefixes.put("http://docs.oasis-open.org/wsfed/federation/200706",
				"fed");
		prefixes.put("http://docs.oasis-open.org/wsfed/authorization/200706",
				"auth");
		prefixes.put("http://www.w3.org/2005/08/addressing", "wsa");
		prefixes.put(
				"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702",
				"sp");
		prefixes.put("http://schemas.xmlsoap.org/ws/2004/09/mex", "mex");
		prefixes
				.put(
						"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
						"wsse");
		prefixes
				.put(
						"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
						"wsu");
	}

	@Override
	public String getPreferredPrefix(String namespaceUri, String suggestion,
			boolean requirePrefix) {
		LOG.debug("get preferred prefix: " + namespaceUri);
		LOG.debug("suggestion: " + suggestion);
		String prefix = prefixes.get(namespaceUri);
		if (null != prefix) {
			return prefix;
		}
		return suggestion;
	}

}
