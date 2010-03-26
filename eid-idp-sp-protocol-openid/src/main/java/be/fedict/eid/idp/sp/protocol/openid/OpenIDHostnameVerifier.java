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

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class OpenIDHostnameVerifier implements HostnameVerifier {

	private static final Log LOG = LogFactory
			.getLog(OpenIDHostnameVerifier.class);

	public boolean verify(String urlHostName, SSLSession session) {
		String peerHostname = session.getPeerHost();
		LOG.debug("URL hostname: " + urlHostName);
		LOG.debug("peer hostname: " + session.getPeerHost());
		if (false == urlHostName.equals(peerHostname)) {
			LOG.warn("different host names!");
		}
		return true;
	}
}
