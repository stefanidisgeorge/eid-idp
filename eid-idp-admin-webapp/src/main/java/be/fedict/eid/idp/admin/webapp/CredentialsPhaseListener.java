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

package be.fedict.eid.idp.admin.webapp;

import java.security.cert.X509Certificate;

import javax.faces.event.PhaseEvent;
import javax.faces.event.PhaseId;
import javax.faces.event.PhaseListener;
import javax.servlet.http.HttpSession;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jboss.seam.Component;
import org.jboss.seam.security.Credentials;

public class CredentialsPhaseListener implements PhaseListener {

	private static final long serialVersionUID = 1L;

	private static final Log LOG = LogFactory
			.getLog(CredentialsPhaseListener.class);

	public void afterPhase(PhaseEvent event) {
		// empty
	}

	public void beforePhase(PhaseEvent event) {
		HttpSession httpSession = (HttpSession) event.getFacesContext()
				.getExternalContext().getSession(true);
		String userId = (String) httpSession.getAttribute("eid.identifier");
		if (null != userId) {
			X509Certificate authnCertificate = (X509Certificate) httpSession
					.getAttribute("eid.certs.authn");
			String adminId = DigestUtils.sha256Hex(authnCertificate
					.getPublicKey().getEncoded());
			Credentials credentials = (Credentials) Component
					.getInstance(Credentials.class);
			/*
			 * Pass the eID credentials to the JBoss Seam security framework.
			 */
			credentials.setUsername(userId);
			credentials.setPassword(adminId);
		}
	}

	public PhaseId getPhaseId() {
		return PhaseId.ANY_PHASE;
	}
}
