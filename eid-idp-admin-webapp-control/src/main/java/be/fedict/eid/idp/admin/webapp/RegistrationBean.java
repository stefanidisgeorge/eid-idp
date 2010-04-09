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

import javax.ejb.EJB;
import javax.ejb.Remove;
import javax.ejb.Stateful;

import org.jboss.ejb3.annotation.LocalBinding;
import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.Destroy;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Logger;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.log.Log;

import be.fedict.eid.idp.model.admin.AdminManager;

@Stateful
@Name("idpRegistration")
@LocalBinding(jndiBinding = "fedict/eid/idp/admin/webapp/RegistrationBean")
public class RegistrationBean implements Registration {

	@Logger
	private Log log;

	@In(required = false, scope = ScopeType.SESSION, value = "eid.certs.authn")
	private X509Certificate authnCertificate;

	@EJB
	private AdminManager adminManager;

	@Remove
	@Destroy
	@Override
	public void destroy() {
		this.log.debug("destroy");
	}

	@Override
	public void register() {
		this.log.debug("register");
		this.log.debug("identity: #0", this.authnCertificate
				.getSubjectX500Principal());
		this.adminManager.register(this.authnCertificate);
	}
}
