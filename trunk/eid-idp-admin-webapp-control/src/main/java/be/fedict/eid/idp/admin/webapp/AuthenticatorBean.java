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

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.faces.application.Application;
import javax.faces.application.ViewHandler;
import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;

import org.jboss.ejb3.annotation.LocalBinding;
import org.jboss.seam.Component;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Logger;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.faces.Redirect;
import org.jboss.seam.log.Log;
import org.jboss.seam.security.Credentials;
import org.jboss.seam.security.Identity;

import be.fedict.eid.idp.model.admin.AdminManager;

@Stateless
@Name("idpAuthenticator")
@LocalBinding(jndiBinding = "fedict/eid/idp/admin/webapp/AuthenticatorBean")
public class AuthenticatorBean implements Authenticator {

	@In
	private FacesContext facesContext;

	@Logger
	private Log log;

	@In
	private Credentials credentials;

	@In
	private Identity identity;

	@EJB
	private AdminManager adminManager;

	@Override
	public boolean authenticate() {
		String userId = this.credentials.getUsername();
		if (null == userId) {
			this.log.debug("no username credential set");
			return false;
		}
		this.log.debug("authenticate: #0", userId);
		String authnCertificateId = this.credentials.getPassword();
		if (this.adminManager.isAdmin(authnCertificateId)) {
			this.identity.addRole("admin");
		}
		return true;
	}

	@Override
	public String getTargetPage() {
		Redirect redirect = (Redirect) Component.getInstance(Redirect.class);
		String viewId = redirect.getViewId();
		this.log.debug("redirect viewId: #0", viewId);

		Application application = this.facesContext.getApplication();
		ViewHandler viewHandler = application.getViewHandler();
		String actionUrl = viewHandler.getActionURL(this.facesContext, viewId);
		this.log.debug("action url: #0", actionUrl);

		ExternalContext externalContext = this.facesContext
				.getExternalContext();
		String requestContextPath = externalContext.getRequestContextPath();
		this.log.debug("request context path: #0", requestContextPath);
		String targetPage = actionUrl.substring(requestContextPath.length()
				+ "/".length());
		this.log.debug("target page: #0", targetPage);
		return targetPage;
	}
}
