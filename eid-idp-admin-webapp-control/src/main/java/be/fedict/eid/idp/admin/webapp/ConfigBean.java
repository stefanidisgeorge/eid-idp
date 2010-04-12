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

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.ejb.Remove;
import javax.ejb.Stateful;

import org.jboss.ejb3.annotation.LocalBinding;
import org.jboss.seam.annotations.Destroy;
import org.jboss.seam.annotations.Logger;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.log.Log;

import be.fedict.eid.idp.model.ConfigManager;

@Stateful
@Name("idpConfig")
@LocalBinding(jndiBinding = "fedict/eid/idp/admin/webapp/ConfigBean")
public class ConfigBean implements Config {

	@Logger
	private Log log;

	@EJB
	private ConfigManager configManager;

	private String xkmsUrl;

	@Override
	@PostConstruct
	public void postConstruct() {
		this.log.debug("postConstruct");
		this.xkmsUrl = this.configManager.getXkmsUrl();
	}

	@Remove
	@Destroy
	@Override
	public void destroy() {
		this.log.debug("destroy");
	}

	@Override
	public String getXkmsUrl() {
		return this.xkmsUrl;
	}

	@Override
	public String save() {
		this.log.debug("save");
		this.configManager.setXkmsUrl(this.xkmsUrl);
		return null;
	}

	@Override
	public void setXkmsUrl(String xkmsUrl) {
		this.xkmsUrl = xkmsUrl;
	}
}
