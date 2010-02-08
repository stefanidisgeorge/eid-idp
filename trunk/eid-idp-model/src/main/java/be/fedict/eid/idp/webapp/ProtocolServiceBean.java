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

package be.fedict.eid.idp.webapp;

import java.util.List;

import javax.ejb.EJB;
import javax.ejb.Remove;
import javax.ejb.Stateful;

import org.jboss.ejb3.annotation.LocalBinding;
import org.jboss.seam.annotations.Destroy;
import org.jboss.seam.annotations.Factory;
import org.jboss.seam.annotations.Logger;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.datamodel.DataModel;
import org.jboss.seam.log.Log;

import be.fedict.eid.idp.model.ProtocolServiceManager;
import be.fedict.eid.idp.spi.protocol.IdentityProviderProtocolType;

@Stateful
@Name("idpProtocolService")
@LocalBinding(jndiBinding = "fedict/eid/idp/webapp/ProtocolServiceBean")
public class ProtocolServiceBean implements ProtocolService {

	@Logger
	private Log log;

	@DataModel
	private List<IdentityProviderProtocolType> idpProtocolServices;

	@EJB
	private ProtocolServiceManager protocolServiceManager;

	@Factory("idpProtocolServices")
	public void initProtocolServices() {
		this.log.debug("init idpProtocolServices");
		this.idpProtocolServices = this.protocolServiceManager
				.getProtocolServices();
	}

	@Remove
	@Destroy
	public void destroy() {
		this.log.debug("destroy");
	}
}
