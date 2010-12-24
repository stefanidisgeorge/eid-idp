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

package be.fedict.eid.idp.model.admin;

import java.security.cert.X509Certificate;

import javax.ejb.Stateless;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import be.fedict.eid.idp.entity.AdministratorEntity;
import be.fedict.eid.idp.entity.RegistrationEntity;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

@Stateless
public class AdminManagerBean implements AdminManager {

	private static final Log LOG = LogFactory.getLog(AdminManagerBean.class);

	@PersistenceContext
	private EntityManager entityManager;

	public void register(X509Certificate certificate) {
		if (RegistrationEntity.isRegistered(certificate, this.entityManager)) {
			LOG.debug("already registered: "
					+ certificate.getSubjectX500Principal());
			return;
		}

		if (false == AdministratorEntity.hasAdmins(this.entityManager)) {
			LOG.debug("registering as administrator");
			AdministratorEntity administrator = new AdministratorEntity(
					certificate);
			this.entityManager.persist(administrator);
		} else {
			RegistrationEntity registration = new RegistrationEntity(
					certificate);
			this.entityManager.persist(registration);
			LOG.debug("certificate registered: "
					+ certificate.getSubjectX500Principal());
		}
	}

	public boolean isAdmin(String adminId) {
		LOG.debug("checking admin privileges for: " + adminId);
		AdministratorEntity administrator = this.entityManager.find(
				AdministratorEntity.class, adminId);
		return null != administrator;
	}
}
