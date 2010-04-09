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

package be.fedict.eid.idp.model.entity;

import java.io.Serializable;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.Id;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.Query;
import javax.persistence.Table;

import org.apache.commons.codec.digest.DigestUtils;

import static be.fedict.eid.idp.model.entity.AdministratorEntity.COUNT_QUERY;

@Entity
@Table(name = "idp_administrators")
@NamedQueries(@NamedQuery(name = COUNT_QUERY, query = "SELECT COUNT(admin) FROM AdministratorEntity AS admin"))
public class AdministratorEntity implements Serializable {

	public static final String COUNT_QUERY = "AdministratorEntity.query.count";

	private static final long serialVersionUID = 1L;

	private String id;

	private String subject;

	public AdministratorEntity() {
		super();
	}

	public AdministratorEntity(X509Certificate certificate) {
		this.id = getId(certificate);
		this.subject = certificate.getSubjectX500Principal().toString();
	}

	@Id
	public String getId() {
		return this.id;
	}

	public void setId(String id) {
		this.id = id;
	}

	@Column(nullable = false)
	public String getSubject() {
		return this.subject;
	}

	public void setSubject(String subject) {
		this.subject = subject;
	}

	private static String getId(X509Certificate certificate) {
		PublicKey publicKey = certificate.getPublicKey();
		byte[] encodedPublicKey = publicKey.getEncoded();
		String id = DigestUtils.sha256Hex(encodedPublicKey);
		return id;
	}

	public static boolean isAdministrator(X509Certificate certificate,
			EntityManager entityManager) {
		String id = getId(certificate);
		AdministratorEntity registration = entityManager.find(
				AdministratorEntity.class, id);
		return null != registration;
	}

	public static boolean hasAdmins(EntityManager entityManager) {
		Query query = entityManager.createNamedQuery(COUNT_QUERY);
		Long count = (Long) query.getSingleResult();
		return 0 != count;
	}
}
