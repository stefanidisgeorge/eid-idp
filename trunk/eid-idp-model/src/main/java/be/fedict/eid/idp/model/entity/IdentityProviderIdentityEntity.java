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

import static be.fedict.eid.idp.model.entity.IdentityProviderIdentityEntity.ALL_QUERY;

import java.io.Serializable;
import java.util.List;

import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.Query;
import javax.persistence.Table;

/**
 * The eID IdP identities. Later on we will also support PKCS#11 HSMs and such.
 * 
 * @author Frank Cornelis
 * 
 */
@Entity
@Table(name = "idp_identity")
@NamedQueries(@NamedQuery(name = ALL_QUERY, query = "FROM IdentityProviderIdentityEntity"))
public class IdentityProviderIdentityEntity implements Serializable {

	private static final long serialVersionUID = 1L;

	public static final String ALL_QUERY = "IdentityProviderIdentityEntity.all";

	private long id;

	private String p12Location;

	private String p12Password;

	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	public long getId() {
		return this.id;
	}

	public void setId(long id) {
		this.id = id;
	}

	public IdentityProviderIdentityEntity() {
		super();
	}

	public IdentityProviderIdentityEntity(String p12Location, String p12Password) {
		this.p12Location = p12Location;
		this.p12Password = p12Password;
	}

	public String getP12Location() {
		return this.p12Location;
	}

	public void setP12Location(String p12Location) {
		this.p12Location = p12Location;
	}

	public String getP12Password() {
		return this.p12Password;
	}

	public void setP12Password(String p12Password) {
		this.p12Password = p12Password;
	}

	public static List<IdentityProviderIdentityEntity> getAll(
			EntityManager entityManager) {
		Query query = entityManager.createNamedQuery(ALL_QUERY);
		return query.getResultList();
	}
}
