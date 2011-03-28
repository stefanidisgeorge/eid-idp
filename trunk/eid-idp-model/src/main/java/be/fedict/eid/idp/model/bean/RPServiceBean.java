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

package be.fedict.eid.idp.model.bean;

import be.fedict.eid.idp.entity.RPAttributeEntity;
import be.fedict.eid.idp.entity.RPEntity;
import be.fedict.eid.idp.entity.SecretKeyAlgorithm;
import be.fedict.eid.idp.model.RPService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.ejb.Stateless;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import java.util.List;

@Stateless
public class RPServiceBean implements RPService {

        private static Log LOG = LogFactory.getLog(RPServiceBean.class);

        @PersistenceContext
        private EntityManager entityManager;

        @Override
        public List<RPEntity> listRPs() {

                return RPEntity.listRPs(this.entityManager);
        }

        @Override
        public void remove(RPEntity rp) {

                RPEntity attachedRp = this.entityManager.find(RPEntity.class, rp.getId());
                this.entityManager.remove(attachedRp);
        }

        @Override
        public RPEntity save(RPEntity rp) {

                RPEntity attachedRp = null;
                if (null != rp.getId()) {
                        attachedRp = this.entityManager.find(RPEntity.class, rp.getId());
                }
                if (null != attachedRp) {
                        // save

                        // configuration
                        attachedRp.setName(rp.getName());
                        attachedRp.setRequestSigningRequired(rp.isRequestSigningRequired());
                        if (null != rp.getDomain() && rp.getDomain().trim().isEmpty()) {
                                attachedRp.setDomain(null);
                        } else {
                                attachedRp.setDomain(rp.getDomain().trim());
                        }
                        if (null != rp.getTargetURL() && rp.getTargetURL().trim().isEmpty()) {
                                attachedRp.setTargetURL(null);
                        } else {
                                attachedRp.setTargetURL(rp.getTargetURL().trim());
                        }

                        // pki
                        if (null != rp.getAuthnTrustDomain() && rp.getAuthnTrustDomain().trim().isEmpty()) {
                                attachedRp.setAuthnTrustDomain(null);
                        } else {
                                attachedRp.setAuthnTrustDomain(rp.getAuthnTrustDomain());
                        }

                        if (null != rp.getIdentityTrustDomain() && rp.getIdentityTrustDomain().trim().isEmpty()) {
                                attachedRp.setIdentityTrustDomain(null);
                        } else {
                                attachedRp.setIdentityTrustDomain(rp.getIdentityTrustDomain());
                        }

                        // secrets
                        if (null != rp.getIdentifierSecretKey() && rp.getIdentifierSecretKey().trim().isEmpty()) {
                                attachedRp.setIdentifierSecretKey(null);
                        } else {
                                attachedRp.setIdentifierSecretKey(rp.getIdentifierSecretKey().trim());
                        }

                        attachedRp.setAttributeSecretAlgorithm(rp.getAttributeSecretAlgorithm());
                        attachedRp.setAttributePublicKey(rp.getAttributePublicKey());
                        if (rp.getAttributeSecretAlgorithm() == SecretKeyAlgorithm.NONE) {

                                attachedRp.setAttributeSecretKey(null);

                        } else {

                                if (null != rp.getAttributeSecretKey() && rp.getAttributeSecretKey().trim().isEmpty()) {
                                        attachedRp.setAttributeSecretKey(null);
                                } else {
                                        attachedRp.setAttributeSecretKey(rp.getAttributeSecretKey().trim());
                                }
                        }

                        // signing
                        attachedRp.setEncodedCertificate(rp.getEncodedCertificate());

                        // attributes
                        for (RPAttributeEntity rpAttribute : rp.getAttributes()) {
                                attachedRp.getAttributes().
                                        get(attachedRp.getAttributes().
                                                indexOf(rpAttribute)).
                                        setEncrypted(rpAttribute.isEncrypted());
                        }

                        return attachedRp;
                } else {
                        // add
                        if (null != rp.getDomain() &&
                                rp.getDomain().trim().isEmpty()) {
                                rp.setDomain(null);
                        }
                        if (null != rp.getTargetURL() &&
                                rp.getTargetURL().trim().isEmpty()) {
                                rp.setTargetURL(null);
                        }
                        if (null != rp.getAuthnTrustDomain() &&
                                rp.getAuthnTrustDomain().trim().isEmpty()) {
                                rp.setAuthnTrustDomain(null);
                        }
                        if (null != rp.getIdentityTrustDomain() &&
                                rp.getIdentityTrustDomain().trim().isEmpty()) {
                                rp.setIdentityTrustDomain(null);
                        }
                        if (null != rp.getIdentifierSecretKey() &&
                                rp.getIdentifierSecretKey().trim().isEmpty()) {
                                rp.setIdentifierSecretKey(null);
                        }

                        this.entityManager.persist(rp);
                        for (RPAttributeEntity rpAttribute : rp.getAttributes()) {
                                RPAttributeEntity newRpAttribute =
                                        new RPAttributeEntity(rp, rpAttribute.getAttribute());
                                this.entityManager.persist(newRpAttribute);
                        }
                        return rp;
                }
        }

        @Override
        public RPEntity find(String domain) {
                return RPEntity.findRP(this.entityManager, domain);
        }
}
