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
import be.fedict.eid.idp.model.PkiUtil;
import be.fedict.eid.idp.model.RPService;
import be.fedict.eid.idp.model.exception.KeyLoadException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.ejb.Stateless;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import java.security.PrivateKey;
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
        public RPEntity save(RPEntity rp) throws KeyLoadException {

                RPEntity attachedRp = this.entityManager.find(RPEntity.class, rp.getId());
                if (null != attachedRp) {
                        // save

                        // configuration
                        attachedRp.setName(rp.getName());
                        attachedRp.setRequestSigningRequired(rp.isRequestSigningRequired());
                        if (null != rp.getDomain() && rp.getDomain().trim().isEmpty()) {
                                attachedRp.setDomain(null);
                        } else {
                                attachedRp.setDomain(rp.getDomain());
                        }
                        if (null != rp.getTargetURL() && rp.getTargetURL().trim().isEmpty()) {
                                attachedRp.setTargetURL(null);
                        } else {
                                attachedRp.setTargetURL(rp.getTargetURL());
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
                        if (rp.getAttributeSecretAlgorithm() == SecretKeyAlgorithm.NONE) {

                                attachedRp.setAttributeSecretAlgorithm(rp.getAttributeSecretAlgorithm());
                                attachedRp.setAttributeAsymmetricSecretKey(null);
                                attachedRp.setAttributeSymmetricSecretKey(null);

                        } else {
                                if (null != rp.getIdentifierSecretKey() && rp.getIdentifierSecretKey().trim().isEmpty()) {
                                        attachedRp.setIdentifierSecretKey(null);
                                } else {
                                        attachedRp.setIdentifierSecretKey(rp.getIdentifierSecretKey());
                                }
                                if (null != rp.getAttributeSecretAlgorithm()) {
                                        attachedRp.setAttributeSecretAlgorithm(null);
                                } else {
                                        attachedRp.setAttributeSecretAlgorithm(rp.getAttributeSecretAlgorithm());
                                }

                                attachedRp.setAttributeAsymmetricSecretKey(rp.getAttributeAsymmetricSecretKey());
                                attachedRp.setAttributeSecretAlgorithm(getAttributeSecretAlgorithm(attachedRp));

                                if (null != rp.getAttributeSymmetricSecretKey() && rp.getAttributeSymmetricSecretKey().trim().isEmpty()) {
                                        attachedRp.setAttributeSymmetricSecretKey(null);
                                } else {
                                        attachedRp.setAttributeSymmetricSecretKey(rp.getAttributeSymmetricSecretKey());
                                }
                        }

                        // check not both symmetric and asymmetric is set ...
                        if (null != attachedRp.getAttributeAsymmetricSecretKey() &&
                                null != attachedRp.getAttributeSymmetricSecretKey()) {
                                throw new KeyLoadException("Both symmetric as " +
                                        "assymetric attribute secret key is set, pick one...");
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
                        this.entityManager.persist(rp);
                        rp.setAttributeSecretAlgorithm(getAttributeSecretAlgorithm(rp));
                        for (RPAttributeEntity rpAttribute : rp.getAttributes()) {
                                RPAttributeEntity newRpAttribute =
                                        new RPAttributeEntity(rp, rpAttribute.getAttribute());
                                this.entityManager.persist(newRpAttribute);
                        }
                        return rp;
                }
        }

        private SecretKeyAlgorithm getAttributeSecretAlgorithm(RPEntity rp) {

                if (null != rp.getAttributeAsymmetricSecretKey()) {
                        PrivateKey attributeSecret;
                        try {
                                attributeSecret = PkiUtil.getPrivate(
                                        rp.getAttributeAsymmetricSecretKey());
                        } catch (KeyLoadException e) {
                                throw new RuntimeException(e);
                        }
                        if (attributeSecret.getAlgorithm().equals("DSA")) {
                                return SecretKeyAlgorithm.PKI_DSA;

                        } else if (attributeSecret.getAlgorithm().equals("RSA")) {
                                return SecretKeyAlgorithm.PKI_RSA;
                        }
                }

                return rp.getAttributeSecretAlgorithm();
        }

        @Override
        public RPEntity find(String domain) {
                return RPEntity.findRP(this.entityManager, domain);
        }
}
