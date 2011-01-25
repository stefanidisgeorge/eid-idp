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

import be.fedict.eid.idp.entity.AttributeEntity;
import be.fedict.eid.idp.entity.RPAttributeEntity;
import be.fedict.eid.idp.entity.RPEntity;
import be.fedict.eid.idp.model.AttributeService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.ejb.Stateless;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import java.util.Iterator;
import java.util.List;

@Stateless
public class AttributeServiceBean implements AttributeService {

        private static final Log LOG = LogFactory.getLog(AttributeServiceBean.class);

        @PersistenceContext
        private EntityManager entityManager;

        @Override
        public List<AttributeEntity> listAttributes() {
                return AttributeEntity.listAttributes(this.entityManager);
        }

        @Override
        public AttributeEntity saveAttribute(String name) {

                AttributeEntity attribute = this.entityManager.find(
                        AttributeEntity.class, name);
                if (null == attribute) {
                        attribute = new AttributeEntity(name);
                        this.entityManager.persist(attribute);
                }
                return attribute;
        }

        @Override
        public RPEntity setAttributes(RPEntity rp, List<String> attributes) {

                LOG.debug("set attributes: " + rp.getName());

                RPEntity attachedRp = this.entityManager.find(RPEntity.class, rp.getId());
                List<RPAttributeEntity> oldRpAttributes = attachedRp.getAttributes();

                // add new ones
                for (String attributeName : attributes) {

                        boolean found = false;
                        for (RPAttributeEntity oldRpAttribute : oldRpAttributes) {
                                if (oldRpAttribute.getAttribute().getName().equals(attributeName)) {
                                        // already in, ok
                                        found = true;
                                        break;
                                }
                        }

                        if (!found) {

                                // new one
                                AttributeEntity attribute = this.entityManager.
                                        find(AttributeEntity.class, attributeName);
                                RPAttributeEntity rpAttribute =
                                        new RPAttributeEntity(attachedRp, attribute);
                                this.entityManager.persist(rpAttribute);
                                attachedRp.getAttributes().add(rpAttribute);
                        }
                }

                // remove old ones
                Iterator<RPAttributeEntity> iter = attachedRp.getAttributes().iterator();
                while (iter.hasNext()) {
                        RPAttributeEntity rpAttribute = iter.next();
                        if (!attributes.contains(rpAttribute.getAttribute().getName())) {
                                // removed one
                                iter.remove();
//                                attachedRp.getAttributes().remove(rpAttribute);
                                this.entityManager.remove(rpAttribute);
                        }
                }

                return attachedRp;
        }
}
