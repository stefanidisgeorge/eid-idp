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

import org.richfaces.event.UploadEvent;

import javax.ejb.Local;
import javax.faces.model.SelectItem;
import java.io.IOException;
import java.security.PrivateKey;
import java.util.List;

@Local
public interface RP {

        /*
        * Accessors
        */
        List<String> getSourceAttributes();

        void setSourceAttributes(List<String> sourceAttributes);

        List<String> getSelectedAttributes();

        void setSelectedAttributes(List<String> selectedAttributes);

        String getSelectedTab();

        void setSelectedTab(String selectedTab);

        PrivateKey getAttributeAssymetricSecret();

        /*
        * Listeners.
        */
        void uploadListener(UploadEvent event) throws IOException;

        void uploadListenerSecret(UploadEvent event) throws IOException;

        /*
        * Factories
        */
        void rpListFactory();

        List<SelectItem> secretAlgorithmsFactory();

        /*
        * Actions.
        */
        String add();

        String modify();

        String save();

        void select();

        String remove();

        String back();

        String selectAttributes();

        String saveSelect();

        void initSelect();

        /*
        * Lifecycle.
        */
        void destroy();

        void postConstruct();
}
