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

package be.fedict.eid.idp.sp;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.servlet.http.HttpServletRequest;
import java.security.NoSuchAlgorithmException;

public class SPBean {

        private static final Log LOG = LogFactory.getLog(SPBean.class);

        private HttpServletRequest request;

        private static SecretKey aes128SecretKey;

        static {

                try {
                        // generate some symmetric keys
                        KeyGenerator kgen = KeyGenerator.getInstance("AES");

                        kgen.init(128);
                        aes128SecretKey = kgen.generateKey();
                } catch (NoSuchAlgorithmException e) {
                        throw new RuntimeException(e);
                }

        }

        public String getAes128SecretKey() {

                return new String(Hex.encode(aes128SecretKey.getEncoded()));
        }
}
