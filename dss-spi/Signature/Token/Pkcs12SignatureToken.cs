/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2011 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2011 ARHS Developments S.A. (rue Nicolas BovÃ© 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

using System.IO;
using Org.BouncyCastle.Asn1.X509;
using Sharpen;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.Pkcs;
using System.Collections.Generic;
using Org.BouncyCastle.X509;

namespace EU.Europa.EC.Markt.Dss.Signature.Token
{
    /// <summary>Class holding all PKCS#12 file access logic.</summary>
    /// <remarks>Class holding all PKCS#12 file access logic.</remarks>
    /// <version>$Revision: 1887 $ - $Date: 2013-04-23 14:56:09 +0200 (mar., 23 avr. 2013) $
    /// 	</version>
    public class Pkcs12SignatureToken
    {
        private string password;
        private FilePath pkcs12File;

        //jbonilla
        IList<IDssPrivateKeyEntry> keys;

        //jbonilla
        public string Path 
        {
            get
            {
                return pkcs12File.GetAbsolutePath();
            }
        }

        //jbonilla
        public string Password
        {
            get
            {
                return password;
            }
        }

        /// <summary>Create a SignatureTokenConnection with the provided password and path to PKCS#12 file.
        /// 	</summary>
        /// <remarks>
        /// Create a SignatureTokenConnection with the provided password and path to PKCS#12 file. The default constructor
        /// for Pkcs12SignatureToken.
        /// </remarks>
        /// <param name="password"></param>
        /// <param name="pkcs12FilePath"></param>
        public Pkcs12SignatureToken(string password, string pkcs12FilePath)
            : this(password, new FilePath(pkcs12FilePath))
        {
        }

        /// <summary>Create a SignatureTokenConnection with the provided password and path to PKCS#12 file.
        /// 	</summary>
        /// <remarks>
        /// Create a SignatureTokenConnection with the provided password and path to PKCS#12 file. The default constructor
        /// for Pkcs12SignatureToken.
        /// </remarks>
        /// <param name="password"></param>
        /// <param name="pkcs12FilePath"></param>
        public Pkcs12SignatureToken(string password, FilePath pkcs12File)
        {
            this.password = password;
            this.pkcs12File = pkcs12File;
        }

        /// <exception cref="Sharpen.KeyStoreException"></exception>
        public IList<IDssPrivateKeyEntry> GetKeys()
        {
            if (keys != null)
                return keys;

            IList<IDssPrivateKeyEntry> list = new List<IDssPrivateKeyEntry>();
            Pkcs12Store keyStore = new Pkcs12StoreBuilder().Build();
            FileInputStream input = new FileInputStream(pkcs12File);
            keyStore.Load(input, password.ToCharArray());
            input.Close();

            foreach (string alias in keyStore.Aliases)
            {
                bool[] keyUsage;
                if (!(keyStore.IsKeyEntry(alias)
                    && keyStore.GetKey(alias).Key.IsPrivate
                    && ((keyUsage = keyStore.GetCertificate(alias).Certificate.GetKeyUsage()) == null
                    || keyUsage[0])))
                {
                    continue;
                }    

                X509CertificateEntry[] x = keyStore.GetCertificateChain(alias);
                X509Certificate[] chain = new X509Certificate[x.Length];

                for (int k = 0; k < x.Length; ++k)
                {
                    chain[k] = x[k].Certificate;
                }

                AsymmetricKeyParameter privateKey = keyStore.GetKey(alias).Key;

                list.AddItem(new KSPrivateKeyEntry(chain[0], chain, privateKey));
            }
            this.keys = list;

            return list;
        }
    }
}
