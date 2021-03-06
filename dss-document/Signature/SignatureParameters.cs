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

using System;
using System.Collections.Generic;
using EU.Europa.EC.Markt.Dss;
using EU.Europa.EC.Markt.Dss.Signature;
using Sharpen;
using Org.BouncyCastle.X509;

namespace EU.Europa.EC.Markt.Dss.Signature
{
	/// <summary>Parameters for a Signature creation/extension</summary>
	/// <version>$Revision: 1887 $ - $Date: 2013-04-23 14:56:09 +0200 (mar., 23 avr. 2013) $
	/// 	</version>
	public class SignatureParameters
	{
        /// <summary>Get or Set the signing date</summary>        
		public DateTime SigningDate { get; set; }

        /// <summary>Get or Set the signing certificate</summary>        
        public X509Certificate SigningCertificate { get; set; }

        /// <summary>Get or Set the certificate chain</summary>		
        public IReadOnlyList<X509Certificate> CertificateChain { get; set; }

        /// <summary>Return or Set the type of signature policy</summary>
        public SignaturePolicy SignaturePolicy { get; set; }
        
        /// <summary>Get or Set the signature policy (EPES)</summary>
        public string SignaturePolicyID { get; set; }

        /// <summary>Return or Set the hash algorithm for the signature policy 
        /// or Set the hash algorithm for the explicit signature policy</summary>
        public string SignaturePolicyHashAlgo { get; set; }

        /// <summary>Get the hash value of the explicit signature policy 
        /// or Set the hash value of implicit signature policy</summary>        
        public byte[] SignaturePolicyHashValue { get; set; }

        /// <summary>Get or Set claimed role</summary>
        public string ClaimedSignerRole { get; set; }

        /// <summary>Get or Set signature format</summary>
        public SignatureFormat SignatureFormat { get; set; }

        /// <summary>Get or Set Signature packaging</summary>
        public SignaturePackaging SignaturePackaging { get; set; }
        
        /// <returns>the signatureAlgorithm</returns>
        public SignatureAlgorithm SignatureAlgorithm { get; set; }

        /// <returns>the digestAlgorithm</returns>
        public DigestAlgorithm DigestAlgorithm { get; set; }

        /// <returns>the reason</returns>
        public string Reason { get; set; }

        /// <returns>the contactInfo</returns>
        public string ContactInfo { get; set; }

        /// <returns>the location</returns>
        public string Location { get; set; }

        /// <returns>the commitmentTypeIndication</returns>
        public IReadOnlyList<string> CommitmentTypeIndication { get; set; }

        public SignatureParameters()
        {
            this.CertificateChain = new List<X509Certificate>();
            this.SignaturePolicy = SignaturePolicy.NO_POLICY;
            this.DigestAlgorithm = DigestAlgorithm.SHA1;
            this.SignatureAlgorithm = SignatureAlgorithm.RSA;
        }

        /// <summary>Set the certificate chain</summary>
		/// <param name="certificateChain"></param>
		public void SetCertificateChain(params X509Certificate[] certificateChain)
		{
			var list = new List<X509Certificate>();
			foreach (X509Certificate c in certificateChain)
				list.Add(c);

			this.CertificateChain = list;
		}
	}
}
