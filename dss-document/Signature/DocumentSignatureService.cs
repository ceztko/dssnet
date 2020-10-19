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

using EU.Europa.EC.Markt.Dss.Signature.Token;
using Org.BouncyCastle.Crypto.Signers;

namespace EU.Europa.EC.Markt.Dss.Signature
{
	public abstract class DocumentSignatureService
	{
		public Document SignDocument(Document document, SignatureParameters parameters, IDssPrivateKeyEntry privateKey)
		{
			return SignDocumentInternal(document, parameters, (bytes) =>
			   DigestEncrypt.Encrypt(bytes, parameters.DigestAlgorithm, privateKey));
		}

		public Document SignDocument(Document document, SignatureParameters parameters, DigestSigner signer)
        {
			return SignDocumentInternal(document, parameters, signer);
		}

		public abstract Document ExtendDocument(Document document, Document originalDocument, SignatureParameters
			 parameters);

		protected abstract Document SignDocumentInternal(Document document, SignatureParameters parameters, DigestSigner signer);
	}
}
