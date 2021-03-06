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

using System.Collections.Generic;
using EU.Europa.EC.Markt.Dss.Signature;
using EU.Europa.EC.Markt.Dss.Validation;
using EU.Europa.EC.Markt.Dss.Validation.Cades;
using Org.BouncyCastle.Cms;
using Sharpen;

namespace EU.Europa.EC.Markt.Dss.Validation.Cades
{
	/// <summary>Validation of CMS document</summary>
	/// <version>$Revision: 1887 $ - $Date: 2013-04-23 14:56:09 +0200 (mar., 23 avr. 2013) $
	/// 	</version>
	public class CMSDocumentValidator : SignedDocumentValidator
	{
		private CmsSignedData cmsSignedData;

		/// <summary>The default constructor for PKCS7DocumentValidator.</summary>
		/// <remarks>The default constructor for PKCS7DocumentValidator.</remarks>
		/// <exception cref="System.IO.IOException"></exception>
		/// <exception cref="Org.Bouncycastle.Cms.CmsException"></exception>
		public CMSDocumentValidator(Document document)
		{
			this.Document = document;
			this.cmsSignedData = new CmsSignedData(document.OpenStream());
		}

		/// <summary>The default constructor for PKCS7DocumentValidator.</summary>
		/// <remarks>The default constructor for PKCS7DocumentValidator.</remarks>
		/// <exception cref="System.IO.IOException"></exception>
		/// <exception cref="Org.Bouncycastle.Cms.CmsException"></exception>
		public CMSDocumentValidator(Document document, CmsSignedData cmsSignedData)
		{
			this.Document = document;
			this.cmsSignedData = cmsSignedData;
		}

		public override IList<AdvancedSignature> GetSignatures()
		{
			IList<AdvancedSignature> infos = new List<AdvancedSignature>();
			foreach (object o in this.cmsSignedData.GetSignerInfos().GetSigners())
			{
				SignerInformation i = (SignerInformation)o;
				CAdESSignature info = new CAdESSignature(this.cmsSignedData, i.SignerID);
				infos.Add(info);
			}
			return infos;
		}
	}
}
