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

using EU.Europa.EC.Markt.Dss.Validation;
using EU.Europa.EC.Markt.Dss.Validation.Tsp;
using Org.BouncyCastle.Asn1.Cms;
//using Org.Apache.Commons.IO;
//using Org.BouncyCastle.Cert;
//using Org.BouncyCastle.Cert.Jcajce;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;
//using Org.BouncyCastle.Jce.Provider;
//using Org.BouncyCastle.Operator;
//using Org.BouncyCastle.Operator.BC;
using Sharpen;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
//using Sharpen.Logging;

namespace EU.Europa.EC.Markt.Dss.Signature.Cades
{
    /// <summary>CAdES implementation of DocumentSignatureService</summary>
    /// <version>$Revision: 1887 $ - $Date: 2013-04-23 14:56:09 +0200 (mar., 23 avr. 2013) $
    /// 	</version>
    public class CAdESService : DocumentSignatureService
    {
        /// <param name="tspSource">the tspSource to set</param>
        public ITspSource TspSource { get; set; }

        /// <param name="verifier">the verifier to set</param>
        public CertificateVerifier Verifier { get; set; }

        /// <summary>The default constructor for CAdESService.</summary>
        /// <remarks>The default constructor for CAdESService.</remarks>
        public CAdESService()
        {
            //jbonilla No se puede implementar en C#
            //Security.AddProvider(new BouncyCastleProvider());
        }

        /// <summary>Because some information are stored in the profile, a profile is not Thread-safe.
        /// 	</summary>
        /// <remarks>
        /// Because some information are stored in the profile, a profile is not Thread-safe. The software must create one
        /// for each request.
        /// </remarks>
        /// <returns>A new instance of signatureProfile corresponding to the parameters.</returns>
        private CAdESProfileBES GetSigningProfile(SignatureParameters parameters)
        {
            //jbonilla    	
            SignatureFormat signFormat = parameters.SignatureFormat;
            if (signFormat.Equals(SignatureFormat.CAdES_BES))
            {
                return new CAdESProfileBES();
            }
            else
            {
                if (signFormat.Equals(SignatureFormat.CAdES_EPES))
                {
                    return new CAdESProfileEPES();
                }
            }
            return new CAdESProfileEPES();
        }

        private CAdESSignatureExtension GetExtensionProfile(SignatureParameters parameters
            )
        {
            //jbonilla    	
            SignatureFormat signFormat = parameters.SignatureFormat;
            if (signFormat.Equals(SignatureFormat.CAdES_BES) || signFormat.Equals(SignatureFormat
                .CAdES_EPES))
            {
                return null;
            }
            else if (signFormat.Equals(SignatureFormat.CAdES_T))
            {
                CAdESProfileT extensionT = new CAdESProfileT();
                extensionT.SetSignatureTsa(TspSource);
                return extensionT;
            }
            else if (signFormat.Equals(SignatureFormat.CAdES_C))
            {
                CAdESProfileC extensionC = new CAdESProfileC();
                extensionC.SetSignatureTsa(TspSource);
                extensionC.SetCertificateVerifier(Verifier);
                return extensionC;
            }
            else if (signFormat.Equals(SignatureFormat.CAdES_X))
            {
                CAdESProfileX extensionX = new CAdESProfileX();
                extensionX.SetSignatureTsa(TspSource);
                extensionX.SetExtendedValidationType(1);
                extensionX.SetCertificateVerifier(Verifier);
                return extensionX;
            }
            else if (signFormat.Equals(SignatureFormat.CAdES_XL))
            {
                CAdESProfileXL extensionXL = new CAdESProfileXL();
                extensionXL.SetSignatureTsa(TspSource);
                extensionXL.SetExtendedValidationType(1);
                extensionXL.SetCertificateVerifier(Verifier);
                return extensionXL;
            }
            else if (signFormat.Equals(SignatureFormat.CAdES_A))
            {
                CAdESProfileA extensionA = new CAdESProfileA();
                extensionA.SetSignatureTsa(TspSource);
                extensionA.SetCertificateVerifier(Verifier);
                extensionA.SetExtendedValidationType(1);
                return extensionA;
            }

            throw new ArgumentException("Unsupported signature format " + parameters.SignatureFormat);
        }

        /// <summary><inheritDoc></inheritDoc></summary>
        /// <exception cref="System.IO.IOException"></exception>
        protected override Document SignDocumentInternal(Document document, SignatureParameters parameters,
            DigestSigner signer)
        {
            if (parameters.SignaturePackaging != SignaturePackaging.ENVELOPING &&
                parameters.SignaturePackaging != SignaturePackaging.DETACHED)
            {
                throw new ArgumentException("Unsupported signature packaging " + parameters.SignaturePackaging);
            }

            ExternalDigestSigner factory = new ExternalDigestSigner(signer, parameters);
            CmsSignedDataGenerator generator = CreateCMSSignedDataGenerator(
                factory, parameters, GetSigningProfile(parameters), true, null);
            byte[] toBeSigned = Streams.ReadAll(document.OpenStream());
            var content = new CmsProcessableByteArray(toBeSigned);
            CmsSignedData data = generator.Generate(content, parameters.SignaturePackaging != SignaturePackaging.DETACHED);
            Document signedDocument = new CMSSignedDocument(data);
            CAdESSignatureExtension extension = GetExtensionProfile(parameters);
            if (extension != null)
            {
                signedDocument = extension.ExtendSignatures(
                    new CMSSignedDocument(data), document, parameters);
            }
            return signedDocument;
        }

        /// <summary>Add a signature to the already CMS signed data document.</summary>
        /// <remarks>Add a signature to the already CMS signed data document.</remarks>
        /// <param name="_signedDocument"></param>
        /// <param name="parameters"></param>
        /// <param name="signatureValue"></param>
        /// <returns></returns>
        /// <exception cref="System.IO.IOException">System.IO.IOException</exception>
        public Document AddASignatureToDocument(Document _signedDocument, SignatureParameters
             parameters, byte[] signatureValue)
        {
            return null;
            /*
            if (parameters.SignaturePackaging != SignaturePackaging.ENVELOPING)
            {
                throw new ArgumentException("Unsupported signature packaging " + parameters.SignaturePackaging);
            }
            try
            {
                CmsSignedData originalSignedData = null;
                using (var stream = _signedDocument.OpenStream())
                {
                    originalSignedData = new CmsSignedData(stream);
                }

                //jbonilla - No aplica para C#
                //string jsAlgorithm = parameters.GetSignatureAlgorithm().GetJavaSignatureAlgorithm
                //    (parameters.GetDigestAlgorithm());
                //PreComputedContentSigner cs = new PreComputedContentSigner(jsAlgorithm, signatureValue
                //    );
                ExternalSignatureFactory s = new ExternalSignatureFactory(signatureValue);
                //DigestCalculatorProvider digestCalculatorProvider = new BcDigestCalculatorProvider
                //    ();
                //CMSSignedDataGenerator generator = CreateCMSSignedDataGenerator(cs, digestCalculatorProvider
                //    , parameters, GetSigningProfile(parameters), true, originalSignedData);
                CmsSignedDataGenerator generator = CreateCMSSignedDataGenerator(
                    s, parameters, GetSigningProfile(parameters), true, originalSignedData);

                //if (originalSignedData == null || originalSignedData.SignedContent.GetContent
                //    () == null)                
                if (originalSignedData == null || originalSignedData.SignedContent == null)
                {
                    throw new RuntimeException("Cannot retrieve orignal content");
                }
                //byte[] octetString = (byte[])originalSignedData.SignedContent.GetContent();
                //CmsProcessableByteArray content = new CmsProcessableByteArray(octetString);
                CmsProcessable content = originalSignedData.SignedContent;
                CmsSignedData data = generator.Generate(content, true);
                Document signedDocument = new CMSSignedDocument(data);
                CAdESSignatureExtension extension = GetExtensionProfile(parameters);
                if (extension != null)
                {
                    signedDocument = extension.ExtendSignatures(new CMSSignedDocument(data), null, parameters);
                }
                return signedDocument;
            }
            catch (CmsException e)
            {
                throw new RuntimeException(e);
            }
            */
        }

        /*
        /// <exception cref="System.IO.IOException"></exception>
        public override Document ExtendDocument(Document document, Document originalDocument
            , SignatureParameters parameters)
        {
            CAdESSignatureExtension extension = GetExtensionProfile(parameters);
            if (extension != null)
            {
                return extension.ExtendSignatures(document, originalDocument, parameters);
            }
            else
            {
                //LOG.Info("No extension for " + parameters.SignatureFormat);
            }
            return document;
        }
        */

        private CmsSignedDataGenerator CreateCMSSignedDataGenerator(ISignatureFactory factory,
            SignatureParameters parameters, CAdESProfileBES cadesProfile,
            bool includeUnsignedAttributes, CmsSignedData originalSignedData
            )
        {
            var signedAttrGen = new DefaultSignedAttributeTableGenerator(
                new AttributeTable(cadesProfile.GetSignedAttributes(parameters)));

            var unsignedAttrGen = new SimpleAttributeTableGenerator(
                includeUnsignedAttributes
                ? new AttributeTable(cadesProfile.GetUnsignedAttributes(parameters))
                : null);

            SignerInfoGeneratorBuilder sigInfoGeneratorBuilder = new SignerInfoGeneratorBuilder();
            sigInfoGeneratorBuilder.WithSignedAttributeGenerator(signedAttrGen);
            sigInfoGeneratorBuilder.WithUnsignedAttributeGenerator(unsignedAttrGen);

            CmsSignedDataGenerator generator = new CmsSignedDataGenerator();
            generator.AddSignerInfoGenerator(sigInfoGeneratorBuilder.Build(factory, parameters.SigningCertificate));

            if (originalSignedData != null)
                generator.AddSigners(originalSignedData.GetSignerInfos());

            var certs = new List<X509Certificate>();
            certs.Add(parameters.SigningCertificate);
            if (parameters.CertificateChain != null)
            {
                foreach (X509Certificate cert in parameters.CertificateChain)
                {
                    if (!cert.SubjectDN.Equals(parameters.SigningCertificate.SubjectDN))
                        certs.Add(cert);
                }
            }
            IX509Store certStore = X509StoreFactory.Create("Certificate/Collection",
                new X509CollectionStoreParameters(certs));
            generator.AddCertificates(certStore);
            if (originalSignedData != null)
                generator.AddCertificates(originalSignedData.GetCertificates("Collection"));

            return generator;
        }
    }
}
