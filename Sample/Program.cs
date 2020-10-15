using EU.Europa.EC.Markt.Dss;
using EU.Europa.EC.Markt.Dss.Signature;
using EU.Europa.EC.Markt.Dss.Signature.Cades;
using EU.Europa.EC.Markt.Dss.Signature.Token;
using EU.Europa.EC.Markt.Dss.Validation;
using EU.Europa.EC.Markt.Dss.Validation.Crl;
using EU.Europa.EC.Markt.Dss.Validation.Ocsp;
using EU.Europa.EC.Markt.Dss.Validation.Report;
using EU.Europa.EC.Markt.Dss.Validation.Tsp;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Utilities.IO;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Sample
{
    class Program
    {
        static void Main(string[] args)
        {
            string pathParaFirmar = @"D:\Desktop\test.pdf";
            string pathParaFirmado = @"D:\Desktop\out.p7m";
            string pathCertificadoFirma = @"D:\Desktop\test.p12";

            Document toBeSigned = new FileDocument(pathParaFirmar);
            AsyncSignatureTokenConnection token = new Pkcs12SignatureToken("test", pathCertificadoFirma);
            IDssPrivateKeyEntry privateKey = token.GetKeys()[0];

            SignatureParameters parameters = new SignatureParameters();
            parameters.SignaturePackaging = SignaturePackaging.ENVELOPING;
            parameters.SigningCertificate = privateKey.GetCertificate();
            parameters.CertificateChain = privateKey.GetCertificateChain();
            parameters.SigningDate = DateTime.Now;
            parameters.DigestAlgorithm = DigestAlgorithm.SHA256;

            CAdESService service = new CAdESService();

            parameters.SignatureFormat = EU.Europa.EC.Markt.Dss.Signature.SignatureFormat.CAdES_BES;

            /*
            var ocspSource1 = new OnlineOcspSource();
            var crlSource1 = new FileCacheCrlSource();
            var crlOnline1 = new OnlineCrlSource();
            crlOnline1.IntermediateAcUrl = @"http://www.eci.bce.ec/CRL/cacrl.crl";
            crlSource1.CachedSource = crlOnline1;
            var verifier1 = new OCSPAndCRLCertificateVerifier(crlSource1, ocspSource1);
            var estado = verifier1.Check(privateKey.GetCertificate(), privateKey.GetCertificateChain()[1], DateTime.Now);
            */

            /*
            //parameters.SignatureFormat = SignatureFormat.CAdES_T; //Se añade TSA.
            parameters.SignatureFormat = EU.Europa.EC.Markt.Dss.Signature.SignatureFormat.CAdES_C; //Se añade CRL y OCSP.
            //parameters.SignatureFormat = SignatureFormat.CAdES_X; //No se añade nada más al código.
            //parameters.SignatureFormat = EU.Europa.EC.Markt.Dss.Signature.SignatureFormat.CAdES_XL; //No se añade nada más al código.

            string urlTss = @"http://tsp.iaik.tugraz.at/tsp/TspRequest";
            string username = "";
            string password = "";


            OnlineTspSource tspSource = new OnlineTspSource(urlTss, username, password);
            service.TspSource = tspSource;

            OnlineOcspSource ocspSource = new OnlineOcspSource();
            TrustedListCertificateVerifier verifier = new TrustedListCertificateVerifier();
            FileCacheCrlSource crlSource = new FileCacheCrlSource();
            OnlineCrlSource crlOnline = new OnlineCrlSource();
            crlOnline.IntermediateAcUrl = @"http://www.eci.bce.ec/CRL/cacrl.crl";
            //@"http://www.eci.bce.ec/CRL/pruebas/cacrl.crl"

            crlSource.CachedSource = crlOnline;
            verifier.CrlSource = crlSource;
            verifier.OcspSource = ocspSource;

            ValidationContext validationContext = verifier.ValidateCertificate(parameters.SigningCertificate, DateTime.Now,
                new EU.Europa.EC.Markt.Dss.Validation.Certificate.CompositeCertificateSource(
                    new EU.Europa.EC.Markt.Dss.Validation.Certificate.ListCertificateSource(parameters.CertificateChain)), null, null);

            service.Verifier = verifier;
            */

            Document contentInCMS = null;

            try
            {
                CmsSignedData cmsData = new CmsSignedData(toBeSigned.OpenStream());
                if (cmsData != null && cmsData.SignedContent != null
                    && cmsData.SignedContent.GetContent() != null)
                {
                    Stream buf = new MemoryStream();
                    cmsData.SignedContent.Write(buf);
                    buf.Seek(0, SeekOrigin.Begin);
                    contentInCMS = new InMemoryDocument(Streams.ReadAll(buf));
                }
            }
            catch (CmsException)
            {
            }

            Stream iStream = service.ToBeSigned(contentInCMS ?? toBeSigned, parameters);

            byte[] signatureValue = token.Sign(iStream, parameters.DigestAlgorithm, privateKey);

            // We invoke the service to sign the document with the signature value obtained in the previous step.
            Document signedDocument = contentInCMS != null
                ? service.AddASignatureToDocument(toBeSigned, parameters, signatureValue)
                : service.SignDocument(toBeSigned, parameters, signatureValue);

            FileStream fs = new FileStream(pathParaFirmado, FileMode.OpenOrCreate);
            Streams.PipeAll(signedDocument.OpenStream(), fs);
            fs.Close();

            return;

            // Already signed document
            Document document = new FileDocument(pathParaFirmado);

            SignedDocumentValidator validator;
            validator = SignedDocumentValidator.FromDocument(document);
            //validator.CertificateVerifier = verifier;
            validator.ExternalContent = document;

            ValidationReport report = validator.ValidateDocument();
            SignatureInformation info = report.SignatureInformationList[0];
            Console.WriteLine("--> Final_Conclusion: ");
            Console.WriteLine(info.FinalConclusion); // --> AdES            
            Console.ReadKey();
        }
    }
}
