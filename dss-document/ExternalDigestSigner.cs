using EU.Europa.EC.Markt.Dss.Signature;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using System;
using System.IO;

namespace EU.Europa.EC.Markt.Dss
{
    /// <summary>
    /// The class can be used to create a custom signer
    /// </summary>
    public class ExternalDigestSigner : ISignatureFactory, IStreamCalculator, IBlockResult
    {
        DigestSigner signer;
        DigestAlgorithm m_digestAlgorithm;
        MemoryStream m_stream;

        public ExternalDigestSigner(DigestSigner signer, SignatureParameters parameters)
		{
            m_stream = new MemoryStream();
            this.signer = signer;
            m_digestAlgorithm = parameters.DigestAlgorithm;
        }

        /// <summary>
        /// Bouncy castle wants to know the algorithm details (digest and encryption)
        /// to construct the CMS
        /// </summary>
        object ISignatureFactory.AlgorithmDetails
        {
            get
            {
                switch (m_digestAlgorithm.GetName())
                {
                    case "SHA-1":
                        return new AlgorithmIdentifier(PkcsObjectIdentifiers.Sha1WithRsaEncryption);
                    case "SHA-256":
                        return new AlgorithmIdentifier(PkcsObjectIdentifiers.Sha256WithRsaEncryption);
                    case "SHA-512":
                        return new AlgorithmIdentifier(PkcsObjectIdentifiers.Sha512WithRsaEncryption);
                    default:
                        throw new NotSupportedException();
                }
            }
        }

        IStreamCalculator ISignatureFactory.CreateCalculator()
        {
            return this;
        }

        Stream IStreamCalculator.Stream => m_stream;

        // The result must be an IBlockResult
        object IStreamCalculator.GetResult()
        {
            return this;
        }

        // Returns the signed digest
        byte[] IBlockResult.Collect()
        {
            return signer(m_stream.ToArray());
        }

        // Not needed
        int IBlockResult.Collect(byte[] destination, int offset)
        {
            throw new NotImplementedException();
        }
    }

    public delegate byte[] DigestSigner(byte[] bytes);
}
