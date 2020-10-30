using EU.Europa.EC.Markt.Dss.Signature;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
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
        /// <remarks>Result must be of type AlgorithmIdentifier</remarks>
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

        /// <remarks>The result must be an IBlockResult</remarks>
        object IStreamCalculator.GetResult()
        {
            // Result must be of type IBlockResult, su just return this
            return this;
        }

        // Returns the signed digest
        byte[] IBlockResult.Collect()
        {
            // The collected array contains the document digest and parameters
            // to be signed but it needs to be further digested by the indended
            // hashing algorithm
            byte[] toDigest = m_stream.ToArray();
            IDigest digester = DigestUtilities.GetDigest(m_digestAlgorithm.GetName());
            digester.BlockUpdate(toDigest, 0, toDigest.Length);
            byte[] digestValue = DigestUtilities.DoFinal(digester);
            // Wrap digest value in DER encoding (should be RFC3770 compliant)
            DigestInfo digestInfo = new DigestInfo(m_digestAlgorithm.GetAlgorithmIdentifier(), digestValue);
            byte[] wrapped = digestInfo.GetDerEncoded();
            return signer(wrapped);
        }

        // Not needed
        int IBlockResult.Collect(byte[] destination, int offset)
        {
            throw new NotImplementedException();
        }
    }

    public delegate byte[] DigestSigner(byte[] bytes);
}
