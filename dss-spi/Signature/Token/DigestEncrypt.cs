using EU.Europa.EC.Markt.Dss;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Text;

namespace EU.Europa.EC.Markt.Dss.Signature.Token
{
    /// <summary>
    /// This class encrypt a digest in RFC3770 compliant mode
    /// </summary>
    public static class DigestEncrypt
    {
        public static byte[] Encrypt(byte[] digestValue, DigestAlgorithm digestAlgo,
            IDssPrivateKeyEntry keyEntry)
        {
            DigestInfo digestInfo = new DigestInfo(digestAlgo.GetAlgorithmIdentifier(), digestValue);
            IBufferedCipher cipher = CipherUtilities.GetCipher(
                keyEntry.GetSignatureAlgorithm().GetPadding());
            cipher.Init(true, ((KSPrivateKeyEntry)keyEntry).PrivateKey);
            return cipher.DoFinal(digestInfo.GetDerEncoded());
        }
    }
}
