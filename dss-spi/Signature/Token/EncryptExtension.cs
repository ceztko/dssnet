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
    /// Utils class for encryption
    /// </summary>
    public static class EncryptExtension
    {
        public static byte[] Encrypt(this IDssPrivateKeyEntry keyEntry, byte[] digestValue)
        {
            IBufferedCipher cipher = CipherUtilities.GetCipher(
                keyEntry.GetSignatureAlgorithm().GetPadding());
            cipher.Init(true, ((KSPrivateKeyEntry)keyEntry).PrivateKey);
            return cipher.DoFinal(digestValue);
        }
    }
}
