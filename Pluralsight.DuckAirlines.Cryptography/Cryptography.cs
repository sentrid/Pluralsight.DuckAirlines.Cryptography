using System;
using System.IO;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Pluralsight.DuckAirlines.Cryptography
{
    public static class Cryptography
    {
        public static byte[] Encrypt(string plainTextDataFileName, string certificateFileName)
        {
            
        }

        public static string Decrypt(string encryptedDataFileName, string privateKeyFileName)
        {
            
        }

        public static string Sign(string data, string privateKeyFileName)
        {
            
        }

        public static bool ValidateSignature(string data, string encodedSignature, string certificateFileName)
        {
            
        }
    }
}