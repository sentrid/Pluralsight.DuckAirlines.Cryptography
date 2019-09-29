using System.IO;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.X509;

namespace Pluralsight.DuckAirlines.Cryptography
{
    public class CryptographyOperations
    {
        private const string RootDirectory = @"C:\Pluralsight\Keys\DuckAir";

        public static byte[] Encrypt(string plainTextData, string certificateFileName)
        {
            var bytesToEncrypt = Encoding.UTF8.GetBytes(plainTextData);
            var encryptionEngine = new Pkcs1Encoding(new RsaEngine());

            var parser = new X509CertificateParser();
            var certificate = parser.ReadCertificate(new FileStream(certificateFileName, FileMode.Open));
            encryptionEngine.Init(true, certificate.GetPublicKey());
            var processBlock = encryptionEngine.ProcessBlock(bytesToEncrypt, 0, bytesToEncrypt.Length);
            return processBlock;
        }

        public static string Decrypt(byte[] encryptedData, string privateKeyFileName)
        {
            var decryptionEngine = new Pkcs1Encoding(new RsaEngine());
            var rawKeyFromFile = File.ReadAllText(privateKeyFileName);
            var pemObject = (AsymmetricCipherKeyPair) new PemReader(new StringReader(rawKeyFromFile)).ReadObject();
            decryptionEngine.Init(false, pemObject.Private);
            var decryptedByteData = decryptionEngine.ProcessBlock(encryptedData, 0, encryptedData.Length);
            var plainTextData = Encoding.UTF8.GetString(decryptedByteData);
            return plainTextData;
        }
    }
}