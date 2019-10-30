using System;
using System.IO;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Pluralsight.DuckAirlines.Cryptography
{
    public class CryptographyOperations
    {
        public static string RootDirectory { get; } = @"C:\Pluralsight\Keys\DuckAir";

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

        public static string Sign(string data, string privateKeyFileName)
        {
            var rawKeyFromFile = File.ReadAllText(privateKeyFileName);
            var pemObject = (AsymmetricCipherKeyPair)new PemReader(new StringReader(rawKeyFromFile)).ReadObject();
            var signer = SignerUtilities.InitSigner("SHA1withRSA", true, pemObject.Private, new SecureRandom());

            var dataAsBytes = Encoding.UTF8.GetBytes(data);
            signer.BlockUpdate(dataAsBytes, 0, dataAsBytes.Length);
            var signature = signer.GenerateSignature();
            
            var encodedSignature = Convert.ToBase64String(signature);

            return encodedSignature;
        }

        public static bool ValidateSignature(string data, string encodedSignature, string certificateFileName)
        {
            var parser = new X509CertificateParser();
            var certificate = parser.ReadCertificate(new FileStream(certificateFileName, FileMode.Open));
            var validator = SignerUtilities.GetSigner("SHA1withRSA");
            validator.Init(false, certificate.GetPublicKey());
            var signature = Convert.FromBase64String(encodedSignature);
            var dataAsBytes = Encoding.UTF8.GetBytes(data);
            validator.BlockUpdate(dataAsBytes,0,dataAsBytes.Length);
            return validator.VerifySignature(signature);
        }
    }
}