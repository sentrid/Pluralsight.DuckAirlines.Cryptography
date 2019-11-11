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
    /// <summary>
    /// Class Cryptography.
    /// </summary>
    /// TODO Edit XML Comment Template for Cryptography
    public static class Cryptography
    {
        /// <summary>
        /// Encrypts the specified plain text data.
        /// </summary>
        /// <param name="plainTextDataFileName">The plain text data.</param>
        /// <param name="certificateFileName">Name of the certificate file.</param>
        /// <returns>System.Byte[].</returns>
        /// TODO Edit XML Comment Template for Encrypt
        public static byte[] Encrypt(string plainTextDataFileName, string certificateFileName)
        {
            var plainTextData = File.ReadAllText(plainTextDataFileName);
            var bytesToEncrypt = Encoding.UTF8.GetBytes(plainTextData);
            var encryptionEngine = new Pkcs1Encoding(new RsaEngine());

            var parser = new X509CertificateParser();
            var certificateFileStream = new FileStream(certificateFileName, FileMode.Open);
            var certificate = parser.ReadCertificate(certificateFileStream);
            encryptionEngine.Init(true, certificate.GetPublicKey());
            var processBlock = encryptionEngine.ProcessBlock(bytesToEncrypt, 0, bytesToEncrypt.Length);
            return processBlock;
        }

        /// <summary>
        /// Decrypts the specified encrypted data.
        /// </summary>
        /// <param name="encryptedDataFileName"></param>
        /// <param name="privateKeyFileName">Name of the private key file.</param>
        /// <returns>System.String.</returns>
        /// TODO Edit XML Comment Template for Decrypt
        public static string Decrypt(string encryptedDataFileName, string privateKeyFileName)
        {
            byte[] encryptedData = File.ReadAllBytes(encryptedDataFileName);
            var decryptionEngine = new Pkcs1Encoding(new RsaEngine());

            var rawKeyFromFile = File.ReadAllText(privateKeyFileName);
            var rawKey = new StringReader(rawKeyFromFile);
            var pemReader = new PemReader(rawKey);
            var pemObject = (AsymmetricCipherKeyPair)pemReader.ReadObject();

            decryptionEngine.Init(false, pemObject.Private);
            var decryptedByteData = decryptionEngine.ProcessBlock(encryptedData, 0, encryptedData.Length);
            var plainTextData = Encoding.UTF8.GetString(decryptedByteData);
            return plainTextData;
        }

        /// <summary>
        /// Signs the specified data.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <param name="privateKeyFileName">Name of the private key file.</param>
        /// <returns>System.String.</returns>
        /// TODO Edit XML Comment Template for Sign
        public static string Sign(string data, string privateKeyFileName)
        {
            var dataAsBytes = Encoding.UTF8.GetBytes(data);

            var rawKeyFromFile = File.ReadAllText(privateKeyFileName);
            var rawKey = new StringReader(rawKeyFromFile);
            var pemReader = new PemReader(rawKey);
            var pemObject = (AsymmetricCipherKeyPair)pemReader.ReadObject();
            var signer = SignerUtilities.InitSigner("SHA1withRSA", true, pemObject.Private, new SecureRandom());
            signer.BlockUpdate(dataAsBytes, 0, dataAsBytes.Length);
            var signature = signer.GenerateSignature();

            var encodedSignature = Convert.ToBase64String(signature);

            return encodedSignature;
        }

        /// <summary>
        /// Validates the signature.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <param name="encodedSignature">The encoded signature.</param>
        /// <param name="certificateFileName">Name of the certificate file.</param>
        /// <returns><c>true</c> if XXXX, <c>false</c> otherwise.</returns>
        /// TODO Edit XML Comment Template for ValidateSignature
        public static bool ValidateSignature(string data, string encodedSignature, string certificateFileName)
        {
            var parser = new X509CertificateParser();
            var certificate = parser.ReadCertificate(new FileStream(certificateFileName, FileMode.Open));
            var validator = SignerUtilities.InitSigner("SHA1withRSA", false, certificate.GetPublicKey(), new SecureRandom());
            //var validator = SignerUtilities.GetSigner("SHA1withRSA");
            //validator.Init(false, certificate.GetPublicKey());
            var signature = Convert.FromBase64String(encodedSignature);
            var dataAsBytes = Encoding.UTF8.GetBytes(data);
            validator.BlockUpdate(dataAsBytes,0,dataAsBytes.Length);
            return validator.VerifySignature(signature);
        }
    }
}