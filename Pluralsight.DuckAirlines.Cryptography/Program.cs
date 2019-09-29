using System;
using System.IO;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Pluralsight.TrustUs.DataStructures;

namespace Pluralsight.DuckAirlines.Cryptography
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                ShowHelp();
                return;
            }

            switch (args[0])
            {
                case "create":
                    var keyConfiguration = Key.ConfigureKeyPair();
                    Key.GenerateKeyPair(keyConfiguration);
                    break;
                case "encrypt":
                    var encrypt = CryptographyOperations.Encrypt("I am the very model of a modern major general.", @"C:\Pluralsight\Keys\DuckAir\FlightOps.cer");
                    CryptographyOperations.Decrypt(encrypt, @"C:\Pluralsight\Keys\DuckAir\FlightOperations.key");
                    break;
                default:
                    ShowHelp();
                    return;
            }
        }

        private static void ShowHelp()
        {
            Console.WriteLine("HELP!!");
        }
    }
}