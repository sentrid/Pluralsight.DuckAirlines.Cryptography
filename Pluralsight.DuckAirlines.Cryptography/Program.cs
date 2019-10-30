using System;
using System.IO;

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
                    if (!Directory.Exists(@"C:\Pluralsight\Keys\DuckAir"))
                        Directory.CreateDirectory(@"C:\Pluralsight\Keys\DuckAir");
                    var keyConfiguration = Key.ConfigureKeyPair();
                    Key.GenerateKeyPair(keyConfiguration);
                    break;
                case "encrypt":
                    var encrypt = CryptographyOperations.Encrypt("I am the very model of a modern major general.",
                        @"C:\Pluralsight\Keys\DuckAir\FlightOps.cer");
                    CryptographyOperations.Decrypt(encrypt, @"C:\Pluralsight\Keys\DuckAir\FlightOperations.key");
                    break;
                case "sign":
                    var signature = CryptographyOperations.Sign("I am the very model of a modern major general.",
                        @"C:\Pluralsight\Keys\DuckAIr\DonaldMallard.key");
                    var isValid = CryptographyOperations.ValidateSignature(
                        "I am the very model of a modern major general.", signature,
                        @"C:\Pluralsight\Keys\DuckAir\DonaldMallard.cer");
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