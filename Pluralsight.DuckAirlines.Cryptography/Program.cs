using System;
using System.IO;

namespace Pluralsight.DuckAirlines.Cryptography
{
    /// <summary>
    /// Class Program.
    /// </summary>
    /// TODO Edit XML Comment Template for Program
    internal class Program
    {
        /// <summary>
        /// The key directory
        /// </summary>
        /// TODO Edit XML Comment Template for KeyDirectory
        private const string KeyDirectory = @"C:\Pluralsight\Keys\DuckAir";

        /// <summary>
        /// Defines the entry point of the application.
        /// </summary>
        /// <param name="args">The arguments.</param>
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
                    if (!Directory.Exists(KeyDirectory))
                    {
                        Directory.CreateDirectory(KeyDirectory);
                    }
                    var keyConfiguration = Key.ConfigureKeyPair();
                    Key.GenerateKeyPair(keyConfiguration);
                    break;

                case "encrypt":
                    // args[1] = certificate file name
                    // args[2] = plain text file name
                    // args[3] = encrypted data file name
                    var encrypt = Cryptography.Encrypt(
                        args[2],
                        args[1]);
                    File.WriteAllBytes(args[3], encrypt);
                    break;

                case "decrypt":
                    // args[1] = private key file name
                    // args[2] = encrypted data file name
                    // args[3] = plain text file name
                    var encrypted = File.ReadAllBytes(args[2]);
                    var plainText = Cryptography.Decrypt(encrypted, args[1]);
                    File.WriteAllText(args[3], plainText);
                    break;

                case "sign":
                    // args[1] = private key file name
                    // args[2] = data file name
                    // args[3] = signature file name
                    var dataToBeSigned = File.ReadAllText(args[2]);
                    var generatedSignature = Cryptography.Sign(dataToBeSigned,
                        args[1]);
                    File.WriteAllText(args[3], generatedSignature);
                    break;

                case "verify":
                    // args[1] = certificate file name
                    // args[2] = data file name
                    // args[3] = signature file name
                    var dataToBeVerified = File.ReadAllText(args[2]);
                    var existingSignature = File.ReadAllText(args[3]);
                    var isValid = Cryptography.ValidateSignature(
                        dataToBeVerified, existingSignature,args[1]);
                    if (isValid)
                    {
                        Console.Write("The signature for the data provided is valid");
                    }
                    else
                    {
                        Console.WriteLine("There is a signature and data mismatch.");
                    }
                    break;

                default:
                    ShowHelp();
                    return;
            }
        }

        /// <summary>
        /// Shows the help.
        /// </summary>
        /// TODO Edit XML Comment Template for ShowHelp
        private static void ShowHelp()
        {
            Console.WriteLine("HELP!!");
        }
    }
}