using System;
using System.IO;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Pluralsight.DuckAirlines.Cryptography.DataStructures;

namespace Pluralsight.DuckAirlines.Cryptography
{
    public static class Key
    {
        private const string RootDirectory = @"C:\Pluralsight\Keys\DuckAir";

        public static void GenerateKeyPair(KeyConfiguration keyConfiguration)
        {
            
        }

        public static KeyConfiguration ConfigureKeyPair()
        {
            
        }
    }
}