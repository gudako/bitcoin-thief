using System;
using System.Linq;
using System.Security.Cryptography;
using BitcoinThief.Keccak256;
using Secp256k1Net;

namespace BitcoinThief.CoinPhasing.Traits
{
    public static class Ether
    {
        public static Func<CoinKeyPair> UcAddressGenerator = () => _AddressGenerator(Generic.HexCase.Uppercase);

        public static Func<CoinKeyPair> LcAddressGenerator = () => _AddressGenerator(Generic.HexCase.Lowercase);

        public static Func<CoinKeyPair> CcAddressGenerator = () => _AddressGenerator(Generic.HexCase.Checksummed);

        public static Func<string, bool> AddressValidator = _AddressValidator;

        private static (byte[], string) _NewPrivKey()
        {
            var raw = new byte[32];
            var rand = new RNGCryptoServiceProvider();
            rand.GetBytes(raw, 0, 32);

            return (raw, "0x" + raw.ToHex());
        }

        private static byte[] _PrivToPubKey(byte[] privKey)
        {
            using (var secp256K1 = new Secp256k1())
            {
                var pubKey = new byte[64];
                secp256K1.PublicKeyCreate(pubKey, privKey);
                return pubKey;
            }
        }

        private static CoinKeyPair _AddressGenerator(Generic.HexCase hCase)
        {
            var priv = _NewPrivKey();
            var privKey = priv.Item1;
            var wif = priv.Item2;
            var pub = _PrivToPubKey(privKey);

            var address = "0x" + new Keccak256Managed().ComputeHash(pub).SubArray(16, 20).ToHex(hCase);
            return new CoinKeyPair(wif, address);
        }

        private static bool _AddressValidator(string data)
        {
            if (!data.StartsWith("0x")) return false;
            if (data.Length != 42) return false;

            var data1 = data.Remove(0, 2);
            if (!data1.All(c => c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z')) return false;
            if (data1 == data.ToUpper()) return true;
            if (data1 == data.ToLower()) return true;

            return data1 == data1.HexToByteArray().ToHex(Generic.HexCase.Checksummed);
        }
    }
}