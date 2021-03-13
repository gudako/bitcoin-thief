using System;
using System.Linq;
using System.Security.Cryptography;
using BitcoinThief.Encoding;
using BitcoinThief.Ripemd160;
using Secp256k1Net;

namespace BitcoinThief.CoinPhasing.Traits
{
    public static class Bitcoin
    {
        public static Func<CoinKeyPair> P2PkhGenerator => _P2PkhGenerator;

        public static Func<CoinKeyPair> P2ShGenerator => _P2ShGenerator;

        public static Func<CoinKeyPair> P2WpkhGenerator => _P2WpkhGenerator;

        public static Func<CoinKeyPair> P2WshGenerator => _P2WshGenerator;

        public static Func<string, bool> P2PkhValidator => _P2PkhValidator;

        public static Func<string, bool> P2ShValidator => _P2ShValidator;

        public static Func<string, bool> P2WpkhValidator => _P2WpkhValidator;

        public static Func<string, bool> P2WshValidator => _P2WshValidator;

        private static (byte[], string) _NewPrivKey()
        {
            var raw = new byte[32];
            var rand = new RNGCryptoServiceProvider();
            rand.GetBytes(raw, 0, 32);

            var wif = new byte[32 + 1];
            wif[0] = 0x80;
            Array.Copy(raw, 0, wif, 1, 32);

            return (raw, new Base58CheckEncoder().Encode(wif));
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

        private static CoinKeyPair _P2PkhGenerator()
        {
            regenerate:
            var priv = _NewPrivKey();
            var privKey = priv.Item1;
            var wif = priv.Item2;
            var pub = _PrivToPubKey(privKey);

            var pkHash = new Ripemd160Managed().ComputeHash(new SHA256Managed().ComputeHash(pub));
            var pkHashVersioned = new byte[20 + 1];
            pkHashVersioned[0] = 0x00;
            Array.Copy(pkHash, 0, pkHashVersioned, 1, 20);
            var addr = new Base58CheckEncoder().Encode(pkHashVersioned);

            // Some addresses ends up to be 26 chars while most are 27 chars long.
            // For stability reason, 26 chars long addresses are filtered out and the program would redo the generation.
            if (addr.Length != 27) goto regenerate;
            return new CoinKeyPair(wif, addr);
        }

        private static CoinKeyPair _P2ShGenerator()
        {
            var priv = _NewPrivKey();
            var privKey = priv.Item1;
            var wif = priv.Item2;
            var pub = _PrivToPubKey(privKey);

            var redeemScript = new byte[35];
            redeemScript[0] = 0x21;
            redeemScript[34] = 0xac;
            Array.Copy(pub, 0, redeemScript, 1, 33);

            var psVersioned = new byte[20 + 1];
            psVersioned[0] = 0x05;

            var sHash = new Ripemd160Managed().ComputeHash(new SHA256Managed().ComputeHash(redeemScript));
            Array.Copy(sHash, 0, psVersioned, 1, 20);
            return new CoinKeyPair(wif, new Base58CheckEncoder().Encode(psVersioned));
        }

        private static CoinKeyPair _P2WpkhGenerator()
        {
            var priv = _NewPrivKey();
            var privKey = priv.Item1;
            var wif = priv.Item2;
            var pub = _PrivToPubKey(privKey);

            var pkHash = new Ripemd160Managed().ComputeHash(new SHA256Managed().ComputeHash(pub));
            return new CoinKeyPair(wif, new Bech32Encoder().Encode("bc", pkHash));
        }

        private static CoinKeyPair _P2WshGenerator()
        {
            var priv = _NewPrivKey();
            var privKey = priv.Item1;
            var wif = priv.Item2;
            var pub = _PrivToPubKey(privKey);

            var redeemScript = new byte[35];
            redeemScript[0] = 0x21;
            redeemScript[34] = 0xac;
            Array.Copy(pub, 0, redeemScript, 1, 33);

            var sHash = new SHA256Managed().ComputeHash(redeemScript);
            return new CoinKeyPair(wif, new Bech32Encoder().Encode("bc", sHash));
        }

        private static bool _P2PkhValidator(string data)
        {
            if (data.Length != 27) return false;
            if (!data.All(c => c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z')) return false;
            return new Base58CheckEncoder().TryDecode(data, out _);
        }

        private static bool _P2ShValidator(string data)
        {
            if (data.Length != 34) return false;
            if (!data.All(c => c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z')) return false;
            return new Base58CheckEncoder().TryDecode(data, out _);
        }

        private static bool _P2WpkhValidator(string data)
        {
            if (data.Length != 42) return false;
            if (!data.All(c => c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z')) return false;
            return new Base58CheckEncoder().TryDecode(data, out _);
        }

        private static bool _P2WshValidator(string data)
        {
            if (data.Length != 34) return false;
            if (!data.All(c => c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z')) return false;
            return new Base58CheckEncoder().TryDecode(data, out _);
        }
    }
}