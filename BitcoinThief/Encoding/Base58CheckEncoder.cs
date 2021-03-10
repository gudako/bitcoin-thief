using System;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;

namespace BitcoinThief.Encoding
{
    /// <summary>
    ///     Indicates a base58 encoder.
    /// </summary>
    public class Base58CheckEncoder
    {
        private readonly string _alphabet;

        /// <summary>
        ///     Create a new base58check encoder with the specified alphabet.
        /// </summary>
        /// <param name="alphabet">The baase58check alphabet. Default to Bitcoin alphabet.</param>
        public Base58CheckEncoder(string alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
        {
            _alphabet = alphabet;
        }

        // //// //////// GENERIC PRIVATE METHOD //////// //// //

        private static byte[] _GetChecksum(byte[] data)
        {
            SHA256 sha256 = new SHA256Managed();
            var hash1 = sha256.ComputeHash(data);
            var hash2 = sha256.ComputeHash(hash1);

            var result = new byte[4];
            Buffer.BlockCopy(hash2, 0, result, 0, result.Length);

            return result;
        }

        // //// //////// GENERIC PUBLIC METHOD //////// //// //

        /// <summary>
        ///     Try decode a base58check string into bytes. The function checks whether the input string is valid.
        /// </summary>
        /// <param name="data">The base58check string data to be decoded.</param>
        /// <param name="result">The decoded bytes. Yields <c>null</c> if <paramref name="data" /> is invalid.</param>
        /// <returns>A <see cref="bool" /> value indicating whether the input <paramref name="data" /> is valid.</returns>
        public bool TryDecode(string data, out byte[] result)
        {
            result = null;

            BigInteger intData = 0;
            foreach (var digit in data.Select(t => _alphabet.IndexOf(t)))
            {
                if (digit < 0) return false;
                intData = intData * 58 + digit;
            }

            var leadingZeroCount = data.TakeWhile(c => c == '1').Count();
            var leadingZeros = Enumerable.Repeat((byte) 0, leadingZeroCount);
            var bytesWithoutLeadingZeros = intData.ToByteArray().Reverse().SkipWhile(b => b == 0);

            var res = leadingZeros.Concat(bytesWithoutLeadingZeros).ToArray();

            if (!_GetChecksum(res.SubArray(0, res.Length - 4))
                .SequenceEqual(res.SubArray(res.Length - 4)))
                return false;

            result = res;
            return true;
        }

        /// <summary>
        ///     Encodes a binary data into base58check string.
        /// </summary>
        /// <remarks>
        ///     Make sure you append the version byte before passing the <paramref name="data" /> argument.
        /// </remarks>
        /// <param name="data">The data to be encoded.</param>
        /// <returns>The encoded base58check string.</returns>
        public string Encode(byte[] data)
        {
            var checksum = _GetChecksum(data);
            var data1 = data.ConcatArrays(checksum);
            var intData = data1.Aggregate<byte, BigInteger>(0, (current, t) => current * 256 + t);

            var result = string.Empty;
            while (intData > 0)
            {
                var remainder = (int) (intData % 58);
                intData /= 58;
                result = _alphabet[remainder] + result;
            }

            for (var i = 0; i < data1.Length && data1[i] == 0; i++) result = '1' + result;
            return result;
        }
    }
}
