using System;
using System.Globalization;
using System.Text;
using BitcoinThief.Keccak256;

namespace BitcoinThief
{
    /// <summary>
    ///     Gives generic static functions.
    /// </summary>
    public static class Generic
    {
        public enum HexCase
        {
            Uppercase,
            Lowercase,
            Checksummed
        }

        /// <summary>
        ///     Concatenate two arrays and the result into a new array.
        /// </summary>
        /// <typeparam name="T">The type of the items in the array.</typeparam>
        /// <param name="x">The first array to concatenate.</param>
        /// <param name="y">The second array to concatenate.</param>
        /// <returns>The concatenated new array.</returns>
        public static T[] ConcatArrays<T>(this T[] x, T[] y)
        {
            var z = new T[x.Length + y.Length];
            x.CopyTo(z, 0);
            y.CopyTo(z, x.Length);
            return z;
        }

        /// <summary>
        ///     Returns a sub-array of an array.
        /// </summary>
        /// <typeparam name="T">The type of the items in the array.</typeparam>
        /// <param name="src">The source array.</param>
        /// <param name="start">The index to start from.</param>
        /// <param name="length">The length to chop.</param>
        /// <returns>The chopped new array.</returns>
        public static T[] SubArray<T>(this T[] src, int start, int length)
        {
            var result = new T[length];
            Buffer.BlockCopy(src, start, result, 0, length);
            return result;
        }

        /// <summary>
        ///     Returns a sub-array of an array from the specified start index to the end of the array.
        /// </summary>
        /// <typeparam name="T">The type of the items in the array.</typeparam>
        /// <param name="src">The source array.</param>
        /// <param name="start">The index to start from.</param>
        /// <returns>The chopped new array.</returns>
        public static T[] SubArray<T>(this T[] src, int start)
        {
            return SubArray(src, start, src.Length - start);
        }

        /// <summary>
        ///     Convert a hex string to a byte array.
        /// </summary>
        /// <param name="hex">
        ///     The hex string to be converted.
        ///     Accepted no matter it is uppercase, lowercase or mixed.
        /// </param>
        /// <returns>The result byte array.</returns>
        public static byte[] HexToByteArray(this string hex)
        {
            if (hex.Length % 2 != 0)
                throw new ArgumentException("The binary key cannot have an odd number of digits.");

            var data = new byte[hex.Length / 2];
            for (var index = 0; index < data.Length; index++)
            {
                var byteValue = hex.Substring(index * 2, 2);
                data[index] = byte.Parse(byteValue, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            }

            return data;
        }

        /// <summary>
        ///     Convert a byte array to a hex string.
        /// </summary>
        /// <param name="data">The byte array to be converted.</param>
        /// <param name="hCase">The case of the result hex string.</param>
        /// <returns>The result hex string.</returns>
        /// <remarks>Encoding to checksummed hex only supports 20 bytes long <paramref name="data" />.</remarks>
        public static string ToHex(this byte[] data, HexCase hCase = HexCase.Lowercase)
        {
            var result = new StringBuilder(data.Length * 2);
            var hexAlphabet = hCase == HexCase.Lowercase ? "0123456789abcdef" : "0123456789ABCDEF";

            foreach (var b in data)
            {
                result.Append(hexAlphabet[b >> 4]);
                result.Append(hexAlphabet[b & 0xF]);
            }

            if (hCase != HexCase.Checksummed) return result.ToString();

            if (data.Length != 20)
                throw new FormatException("Encoding to checksummed hex only supports 20 bytes long data.");

            var checksum = new Keccak256Managed().ComputeHash(data).ToHex();
            for (var x = 0; x <= 39; x++)
            {
                if (result[x] >= '0' && result[x] <= '9') continue;
                var lower = checksum[x] <= '7';
                if (lower) result[x] += (char) ('a' - 'A');
            }

            return result.ToString();
        }
    }
}