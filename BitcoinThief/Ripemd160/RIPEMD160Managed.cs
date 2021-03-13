// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

// Contributed to .NET Foundation by Darren R. Starr - Conscia Norway AS
//
// Awaiting permission from Antoon Bosselaers - Katholieke Universiteit Leuven 
//   for permission/clarification regarding the use the original code from which
//   this C# port is created.
//  Until he clarifies the license status of his code (referenced at
//   https://homes.esat.kuleuven.be/~bosselae/ripemd160.html) the legal license
//   status of this code is not clear. 

using System;
using System.Linq;

namespace BitcoinThief.Ripemd160
{
    public class Ripemd160Managed : Ripemd160
    {
        private static readonly int RmDsize = 160;
        private readonly byte[] _unhashedBuffer = new byte[64];
        private long _hashedLength;
        private uint[] _mDbuf = new uint[RmDsize / 32];
        private int _unhashedBufferLength;
        private uint[] _x = new uint[16]; /* current 16-word chunk        */

        public Ripemd160Managed()
        {
            Initialize();
        }

        private static uint ReadUInt32(byte[] buffer, long offset)
        {
            return
                (Convert.ToUInt32(buffer[3 + offset]) << 24) |
                (Convert.ToUInt32(buffer[2 + offset]) << 16) |
                (Convert.ToUInt32(buffer[1 + offset]) << 8) |
                Convert.ToUInt32(buffer[0 + offset]);
        }

        private static uint RotateLeft(uint value, int bits)
        {
            return (value << bits) | (value >> (32 - bits));
        }

        /* the five basic functions F(), G() and H() */
        private static uint F(uint x, uint y, uint z)
        {
            return x ^ y ^ z;
        }

        private static uint G(uint x, uint y, uint z)
        {
            return (x & y) | (~x & z);
        }

        private static uint H(uint x, uint y, uint z)
        {
            return (x | ~y) ^ z;
        }

        private static uint I(uint x, uint y, uint z)
        {
            return (x & z) | (y & ~z);
        }

        private static uint J(uint x, uint y, uint z)
        {
            return x ^ (y | ~z);
        }

        /* the ten basic operations FF() through III() */

        private static void Ff(ref uint a, uint b, ref uint c, uint d, uint e, uint x, int s)
        {
            a += F(b, c, d) + x;
            a = RotateLeft(a, s) + e;
            c = RotateLeft(c, 10);
        }

        private static void Gg(ref uint a, uint b, ref uint c, uint d, uint e, uint x, int s)
        {
            a += G(b, c, d) + x + 0x5a827999;
            a = RotateLeft(a, s) + e;
            c = RotateLeft(c, 10);
        }

        private static void Hh(ref uint a, uint b, ref uint c, uint d, uint e, uint x, int s)
        {
            a += H(b, c, d) + x + 0x6ed9eba1;
            a = RotateLeft(a, s) + e;
            c = RotateLeft(c, 10);
        }

        private static void Ii(ref uint a, uint b, ref uint c, uint d, uint e, uint x, int s)
        {
            a += I(b, c, d) + x + 0x8f1bbcdc;
            a = RotateLeft(a, s) + e;
            c = RotateLeft(c, 10);
        }

        private static void Jj(ref uint a, uint b, ref uint c, uint d, uint e, uint x, int s)
        {
            a += J(b, c, d) + x + 0xa953fd4e;
            a = RotateLeft(a, s) + e;
            c = RotateLeft(c, 10);
        }

        private static void Fff(ref uint a, uint b, ref uint c, uint d, uint e, uint x, int s)
        {
            a += F(b, c, d) + x;
            a = RotateLeft(a, s) + e;
            c = RotateLeft(c, 10);
        }

        private static void Ggg(ref uint a, uint b, ref uint c, uint d, uint e, uint x, int s)
        {
            a += G(b, c, d) + x + 0x7a6d76e9;
            a = RotateLeft(a, s) + e;
            c = RotateLeft(c, 10);
        }

        private static void Hhh(ref uint a, uint b, ref uint c, uint d, uint e, uint x, int s)
        {
            a += H(b, c, d) + x + 0x6d703ef3;
            a = RotateLeft(a, s) + e;
            c = RotateLeft(c, 10);
        }

        private static void Iii(ref uint a, uint b, ref uint c, uint d, uint e, uint x, int s)
        {
            a += I(b, c, d) + x + 0x5c4dd124;
            a = RotateLeft(a, s) + e;
            c = RotateLeft(c, 10);
        }

        private static void Jjj(ref uint a, uint b, ref uint c, uint d, uint e, uint x, int s)
        {
            a += J(b, c, d) + x + 0x50a28be6;
            a = RotateLeft(a, s) + e;
            c = RotateLeft(c, 10);
        }

        /// initializes MDbuffer to "magic constants"
        private static void MDinit(ref uint[] mDbuf)
        {
            mDbuf[0] = 0x67452301;
            mDbuf[1] = 0xefcdab89;
            mDbuf[2] = 0x98badcfe;
            mDbuf[3] = 0x10325476;
            mDbuf[4] = 0xc3d2e1f0;
        }

        /// the compression function.
        /// transforms MDbuf using message bytes X[0] through X[15]
        private static void Compress(ref uint[] mDbuf, uint[] x)
        {
            var aa = mDbuf[0];
            var bb = mDbuf[1];
            var cc = mDbuf[2];
            var dd = mDbuf[3];
            var ee = mDbuf[4];
            var aaa = mDbuf[0];
            var bbb = mDbuf[1];
            var ccc = mDbuf[2];
            var ddd = mDbuf[3];
            var eee = mDbuf[4];

            /* round 1 */
            Ff(ref aa, bb, ref cc, dd, ee, x[0], 11);
            Ff(ref ee, aa, ref bb, cc, dd, x[1], 14);
            Ff(ref dd, ee, ref aa, bb, cc, x[2], 15);
            Ff(ref cc, dd, ref ee, aa, bb, x[3], 12);
            Ff(ref bb, cc, ref dd, ee, aa, x[4], 5);
            Ff(ref aa, bb, ref cc, dd, ee, x[5], 8);
            Ff(ref ee, aa, ref bb, cc, dd, x[6], 7);
            Ff(ref dd, ee, ref aa, bb, cc, x[7], 9);
            Ff(ref cc, dd, ref ee, aa, bb, x[8], 11);
            Ff(ref bb, cc, ref dd, ee, aa, x[9], 13);
            Ff(ref aa, bb, ref cc, dd, ee, x[10], 14);
            Ff(ref ee, aa, ref bb, cc, dd, x[11], 15);
            Ff(ref dd, ee, ref aa, bb, cc, x[12], 6);
            Ff(ref cc, dd, ref ee, aa, bb, x[13], 7);
            Ff(ref bb, cc, ref dd, ee, aa, x[14], 9);
            Ff(ref aa, bb, ref cc, dd, ee, x[15], 8);

            /* round 2 */
            Gg(ref ee, aa, ref bb, cc, dd, x[7], 7);
            Gg(ref dd, ee, ref aa, bb, cc, x[4], 6);
            Gg(ref cc, dd, ref ee, aa, bb, x[13], 8);
            Gg(ref bb, cc, ref dd, ee, aa, x[1], 13);
            Gg(ref aa, bb, ref cc, dd, ee, x[10], 11);
            Gg(ref ee, aa, ref bb, cc, dd, x[6], 9);
            Gg(ref dd, ee, ref aa, bb, cc, x[15], 7);
            Gg(ref cc, dd, ref ee, aa, bb, x[3], 15);
            Gg(ref bb, cc, ref dd, ee, aa, x[12], 7);
            Gg(ref aa, bb, ref cc, dd, ee, x[0], 12);
            Gg(ref ee, aa, ref bb, cc, dd, x[9], 15);
            Gg(ref dd, ee, ref aa, bb, cc, x[5], 9);
            Gg(ref cc, dd, ref ee, aa, bb, x[2], 11);
            Gg(ref bb, cc, ref dd, ee, aa, x[14], 7);
            Gg(ref aa, bb, ref cc, dd, ee, x[11], 13);
            Gg(ref ee, aa, ref bb, cc, dd, x[8], 12);

            /* round 3 */
            Hh(ref dd, ee, ref aa, bb, cc, x[3], 11);
            Hh(ref cc, dd, ref ee, aa, bb, x[10], 13);
            Hh(ref bb, cc, ref dd, ee, aa, x[14], 6);
            Hh(ref aa, bb, ref cc, dd, ee, x[4], 7);
            Hh(ref ee, aa, ref bb, cc, dd, x[9], 14);
            Hh(ref dd, ee, ref aa, bb, cc, x[15], 9);
            Hh(ref cc, dd, ref ee, aa, bb, x[8], 13);
            Hh(ref bb, cc, ref dd, ee, aa, x[1], 15);
            Hh(ref aa, bb, ref cc, dd, ee, x[2], 14);
            Hh(ref ee, aa, ref bb, cc, dd, x[7], 8);
            Hh(ref dd, ee, ref aa, bb, cc, x[0], 13);
            Hh(ref cc, dd, ref ee, aa, bb, x[6], 6);
            Hh(ref bb, cc, ref dd, ee, aa, x[13], 5);
            Hh(ref aa, bb, ref cc, dd, ee, x[11], 12);
            Hh(ref ee, aa, ref bb, cc, dd, x[5], 7);
            Hh(ref dd, ee, ref aa, bb, cc, x[12], 5);

            /* round 4 */
            Ii(ref cc, dd, ref ee, aa, bb, x[1], 11);
            Ii(ref bb, cc, ref dd, ee, aa, x[9], 12);
            Ii(ref aa, bb, ref cc, dd, ee, x[11], 14);
            Ii(ref ee, aa, ref bb, cc, dd, x[10], 15);
            Ii(ref dd, ee, ref aa, bb, cc, x[0], 14);
            Ii(ref cc, dd, ref ee, aa, bb, x[8], 15);
            Ii(ref bb, cc, ref dd, ee, aa, x[12], 9);
            Ii(ref aa, bb, ref cc, dd, ee, x[4], 8);
            Ii(ref ee, aa, ref bb, cc, dd, x[13], 9);
            Ii(ref dd, ee, ref aa, bb, cc, x[3], 14);
            Ii(ref cc, dd, ref ee, aa, bb, x[7], 5);
            Ii(ref bb, cc, ref dd, ee, aa, x[15], 6);
            Ii(ref aa, bb, ref cc, dd, ee, x[14], 8);
            Ii(ref ee, aa, ref bb, cc, dd, x[5], 6);
            Ii(ref dd, ee, ref aa, bb, cc, x[6], 5);
            Ii(ref cc, dd, ref ee, aa, bb, x[2], 12);

            /* round 5 */
            Jj(ref bb, cc, ref dd, ee, aa, x[4], 9);
            Jj(ref aa, bb, ref cc, dd, ee, x[0], 15);
            Jj(ref ee, aa, ref bb, cc, dd, x[5], 5);
            Jj(ref dd, ee, ref aa, bb, cc, x[9], 11);
            Jj(ref cc, dd, ref ee, aa, bb, x[7], 6);
            Jj(ref bb, cc, ref dd, ee, aa, x[12], 8);
            Jj(ref aa, bb, ref cc, dd, ee, x[2], 13);
            Jj(ref ee, aa, ref bb, cc, dd, x[10], 12);
            Jj(ref dd, ee, ref aa, bb, cc, x[14], 5);
            Jj(ref cc, dd, ref ee, aa, bb, x[1], 12);
            Jj(ref bb, cc, ref dd, ee, aa, x[3], 13);
            Jj(ref aa, bb, ref cc, dd, ee, x[8], 14);
            Jj(ref ee, aa, ref bb, cc, dd, x[11], 11);
            Jj(ref dd, ee, ref aa, bb, cc, x[6], 8);
            Jj(ref cc, dd, ref ee, aa, bb, x[15], 5);
            Jj(ref bb, cc, ref dd, ee, aa, x[13], 6);

            /* parallel round 1 */
            Jjj(ref aaa, bbb, ref ccc, ddd, eee, x[5], 8);
            Jjj(ref eee, aaa, ref bbb, ccc, ddd, x[14], 9);
            Jjj(ref ddd, eee, ref aaa, bbb, ccc, x[7], 9);
            Jjj(ref ccc, ddd, ref eee, aaa, bbb, x[0], 11);
            Jjj(ref bbb, ccc, ref ddd, eee, aaa, x[9], 13);
            Jjj(ref aaa, bbb, ref ccc, ddd, eee, x[2], 15);
            Jjj(ref eee, aaa, ref bbb, ccc, ddd, x[11], 15);
            Jjj(ref ddd, eee, ref aaa, bbb, ccc, x[4], 5);
            Jjj(ref ccc, ddd, ref eee, aaa, bbb, x[13], 7);
            Jjj(ref bbb, ccc, ref ddd, eee, aaa, x[6], 7);
            Jjj(ref aaa, bbb, ref ccc, ddd, eee, x[15], 8);
            Jjj(ref eee, aaa, ref bbb, ccc, ddd, x[8], 11);
            Jjj(ref ddd, eee, ref aaa, bbb, ccc, x[1], 14);
            Jjj(ref ccc, ddd, ref eee, aaa, bbb, x[10], 14);
            Jjj(ref bbb, ccc, ref ddd, eee, aaa, x[3], 12);
            Jjj(ref aaa, bbb, ref ccc, ddd, eee, x[12], 6);

            /* parallel round 2 */
            Iii(ref eee, aaa, ref bbb, ccc, ddd, x[6], 9);
            Iii(ref ddd, eee, ref aaa, bbb, ccc, x[11], 13);
            Iii(ref ccc, ddd, ref eee, aaa, bbb, x[3], 15);
            Iii(ref bbb, ccc, ref ddd, eee, aaa, x[7], 7);
            Iii(ref aaa, bbb, ref ccc, ddd, eee, x[0], 12);
            Iii(ref eee, aaa, ref bbb, ccc, ddd, x[13], 8);
            Iii(ref ddd, eee, ref aaa, bbb, ccc, x[5], 9);
            Iii(ref ccc, ddd, ref eee, aaa, bbb, x[10], 11);
            Iii(ref bbb, ccc, ref ddd, eee, aaa, x[14], 7);
            Iii(ref aaa, bbb, ref ccc, ddd, eee, x[15], 7);
            Iii(ref eee, aaa, ref bbb, ccc, ddd, x[8], 12);
            Iii(ref ddd, eee, ref aaa, bbb, ccc, x[12], 7);
            Iii(ref ccc, ddd, ref eee, aaa, bbb, x[4], 6);
            Iii(ref bbb, ccc, ref ddd, eee, aaa, x[9], 15);
            Iii(ref aaa, bbb, ref ccc, ddd, eee, x[1], 13);
            Iii(ref eee, aaa, ref bbb, ccc, ddd, x[2], 11);

            /* parallel round 3 */
            Hhh(ref ddd, eee, ref aaa, bbb, ccc, x[15], 9);
            Hhh(ref ccc, ddd, ref eee, aaa, bbb, x[5], 7);
            Hhh(ref bbb, ccc, ref ddd, eee, aaa, x[1], 15);
            Hhh(ref aaa, bbb, ref ccc, ddd, eee, x[3], 11);
            Hhh(ref eee, aaa, ref bbb, ccc, ddd, x[7], 8);
            Hhh(ref ddd, eee, ref aaa, bbb, ccc, x[14], 6);
            Hhh(ref ccc, ddd, ref eee, aaa, bbb, x[6], 6);
            Hhh(ref bbb, ccc, ref ddd, eee, aaa, x[9], 14);
            Hhh(ref aaa, bbb, ref ccc, ddd, eee, x[11], 12);
            Hhh(ref eee, aaa, ref bbb, ccc, ddd, x[8], 13);
            Hhh(ref ddd, eee, ref aaa, bbb, ccc, x[12], 5);
            Hhh(ref ccc, ddd, ref eee, aaa, bbb, x[2], 14);
            Hhh(ref bbb, ccc, ref ddd, eee, aaa, x[10], 13);
            Hhh(ref aaa, bbb, ref ccc, ddd, eee, x[0], 13);
            Hhh(ref eee, aaa, ref bbb, ccc, ddd, x[4], 7);
            Hhh(ref ddd, eee, ref aaa, bbb, ccc, x[13], 5);

            /* parallel round 4 */
            Ggg(ref ccc, ddd, ref eee, aaa, bbb, x[8], 15);
            Ggg(ref bbb, ccc, ref ddd, eee, aaa, x[6], 5);
            Ggg(ref aaa, bbb, ref ccc, ddd, eee, x[4], 8);
            Ggg(ref eee, aaa, ref bbb, ccc, ddd, x[1], 11);
            Ggg(ref ddd, eee, ref aaa, bbb, ccc, x[3], 14);
            Ggg(ref ccc, ddd, ref eee, aaa, bbb, x[11], 14);
            Ggg(ref bbb, ccc, ref ddd, eee, aaa, x[15], 6);
            Ggg(ref aaa, bbb, ref ccc, ddd, eee, x[0], 14);
            Ggg(ref eee, aaa, ref bbb, ccc, ddd, x[5], 6);
            Ggg(ref ddd, eee, ref aaa, bbb, ccc, x[12], 9);
            Ggg(ref ccc, ddd, ref eee, aaa, bbb, x[2], 12);
            Ggg(ref bbb, ccc, ref ddd, eee, aaa, x[13], 9);
            Ggg(ref aaa, bbb, ref ccc, ddd, eee, x[9], 12);
            Ggg(ref eee, aaa, ref bbb, ccc, ddd, x[7], 5);
            Ggg(ref ddd, eee, ref aaa, bbb, ccc, x[10], 15);
            Ggg(ref ccc, ddd, ref eee, aaa, bbb, x[14], 8);

            /* parallel round 5 */
            Fff(ref bbb, ccc, ref ddd, eee, aaa, x[12], 8);
            Fff(ref aaa, bbb, ref ccc, ddd, eee, x[15], 5);
            Fff(ref eee, aaa, ref bbb, ccc, ddd, x[10], 12);
            Fff(ref ddd, eee, ref aaa, bbb, ccc, x[4], 9);
            Fff(ref ccc, ddd, ref eee, aaa, bbb, x[1], 12);
            Fff(ref bbb, ccc, ref ddd, eee, aaa, x[5], 5);
            Fff(ref aaa, bbb, ref ccc, ddd, eee, x[8], 14);
            Fff(ref eee, aaa, ref bbb, ccc, ddd, x[7], 6);
            Fff(ref ddd, eee, ref aaa, bbb, ccc, x[6], 8);
            Fff(ref ccc, ddd, ref eee, aaa, bbb, x[2], 13);
            Fff(ref bbb, ccc, ref ddd, eee, aaa, x[13], 6);
            Fff(ref aaa, bbb, ref ccc, ddd, eee, x[14], 5);
            Fff(ref eee, aaa, ref bbb, ccc, ddd, x[0], 15);
            Fff(ref ddd, eee, ref aaa, bbb, ccc, x[3], 13);
            Fff(ref ccc, ddd, ref eee, aaa, bbb, x[9], 11);
            Fff(ref bbb, ccc, ref ddd, eee, aaa, x[11], 11);

            // combine results */
            ddd += cc + mDbuf[1]; /* final result for MDbuf[0] */
            mDbuf[1] = mDbuf[2] + dd + eee;
            mDbuf[2] = mDbuf[3] + ee + aaa;
            mDbuf[3] = mDbuf[4] + aa + bbb;
            mDbuf[4] = mDbuf[0] + bb + ccc;
            mDbuf[0] = ddd;
        }

        /// puts bytes from strptr into X and pad out; appends length 
        /// and finally, compresses the last block(s)
        /// note: length in bits == 8 * (lswlen + 2^32 mswlen).
        /// note: there are (lswlen mod 64) bytes left in strptr.
        private static void MDfinish(ref uint[] mDbuf, byte[] strptr, long index, uint lswlen, uint mswlen)
        {
            //UInt32 i;                                 /* counter       */
            var x = Enumerable.Repeat((uint) 0, 16).ToArray(); /* message words */

            /* put bytes from strptr into X */
            for (var i = 0; i < (lswlen & 63); i++)
                /* byte i goes into word X[i div 4] at pos.  8*(i mod 4)  */
                x[i >> 2] ^= Convert.ToUInt32(strptr[i + index]) << (8 * (i & 3));

            /* append the bit m_n == 1 */
            x[(lswlen >> 2) & 15] ^= (uint) 1 << Convert.ToInt32(8 * (lswlen & 3) + 7);

            if ((lswlen & 63) > 55)
            {
                /* length goes to next block */
                Compress(ref mDbuf, x);
                x = Enumerable.Repeat((uint) 0, 16).ToArray();
            }

            /* append length in bits*/
            x[14] = lswlen << 3;
            x[15] = (lswlen >> 29) | (mswlen << 3);
            Compress(ref mDbuf, x);
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            var index = 0;
            while (index < cbSize)
            {
                var bytesRemaining = cbSize - index;
                if (_unhashedBufferLength > 0)
                {
                    if (bytesRemaining + _unhashedBufferLength >= _unhashedBuffer.Length)
                    {
                        Array.Copy(array, ibStart + index, _unhashedBuffer, _unhashedBufferLength,
                            _unhashedBuffer.Length - _unhashedBufferLength);
                        index += _unhashedBuffer.Length - _unhashedBufferLength;
                        _unhashedBufferLength = _unhashedBuffer.Length;

                        for (var i = 0; i < 16; i++)
                            _x[i] = ReadUInt32(_unhashedBuffer, i * 4);

                        Compress(ref _mDbuf, _x);
                        _unhashedBufferLength = 0;
                    }
                    else
                    {
                        Array.Copy(array, ibStart + index, _unhashedBuffer, _unhashedBufferLength, bytesRemaining);
                        _unhashedBufferLength += bytesRemaining;
                        index += bytesRemaining;
                    }
                }
                else
                {
                    if (bytesRemaining >= _unhashedBuffer.Length)
                    {
                        for (var i = 0; i < 16; i++)
                            _x[i] = ReadUInt32(array, index + i * 4);
                        index += _unhashedBuffer.Length;

                        Compress(ref _mDbuf, _x);
                    }
                    else
                    {
                        Array.Copy(array, ibStart + index, _unhashedBuffer, 0, bytesRemaining);
                        _unhashedBufferLength = bytesRemaining;
                        index += bytesRemaining;
                    }
                }
            }

            _hashedLength += cbSize;
        }

        protected override byte[] HashFinal()
        {
            MDfinish(ref _mDbuf, _unhashedBuffer, 0, Convert.ToUInt32(_hashedLength), 0);

            var result = new byte[RmDsize / 8];

            for (var i = 0; i < RmDsize / 8; i += 4)
            {
                result[i] = Convert.ToByte(_mDbuf[i >> 2] & 0xFF); /* implicit cast to byte  */
                result[i + 1] = Convert.ToByte((_mDbuf[i >> 2] >> 8) & 0xFF); /*  extracts the 8 least  */
                result[i + 2] = Convert.ToByte((_mDbuf[i >> 2] >> 16) & 0xFF); /*  significant bits.     */
                result[i + 3] = Convert.ToByte((_mDbuf[i >> 2] >> 24) & 0xFF);
            }

            return result;
        }

        public sealed override void Initialize()
        {
            MDinit(ref _mDbuf);
            _x = Enumerable.Repeat((uint) 0, 16).ToArray();
            _hashedLength = 0;
            _unhashedBufferLength = 0;
        }
    }
}