using System;
using System.Runtime.CompilerServices;

namespace BitcoinThief.Keccak256
{
    /// <summary>
    ///     Represents a managed implementation of the Keccak sponge function and permutation.
    /// </summary>
    internal sealed class KeccakSpongeManaged
    {
        /// <summary>
        ///     The delimiter used for Keccak hash implementations.
        /// </summary>
        public const int KeccakDelimiter = 0x06;

        /// <summary>
        ///     The delimiter used for Shake hash implementations.
        /// </summary>
        public const int ShakeDelimiter = 0x1f;

        /// <summary>
        ///     The number of Keccak rounds.
        /// </summary>
        private const int KeccakRounds = 24;

        /// <summary>
        ///     The state delimiter.
        /// </summary>
        private readonly int _delimiter;

        /// <summary>
        ///     The Iota permutation round constants.
        /// </summary>
        private readonly ulong[] _iotaRoundConstants =
        {
            0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
            0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
            0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
            0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
            0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
            0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
        };

        /// <summary>
        ///     The output length of the hash.
        /// </summary>
        private readonly int _outputLength;

        /// <summary>
        ///     The rate in bytes of the sponge state.
        /// </summary>
        private readonly int _rateBytes;

        /// <summary>
        ///     The state block size.
        /// </summary>
        private int _blockSize;

        /// <summary>
        ///     The state input pointer.
        /// </summary>
        private int _inputPointer;

        /// <summary>
        ///     The state output pointer.
        /// </summary>
        private int _outputPointer;

        /// <summary>
        ///     The hash result.
        /// </summary>
        private byte[] _result;

        /// <summary>
        ///     The state.
        /// </summary>
        private ulong[] _state;

        /// <summary>
        ///     Creates a new instance of the <see cref="KeccakSpongeManaged" /> class.
        /// </summary>
        /// <param name="rateBytes">The rate in bytes of the sponge state.</param>
        /// <param name="delimiter">The state delimiter.</param>
        /// <param name="outputLength">The output length of the hash.</param>
        public KeccakSpongeManaged(int rateBytes, int delimiter, int outputLength)
        {
            _rateBytes = rateBytes;
            _delimiter = delimiter;
            _outputLength = outputLength;
        }

        /// <summary>
        ///     Initializes the sponge state.
        /// </summary>
        public void Initialize()
        {
            _blockSize = default;
            _inputPointer = default;
            _outputPointer = default;
            _state = new ulong[25];
            _result = new byte[_outputLength];
        }

        /// <summary>
        ///     Absorbs data into the sponge state.
        /// </summary>
        /// <param name="array">The array of bytes to absorb.</param>
        /// <param name="start">The start index within the byte array.</param>
        /// <param name="size">The block size, or length of bytes to absorb.</param>
        public void Absorb(byte[] array, int start, int size)
        {
            while (size > 0)
            {
                _blockSize = Math.Min(size, _rateBytes);

                for (var i = start; i < _blockSize; i++)
                {
                    var x = Convert.ToByte(Buffer.GetByte(_state, i) ^ array[i + _inputPointer]);
                    Buffer.SetByte(_state, i, x);
                }

                _inputPointer += _blockSize;
                size -= _blockSize;

                if (_blockSize == _rateBytes)
                {
                    Permute(_state);
                    _blockSize = 0;
                }
            }
        }

        /// <summary>
        ///     Squeezes the hash out of the sponge state.
        /// </summary>
        /// <returns>A hash of the input data.</returns>
        public byte[] Squeeze()
        {
            var pad = Convert.ToByte(Buffer.GetByte(_state, _blockSize) ^ _delimiter);
            Buffer.SetByte(_state, _blockSize, pad);

            if ((_delimiter & 0x80) != 0 && _blockSize == _rateBytes - 1) Permute(_state);

            pad = Convert.ToByte(Buffer.GetByte(_state, _rateBytes - 1) ^ 0x80);
            Buffer.SetByte(_state, _rateBytes - 1, pad);
            Permute(_state);

            var outputBytesLeft = _outputLength;

            while (outputBytesLeft > 0)
            {
                _blockSize = Math.Min(outputBytesLeft, _rateBytes);
                Buffer.BlockCopy(_state, 0, _result, _outputPointer, _blockSize);
                _outputPointer += _blockSize;
                outputBytesLeft -= _blockSize;

                if (outputBytesLeft > 0) Permute(_state);
            }

            return _result;
        }

        /// <summary>
        ///     Performs the Keccak permutation.
        /// </summary>
        /// <param name="state">The state upon which to perform the permutation.</param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void Permute(ulong[] state)
        {
            ulong c0, c1, c2, c3, c4, d0, d1, d2, d3, d4;

            for (var round = 0; round < KeccakRounds; round++)
            {
                Theta();
                RhoPi();
                Chi();
                Iota(round);
            }

            void Theta()
            {
                c0 = state[0] ^ state[5] ^ state[10] ^ state[15] ^ state[20];
                c1 = state[1] ^ state[6] ^ state[11] ^ state[16] ^ state[21];
                c2 = state[2] ^ state[7] ^ state[12] ^ state[17] ^ state[22];
                c3 = state[3] ^ state[8] ^ state[13] ^ state[18] ^ state[23];
                c4 = state[4] ^ state[9] ^ state[14] ^ state[19] ^ state[24];

                d0 = Rotl64(c1, 1) ^ c4;
                d1 = Rotl64(c2, 1) ^ c0;
                d2 = Rotl64(c3, 1) ^ c1;
                d3 = Rotl64(c4, 1) ^ c2;
                d4 = Rotl64(c0, 1) ^ c3;

                state[00] ^= d0;
                state[05] ^= d0;
                state[10] ^= d0;
                state[15] ^= d0;
                state[20] ^= d0;
                state[01] ^= d1;
                state[06] ^= d1;
                state[11] ^= d1;
                state[16] ^= d1;
                state[21] ^= d1;
                state[02] ^= d2;
                state[07] ^= d2;
                state[12] ^= d2;
                state[17] ^= d2;
                state[22] ^= d2;
                state[03] ^= d3;
                state[08] ^= d3;
                state[13] ^= d3;
                state[18] ^= d3;
                state[23] ^= d3;
                state[04] ^= d4;
                state[09] ^= d4;
                state[14] ^= d4;
                state[19] ^= d4;
                state[24] ^= d4;
            }

            void RhoPi()
            {
                var a = Rotl64(state[1], 1);

                state[01] = Rotl64(state[06], 44);
                state[06] = Rotl64(state[09], 20);
                state[09] = Rotl64(state[22], 61);
                state[22] = Rotl64(state[14], 39);
                state[14] = Rotl64(state[20], 18);
                state[20] = Rotl64(state[02], 62);
                state[02] = Rotl64(state[12], 43);
                state[12] = Rotl64(state[13], 25);
                state[13] = Rotl64(state[19], 08);
                state[19] = Rotl64(state[23], 56);
                state[23] = Rotl64(state[15], 41);
                state[15] = Rotl64(state[04], 27);
                state[04] = Rotl64(state[24], 14);
                state[24] = Rotl64(state[21], 02);
                state[21] = Rotl64(state[08], 55);
                state[08] = Rotl64(state[16], 45);
                state[16] = Rotl64(state[05], 36);
                state[05] = Rotl64(state[03], 28);
                state[03] = Rotl64(state[18], 21);
                state[18] = Rotl64(state[17], 15);
                state[17] = Rotl64(state[11], 10);
                state[11] = Rotl64(state[07], 06);
                state[07] = Rotl64(state[10], 03);
                state[10] = a;
            }

            void Chi()
            {
                for (var i = 0; i < 25; i += 5)
                {
                    c0 = state[0 + i] ^ (~state[1 + i] & state[2 + i]);
                    c1 = state[1 + i] ^ (~state[2 + i] & state[3 + i]);
                    c2 = state[2 + i] ^ (~state[3 + i] & state[4 + i]);
                    c3 = state[3 + i] ^ (~state[4 + i] & state[0 + i]);
                    c4 = state[4 + i] ^ (~state[0 + i] & state[1 + i]);

                    state[0 + i] = c0;
                    state[1 + i] = c1;
                    state[2 + i] = c2;
                    state[3 + i] = c3;
                    state[4 + i] = c4;
                }
            }

            void Iota(int round)
            {
                state[0] ^= _iotaRoundConstants[round];
            }
        }

        /// <summary>
        ///     Rotates a 64-bit integer left.
        /// </summary>
        /// <param name="x">The 64-bit integer to rotate.</param>
        /// <param name="y">The value to rotate by.</param>
        /// <returns>A logically rotated 64-bit integer.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ulong Rotl64(ulong x, byte y)
        {
            return (x << y) | (x >> (64 - y));
        }
    }
}