using System.Security.Cryptography;

namespace BitcoinThief.Keccak256
{
    /// <summary>
    ///     Computes the SHA3 hash for the input data.
    /// </summary>
    public abstract class Sha3 : HashAlgorithm
    {
        /// <summary>
        ///     Creates an instance of the default implementation of SHA3 Keccak 256.
        /// </summary>
        /// <returns>A new instance of the default implementation of SHA3 Keccak 256.</returns>
        public static Sha3 CreateKeccak256()
        {
            return new Keccak256Managed();
        }
    }
}