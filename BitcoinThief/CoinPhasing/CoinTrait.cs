using System;
using System.Collections.Generic;
using BitcoinThief.CoinPhasing.Traits;

namespace BitcoinThief.CoinPhasing
{
    /// <summary>
    ///     Represents the trait of a specific address type of a crypto.
    /// </summary>
    public readonly struct CoinTrait
    {
        private readonly string _symbol;
        private readonly string _addrt;
        private readonly Func<CoinKeyPair> _generator;
        private readonly Func<string, bool> _validator;

        private CoinTrait(string symbol, string addrt,
            Func<CoinKeyPair> generator, Func<string, bool> validator, int defBatchSize)
        {
            _symbol = symbol;
            _addrt = addrt;
            _generator = generator;
            _validator = validator;
        }

        /// <summary>
        ///     Generates a random new key pair.
        /// </summary>
        /// <returns>A random new key pair.</returns>
        public CoinKeyPair Generate()
        {
            return _generator();
        }

        /// <summary>
        ///     Returns all defined <see cref="CoinTrait" /> objects in the application.
        /// </summary>
        public static IEnumerable<CoinTrait> All = new[]
        {
            new CoinTrait("btc","p2pkh",Bitcoin.P2PkhGenerator,Bitcoin.P2PkhValidator, 40),
            new CoinTrait("btc","p2sh",Bitcoin.P2ShGenerator,Bitcoin.P2ShValidator, 40),
            new CoinTrait("btc","p2wpkh",Bitcoin.P2WpkhGenerator,Bitcoin.P2WpkhValidator, 20),
            new CoinTrait("btc","p2wsh",Bitcoin.P2WshGenerator,Bitcoin.P2WshValidator, 10)

        };
    }
}
