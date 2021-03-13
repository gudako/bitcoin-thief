// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

// Contributed to .NET Foundation by Darren R. Starr - Conscia Norway AS

using System.Security.Cryptography;

namespace BitcoinThief.Ripemd160
{
    public abstract class Ripemd160 : HashAlgorithm
    {
        public new static Ripemd160 Create()
        {
            return new Ripemd160Managed();
        }

        public new static Ripemd160 Create(string hashname)
        {
            return new Ripemd160Managed();
        }
    }
}