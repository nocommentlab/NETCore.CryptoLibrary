using System;
using System.Security.Cryptography;

namespace it.ncl.netcore.cryptolibrary.Encryption.PBKDF2
{
    /// <summary>
    /// Password-Based Key Derivation Function 2 Provider
    /// Thanks to: https://www.cidean.com/blog/2019/password-hashing-using-rfc2898derivebytes/
    /// </summary>
    public class PBKDF2Provider
    {

        public static string Generate(string password, int INT32_Iterations = 100000)
        {
            //generate a random salt for hashing
            byte[] vBYTE_Salt = new byte[24];
            new RNGCryptoServiceProvider().GetBytes(vBYTE_Salt);

            //hash password given salt and iterations (default to 1000)
            //iterations provide difficulty when cracking
            Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(password, vBYTE_Salt, INT32_Iterations);
            byte[] hash = pbkdf2.GetBytes(24);

            //return delimited string with salt | #iterations | hash
            return Convert.ToBase64String(vBYTE_Salt) + "|" + INT32_Iterations + "|" +
                Convert.ToBase64String(hash);

        }


        public static bool IsValid(string STRING_ClearText, string STRING_HashedPassword)
        {
            //extract original values from delimited hash text
            var origHashedParts = STRING_HashedPassword.Split('|');
            var origSalt = Convert.FromBase64String(origHashedParts[0]);
            var origIterations = Int32.Parse(origHashedParts[1]);
            var origHash = origHashedParts[2];

            //generate hash from test password and original salt and iterations
            var pbkdf2 = new Rfc2898DeriveBytes(STRING_ClearText, origSalt, origIterations);
            byte[] testHash = pbkdf2.GetBytes(24);

            //if hash values match then return success
            if (Convert.ToBase64String(testHash) == origHash)
                return true;

            //no match return false
            return false;

        }
    }
}
