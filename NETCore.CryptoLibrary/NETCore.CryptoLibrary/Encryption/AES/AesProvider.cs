using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace it.ncl.netcore.cryptolibrary.Encryption.AES
{
    public class AesProvider
    {
        /// <summary>
        /// Generates an AesParameters that contains a random Key and IV
        /// </summary>
        /// <returns>AesParameters</returns>
        public static AesParamenters GeneratesAesParameters()
        {
            AesParamenters aesParameters;

            using (Aes aes = Aes.Create())
            {
                aesParameters = new AesParamenters();
                Array.Copy(aes.Key, aesParameters.Key, aesParameters.Key.Length);
                Array.Copy(aes.IV, aesParameters.IV, aesParameters.IV.Length);
            }
            return aesParameters;
        }

        /// <summary>
        /// Encrypt a buffer with AES CBC
        /// </summary>
        /// <param name="vBYTE_PlainData">The buffer to encrypt</param>
        /// <param name="vBYTE_Key">The Key encryption</param>
        /// <param name="vBYTE_IV">The IV encryption</param>
        /// <returns></returns>
        private static byte[] AES_CBC_Encryption(byte[] vBYTE_PlainData, byte[] vBYTE_Key, byte[] vBYTE_IV)
        {
            //TODO: Check the input

            byte[] plainBytes = vBYTE_PlainData;
            byte[] bKey = new byte[32];
            byte[] bIv = new byte[16];

            Array.Copy(vBYTE_Key, bKey, bKey.Length);
            Array.Copy(vBYTE_IV, bIv, bIv.Length);

            byte[] vBYTE_EncryptedData = null; // encrypted data
            using (Aes Aes = Aes.Create())
            {
                try
                {
                    using (MemoryStream memoryStream = new MemoryStream())
                    {
                        using (CryptoStream cryptoStream = new CryptoStream(memoryStream, Aes.CreateEncryptor(bKey, vBYTE_IV), CryptoStreamMode.Write))
                        {
                            cryptoStream.Write(plainBytes, 0, plainBytes.Length);
                            cryptoStream.FlushFinalBlock();

                            vBYTE_EncryptedData = new byte[Aes.IV.Length + memoryStream.ToArray().Length];

                            Array.Copy(bIv, vBYTE_EncryptedData, bIv.Length);
                            Array.Copy(memoryStream.ToArray(), 0, vBYTE_EncryptedData, Aes.IV.Length, memoryStream.ToArray().Length);
                        }
                    }
                }
                catch
                {
                    vBYTE_EncryptedData = null;
                }
                return vBYTE_EncryptedData;
            }
        }

        /// <summary>
        /// Decrypt a buffer with AES CBC
        /// </summary>
        /// <param name="vBYTE_EncryptedData">The encrypted buffer to decrypt</param>
        /// <param name="vBYTE_Key">The Key decryption</param>
        /// <param name="vBYTE_IV">The IV decryption</param>
        /// <returns></returns>
        private static byte[] AES_CBC_Decryption(byte[] vBYTE_EncryptedData, byte[] vBYTE_Key, byte[] vBYTE_IV)
        {
            //TODO: Check the input

            byte[] bKey = new byte[32];
            byte[] bIv = new byte[16];


            Array.Copy(vBYTE_Key, bKey, bKey.Length);
            Array.Copy(vBYTE_IV, bIv, bIv.Length);


            byte[] vBYTE_DecryptedData = null;

            using (Aes Aes = Aes.Create())
            {
                try
                {
                    using (MemoryStream memoryStream = new MemoryStream(vBYTE_EncryptedData))
                    {
                        using (CryptoStream cryptoStream = new CryptoStream(memoryStream, Aes.CreateDecryptor(bKey, bIv), CryptoStreamMode.Read))
                        {
                            using (MemoryStream tempMemory = new MemoryStream())
                            {
                                byte[] Buffer = new byte[1024];
                                Int32 readBytes = 0;
                                while ((readBytes = cryptoStream.Read(Buffer, 0, Buffer.Length)) > 0)
                                {
                                    tempMemory.Write(Buffer, 0, readBytes);
                                }

                                vBYTE_DecryptedData = tempMemory.ToArray();
                            }
                        }
                    }
                }
                catch
                {
                    vBYTE_DecryptedData = null;
                }

                return vBYTE_DecryptedData;
            }
        }

        /// <summary>
        /// Encrypt a string with the given key. The IV is generated dynamically
        /// </summary>
        /// <param name="STRING_Data">The string to be encrypt</param>
        /// <param name="STRING_Key">The encryption Key</param>
        /// <returns></returns>
        public static string AES_CBC_Encryption_Rand_IV(string STRING_Data, string STRING_Key)
        {
            AesParamenters aesParameter = GeneratesAesParameters();

            /* Adapts the password lenght */
            string paddedKey = (STRING_Key.Length > 32) ? STRING_Key.Substring(0, 32) : STRING_Key.PadLeft(32, '*');

            var vBYTE_paddedKey = Encoding.UTF8.GetBytes(paddedKey);

            byte[] plainBytes = Encoding.UTF8.GetBytes(STRING_Data);

            var encryptBytes = AES_CBC_Encryption(plainBytes, vBYTE_paddedKey, aesParameter.IV);

            if (encryptBytes == null)
            {
                return null;
            }
            return Convert.ToBase64String(encryptBytes);
        }

        /// <summary>
        /// Encrypt a buffer with the given key. The IV is generated dynamically
        /// </summary>
        /// <param name="vBYTE_Data">The plain buffer</param>
        /// <param name="STRING_Key">The encryption key</param>
        /// <returns></returns>
        public static byte[] AES_CBC_Encryption_Rand_IV(byte[] vBYTE_Data, string STRING_Key)
        {
            AesParamenters aesParameters = GeneratesAesParameters();

            /* Adapts the password lenght */
            string paddedKey = (STRING_Key.Length > 32) ? STRING_Key.Substring(0, 32) : STRING_Key.PadLeft(32, '*');

            var vBYTE_paddedKey = Encoding.UTF8.GetBytes(paddedKey);


            var encryptBytes = AES_CBC_Encryption(vBYTE_Data, vBYTE_paddedKey, aesParameters.IV);
            if (encryptBytes == null)
            {
                return null;
            }
            return encryptBytes;
        }

        /// <summary>
        /// Decrypt a string with the given key.
        /// The IV is extracted from the first 16 bytes of the encrypted string
        /// </summary>
        /// <param name="STRING_Data">The encrypted string</param>
        /// <param name="STRING_Key">The decryption key</param>
        /// <returns></returns>
        public static string AES_CBC_Decryption_Rand_IV(string STRING_Data, string STRING_Key)
        {
            byte[] vBYTE_ExtractedIv = new byte[16];
            byte[] vBYTE_ExtractedEncryptedPayload;

            /* Adapts the password lenght */
            string paddedKey = (STRING_Key.Length > 32) ? STRING_Key.Substring(0, 32) : STRING_Key.PadLeft(32, '*');

            var vBYTE_paddedKey = Encoding.UTF8.GetBytes(paddedKey);

            byte[] encryptedBytes = Convert.FromBase64String(STRING_Data);

            /* Extracts the IV */
            Array.Copy(encryptedBytes, vBYTE_ExtractedIv, vBYTE_ExtractedIv.Length);

            /* Extracts the Encrypted Payload */
            vBYTE_ExtractedEncryptedPayload = new byte[encryptedBytes.Length - vBYTE_ExtractedIv.Length];
            Array.Copy(encryptedBytes, vBYTE_ExtractedIv.Length, vBYTE_ExtractedEncryptedPayload, 0, vBYTE_ExtractedEncryptedPayload.Length);

            byte[] decryptBytes = AES_CBC_Decryption(vBYTE_ExtractedEncryptedPayload, vBYTE_paddedKey, vBYTE_ExtractedIv);

            if (decryptBytes == null)
            {
                return null;
            }
            return Encoding.UTF8.GetString(decryptBytes);
        }

        /// <summary>
        /// Decrypt a buffer with the given key
        /// </summary>
        /// <param name="vBYTE_Data">The encrypted buffer</param>
        /// <param name="STRING_Key">The decryption key</param>
        /// <returns></returns>
        public static byte[] AES_CBC_Decryption_Rand_IV(byte[] vBYTE_Data, string STRING_Key)
        {

            byte[] vBYTE_ExtractedIv = new byte[16];
            byte[] vBYTE_ExtractedEncryptedPayload;

            /* Adapts the password lenght */
            string paddedKey = (STRING_Key.Length > 32) ? STRING_Key.Substring(0, 32) : STRING_Key.PadLeft(32, '*');

            var vBYTE_paddedKey = Encoding.UTF8.GetBytes(paddedKey);

            /* Extracts the IV */
            Array.Copy(vBYTE_Data, vBYTE_ExtractedIv, vBYTE_ExtractedIv.Length);

            /* Extracts the Encrypted Payload */
            vBYTE_ExtractedEncryptedPayload = new byte[vBYTE_Data.Length - vBYTE_ExtractedIv.Length];
            Array.Copy(vBYTE_Data, vBYTE_ExtractedIv.Length, vBYTE_ExtractedEncryptedPayload, 0, vBYTE_ExtractedEncryptedPayload.Length);

            byte[] decryptBytes = AES_CBC_Decryption(vBYTE_ExtractedEncryptedPayload, vBYTE_paddedKey, vBYTE_ExtractedIv);

            if (decryptBytes == null)
            {
                return null;
            }
            return decryptBytes;
        }
    }
}
