using Security.Cryptography;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace GenerateKey
{
    public static class Cryptography
    {
        #region Settings

        private static int _iterations = 2;
        private static int _keySize = 256;

        private static string _hash = "SHA1";
        private static string _salt = "aselrias38490a32"; // Random
        private static string _vector = "8947az34awl3"; // Random
        private static byte[] _tag; //set by encryption used by decription

        #endregion

        public static string Encrypt(string value, string password)
        {
            return Encrypt<AesManaged>(value, password);
        }
        public static string Encrypt<T>(string value, string password)
                where T : SymmetricAlgorithm, new()
        {
            byte[] vectorBytes = GetBytes<ASCIIEncoding>(_vector);
            byte[] saltBytes = GetBytes<ASCIIEncoding>(_salt);
            byte[] valueBytes = GetBytes<UTF8Encoding>(value);

            byte[] encrypted;
            using (var cipher = new AuthenticatedAesCng())
            {
                PasswordDeriveBytes _passwordBytes =
                    new PasswordDeriveBytes(password, saltBytes, _hash, _iterations);
                byte[] keyBytes = _passwordBytes.GetBytes(_keySize / 8);

                cipher.CngMode = CngChainingMode.Ccm;

                cipher.Key = keyBytes;

                var length = vectorBytes.Length;

                cipher.IV = vectorBytes;

                cipher.AuthenticatedData = Encoding.UTF8.GetBytes("Additional authenticated data");
                
                using (MemoryStream ms = new MemoryStream())

                using (IAuthenticatedCryptoTransform encryptor = cipher.CreateAuthenticatedEncryptor())

                using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))

                {

                    byte[] plaintext = Encoding.UTF8.GetBytes(value);

                    cs.Write(plaintext, 0, plaintext.Length);

                    cs.FlushFinalBlock();

                    _tag = encryptor.GetTag();

                    encrypted = ms.ToArray();

                }

                cipher.Clear();
            }
            return Convert.ToBase64String(encrypted);
        }

        public static string Decrypt(string value, string password)
        {
            return Decrypt<AesManaged>(value, password);
        }
        public static string Decrypt<T>(string value, string password) where T : SymmetricAlgorithm, new()
        {
            byte[] vectorBytes = GetBytes<ASCIIEncoding>(_vector);
            byte[] saltBytes = GetBytes<ASCIIEncoding>(_salt);
            byte[] valueBytes = Convert.FromBase64String(value);

            byte[] decrypted;

            using (var cipher = new AuthenticatedAesCng())
            {
                PasswordDeriveBytes _passwordBytes = new PasswordDeriveBytes(password, saltBytes, _hash, _iterations);
                byte[] keyBytes = _passwordBytes.GetBytes(_keySize / 8);

                cipher.CngMode = CngChainingMode.Ccm;

                cipher.Key = keyBytes;

                var length = vectorBytes.Length;

                cipher.IV = vectorBytes;

                cipher.AuthenticatedData = Encoding.UTF8.GetBytes("Additional authenticated data");

                cipher.Tag = _tag;
                
                using (MemoryStream ms = new MemoryStream())

                using (CryptoStream cs = new CryptoStream(ms, cipher.CreateDecryptor(), CryptoStreamMode.Write))

                {

                    cs.Write(valueBytes, 0, valueBytes.Length);

                    cs.FlushFinalBlock();

                    decrypted = ms.ToArray();

                }
            }

            return Encoding.UTF8.GetString(decrypted, 0, decrypted.Length);
        }


        public static byte[] GetBytes<T>(String str)
        {

            if (typeof(T) == typeof(ASCIIEncoding))
                return ASCIIEncoding.ASCII.GetBytes(str);

            return UTF8Encoding.UTF8.GetBytes(str);

        }
    }





}
