using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace GenerateKey
{
    class Program
    {
        static void Main(string[] args)
        {
            //Example adapted from:
            //https://blogs.msdn.microsoft.com/shawnfa/2009/03/17/authenticated-symmetric-encryption-in-net/

            var encrypted = Cryptography.Encrypt("sausages", "password");

            Console.WriteLine("Encrypted: " + encrypted);

            var result = Cryptography.Decrypt(encrypted, "password");

            Console.WriteLine("Result: " + result);

            Console.ReadKey();
        }
        


    }
}
