using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Numerics;
using System.Security.Cryptography;


namespace MyRSA
{
    class Program
    {
        static void Main(string[] args)
        {
            SimpleRSA rsa = new SimpleRSA(1);

            BigInteger n = 0;

            // тест генерации простых чисел
            do {
                n = rsa.GetRandomBigInteger(16);
                Console.Write(".");

            } while (!rsa.CheckPrime(n));

            Console.WriteLine(n);
            Console.ReadKey();
        }
    }
}
