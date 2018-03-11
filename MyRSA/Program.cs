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

            SimpleRSA rsa = new SimpleRSA(256);

            BigInteger[] test = rsa.GetDigitalSignature(218739);

            Console.WriteLine("msg: " + test[0]);
            Console.WriteLine("sig: " + test[1]);

            Console.WriteLine();

            if (rsa.CheckDigitalSignature(test[0], test[1]))
                Console.WriteLine("Проверка пройдена!");
            else
                Console.WriteLine("Проверка не пройдена!");


            if (rsa.CheckDigitalSignature(test[0] - 1, test[1]))
                Console.WriteLine("Проверка пройдена!");
            else
                Console.WriteLine("Проверка не пройдена!");

            Console.ReadKey();
        }
    }
}
