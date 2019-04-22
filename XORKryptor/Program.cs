/*
 * XORKryptor
 * A .NET XOR encryption tool, intended to encrypt Cobalt strike beacon payloads,
 * but can be used on any file.
 * 
 * By Antonio Piazza
 * 4n7m4n
 * Twitter: @antman1p
 * 
 * Held by the hand and taught/mentored/instructed by Dwight Hohnstein
 * Twitter: @djhohnstein
 * 
 */

using System;
using System.IO;

namespace ShellCodeRunner
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length != 1)
            {
                Console.WriteLine("ERROR: Pass only the path to the shell code file to encrypt");
                Environment.Exit(1);
            }
            if (!File.Exists(args[0]))
            {
                Console.WriteLine("Could not find the shellcode bin file: {0}", args[0]);
                Environment.Exit(1);
            }
            // Call function wiht command line argument which is the unencrypted beacon payload path if arguments pass checks
            getPayLoad(args[0]);
        }

        static void getPayLoad(string bcnPath)
        {
            // Read the bytes from the unencrypted beacon payload file to a byte array
            byte[] uncShell = File.ReadAllBytes(bcnPath);

            // Encryption key.  Change this to whatever you want
            char[] arryKey = { 'p', 'a', 's', 's', 'k', 'e', 'y' };

            // Call the XOR encryption function on the payload with the encryption key
            byte [] payLoad = encrypt(uncShell, arryKey);

            // Write the encrypted payload out to a file
            File.WriteAllBytes("encrypt.bin", payLoad);
            Console.WriteLine("Shellcode has been encrypted.");
        }

        static byte[] encrypt(byte[] shellCode, char[] key)
        {
            // Initialize a new byte array the size of the unencrypted shellcode
            byte[] newByte = new byte[shellCode.Length];

            // Encryption key index
            int j = 0;

            // iterate through each byte of the unecncrypted shellcode
            for (int i = 0; i < shellCode.Length; i++)
            {
                // iterate through the bytes of the encryption key.  If at the end of the array, loop back to the begining 
                if (j == key.Length)
                {
                    j = 0;
                }

                // XOR each byte of the unencrypted payload with the coresponding byte of the encryption key
                newByte[i] = (byte)(shellCode[i] ^ Convert.ToByte(key[j]));
                j++;
            }
            return newByte;
        }
    }
}
