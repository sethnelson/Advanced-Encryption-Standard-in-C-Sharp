/*
    Seth Nelson
    09-01-2025
    COSC-583 Applied Cryptography
    This program implements the FIPS 197 spec for AES encryption.
*/
using System;

class Program
{
    static void Main()
    {
        uint[] exp_key128 = new uint[44];
        uint[] exp_key192 = new uint[52];
        uint[] exp_key256 = new uint[60];
        byte[][] initial_keys = [key128, key192, key256];
        uint[][] expanded_keys = [exp_key128, exp_key192, exp_key256];

        for (int i = 0; i < 3; i++)
        {
            State s = new State(plaintext);
            Console.WriteLine(label[i]);
            Console.WriteLine($"PLAINTEXT:          {s.ToString()}");
            Console.Write("KEY:                ");
            for (int j = 0; j < initial_keys[i].Length; j++) { Console.Write($"{Convert.ToString(initial_keys[i][j], 16).PadLeft(2, '0')}"); }
            Console.WriteLine("\n");
            KeyExpansion(initial_keys[i], expanded_keys[i]);
            Cipher(s, expanded_keys[i]);
            Console.WriteLine();
            InvCipher(s, expanded_keys[i]);
            if (i < 2) Console.WriteLine();
        }
    }

    static void Cipher(State s, uint[] exp_key)
    {
        Console.WriteLine("CIPHER (ENCRYPT):");
        int Nr;
        uint[] b = new uint[4];

        if      (exp_key.Length == 44) { Nr = 10; }
        else if (exp_key.Length == 52) { Nr = 12; }
        else                           { Nr = 14; }


        Console.WriteLine($"round[ 0].input     {s.ToString()}");
        b = exp_key[0..4].ToArray();
        Console.WriteLine($"round[ 0].k_sch     {new State(b).ToString()}");
        AES.AddRoundKey(s, new State(b));
        for (int i = 1; i < Nr; i++)
        {
            Console.WriteLine($"round[{i,2}].start     {s.ToString()}");
            AES.SubBytes(s);
            Console.WriteLine($"round[{i,2}].s_box     {s.ToString()}");
            AES.ShiftRows(s);
            Console.WriteLine($"round[{i,2}].s_row     {s.ToString()}");
            AES.MixColumns(s);
            Console.WriteLine($"round[{i,2}].m_col     {s.ToString()}");
            b = exp_key[(4 * i)..(4 * (i + 1))].ToArray();
            AES.AddRoundKey(s, new State(b));
            Console.WriteLine($"round[{i,2}].k_sch     {new State(b).ToString()}");
        }
        Console.WriteLine($"round[{Nr,2}].start     {s.ToString()}");
        AES.SubBytes(s);
        Console.WriteLine($"round[{Nr,2}].s_box     {s.ToString()}");
        AES.ShiftRows(s);
        Console.WriteLine($"round[{Nr,2}].s_row     {s.ToString()}");
        b = exp_key[(4 * Nr)..(4 * (Nr + 1))].ToArray();
        AES.AddRoundKey(s, new State(b));
        Console.WriteLine($"round[{Nr,2}].k_sch     {new State(b).ToString()}");
        Console.WriteLine($"round[{Nr,2}].output    {s.ToString()}");
    }

    static void InvCipher(State s, uint[] exp_key)
    {
        Console.WriteLine("INVERSE CIPHER (DECRYPT):");
        int Nr;
        uint[] b = new uint[4];

        if      (exp_key.Length == 44) { Nr = 10; }
        else if (exp_key.Length == 52) { Nr = 12; }
        else                           { Nr = 14; }


        Console.WriteLine($"round[ 0].iinput    {s.ToString()}");
        b = exp_key[(Nr*4)..((Nr+1)*4)].ToArray();
        Console.WriteLine($"round[ 0].ik_sch    {new State(b).ToString()}");
        AES.AddRoundKey(s, new State(b));
        for (int i = Nr-1; i > 0; i--)
        {
            Console.WriteLine($"round[{Nr - i,2}].istart    {s.ToString()}");
            AES.InvShiftRows(s);
            Console.WriteLine($"round[{Nr - i,2}].is_row    {s.ToString()}");
            AES.InvSubBytes(s);
            Console.WriteLine($"round[{Nr - i,2}].is_box    {s.ToString()}");
            b = exp_key[(4 * i)..(4 * (i + 1))].ToArray();
            Console.WriteLine($"round[{Nr - i,2}].ik_sch    {new State(b).ToString()}");
            AES.AddRoundKey(s, new State(b));
            Console.WriteLine($"round[{Nr - i,2}].ik_add    {s.ToString()}");
            AES.InvMixColumns(s);
        }
        Console.WriteLine($"round[{Nr,2}].istart    {s.ToString()}");
        AES.InvShiftRows(s);
        Console.WriteLine($"round[{Nr,2}].is_row    {s.ToString()}");
        AES.InvSubBytes(s);
        Console.WriteLine($"round[{Nr,2}].is_box    {s.ToString()}");
        b = exp_key[0..4].ToArray();
        AES.AddRoundKey(s, new State(b));
        Console.WriteLine($"round[{Nr,2}].ik_sch    {new State(b).ToString()}");
        Console.WriteLine($"round[{Nr,2}].ioutput   {s.ToString()}");
    }

    static void KeyExpansion(byte[] key, uint[] w)
    {
        int Nr, Nk;
        uint temp;
        int i = 0;

        if      (key.Length == 16) { Nr = 10; Nk = 4; }
        else if (key.Length == 24) { Nr = 12; Nk = 6; }
        else                       { Nr = 14; Nk = 8; }

        while (i < Nk)
        { 
            w[i] = BitConverter.ToUInt32([key[(4 * i) + 3], key[(4 * i) + 2], key[(4 * i) + 1], key[4 * i]]); //manually implemented little-endian
            i++;
        }

        i = Nk;

        while (i < 4 * (Nr + 1))
        {
            temp = w[i - 1];
            if (i % Nk == 0)
            {
                temp = (AES.SubWord(AES.RotWord(temp))) ^ AES.Rcon[i / Nk];
            }
            else if (Nk > 6 && i % Nk == 4)
            {
                temp = AES.SubWord(temp);
            }
            w[i] = w[i - Nk] ^ temp;
            i++;
        }
    }

    public static string[] label = { //print labels to match test output
    "C.1   AES-128 (Nk=4, Nr=10)\n",
    "C.2   AES-192 (Nk=6, Nr=12)\n",
    "C.3   AES-256 (Nk=8, Nr=14)\n",
    };

    // plaintext and key constants as provided in Appendix C
    public static byte[] plaintext =
    {
        0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb,
        0xcc, 0xdd, 0xee, 0xff
    };

    public static byte[] key128 = new byte[]
    {
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F
    };

    public static byte[] key192 = new byte[]
    {
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17
    };

    public static byte[] key256 = new byte[]
    {
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B,
        0x1C, 0x1D, 0x1E, 0x1F
    };
}