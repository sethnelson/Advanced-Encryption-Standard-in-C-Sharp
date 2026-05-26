/*
    Seth Nelson
    09-01-2025
    COSC-583 Applied Cryptography
    The AES class contains the methods needed to implement the FIPS 197 spec.
*/
public static partial class AES
{
    static public byte FfAdd(byte a, byte b) //Section 4.1
    {
        return (byte)(a ^ b);
    }
    static public byte Xtime(byte a) //4.2.1
    {
        if ((a & 0b1000_0000) != 0)
        {
            a <<= 1;
            a ^= IP;
        }
        else
        {
            a <<= 1;
        }
        return a;
    }
    static public byte FfMultiply(byte a, byte b) //4.2.1
    {
        byte sum = 0;
        for (int i = 0; i < 8; i++)
        {
            if ((a & (1 << i)) != 0) //is this a-sub-i bit set?
            {
                sum ^= b;
            }
            if (i < 7) { b = Xtime(b); } //left shift is multiply by x
        }
        return sum;
    }
    static public uint SubWord(uint w)
    {
        byte[] word = BitConverter.GetBytes(w); //break up integer into bytes
        for (int i = 0; i < 4; i++)
        {
            word[i] = S_BOX[(word[i] & 0xF0) >> 4, word[i] & 0x0F]; //shift, mask, lookup, and assign
        }
        return BitConverter.ToUInt32(word); //convert back to integer
    }
    static public uint RotWord(uint word)
    {
        byte[] w = BitConverter.GetBytes(word);
        byte[] temp = [w[3], w[0], w[1], w[2]];
        return BitConverter.ToUInt32(temp);
    }
    static public void SubBytes(State s) //5.1.1
    {
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                s[i, j] = S_BOX[(s[i, j] & 0xF0) >> 4, s[i, j] & 0x0F]; //shift, mask, lookup, and assign
            }
        }
    }
    static public void ShiftRows(State s) //5.1.2
    {
        byte[] bytes = //create a byte array with the order of the shifted state
        {
            s[0, 0], s[1, 1], s[2, 2], s[3, 3],
            s[0, 1], s[1, 2], s[2, 3], s[3, 0],
            s[0, 2], s[1, 3], s[2, 0], s[3, 1],
            s[0, 3], s[1, 0], s[2, 1], s[3, 2]
        };
        State temp = new State(bytes);

        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                s[i, j] = temp[i, j]; //overwrite state with new values 
            }
        }
    }
    static public void MixColumns(State s)
    {
        byte a, b, c, d;
        for (int i = 0; i < 4; i++)
        {
            a = s[0, i]; b = s[1, i]; c = s[2, i]; d = s[3, i]; //store original values of column
            s[0, i] = (byte)(FfMultiply(0x02, a) ^ FfMultiply(0x03, b) ^ c ^ d); //update each column according to equation 5.6 found in 5.1.3
            s[1, i] = (byte)(a ^ FfMultiply(0x02, b) ^ FfMultiply(0x03, c) ^ d);
            s[2, i] = (byte)(a ^ b ^ FfMultiply(0x02, c) ^ FfMultiply(0x03, d));
            s[3, i] = (byte)(FfMultiply(0x03, a) ^ b ^ c ^ FfMultiply(0x02, d));
        }
    }
    static public void AddRoundKey(State s, State key) //5.1.4
    {
        for (int i = 0; i < 4; i++) //xor states together column-by-column
        {
            s[0, i] ^= key[0, i];
            s[1, i] ^= key[1, i];
            s[2, i] ^= key[2, i];
            s[3, i] ^= key[3, i];
        }
    }
    static public void InvSubBytes(State s)
    {
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                s[i, j] = INV_S_BOX[(s[i, j] & 0xF0) >> 4, s[i, j] & 0x0F];
            }
        }
    }
    static public void InvShiftRows(State s) //5.3.1
    {
        byte[] bytes =
        {
            s[0, 0], s[1, 3], s[2, 2], s[3, 1],
            s[0, 1], s[1, 0], s[2, 3], s[3, 2],
            s[0, 2], s[1, 1], s[2, 0], s[3, 3],
            s[0, 3], s[1, 2], s[2, 1], s[3, 0]
        };
        State temp = new State(bytes);

        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                s[i, j] = temp[i, j];
            }
        }
    }
    static public void InvMixColumns(State s) //5.3.3
    {
        byte a, b, c, d;
        for (int i = 0; i < 4; i++)
        {
            a = s[0, i]; b = s[1, i]; c = s[2, i]; d = s[3, i];
            s[0, i] = (byte)(FfMultiply(0x0e, a) ^ FfMultiply(0x0b, b) ^ FfMultiply(0x0d, c) ^ FfMultiply(0x09, d));
            s[1, i] = (byte)(FfMultiply(0x09, a) ^ FfMultiply(0x0e, b) ^ FfMultiply(0x0b, c) ^ FfMultiply(0x0d, d));
            s[2, i] = (byte)(FfMultiply(0x0d, a) ^ FfMultiply(0x09, b) ^ FfMultiply(0x0e, c) ^ FfMultiply(0x0b, d));
            s[3, i] = (byte)(FfMultiply(0x0b, a) ^ FfMultiply(0x0d, b) ^ FfMultiply(0x09, c) ^ FfMultiply(0x0e, d));
        }
    }
}