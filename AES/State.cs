/*
    Seth Nelson
    09-01-2025
    COSC-583 Applied Cryptography
    The State class provides a convenient way to interact with the 16-byte 4x4 matrix
    as defined in FIPS 197 Section 3.4
*/
public class State
{
    private readonly byte[,] s = new byte[4, 4]; //the essential data structure of the state

    //Constructor using 1-dimensional byte array
    public State(byte[] bytes)
    {
        if (bytes.Length != 16) return;
        int k = 0;
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                this[j, i] = bytes[k]; // write to State as [col, row] because of column ordering (See 3.4)
                k++;
            }
        }
    }

    //Constructor from integer array
    public State(uint[] words)
    {
        if (words.Length != 4) return;
        byte[] bytes = BitConverter.GetBytes(words[3]).
                Concat(BitConverter.GetBytes(words[2])).
                Concat(BitConverter.GetBytes(words[1])).
                Concat(BitConverter.GetBytes(words[0])).Reverse().ToArray(); //reversed to convert to little-endian
        if (bytes.Length != 16) return;
        int k = 0;
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                this[j, i] = bytes[k]; // assigned as [col, row] because of column ordering (See 3.4)
                k++;
            }
        }
    }

    //Accessor method
    public byte this[int row, int col]
    {
        get => s[row, col];
        set => s[row, col] = value;
    }

    //prints a 2-Dimensional matrix of the state
    public void PrintStateHex()
    {
        for (int i = 0; i < 4; i++)
        {
            Console.Write("|");
            for (int j = 0; j < 4; j++)
            {
                Console.Write($"0x{Convert.ToString(this[i, j], 16).PadLeft(2, '0')}|");
            }
            Console.WriteLine();
        }
        Console.WriteLine();
    }

    //custom ToString method
    public override string ToString()
    {
        string s = new string("");
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                s += Convert.ToString(this[j, i], 16).PadLeft(2, '0');
            }
        }
        return s;
    }
}