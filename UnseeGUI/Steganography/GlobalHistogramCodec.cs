using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace UnseeGUI.Steganography
{
  class GlobalHistogramCodec : ICodec
  {
    private static readonly RandomNumberGenerator Random = RandomNumberGenerator.Create();

    IContainer container;
    Dictionary<int, uint> histogram = null;
    byte[] buffer = new byte[8];

    public GlobalHistogramCodec(IContainer container)
    {
      this.container = container;
    }

    public int SizeEstimation
    {
      get { return container.SymbolCount / 8; }
    }

    public byte[] Read()
    {
      var buffer = new byte[SizeEstimation];

      for (int i = 0; i < buffer.Length; ++i)
      {
        buffer[i] = 0;
        for (int b = 0; b < 8; ++b)
          buffer[i] |= (byte)((container[i * 8 + b].Value & 1) << b);
      }

      return buffer;
    }

    private void MakeHistogram()
    {
      if (histogram == null)
      {
        histogram = new Dictionary<int, uint>();
        for (int i = 0; i < container.SymbolCount; ++i)
          if (container[i].Value != 0)
          {
            uint count = 0;
            if (!histogram.TryGetValue(container[i].Value, out count))
              histogram[container[i].Value] = 0;

            histogram[container[i].Value] = count + 1;
          }
      }
    }

    public void Write(byte[] data)
    {
      MakeHistogram();
      for(int i = 0; i < data.Length; ++i)
      {
        for (int b = 0; b < 8; ++b)
        {
          bool set = (data[i] & (1 << b)) != 0;

          int bitIdx = i * 8 + b;

          if (set != ((container[bitIdx].Value & 1) != 0))
          {
            if (container[bitIdx].Value == 1)
              container[bitIdx].Value = 2;
            else if (container[bitIdx].Value == -1)
              container[bitIdx].Value = -2;
            else if (container[bitIdx].Value == container[bitIdx].MaxValue)
              container[bitIdx].Value = container[bitIdx].MaxValue - 1;
            else if (container[bitIdx].Value == container[bitIdx].MinValue)
              container[bitIdx].Value = container[bitIdx].MinValue + 1;
            else
            {
              int candidate1 = container[bitIdx].Value - 1, candidate2 = container[bitIdx].Value + 1;
              uint count1, count2;
              if (!histogram.TryGetValue(candidate1, out count1))
                count1 = 1;

              if (!histogram.TryGetValue(candidate2, out count2))
                count2 = 1;

              Random.GetBytes(buffer);
              uint roll = (uint)(BitConverter.ToUInt64(buffer, 0) % (count1 + count2));
              container[bitIdx].Value = roll < count1 ? candidate1 : candidate2;
            }
          }
        }
      }
    }

    public void SetAccessPassword(string password)
    {
      throw new NotImplementedException();
    }
  }
}
