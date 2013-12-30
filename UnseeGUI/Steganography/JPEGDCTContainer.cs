using BitMiracle.LibJpeg.Classic;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace UnseeGUI.Steganography
{
  class JPEGDCTContainer : IContainer
  {
    private static readonly RandomNumberGenerator Random = RandomNumberGenerator.Create();

    jpeg_decompress_struct decompressInfo = new jpeg_decompress_struct();

    byte[] buffer = new byte[8];
    struct Bit
    {
      public JBLOCK block;
      public int component;

      public short Value
      {
        get
        {
          return block[component];
        }
      }

      public void Set(short value)
      {
        block[component] = value;
      }

      public bool LSB { get { return (block[component] & 1) != 0; } }
    }

    List<Bit> allBits = new List<Bit>();
    Dictionary<short, uint> histogram = null;
    string fileName;
    jvirt_array<JBLOCK>[] coefficients;
    int[] permutation = null;

    public JPEGDCTContainer(Stream jpegFile, string fileName)
    {
      this.fileName = fileName;

      /* Specify data source for decompression */
      decompressInfo.jpeg_stdio_src(jpegFile);
      CopyMarkersSetup();

      /* Read file header, set default decompression parameters */
      decompressInfo.jpeg_read_header(true);

      coefficients = decompressInfo.jpeg_read_coefficients();
      Console.WriteLine(decompressInfo.Comp_info[0]);
      for (int c = 0; c < decompressInfo.Num_components; ++c)
      {
        var array = coefficients[c].Access(0, decompressInfo.Comp_info[c].Height_in_blocks);
        bool evenWidth = decompressInfo.Comp_info[c].Downsampled_width % JpegConstants.DCTSIZE == 0;
        bool evenHeight = decompressInfo.Comp_info[c].Downsampled_height % JpegConstants.DCTSIZE == 0;
        for (int x = 0; x < array.Length - (evenHeight ? 0 : 1); ++x)
          for (int y = 0; y < array[x].Length - (evenWidth ? 0 : 1); ++y)
            for (int i = 0; i < JpegConstants.DCTSIZE2; ++i)
              if (Math.Abs(array[x][y][i]) > 0)
                allBits.Add(new Bit { block = array[x][y], component = i });
      }

      //decompressInfo.jpeg_finish_decompress();
    }

    public int Size
    {
      get { return allBits.Count / 8; }
    }

    public byte this[int index]
    {
      get
      {
        byte res = 0;
        for (int b = 0; b < 8; ++b)
        {
          int bitIdx = index * 8 + b;
          res |= allBits[permutation == null ? bitIdx : permutation[bitIdx]].LSB ? (byte)(1 << b) : (byte)0;
        }

        return res;
      }
      set
      {
        if(histogram == null)
        {
          histogram = new Dictionary<short, uint>();
          foreach(var bit in allBits)
          {
            uint count = 0;
            if (!histogram.TryGetValue(bit.Value, out count))
              histogram[bit.Value] = 0;

            histogram[bit.Value] = count + 1;
          }
        }

        for(int b = 0; b < 8; ++b)
        {
          bool set = (value & (1 << b)) != 0;
          int bitIdx = index * 8 + b;
          if(permutation != null)
            bitIdx = permutation[bitIdx];

          if(set != allBits[bitIdx].LSB)
          {
            if (allBits[bitIdx].Value == 1)
              allBits[bitIdx].Set(2);
            else if (allBits[bitIdx].Value == -1)
              allBits[bitIdx].Set(-2);
            else if(allBits[bitIdx].Value == 1023)
              allBits[bitIdx].Set(1022);
            else if (allBits[bitIdx].Value == -1024)
              allBits[bitIdx].Set(-1023);
            else
            {
              short candidate1 = (short)(allBits[bitIdx].Value - 1), candidate2 = (short)(allBits[bitIdx].Value + 1);
              uint count1, count2;
              if (!histogram.TryGetValue(candidate1, out count1))
                count1 = 1;

              if (!histogram.TryGetValue(candidate2, out count2))
                count2 = 1;

              Random.GetBytes(buffer);
              uint roll = (uint)(BitConverter.ToUInt64(buffer, 0) % (count1 + count2));
              allBits[bitIdx].Set(roll < count1 ? candidate1 : candidate2);
            }
          }
        }
      }
    }

    public void Save()
    {
      jpeg_compress_struct compressInfo = new jpeg_compress_struct();
      var accessTime = File.GetLastAccessTimeUtc(fileName);
      var writeTime = File.GetLastWriteTimeUtc(fileName);
      using (var outFile = new FileStream(fileName, FileMode.Open, FileAccess.Write))
      {
        compressInfo.jpeg_stdio_dest(outFile);
        decompressInfo.jpeg_copy_critical_parameters(compressInfo);
        compressInfo.jpeg_write_coefficients(coefficients);
        CopyMarkersExecute(compressInfo);
        compressInfo.jpeg_finish_compress();
      }

      File.SetLastAccessTimeUtc(fileName, accessTime);
      File.SetLastWriteTimeUtc(fileName, writeTime);
    }

    void CopyMarkersSetup()
    {
      decompressInfo.jpeg_save_markers((int)JPEG_MARKER.COM, 0xFFFF);
      for (int m = 0; m < 16; m++)
        decompressInfo.jpeg_save_markers((int)JPEG_MARKER.APP0 + m, 0xFFFF);
    }

    void CopyMarkersExecute(jpeg_compress_struct destination)
    {
      /* In the current implementation, we don't actually need to examine the
      * option flag here; we just copy everything that got saved.
      * But to avoid confusion, we do not output JFIF and Adobe APP14 markers
      * if the encoder library already wrote one.
      */
      foreach (var marker in decompressInfo.Marker_list)
      {
        if (destination.Write_JFIF_header &&
          marker.Marker == (byte)JPEG_MARKER.APP0 &&
          marker.Data.Length >= 5 &&
          marker.Data[0] == 0x4A &&
          marker.Data[1] == 0x46 &&
          marker.Data[2] == 0x49 &&
          marker.Data[3] == 0x46 &&
          marker.Data[4] == 0)
          continue; /* reject duplicate JFIF */

        if (destination.Write_Adobe_marker &&
          marker.Marker == (byte)JPEG_MARKER.APP14 &&
          marker.Data.Length >= 5 &&
          marker.Data[0] == 0x41 &&
          marker.Data[1] == 0x64 &&
          marker.Data[2] == 0x6F &&
          marker.Data[3] == 0x62 &&
          marker.Data[4] == 0x65)
          continue; /* reject duplicate Adobe */

        destination.jpeg_write_marker(marker.Marker, marker.Data);
      }
    }


    public void SetAccessPassword(string password)
    {
      if (permutation == null)
        permutation = new int[allBits.Count];

      for (int i = 0; i < allBits.Count; ++i)
        permutation[i] = i;

      // 1 iteration since we don't really need this to be cryptographically secure. This is used mainly to spread
      // small payloads evenly over the image
      var salt = BitConverter.GetBytes(1234L);
      Random rand;
      using (var generator = new Rfc2898DeriveBytes(password, salt, 1))
        rand = new System.Random(BitConverter.ToInt32(generator.GetBytes(4), 0));
      
      int n = allBits.Count;
      while (n > 1)
      {
        n--;
        var i = rand.Next(n + 1);
        int temp = permutation[i];
        permutation[i] = permutation[n];
        permutation[n] = temp;
      }
    }
  }
}
