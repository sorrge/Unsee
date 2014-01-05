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

    jpeg_decompress_struct decompressInfo = new jpeg_decompress_struct();

    struct Bit : ISymbol
    {
      public JBLOCK block;
      public int component;

      public int Value
      {
        get
        {
          return block[component];
        }
        set
        {
          if (value > MaxValue || value < MinValue)
            throw new ArgumentOutOfRangeException("value", value, "DCT coefficient is out of range. The range is [-1024, 1023]");

          block[component] = (short)value;
        }
      }

      public bool LSB { get { return (block[component] & 1) != 0; } }

      public int Type
      {
        get { return component; }
      }

      public int MinValue
      {
        get { return -1024; }
      }

      public int MaxValue
      {
        get { return 1023; }
      }
    }

    List<Bit> allBits = new List<Bit>();
    jvirt_array<JBLOCK>[] coefficients;

    public JPEGDCTContainer(Stream jpegFile)
    {
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
        for (int x = 0; x < decompressInfo.Comp_info[c].Downsampled_height / JpegConstants.DCTSIZE; ++x)
          for (int y = 0; y < decompressInfo.Comp_info[c].Downsampled_width / JpegConstants.DCTSIZE; ++y)
            for (int i = 0; i < JpegConstants.DCTSIZE2; ++i)
              allBits.Add(new Bit { block = array[x][y], component = i });
      }

      //decompressInfo.jpeg_finish_decompress();
    }

    public int SizeEstimation
    {
      get { return allBits.Count / 8; }
    }

    public void Save(Stream saveTo)
    {
      jpeg_compress_struct compressInfo = new jpeg_compress_struct();

      compressInfo.jpeg_stdio_dest(saveTo);
      decompressInfo.jpeg_copy_critical_parameters(compressInfo);
      compressInfo.jpeg_write_coefficients(coefficients);
      CopyMarkersExecute(compressInfo);
      compressInfo.jpeg_finish_compress();
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

    public int SymbolCount
    {
      get { return allBits.Count; }
    }

    ISymbol IContainer.this[int index]
    {
      get { return allBits[index]; }
    }
  }
}
