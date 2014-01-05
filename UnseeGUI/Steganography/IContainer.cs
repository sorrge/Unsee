using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace UnseeGUI.Steganography
{
  interface ICodec
  {
    int SizeEstimation { get; } // size in bytes
    byte[] Read();
    void Write(byte[] data);
    void SetAccessPassword(string password);
  }

  interface IContainer
  {
    int SymbolCount { get; }
    ISymbol this[int index] { get; }
    void Save(Stream saveTo);
  }

  interface ISymbol
  {
    int Value { get; set; }
    int Type { get; }
    int MinValue { get; }
    int MaxValue { get; }
  }
}
