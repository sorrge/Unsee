using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace UnseeGUI.Steganography
{
  interface IContainer
  {
    int Size { get; } // size in bytes
    byte this[int index] { get; set; }

    void Save();

    void SetAccessPassword(string password);
  }
}
