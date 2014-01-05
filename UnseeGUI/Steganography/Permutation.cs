using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace UnseeGUI.Steganography
{
  class Permutation : IContainer
  {
    IContainer inner;
    int[] permutation = null;

    public Permutation(IContainer inner, string password)
    {
      this.inner = inner;
      permutation = new int[inner.SymbolCount];

      for (int i = 0; i < permutation.Length; ++i)
        permutation[i] = i;

      // 1 iteration since we don't really need this to be cryptographically secure. This is used mainly to spread
      // small payloads evenly over the image
      var salt = BitConverter.GetBytes(1234L);
      Random rand;
      using (var generator = new Rfc2898DeriveBytes(password, salt, 1))
        rand = new System.Random(BitConverter.ToInt32(generator.GetBytes(4), 0));

      int n = permutation.Length;
      while (n > 1)
      {
        n--;
        var i = rand.Next(n + 1);
        int temp = permutation[i];
        permutation[i] = permutation[n];
        permutation[n] = temp;
      }
    }

    public int SymbolCount
    {
      get { return inner.SymbolCount; }
    }

    public ISymbol this[int index]
    {
      get
      {
        return inner[permutation[index]];
      }
    }

    public void Save(System.IO.Stream saveTo)
    {
      inner.Save(saveTo);
    }
  }
}
