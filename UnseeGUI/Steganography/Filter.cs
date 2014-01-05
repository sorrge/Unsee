using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace UnseeGUI.Steganography
{
  class Filter : IContainer
  {
    IContainer inner;
    List<int> filtered = new List<int>();

    public Filter(IContainer inner)
    {
      Set(inner);
    }

    public int SymbolCount
    {
      get { return filtered.Count; }
    }

    public ISymbol this[int index]
    {
      get { return inner[filtered[index]]; }
    }

    public void Save(System.IO.Stream saveTo)
    {
      inner.Save(saveTo);
    }

    public void Set(IContainer inner)
    {
      this.inner = inner;
      filtered.Clear();
      for (int i = 0; i < inner.SymbolCount; ++i)
        if (inner[i].Value != 0)
          filtered.Add(i);
    }
  }
}
