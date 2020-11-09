using System;
using System.Collections.Generic;
using System.Text;

namespace Sharpen
{
    public static class Extensions
    {
        public static bool IsEmpty<T>(this ICollection<T> col)
        {
            return col.Count == 0;
        }

        public static bool IsEmpty<T>(this IReadOnlyCollection<T> col)
        {
            return col.Count == 0;
        }
    }
}
