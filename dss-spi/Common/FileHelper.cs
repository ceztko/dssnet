using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Sharpen
{
    public static class FileHelper
    {
		public static bool Exists(string path)
		{
			return File.Exists (path) || Directory.Exists(path);
		}

		public static long Length(string path)
		{
			// If you call .Length on a file that doesn't exist, an exception is thrown
			var info = new FileInfo (path);
			return info.Exists ? info.Length : 0;
		}
	}
}
