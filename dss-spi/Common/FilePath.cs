namespace Sharpen
{
	using System;
	using System.Collections.Generic;
	using System.IO;
	using System.Threading;

	public class FilePath
	{
		private string path;

		public FilePath ()
		{
		}

		public FilePath (string path)
			: this ((string) null, path)
		{

		}

		public FilePath (FilePath other, string child)
			: this (other.path, child)
		{

		}

		public FilePath (string other, string child)
		{
			if (other == null) {
				this.path = child;
			} else {
				while (child != null && child.Length > 0 && (child[0] == Path.DirectorySeparatorChar || child[0] == Path.AltDirectorySeparatorChar))
					child = child.Substring (1);

				if (!string.IsNullOrEmpty(other) && other[other.Length - 1] == Path.VolumeSeparatorChar)
					other += Path.DirectorySeparatorChar;

				this.path = Path.Combine (other, child);
			}
		}
		
		public static implicit operator FilePath (string name)
		{
			return new FilePath (name);
		}

		public override bool Equals (object obj)
		{
			FilePath other = obj as FilePath;
			if (other == null)
				return false;
			return GetCanonicalPath () == other.GetCanonicalPath ();
		}
		
		public override int GetHashCode ()
		{
			return path.GetHashCode ();
		}

		public bool CreateNewFile ()
		{
			try {
				File.Open (path, FileMode.CreateNew).Close ();
				return true;
			} catch {
				return false;
			}
		}

		public static FilePath CreateTempFile ()
		{
			return new FilePath (Path.GetTempFileName ());
		}

		public bool Exists()
		{
			return FileHelper.Exists(path);
		}

		public FilePath GetAbsoluteFile ()
		{
			return new FilePath (Path.GetFullPath (path));
		}

		public string GetAbsolutePath ()
		{
			return Path.GetFullPath (path);
		}

		public FilePath GetCanonicalFile ()
		{
			return new FilePath (GetCanonicalPath ());
		}

		public string GetCanonicalPath ()
		{
			string p = Path.GetFullPath (path);
			p.TrimEnd (Path.DirectorySeparatorChar);
			return p;
		}

		public string GetName ()
		{
			return Path.GetFileName (path);
		}

		public FilePath GetParentFile ()
		{
			return new FilePath (Path.GetDirectoryName (path));
		}

		public string GetPath ()
		{
			return path;
		}

		public bool IsAbsolute ()
		{
			return Path.IsPathRooted(path);
		}

		public bool IsDirectory ()
		{
			return Directory.Exists(path);
		}

		public bool IsFile ()
		{
			return File.Exists(path);
		}

		public long Length ()
		{
			return FileHelper.Length (path);
		}

		public FilePath[] ListFiles ()
		{
			try {
				if (IsFile ())
					return null;
				List<FilePath> list = new List<FilePath> ();
				foreach (string filePath in Directory.GetFileSystemEntries (path)) {
					list.Add (new FilePath (filePath));
				}
				return list.ToArray ();
			} catch {
				return null;
			}
		}
		
		public Uri ToURI ()
		{
			return new Uri (path);
		}
		
		public string GetParent ()
		{
			string p = Path.GetDirectoryName (path);
			if (string.IsNullOrEmpty(p) || p == path)
				return null;
			else
				return p;
		}

		public override string ToString ()
		{
			return path;
		}
		
		static internal string pathSeparator {
			get { return Path.PathSeparator.ToString (); }
		}

		static internal char pathSeparatorChar {
			get { return Path.PathSeparator; }
		}

		static internal char separatorChar {
			get { return Path.DirectorySeparatorChar; }
		}

		static internal string separator {
			get { return Path.DirectorySeparatorChar.ToString (); }
		}
	}
}
