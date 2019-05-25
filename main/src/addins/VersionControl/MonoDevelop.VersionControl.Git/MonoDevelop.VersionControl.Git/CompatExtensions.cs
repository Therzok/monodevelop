//
// CompatExtensions.cs
//
// Author:
//       therzok <marius.ungureanu@xamarin.com>
//
// Copyright (c) 2017 (c) Marius Ungureanu
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Alm.GitProcessManagement;
using Microsoft.Alm.GitProcessManagement.Cli;

namespace MonoDevelop.VersionControl.Git
{
	static class CompatExtensions
	{
		public static void Stage (this IRepository repo, string path)
		{
			new UpdateIndexCommand (repo).Add (new [] { path }, UpdateOptions.Default);
		}

		public static void Unstage (this IRepository repo, string path)
		{
			new UpdateIndexCommand (repo).Add (new [] { path }, new UpdateOptions { Flags = UpdateOptionFlags.Remove });
		}

		public static void Remove (this IRepository repo, string path, bool removeFromWorking)
		{
			new UpdateIndexCommand (repo).Add (new [] { path }, new UpdateOptions { Flags = UpdateOptionFlags.ForceRemove });
			if (File.Exists (path))
				File.Delete (path);
			else
				Directory.Delete (path);
		}
	}
}
