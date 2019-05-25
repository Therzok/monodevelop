//
// GitRepository.cs
//
// Author:
//       Lluis Sanchez Gual <lluis@novell.com>
//
// Copyright (c) 2010 Novell, Inc (http://www.novell.com)
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

//#define DEBUG_GIT

using System;
using System.Linq;
using System.IO;
using MonoDevelop.Core;
using System.Collections.Generic;
using System.Text;
using MonoDevelop.Ide;
using ProgressMonitor = MonoDevelop.Core.ProgressMonitor;
using Microsoft.Alm.GitProcessManagement;
using Microsoft.Alm.GitProcessManagement.Cli;

namespace MonoDevelop.VersionControl.Git
{
	[Flags]
	public enum GitUpdateOptions
	{
		None = 0x0,
		SaveLocalChanges = 0x1,
		UpdateSubmodules = 0x2,
		NormalUpdate = SaveLocalChanges | UpdateSubmodules,
	}

	public sealed class GitRepository : UrlBasedRepository
	{
		public Microsoft.Alm.GitProcessManagement.IRepository RootRepository {
			get; set;
		}

		public static event EventHandler BranchSelectionChanged;

		public GitRepository ()
		{
			Url = "git://";
		}

		public GitRepository (VersionControlSystem vcs, FilePath path, string url) : base (vcs)
		{
			RootRepository = Microsoft.Alm.GitProcessManagement.Repository.Open (path);
			RootPath = RootRepository.WorkingDirectory;
			Url = url;
		}

		internal bool Disposed { get; private set; }
		public override void Dispose ()
		{
			Disposed = true;
			base.Dispose ();

			if (VersionControlSystem != null)
				((GitVersionControl)VersionControlSystem).UnregisterRepo (this);

			if (RootRepository != null)
				RootRepository.Dispose ();
			foreach (var rep in cachedSubmodules)
				rep.Item2.Dispose ();
		}

		public override string[] SupportedProtocols {
			get {
				return new [] {"git", "ssh", "http", "https", /*"ftp", "ftps", "rsync",*/ "file"};
			}
		}

		public override bool IsUrlValid (string url)
		{
			if (url.Contains (':')) {
				var tokens = url.Split (new[] { ':' }, 2);
				if (Uri.IsWellFormedUriString (tokens [0], UriKind.RelativeOrAbsolute) ||
					Uri.IsWellFormedUriString (tokens [1], UriKind.RelativeOrAbsolute))
					return true;
			}

			return base.IsUrlValid (url);
		}

		/*public override string[] SupportedNonUrlProtocols {
			get {
				return new string[] {"ssh/scp"};
			}
		}

		public override string Protocol {
			get {
				string p = base.Protocol;
				if (p != null)
					return p;
				return IsUrlValid (Url) ? "ssh/scp" : null;
			}
		}*/

		public override void CopyConfigurationFrom (Repository other)
		{
			base.CopyConfigurationFrom (other);

			var r = (GitRepository)other;
			RootPath = r.RootPath;
			if (!RootPath.IsNullOrEmpty)
				RootRepository = Microsoft.Alm.GitProcessManagement.Repository.Open (RootPath);
		}

		public override string LocationDescription {
			get { return Url ?? RootPath; }
		}

		public override bool AllowLocking {
			get { return false; }
		}

		public override string GetBaseText (FilePath localFile)
		{
			ICommit c = GetHeadCommit (GetRepository (localFile));
			return c == null ? string.Empty : GetCommitTextContent (c, localFile);
		}

		static ICommit GetHeadCommit (Microsoft.Alm.GitProcessManagement.IRepository repository)
		{
			return repository.Head.Commit;
		}

		public IReferenceCollection GetStashes ()
		{
			return RootRepository.ReadReferences (new ReferenceOptions {
				Flags = ReferenceOptionFlags.RefsStash
			});
		}

		//const CheckoutNotifyFlags refreshFlags = CheckoutNotifyFlags.Updated | CheckoutNotifyFlags.Conflict | CheckoutNotifyFlags.Untracked | CheckoutNotifyFlags.Dirty;
		/*bool RefreshFile (string path, CheckoutNotifyFlags flags)
		{
			FilePath fp = RootRepository.FromGitPath (path);
			Gtk.Application.Invoke (delegate {
				if (IdeApp.IsInitialized) {
					MonoDevelop.Ide.Gui.Document doc = IdeApp.Workbench.GetDocument (fp);
					if (doc != null)
						doc.Reload ();
				}
				FileService.NotifyFileChanged (fp);
				VersionControlService.NotifyFileStatusChanged (new FileUpdateEventArgs (this, fp, false));
			});
			return true;
		}

		const int progressThrottle = 200;
		static System.Diagnostics.Stopwatch throttleWatch = new System.Diagnostics.Stopwatch ();
		static bool OnTransferProgress (TransferProgress tp, ProgressMonitor monitor, ref int progress)
		{
			if (progress == 0 && tp.ReceivedObjects == 0) {
				monitor.BeginTask (GettextCatalog.GetString ("Receiving and indexing objects"), 2 * tp.TotalObjects);
				throttleWatch.Restart ();
			}

			int currentProgress = tp.ReceivedObjects + tp.IndexedObjects;
			int steps = currentProgress - progress;
			if (throttleWatch.ElapsedMilliseconds > progressThrottle) {
				monitor.Step (steps);
				throttleWatch.Restart ();
			}
			progress = currentProgress;

			if (tp.IndexedObjects >= tp.TotalObjects) {
				monitor.EndTask ();
				throttleWatch.Stop ();
			}

			return !monitor.CancellationToken.IsCancellationRequested;
		}

		static void OnCheckoutProgress (int completedSteps, int totalSteps, ProgressMonitor monitor, ref int progress)
		{
			if (progress == 0 && completedSteps == 0) {
				monitor.BeginTask (GettextCatalog.GetString ("Checking out files"), totalSteps);
				throttleWatch.Restart ();
			}

			int steps = completedSteps - progress;
			if (throttleWatch.ElapsedMilliseconds > progressThrottle) {
				monitor.Step (steps);
				throttleWatch.Restart ();
			}
			progress = completedSteps;

			if (completedSteps >= totalSteps) {
				monitor.EndTask ();
				throttleWatch.Stop ();
			}
		}

		void NotifyFilesChangedForStash (Stash stash)
		{
			// HACK: Notify file changes.
			foreach (var entry in RootRepository.Diff.Compare<TreeChanges> (stash.WorkTree.Tree, stash.Base.Tree)) {
				if (entry.Status == ChangeKind.Deleted || entry.Status == ChangeKind.Renamed) {
					FileService.NotifyFileRemoved (RootRepository.FromGitPath (entry.OldPath));
				} else {
					FileService.NotifyFileChanged (RootRepository.FromGitPath (entry.Path));
				}
			}
		}*/

		public void ApplyStash (ProgressMonitor monitor, int stashIndex)
		{
			monitor?.BeginTask (GettextCatalog.GetString ("Applying stash"), 1);

			//int progress = 0;
			new StashCommand (RootRepository).Apply (stashIndex);
			monitor?.EndTask ();
			/*
			StashApplyStatus res = RootRepository.Stashes.Apply (stashIndex, new StashApplyOptions {
				CheckoutOptions = new CheckoutOptions {
					OnCheckoutProgress = (path, completedSteps, totalSteps) => OnCheckoutProgress (completedSteps, totalSteps, monitor, ref progress),
					OnCheckoutNotify = RefreshFile,
					CheckoutNotifyFlags = refreshFlags,
				},
			});

			NotifyFilesChangedForStash (RootRepository.Stashes [stashIndex]);

			return res;
			*/
		}

		public void PopStash (ProgressMonitor monitor, int stashIndex)
		{
			monitor?.BeginTask (GettextCatalog.GetString ("Popping stash"), 1);

			new StashCommand (RootRepository).Pop (stashIndex);
			monitor?.EndTask ();
			return;
			/*
			var stash = RootRepository.Stashes [stashIndex];
			int progress = 0;
			StashApplyStatus res = RootRepository.Stashes.Pop (stashIndex, new StashApplyOptions {
				CheckoutOptions = new CheckoutOptions {
					OnCheckoutProgress = (path, completedSteps, totalSteps) => OnCheckoutProgress (completedSteps, totalSteps, monitor, ref progress),
					OnCheckoutNotify = RefreshFile,
					CheckoutNotifyFlags = refreshFlags,
				},
			});
			NotifyFilesChangedForStash (stash);
			return res;
			*/
		}

		public bool TryCreateStash (ProgressMonitor monitor, string message, out Stash stash)
		{
			stash = null;

			monitor?.BeginTask (GettextCatalog.GetString ("Stashing changes"), 1);

			new StashCommand (RootRepository).Save (message);
			monitor?.EndTask ();
			return true;
		}

		IEnumerable<string> ProbeSubmodules ()
		{
			var gitModules = File.ReadAllText (RootPath.Combine (".gitmodules"));
			int readIndex = 0;
			while (readIndex != -1) {
				readIndex = gitModules.IndexOf ('[', readIndex);
				if (readIndex == -1)
					break;

				readIndex = gitModules.IndexOf ('\"', readIndex + 1);
				string modulePath = gitModules.Substring (readIndex + 1, gitModules.IndexOf ('\"', readIndex + 1));
				yield return modulePath;
			}
		}

		DateTime cachedSubmoduleTime = DateTime.MinValue;
		Tuple<FilePath, Microsoft.Alm.GitProcessManagement.IRepository>[] cachedSubmodules = new Tuple<FilePath, Microsoft.Alm.GitProcessManagement.IRepository>[0];
		Tuple<FilePath, Microsoft.Alm.GitProcessManagement.IRepository>[] CachedSubmodules {
			get {
				var submoduleWriteTime = File.GetLastWriteTimeUtc(RootPath.Combine(".gitmodules"));
				if (cachedSubmoduleTime != submoduleWriteTime) {
					cachedSubmoduleTime = submoduleWriteTime;
					cachedSubmodules = ProbeSubmodules ()
						.Select (fp => new Tuple<FilePath, Microsoft.Alm.GitProcessManagement.IRepository> (fp, Microsoft.Alm.GitProcessManagement.Repository.Open (fp)))
						.ToArray ();
				}
				return cachedSubmodules;
			}
		}

		Microsoft.Alm.GitProcessManagement.IRepository GetRepository (FilePath localPath)
		{
			return GroupByRepository (new [] { localPath }).First ().Key;
		}

		IEnumerable<IGrouping<Microsoft.Alm.GitProcessManagement.IRepository, FilePath>> GroupByRepository (IEnumerable<FilePath> files)
		{
			var cache = CachedSubmodules;
			return files.GroupBy (f => {
				var res = cache.FirstOrDefault (s => f.IsChildPathOf (s.Item1) || f.FullPath == s.Item1);
				return res != null ? res.Item2 : RootRepository;
			});
		}

		protected override Revision[] OnGetHistory (FilePath localFile, Revision since)
		{
			var repository = GetRepository (localFile);
			var hc = GetHeadCommit (repository);
			if (hc == null)
				return new GitRevision [0];

			var sinceRev = since != null ? ((GitRevision)since).Commit : null;
			IEnumerable<ICommit> commits = repository.EnumerateCommits (sinceRev, repository.Head, new HistoryOptions {
				HintPath = repository.ToGitPath (localFile),
			});

			return commits.TakeWhile (c => c != sinceRev).Select (commit => {
				var author = commit.Author;
				var shortMessage = commit.FirstLine;
				if (shortMessage.Length > 50) {
					shortMessage = shortMessage.Substring (0, 50) + "…";
				}

				var rev = new GitRevision (this, repository, commit, author.Timestamp.LocalDateTime, author.Username, commit.Message) {
					Email = author.Email,
					ShortMessage = shortMessage,
					FileForChanges = localFile,
				};
				return rev;
			}).ToArray ();
		}

		protected override RevisionPath[] OnGetRevisionChanges (Revision revision)
		{
			var rev = (GitRevision) revision;
			if (rev.Commit == null)
				return new RevisionPath [0];

			var paths = new List<RevisionPath> ();
			var diffs = rev.Commit.ReadDifference (DifferenceOptions.Default);
			foreach (var diff in diffs.Entries) {
				RevisionAction action;
				switch (diff.Target.Type) {
				case TreeDifferenceType.Added:
				case TreeDifferenceType.Copied:
					action = RevisionAction.Add;
					break;

				case TreeDifferenceType.Deleted:
					action = RevisionAction.Delete;
					break;

				case TreeDifferenceType.TypeChange:
				case TreeDifferenceType.Modified:
					action = RevisionAction.Modify;
					break;
				default:
					action = RevisionAction.Other;
					break;
				}

				paths.Add (new RevisionPath(rev.GitRepository.FromGitPath (diff.Path), action, null));
			}
			return paths.ToArray ();
		}

		protected override IEnumerable<VersionInfo> OnGetVersionInfo (IEnumerable<FilePath> paths, bool getRemoteStatus)
		{
			return GetDirectoryVersionInfo (FilePath.Null, paths, getRemoteStatus, false);
		}

		protected override VersionInfo[] OnGetDirectoryVersionInfo (FilePath localDirectory, bool getRemoteStatus, bool recursive)
		{
			return GetDirectoryVersionInfo (localDirectory, null, getRemoteStatus, recursive);
		}

		// Used for checking if we will dupe data.
		// This way we reduce the number of GitRevisions created and RevWalks done.
		Dictionary<Microsoft.Alm.GitProcessManagement.IRepository, GitRevision> versionInfoCacheRevision = new Dictionary<Microsoft.Alm.GitProcessManagement.IRepository, GitRevision> ();
		Dictionary<Microsoft.Alm.GitProcessManagement.IRepository, GitRevision> versionInfoCacheEmptyRevision = new Dictionary<Microsoft.Alm.GitProcessManagement.IRepository, GitRevision> ();
		VersionInfo[] GetDirectoryVersionInfo (FilePath localDirectory, IEnumerable<FilePath> localFileNames, bool getRemoteStatus, bool recursive)
		{
			var versions = new List<VersionInfo> ();

			if (localFileNames != null) {
				var localFiles = new List<FilePath> ();
				foreach (var group in GroupByRepository (localFileNames)) {
					var repository = group.Key;
					GitRevision arev;
					if (!versionInfoCacheEmptyRevision.TryGetValue (repository, out arev)) {
						arev = new GitRevision (this, repository, null);
						versionInfoCacheEmptyRevision.Add (repository, arev);
					}
					foreach (var p in group) {
						if (Directory.Exists (p)) {
							if (recursive)
								versions.AddRange (GetDirectoryVersionInfo (p, getRemoteStatus, true));
							versions.Add (new VersionInfo (p, "", true, VersionStatus.Versioned, arev, VersionStatus.Versioned, null));
						} else
							localFiles.Add (p);
					}
				}
				// No files to check, we are done
				if (localFiles.Count != 0) {
					foreach (var group in GroupByRepository (localFileNames)) {
						var repository = group.Key;

						GitRevision rev = null;
						ICommit headCommit = GetHeadCommit (repository);
						if (headCommit != null) {
							if (!versionInfoCacheRevision.TryGetValue (repository, out rev)) {
								rev = new GitRevision (this, repository, headCommit);
								versionInfoCacheRevision.Add (repository, rev);
							} else if (rev.Commit != headCommit) {
								rev = new GitRevision (this, repository, headCommit);
								versionInfoCacheRevision [repository] = rev;
							}
						}

						GetFilesVersionInfoCore (repository, rev, group.ToList (), versions);
					}
				}
			} else {
				var directories = new List<FilePath> ();
				CollectFiles (directories, localDirectory, recursive);

				// Set directory items as Versioned.
				GitRevision arev = null;
				foreach (var group in GroupByRepository (directories)) {
					var repository = group.Key;
					if (!versionInfoCacheEmptyRevision.TryGetValue (repository, out arev)) {
						arev = new GitRevision (this, repository, null);
						versionInfoCacheEmptyRevision.Add (repository, arev);
					}
					foreach (var p in group)
						versions.Add (new VersionInfo (p, "", true, VersionStatus.Versioned, arev, VersionStatus.Versioned, null));
				}

				ICommit headCommit = GetHeadCommit (RootRepository);
				if (headCommit != null) {
					if (!versionInfoCacheRevision.TryGetValue (RootRepository, out arev)) {
						arev = new GitRevision (this, RootRepository, headCommit);
						versionInfoCacheRevision.Add (RootRepository, arev);
					} else if (arev.Commit != headCommit) {
						arev = new GitRevision (this, RootRepository, headCommit);
						versionInfoCacheRevision [RootRepository] = arev;
					}
				}

				GetDirectoryVersionInfoCore (RootRepository, arev, localDirectory.CanonicalPath, versions, recursive);
			}

			return versions.ToArray ();
		}

		static void GetFilesVersionInfoCore (Microsoft.Alm.GitProcessManagement.IRepository repo, GitRevision rev, List<FilePath> localPaths, List<VersionInfo> versions)
		{
			foreach (var file in repo.ToGitPath (localPaths)) {
				var status = repo.ReadStatus (new StatusOptions {
					Path = file,
				});
				foreach (var st in status.TrackedItems)
					AddStatus (repo, rev, file, versions, st.WorktreeStatus, null);
			}
		}

		static void AddStatus (Microsoft.Alm.GitProcessManagement.IRepository repo, GitRevision rev, string file, List<VersionInfo> versions, TreeDifferenceType status, string directoryPath)
		{
			VersionStatus fstatus = VersionStatus.Versioned;

			if (status != TreeDifferenceType.Unmodified) {
				if ((status & TreeDifferenceType.Added) != 0)
					fstatus |= VersionStatus.ScheduledAdd;
				else if ((status & (TreeDifferenceType.Deleted)) != 0)
					fstatus |= VersionStatus.ScheduledDelete;
				else if ((status & (TreeDifferenceType.TypeChange)) != 0)
					fstatus |= VersionStatus.Modified;
				else if ((status & (TreeDifferenceType.Renamed)) != 0)
					fstatus |= VersionStatus.ScheduledReplace;
				else if ((status & (TreeDifferenceType.Untracked)) != 0)
					fstatus = VersionStatus.Unversioned;
				else if ((status & TreeDifferenceType.Ignored) != 0)
					fstatus = VersionStatus.Ignored;
			}

			var versionPath = repo.FromGitPath (file);
			if (directoryPath != null && versionPath.ParentDirectory != directoryPath) {
				return;
			}

			versions.Add (new VersionInfo (versionPath, "", false, fstatus, rev, fstatus == VersionStatus.Ignored ? VersionStatus.Unversioned : VersionStatus.Versioned, null));
		}

		static void GetDirectoryVersionInfoCore (Microsoft.Alm.GitProcessManagement.IRepository repo, GitRevision rev, FilePath directory, List<VersionInfo> versions, bool recursive)
		{
			var relativePath = repo.ToGitPath (directory);
			var status = repo.ReadStatus (new StatusOptions {
				Path = relativePath != "." ? relativePath : null,
			});

			foreach (var statusEntry in status.TrackedItems) {
				AddStatus (repo, rev, statusEntry.PathCurrent, versions, statusEntry.WorktreeStatus, recursive ? null : directory);
			}

			foreach (var item in status.UnmergedItems) {
				versions.Add (new VersionInfo (item.PathCurrent, "", false, VersionStatus.Versioned | VersionStatus.Conflicted, rev, VersionStatus.Versioned, null));
			}
		}

		protected override VersionControlOperation GetSupportedOperations (VersionInfo vinfo)
		{
			VersionControlOperation ops = base.GetSupportedOperations (vinfo);
			if (GetCurrentRemote () == null)
				ops &= ~VersionControlOperation.Update;
			if (vinfo.IsVersioned && !vinfo.IsDirectory)
				ops |= VersionControlOperation.Annotate;
			if (!vinfo.IsVersioned && vinfo.IsDirectory)
				ops &= ~VersionControlOperation.Add;
			return ops;
		}

		static void CollectFiles (List<FilePath> directories, FilePath dir, bool recursive)
		{
			if (!Directory.Exists (dir))
				return;

			directories.AddRange (Directory.GetDirectories (dir, "*", recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly)
				.Select (f => new FilePath (f)));
		}

		protected override Repository OnPublish (string serverPath, FilePath localPath, FilePath[] files, string message, ProgressMonitor monitor)
		{
			// Initialize the repository
			RootRepository = Microsoft.Alm.GitProcessManagement.Repository.Create (localPath, InitializationOptions.Default);
			RootPath = localPath;
			RootRepository.AddRemote (Url, "origin", RemoteTagOptions.None);

			// Add the project files
			ChangeSet cs = CreateChangeSet (localPath);
			foreach (FilePath fp in files) {
				RootRepository.Stage (RootRepository.ToGitPath (fp));
				cs.AddFile (fp);
			}

			// Create the initial commit
			cs.GlobalComment = message;
			Commit (cs, monitor);

			RootRepository.BranchSetUpstream (new BranchName("master"), new RemoteName ("origin"), new BranchName("master"));
			RootRepository.Push (RootRepository.Head.AsBranch (), RootRepository.ReadRemotes ().FirstOrDefault (x => x.Name == "origin"), PushOptions.Default);
			/*
			RetryUntilSuccess (monitor, credType => RootRepository.Network.Push (RootRepository.Head, new PushOptions {
				OnPushStatusError = delegate (PushStatusError e) {
					RootRepository.Dispose ();
					RootRepository = null;
					if (RootPath.Combine (".git").IsDirectory)
						Directory.Delete (RootPath.Combine (".git"), true);
					throw new VersionControlException (e.Message);
				},
				CredentialsProvider = (url, userFromUrl, types) => GitCredentials.TryGet (url, userFromUrl, types, credType)
			}));
			*/

			return this;
		}

		protected override void OnUpdate (FilePath[] localPaths, bool recurse, ProgressMonitor monitor)
		{
			// TODO: Make it work differently for submodules.
			monitor.BeginTask (GettextCatalog.GetString (GettextCatalog.GetString ("Updating")), 5);

			var head = RootRepository.Head.AsBranch ();
			if (head.PushTarget != null) {
				Fetch (monitor, head.RemoteName);

				GitUpdateOptions options = GitService.StashUnstashWhenUpdating ? GitUpdateOptions.NormalUpdate : GitUpdateOptions.UpdateSubmodules;
				if (GitService.UseRebaseOptionWhenPulling)
					Rebase (head.PushTargetName, options, monitor);
				else
					Merge (head.PushTargetName, options, monitor);

				monitor.Step (1);
			}

			monitor.EndTask ();
		}
		/*
		static void RetryUntilSuccess (ProgressMonitor monitor, Action<GitCredentialsType> func)
		{
			bool retry;
			using (var tfsSession = new TfsSmartSession ()) {
				do {
					var credType = tfsSession.Disposed ? GitCredentialsType.Normal : GitCredentialsType.Tfs;
					try {
						func (credType);
						GitCredentials.StoreCredentials (credType);
						retry = false;
					} catch (AuthenticationException e) {
						GitCredentials.InvalidateCredentials (credType);
						retry = AlertButton.Yes == MessageService.AskQuestion (
							GettextCatalog.GetString ("Remote server error: {0}", e.Message),
							GettextCatalog.GetString ("Retry authentication?"),
							AlertButton.Yes, AlertButton.No);
						if (!retry)
							monitor?.ReportError (e.Message, null);
					} catch (VersionControlException e) {
						GitCredentials.InvalidateCredentials (credType);
						monitor?.ReportError (e.Message, null);
						retry = false;
					} catch (UserCancelledException) {
						GitCredentials.StoreCredentials (credType);
						retry = false;
					} catch (LibGit2SharpException e) {
						GitCredentials.InvalidateCredentials (credType);

						if (credType == GitCredentialsType.Tfs) {
							retry = true;
							tfsSession.Dispose ();
							continue;
						}

						string message;
						// TODO: Remove me once https://github.com/libgit2/libgit2/pull/3137 goes in.
						if (string.Equals (e.Message, "early EOF", StringComparison.OrdinalIgnoreCase))
							message = GettextCatalog.GetString ("Unable to authorize credentials for the repository.");
						else if (e.Message.StartsWith ("Invalid Content-Type", StringComparison.OrdinalIgnoreCase))
							message = GettextCatalog.GetString ("Not a valid git repository.");
						else if (string.Equals (e.Message, "Received unexpected content-type", StringComparison.OrdinalIgnoreCase))
							message = GettextCatalog.GetString ("Not a valid git repository.");
						else
							message = e.Message;

						throw new VersionControlException (message);
					}
				} while (retry);
			}
		}*/

		public void Fetch (ProgressMonitor monitor, string remote)
		{
			monitor.Log.WriteLine (GettextCatalog.GetString ("Fetching from '{0}'", remote));
			//int progress = 0;

			var remotes = RootRepository.ReadRemotes ();
			remotes [remote].Fetch (FetchOptions.Default);
			/*
			RetryUntilSuccess (monitor, credType => RootRepository.Fetch (remote, new FetchOptions {
				CredentialsProvider = (url, userFromUrl, types) => GitCredentials.TryGet (url, userFromUrl, types, credType),
				OnTransferProgress = tp => OnTransferProgress (tp, monitor, ref progress),
			}));
			*/
			monitor.Step (1);
		}

		bool CommonPreMergeRebase (GitUpdateOptions options, ProgressMonitor monitor, out int stashIndex)
		{
			stashIndex = -1;
			monitor.Step (1);

			if ((options & GitUpdateOptions.SaveLocalChanges) != GitUpdateOptions.SaveLocalChanges) {
				const VersionStatus unclean = VersionStatus.Modified | VersionStatus.ScheduledAdd | VersionStatus.ScheduledDelete;
				bool modified = false;
				if (GetDirectoryVersionInfo (RootPath, false, true).Any (v => (v.Status & unclean) != VersionStatus.Unversioned))
					modified = true;

				if (modified) {
					if (MessageService.GenericAlert (
						    MonoDevelop.Ide.Gui.Stock.Question,
						    GettextCatalog.GetString ("You have uncommitted changes"),
						    GettextCatalog.GetString ("What do you want to do?"),
						    AlertButton.Cancel,
						    new AlertButton (GettextCatalog.GetString ("Stash"))) == AlertButton.Cancel)
						return false;

					options |= GitUpdateOptions.SaveLocalChanges;
				}
			}
			if ((options & GitUpdateOptions.SaveLocalChanges) == GitUpdateOptions.SaveLocalChanges) {
				monitor.Log.WriteLine (GettextCatalog.GetString ("Saving local changes"));
				Stash stash;
				if (!TryCreateStash (monitor, GetStashName ("_tmp_"), out stash))
					return false;

				if (stash != null)
					stashIndex = 0;
				monitor.Step (1);
			}
			return true;
		}

		bool ConflictResolver(ProgressMonitor monitor, ICommit resetToIfFail, string message, List<StatusUnmergedEntry> conflicts)
		{
			foreach (var conflictFile in conflicts) {
				ConflictResult res = ResolveConflict (RootRepository.FromGitPath (conflictFile.PathCurrent));
				if (res == ConflictResult.Abort) {
					if (resetToIfFail != null)
						RootRepository.ResetHard (resetToIfFail, null);
					return false;
				}
				if (res == ConflictResult.Skip) {
					Revert (RootRepository.FromGitPath (conflictFile.PathCurrent), false, monitor);
					break;
				}
				if (res == Git.ConflictResult.Continue) {
					Add (RootRepository.FromGitPath (conflictFile.PathCurrent), false, monitor);
				}
			}
			if (!string.IsNullOrEmpty (message)) {
				RootRepository.Commit (message, CommitOptions.Default);
			}
			return true;
		}

		void CommonPostMergeRebase(int stashIndex, GitUpdateOptions options, ProgressMonitor monitor, ICommit oldHead)
		{
			if ((options & GitUpdateOptions.SaveLocalChanges) == GitUpdateOptions.SaveLocalChanges) {
				monitor.Step (1);

				// Restore local changes
				if (stashIndex != -1) {
					monitor.Log.WriteLine (GettextCatalog.GetString ("Restoring local changes"));
					ApplyStash (monitor, stashIndex);
					// FIXME: No StashApplyStatus.Conflicts here.
					var status = RootRepository.ReadStatus (StatusOptions.Default);
					if (status.UnmergedItems.Any () && !ConflictResolver (monitor, oldHead, string.Empty, status.UnmergedItems))
						PopStash (monitor, stashIndex);
					else
						new StashCommand (RootRepository).Drop (stashIndex);

					monitor.Step (1);
				}
			}
			monitor.EndTask ();
		}

		public void Rebase (string branch, GitUpdateOptions options, ProgressMonitor monitor)
		{
			int stashIndex = -1;
			var oldHead = RootRepository.Head.Commit;

			try {
				monitor.BeginTask (GettextCatalog.GetString ("Rebasing"), 5);
				if (!CommonPreMergeRebase (options, monitor, out stashIndex))
					return;
				
				var reference = RootRepository.ReadObject<ICommit> (ObjectId.FromString (new RevParseCommand (RootRepository).ParseName (branch)));
				var result = RootRepository.RebaseBegin (reference, RebaseOptions.Default);
				if (result == RebaseResult.Conflicts) {
					var status = RootRepository.ReadStatus (StatusOptions.Default);
					if (!ConflictResolver (monitor, null, RootRepository.ReadCurrentMergeMessage (), status.UnmergedItems)) {
						RootRepository.RebaseAbort (null);
						return;
					}
					RootRepository.RebaseContinue (null);
				}
				/*
				foreach (var com in toApply) {
					monitor.Log.WriteLine (GettextCatalog.GetString ("Cherry-picking {0} - {1}/{2}", com.Id, i, count));
					CherryPickResult cherryRes = RootRepository.CherryPick (com, com.Author, new CherryPickOptions {
						CheckoutNotifyFlags = refreshFlags,
						OnCheckoutNotify = RefreshFile,
					});
					if (cherryRes.Status == CherryPickStatus.Conflicts)
						ConflictResolver(monitor, toApply.Last(), RootRepository.Info.Message ?? com.Message);
					++i;
				}
				*/
			} finally {
				CommonPostMergeRebase (stashIndex, options, monitor, oldHead);
			}
		}

		public void Merge (string branch, GitUpdateOptions options, ProgressMonitor monitor, MergeOptionFastForwardFlags strategy = MergeOptionFastForwardFlags.Default)
		{
			int stashIndex = -1;
			var oldHead = RootRepository.Head.Commit;

			try {
				monitor.BeginTask (GettextCatalog.GetString ("Merging"), 5);
				CommonPreMergeRebase (options, monitor, out stashIndex);

				var refs = RootRepository.ReadReferences (new ReferenceOptions {
					Flags = ReferenceOptionFlags.RefsHeads,
				})[branch];
				var mergeResult = RootRepository.Merge (refs, MergeOptions.Default);
				/*
  // Do a merge.
  MergeResult mergeResult = RootRepository.Merge (branch, sig, new MergeOptions {
	  CheckoutNotifyFlags = refreshFlags,
	  OnCheckoutNotify = RefreshFile,
  });
  */
				if (mergeResult == MergeCommandResult.Conflict) {
					var status = RootRepository.ReadStatus (StatusOptions.Default);
					ConflictResolver (monitor, RootRepository.Head.Commit, RootRepository.ReadCurrentMergeMessage (), status.UnmergedItems);
				}
			} finally {
				CommonPostMergeRebase (stashIndex, GitUpdateOptions.SaveLocalChanges, monitor, oldHead);
			}
		}

		static ConflictResult ResolveConflict (string file)
		{
			ConflictResult res = ConflictResult.Abort;
			Runtime.RunInMainThread (delegate {
				var dlg = new ConflictResolutionDialog ();
				try {
					dlg.Load (file);
					var dres = (Gtk.ResponseType) MessageService.RunCustomDialog (dlg);
					dlg.Hide ();
					switch (dres) {
					case Gtk.ResponseType.Cancel:
						res = ConflictResult.Abort;
						break;
					case Gtk.ResponseType.Close:
						res = ConflictResult.Skip;
						break;
					case Gtk.ResponseType.Ok:
						res = ConflictResult.Continue;
						dlg.Save (file);
						break;
					}
				} finally {
					dlg.Destroy ();
					dlg.Dispose ();
				}
			}).Wait ();
			return res;
		}

		protected override void OnCommit (ChangeSet changeSet, ProgressMonitor monitor)
		{
			string message = changeSet.GlobalComment;
			if (string.IsNullOrEmpty (message))
				throw new ArgumentException ("Commit message must not be null or empty!", "message");

			var repo = (GitRepository)changeSet.Repository;
			foreach (var item in changeSet.Items.Select (x => x.LocalPath).ToPathStrings ()) {
				repo.RootRepository.Stage (item);
			}

			if (changeSet.ExtendedProperties.Contains ("Git.AuthorName"))

				repo.RootRepository.Commit (message, new CommitOptions {
					AuthorEmail = (string)changeSet.ExtendedProperties ["Git.AuthorEmail"],
					AuthorName = (string)changeSet.ExtendedProperties ["Git.AuthorName"],
				});
			else
				repo.RootRepository.Commit (message, CommitOptions.Default);
		}

		public bool IsUserInfoDefault ()
		{
			string name = null, email = null;

			var config = RootRepository.ReadConfigList ();
			foreach (var entry in config) {
				if (entry.Key == "user.name") {
					name = entry.Value;
				}
				if (entry.Key == "user.email") {
					email = entry.Value;
				}
				if (name != null && email != null)
					break;
			}

			return name == null && email == null;
		}

		public void GetUserInfo (out string name, out string email)
		{
			var config = RootRepository.ReadConfigList ();

			name = null;
			email = null;
			foreach (var entry in config) {
				if (entry.Key == "user.name") {
					name = entry.Value;
				}
				if (entry.Key == "user.email") {
					email = entry.Value;
				}
				if (name != null && email != null)
					break;
			}
			if (name != null && email != null)
				return;
			
			string dlgName = null, dlgEmail = null;
			Runtime.RunInMainThread (() => {
				var dlg = new UserGitConfigDialog ();
				try {
					if ((Gtk.ResponseType)MessageService.RunCustomDialog (dlg) == Gtk.ResponseType.Ok) {
						dlgName = dlg.UserText;
						dlgEmail = dlg.EmailText;
						SetUserInfo (dlgName, dlgEmail);
					}
				} finally {
					dlg.Destroy ();
					dlg.Dispose ();
				}
			}).Wait ();

			name = dlgName;
			email = dlgEmail;
		}

		public void SetUserInfo (string name, string email)
		{
			RootRepository.SetConfigValue ("user.name", name, ConfigLevel.Local);
			RootRepository.SetConfigValue ("user.email", name, ConfigLevel.Local);
		}

		protected override void OnCheckout (FilePath targetLocalPath, Revision rev, bool recurse, ProgressMonitor monitor)
		{
			//int transferProgress = 0;
			//int checkoutProgress = 0;
			Microsoft.Alm.GitProcessManagement.Repository.Clone (Url, targetLocalPath, new CloneOptions {
				ProgressCallback = (progress) => {
					// progress
					return !monitor.CancellationToken.IsCancellationRequested;
				},
				RecurseSubmodules = true,
			});
			/*
			RetryUntilSuccess (monitor, credType => {
				RootPath = Microsoft.Alm.GitProcessManagement.IRepository.Clone (Url, targetLocalPath, new CloneOptions {
					CredentialsProvider = (url, userFromUrl, types) => GitCredentials.TryGet (url, userFromUrl, types, credType),

					OnTransferProgress = (tp) => OnTransferProgress (tp, monitor, ref transferProgress),
					OnCheckoutProgress = (path, completedSteps, totalSteps) => OnCheckoutProgress (completedSteps, totalSteps, monitor, ref checkoutProgress),
					RecurseSubmodules = true,
				});
			});
			*/

			if (monitor.CancellationToken.IsCancellationRequested || RootPath.IsNull)
				return;
			
			RootPath = RootPath.ParentDirectory;
			RootRepository = Microsoft.Alm.GitProcessManagement.Repository.Open (RootPath);
		}

		protected override void OnRevert (FilePath[] localPaths, bool recurse, ProgressMonitor monitor)
		{
			foreach (var group in GroupByRepository (localPaths)) {
				var repository = group.Key;
				var toCheckout = new HashSet<FilePath> ();
				var toUnstage = new HashSet<FilePath> ();

				foreach (var item in group)
					if (item.IsDirectory) {
						foreach (var vi in GetDirectoryVersionInfo (item, false, recurse))
							if (!vi.IsDirectory) {
								if (vi.Status == VersionStatus.Unversioned)
									continue;
								
								if ((vi.Status & VersionStatus.ScheduledAdd) == VersionStatus.ScheduledAdd)
									toUnstage.Add (vi.LocalPath);
								else
									toCheckout.Add (vi.LocalPath);
							}
					} else {
						var vi = GetVersionInfo (item);
						if (vi.Status == VersionStatus.Unversioned)
							continue;

						if ((vi.Status & VersionStatus.ScheduledAdd) == VersionStatus.ScheduledAdd)
							toUnstage.Add (vi.LocalPath);
						else
							toCheckout.Add (vi.LocalPath);
					}

				monitor.BeginTask (GettextCatalog.GetString ("Reverting files"), 1);

				var repoFiles = repository.ToGitPath (toCheckout);
				//int progress = 0;
				if (toCheckout.Any ()) {
					repository.CheckoutIndex (repoFiles, new CheckoutIndexOptions {
						Stage = CheckoutIndexOptionStage.Default,
						Flags = CheckoutIndexOptionFlags.Force
					});
					/*
					repository.CheckoutPaths ("HEAD", repoFiles, new CheckoutOptions {
						OnCheckoutProgress = (path, completedSteps, totalSteps) => OnCheckoutProgress (completedSteps, totalSteps, monitor, ref progress),
						CheckoutModifiers = CheckoutModifiers.Force,
						CheckoutNotifyFlags = refreshFlags,
						OnCheckoutNotify = delegate (string path, CheckoutNotifyFlags notifyFlags) {
							if ((notifyFlags & CheckoutNotifyFlags.Untracked) != 0)
								FileService.NotifyFileRemoved (repository.FromGitPath (path));
							else
								RefreshFile (path, notifyFlags);
							return true;
						}
					});
					*/
					foreach (var file in repoFiles)
						repository.Stage (file);
				}

				foreach (var path in toUnstage) {
					repository.Unstage (repository.ToGitPath (path));
				}
				monitor.EndTask ();
			}
		}

		protected override void OnRevertRevision (FilePath localPath, Revision revision, ProgressMonitor monitor)
		{
			throw new NotSupportedException ();
		}

		protected override void OnRevertToRevision (FilePath localPath, Revision revision, ProgressMonitor monitor)
		{
			throw new NotSupportedException ();
		}

		protected override void OnAdd (FilePath[] localPaths, bool recurse, ProgressMonitor monitor)
		{
			foreach (var group in GroupByRepository (localPaths)) {
				var repository = group.Key;
				var files = group.Where (f => !f.IsDirectory);
				foreach (var file in files) {
					repository.Stage (repository.ToGitPath (file));
				}
			}
		}

		protected override void OnDeleteFiles (FilePath[] localPaths, bool force, ProgressMonitor monitor, bool keepLocal)
		{
			DeleteCore (localPaths, keepLocal);

			foreach (var path in localPaths) {
				if (keepLocal) {
					// Undo addition of files.
					VersionInfo info = GetVersionInfo (path, VersionInfoQueryFlags.IgnoreCache);
					if (info != null && info.HasLocalChange (VersionStatus.ScheduledAdd)) {
						// Revert addition.
						Revert (path, false, monitor);
					}
				} else {
					// Untracked files are not deleted by the rm command, so delete them now
					if (File.Exists (path))
						File.Delete (path);
				}
			}
		}

		protected override void OnDeleteDirectories (FilePath[] localPaths, bool force, ProgressMonitor monitor, bool keepLocal)
		{
			DeleteCore (localPaths, keepLocal);

			foreach (var path in localPaths) {
				if (keepLocal) {
					// Undo addition of directories and files.
					foreach (var info in GetDirectoryVersionInfo (path, false, true)) {
						if (info != null && info.HasLocalChange (VersionStatus.ScheduledAdd)) {
							// Revert addition.
							Revert (path, true, monitor);
						}
					}
				} else {
					// Untracked files are not deleted by the rm command, so delete them now
					foreach (var f in localPaths)
						if (Directory.Exists (f))
							Directory.Delete (f, true);
				}
			}
		}

		void DeleteCore (FilePath[] localPaths, bool keepLocal)
		{
			foreach (var group in GroupByRepository (localPaths)) {
				if (!keepLocal)
					foreach (var f in localPaths) {
						if (File.Exists (f))
							File.Delete (f);
						else if (Directory.Exists (f))
							Directory.Delete (f, true);
					}

				var repository = group.Key;
				var files = repository.ToGitPath (group);

				foreach (var file in files)
					repository.Remove (file, !keepLocal);
			}
		}

		protected override string OnGetTextAtRevision (FilePath repositoryPath, Revision revision)
		{
			var gitRev = (GitRevision)revision;
			return GetCommitTextContent (gitRev.Commit, repositoryPath);
		}

		public override DiffInfo GenerateDiff (FilePath baseLocalPath, VersionInfo versionInfo)
		{
			try {
				var patch = new PatchCommand (RootRepository).Diff (versionInfo.LocalPath);
				// Trim the header by taking out the first 2 lines.
				int diffStart = patch.IndexOf ('\n', patch.IndexOf ('\n') + 1);
				return new DiffInfo (baseLocalPath, versionInfo.LocalPath, patch.Substring (diffStart + 1));
			} catch (System.Exception ex) {
				LoggingService.LogError ("Could not get diff for file '" + versionInfo.LocalPath + "'", ex);
			}
			return null;
		}

		public override DiffInfo[] PathDiff (FilePath baseLocalPath, FilePath[] localPaths, bool remoteDiff)
		{
			var diffs = new List<DiffInfo> ();
			VersionInfo[] vinfos = GetDirectoryVersionInfo (baseLocalPath, localPaths, false, true);
			foreach (VersionInfo vi in vinfos) {
				var diff = GenerateDiff (baseLocalPath, vi);
				if (diff != null)
					diffs.Add (diff);
			}
			return diffs.ToArray ();
		}

		IBlob GetBlob (ICommit c, FilePath file)
		{
			var repo = c.Repository;
			var tree = repo.ReadObject<Tree> (c.TreeId);
			var blob = tree.Blobs.FirstOrDefault (x => x.ObjectName == file);
			return blob.Object;
		}

		string GetCommitTextContent (ICommit c, FilePath file)
		{
			IBlob blob = GetBlob (c, file);
			if (blob == null || !blob.CanRead)
				return string.Empty;
			
			using (var ms = new MemoryStream ((int)blob.Size)) {
				blob.ToStream (ms);
				return ms.ToString ();
			}
		}

		public string GetCurrentRemote ()
		{
			var remotes = new List<string> (GetRemotes ().Select (r => r.Name));
			if (remotes.Count == 0)
				return null;

			return remotes.Contains ("origin") ? "origin" : remotes [0];
		}

		public void Push (ProgressMonitor monitor, string remote, string remoteBranch)
		{
			var branch = RootRepository.Head.AsBranch ();
			var trackedBranch = (IBranch)RootRepository.ReadReferences (new ReferenceOptions {
				Flags = ReferenceOptionFlags.RefsRemotes
			}) [remote, remoteBranch];

			// TODO: Handle exceptions
			RootRepository.Push (branch, trackedBranch, new PushOptions {
				Flags = PushOptionsFlags.SetUpstream,
			});

			monitor.ReportSuccess (GettextCatalog.GetString ("Push operation successfully completed."));
		}

		public void CreateBranchFromCommit (string name, ICommit id)
		{
			RootRepository.CreateBranch (name, id);
		}

		public void CreateBranch (string name, string trackSource, string targetRef)
		{
			ICommit c = null;

			if (!string.IsNullOrEmpty (trackSource)) {
				c = RootRepository.ReadObject<ICommit> (ObjectId.FromString (new RevParseCommand(RootRepository).ParseName (trackSource)));
			}
			RootRepository.CreateBranch (name, c ?? RootRepository.Head.Commit);
			RootRepository.BranchSetUpstream (new BranchName (name), new BranchName (targetRef));
		}

		public void SetBranchTrackRef (string name, string trackSource, string trackRef)
		{
			var branches = RootRepository.ReadReferences (ReferenceOptions.Default);
			var branch = branches [name];
			if (branch != null) {
				RootRepository.BranchSetUpstream (new BranchName (name), new BranchName (trackRef));
			} else
				CreateBranch (name, trackSource, trackRef);
		}

		public void RemoveBranch (string name)
		{
			RootRepository.DeleteBranch (name);
		}

		public void RenameBranch (string name, string newName)
		{
			var branches = RootRepository.ReadReferences (ReferenceOptions.Default);
			var branch = (IBranch)branches [name];
			new BranchCommand (RootRepository).Rename (branch, newName);
		}

		public IRemoteCollection GetRemotes ()
		{
			return RootRepository.ReadRemotes ();
		}

		public bool IsBranchMerged (string branchName)
		{
			var branchHead = RootRepository.ReadReferences (new ReferenceOptions {
				Flags = ReferenceOptionFlags.TipsHeads
			}).Head;
			return RootRepository.FindMergeBase (RootRepository.Head, branchHead) == branchHead.ObjectId;
		}

		public void RenameRemote (string name, string newName)
		{
			RootRepository.RenameRemote (name, newName);
		}

		public void ChangeRemoteUrl (string name, string url)
		{
			RootRepository.SetRemoteFetchUrl (name, url);
			RootRepository.SetRemotePushUrl (name, url);
		}

		public void ChangeRemotePushUrl (string name, string url)
		{
			RootRepository.SetRemotePushUrl (name, url);
		}

		public void AddRemote (string name, string url, bool importTags)
		{
			if (string.IsNullOrEmpty (name))
				throw new InvalidOperationException ("Name not set");

			RootRepository.AddRemote (url, name, importTags ? RemoteTagOptions.AllTags : RemoteTagOptions.None);
		}

		public void RemoveRemote (string name)
		{
			RootRepository.RemoveRemote (name);
		}

		public IEnumerable<IBranch> GetBranches ()
		{
			return RootRepository.ReadReferences (new ReferenceOptions {
				Flags = ReferenceOptionFlags.RefsHeads,
			}).LocalBranches;
		}

		public IEnumerable<string> GetTags ()
		{
			return RootRepository.ReadReferences (new ReferenceOptions {
				Flags = ReferenceOptionFlags.RefsTags,
			}).Tags.Select (t => t.Name);
		}

		public void AddTag (string name, Revision rev, string message)
		{
			var gitRev = (GitRevision)rev;
			RootRepository.CreateTag (gitRev.Commit, name, message, TagOptions.Default);
		}

		public void RemoveTag (string name)
		{
			RootRepository.DeleteTag (name);
		}

		public void PushTag (string name)
		{

			RootRepository.Push (RootRepository.Head.AsBranch (), RootRepository.Head.AsBranch ().PushTarget, new PushOptions {
				Flags = PushOptionsFlags.Tags,
			});
		}

		public IEnumerable<string> GetRemoteBranches (string remoteName)
		{
			var refs = RootRepository.ReadReferences (new ReferenceOptions {
				Flags = ReferenceOptionFlags.RefsRemotes,
			}).RemoteBranches;
			return refs.Select (x => x.LocalName);
		}

		public string GetCurrentBranch ()
		{
			return RootRepository.Head.Name;
		}

		public bool SwitchToBranch (ProgressMonitor monitor, string branch)
		{
			Stash stash;
			int stashIndex = -1;

			monitor.BeginTask (GettextCatalog.GetString ("Switching to branch {0}", branch), GitService.StashUnstashWhenSwitchingBranches ? 4 : 2);

			// Get a list of files that are different in the target branch
			var statusList = GitUtil.GetChangedFiles (RootRepository, branch);

			if (GitService.StashUnstashWhenSwitchingBranches) {
				// Remove the stash for this branch, if exists
				string currentBranch = GetCurrentBranch ();
				stashIndex = GetStashForBranch (RootRepository, currentBranch);
				if (stashIndex != -1) {
					new StashCommand (RootRepository).Drop (stashIndex);
				}

				if (!TryCreateStash (monitor, GetStashName (currentBranch), out stash))
					return false;
				
				monitor.Step (1);
			}

			try {
				//int progress = 0;

				var b = RootRepository.ReadReferences (new ReferenceOptions {
					Flags = ReferenceOptionFlags.RefsHeads,
				})[branch];
				RootRepository.Checkout (b, CheckoutOptions.Default);
				/*
				RootRepository.Checkout (branch, new CheckoutOptions {
					OnCheckoutProgress = (path, completedSteps, totalSteps) => OnCheckoutProgress (completedSteps, totalSteps, monitor, ref progress),
					OnCheckoutNotify = RefreshFile,
					CheckoutNotifyFlags = refreshFlags,
				});
				*/
			} finally {
				// Restore the branch stash
				if (GitService.StashUnstashWhenSwitchingBranches) {
					stashIndex = GetStashForBranch (RootRepository, branch);
					if (stashIndex != -1)
						PopStash (monitor, stashIndex);
					monitor.Step (1);
				}
			}
			// Notify file changes
			NotifyFileChanges (monitor, statusList);

			BranchSelectionChanged?.Invoke (this, EventArgs.Empty);

			monitor.EndTask ();
			return true;
		}

		void NotifyFileChanges (ProgressMonitor monitor, ITreeDifference statusList)
		{
			// Files added to source branch not present to target branch.
			var removed = statusList.Entries.Where (c => c.Target.Type == TreeDifferenceType.Added).Select (c => GetRepository (c.Path).FromGitPath (c.Path)).ToList ();
			var modified = statusList.Entries.Where (c => c.Target.Type != TreeDifferenceType.Added).Select (c => GetRepository (c.Path).FromGitPath (c.Path)).ToList ();

			monitor.BeginTask (GettextCatalog.GetString ("Updating solution"), removed.Count + modified.Count);

			FileService.NotifyFilesChanged (modified, true);
			monitor.Step (modified.Count);

			FileService.NotifyFilesRemoved (removed);
			monitor.Step (removed.Count);

			monitor.EndTask ();
		}

		static string GetStashName (string branchName)
		{
			return "__MD_" + branchName;
		}

		public static string GetStashBranchName (string stashName)
		{
			return stashName.StartsWith ("__MD_", StringComparison.Ordinal) ? stashName.Substring (5) : null;
		}

		static int GetStashForBranch (IRepository repo, string branchName)
		{
			IReadOnlyList<IStash> stashes = repo.ReadReferences (new ReferenceOptions { Flags = ReferenceOptionFlags.RefsStash }).Stashes;
			string sn = GetStashName (branchName);

			int count = stashes.Count ();
			for (int i = 0; i < count; ++i) {
				if (stashes[i].StashMessage.IndexOf (sn, StringComparison.InvariantCulture) != -1)
					return i;
			}
			return -1;
		}

		public ChangeSet GetPushChangeSet (string remote, string branch)
		{
			ChangeSet cset = CreateChangeSet (RootPath);

			var b = RootRepository.ReadReferences (new ReferenceOptions {
				Flags = ReferenceOptionFlags.RefsHeads | ReferenceOptionFlags.RefsRemotes,
			}) [remote + "/" + branch];
			ICommit reference = b.Commit;
			ICommit compared = RootRepository.Head.Commit;

			foreach (var change in GitUtil.CompareCommits (RootRepository, reference, compared).Entries) {
				VersionStatus status;
				switch (change.Target.Type) {
				case TreeDifferenceType.Added:
				case TreeDifferenceType.Copied:
					status = VersionStatus.ScheduledAdd;
					break;
				case TreeDifferenceType.Deleted:
					status = VersionStatus.ScheduledDelete;
					break;
				case TreeDifferenceType.Renamed:
					status = VersionStatus.ScheduledReplace;
					break;
				default:
					status = VersionStatus.Modified;
					break;
				}
				var vi = new VersionInfo (RootRepository.FromGitPath (change.Path), "", false, status | VersionStatus.Versioned, null, VersionStatus.Versioned, null);
				cset.AddFile (vi);
			}
			return cset;
		}

		public DiffInfo[] GetPushDiff (string remote, string branch)
		{
			var b = RootRepository.ReadReferences (new ReferenceOptions {
				Flags = ReferenceOptionFlags.RefsHeads | ReferenceOptionFlags.RefsRemotes,
			}) [remote + "/" + branch];

			ICommit reference = b.Commit;
			ICommit compared = RootRepository.Head.Commit;

			var diffs = new List<DiffInfo> ();
			foreach (var change in GitUtil.CompareCommits (RootRepository, reference, compared).Entries) {
				string path = change.Path;

				var patch = new PatchCommand (RootRepository).Diff (path, reference, compared);
				// Trim the header by taking out the first 2 lines.
				int diffStart = patch.IndexOf ('\n', patch.IndexOf ('\n') + 1);
				diffs.Add (new DiffInfo (RootPath, RootRepository.FromGitPath (path), patch.Substring (diffStart + 1)));
			}
			return diffs.ToArray ();
		}

		protected override void OnMoveFile (FilePath localSrcPath, FilePath localDestPath, bool force, ProgressMonitor monitor)
		{
			var srcRepo = GetRepository (localSrcPath);
			var dstRepo = GetRepository (localDestPath);

			VersionInfo vi = GetVersionInfo (localSrcPath, VersionInfoQueryFlags.IgnoreCache);
			if (vi == null || !vi.IsVersioned) {
				base.OnMoveFile (localSrcPath, localDestPath, force, monitor);
				return;
			}

			vi = GetVersionInfo (localDestPath, VersionInfoQueryFlags.IgnoreCache);
			if (vi != null && ((vi.Status & (VersionStatus.ScheduledDelete | VersionStatus.ScheduledReplace)) != VersionStatus.Unversioned))
				dstRepo.Unstage (localDestPath);

			if (srcRepo == dstRepo) {
				if (string.Equals (localSrcPath, localDestPath, StringComparison.OrdinalIgnoreCase)) {
					try {
						string temp = Path.GetTempFileName ();
						File.Delete (temp);
						File.Move (localSrcPath, temp);
						DeleteFile (localSrcPath, true, monitor, false);
						File.Move (temp, localDestPath);
					} finally {
						srcRepo.Stage (localDestPath);
					}
				} else {
					//srcRepo.Move (localSrcPath, localDestPath);
				}
				ClearCachedVersionInfo (localSrcPath, localDestPath);
			} else {
				File.Copy (localSrcPath, localDestPath);
				srcRepo.Remove (localSrcPath, true);
				dstRepo.Stage (localDestPath);
			}
		}

		protected override void OnMoveDirectory (FilePath localSrcPath, FilePath localDestPath, bool force, ProgressMonitor monitor)
		{
			VersionInfo[] versionedFiles = GetDirectoryVersionInfo (localSrcPath, false, true);
			base.OnMoveDirectory (localSrcPath, localDestPath, force, monitor);
			monitor.BeginTask (GettextCatalog.GetString ("Moving files"), versionedFiles.Length);
			foreach (VersionInfo vif in versionedFiles) {
				if (vif.IsDirectory)
					continue;
				FilePath newDestPath = vif.LocalPath.ToRelative (localSrcPath).ToAbsolute (localDestPath);
				Add (newDestPath, false, monitor);
				monitor.Step (1);
			}
			monitor.EndTask ();
		}

		public override Annotation [] GetAnnotations (FilePath repositoryPath, Revision since)
		{
			var repository = GetRepository (repositoryPath);
			ICommit hc = GetHeadCommit (repository);
			//ICommit sinceCommit = since != null ? ((GitRevision)since).Commit : null;
			if (hc == null)
				return new Annotation [0];

			//var list = new List<Annotation> ();

			//var baseDocument = Mono.TextEditor.TextDocument.CreateImmutableDocument (GetBaseText (repositoryPath));
			//var workingDocument = Mono.TextEditor.TextDocument.CreateImmutableDocument (File.ReadAllText (repositoryPath));

			repositoryPath = repository.ToGitPath (repositoryPath);

			// TODO:
			return new Annotation [0];
			/*
			var status = repository.RetrieveStatus (repositoryPath);
			if (status != FileStatus.NewInIndex && status != FileStatus.NewInWorkdir) {
				foreach (var hunk in repository.Blame (repositoryPath, new BlameOptions { FindExactRenames = true, StartingAt = sinceCommit })) {
					var commit = hunk.FinalCommit;
					var author = hunk.FinalSignature;
					var working = new Annotation (new GitRevision (this, repository, commit), author.Name, author.When.LocalDateTime, String.Format ("<{0}>", author.Email));
					for (int i = 0; i < hunk.LineCount; ++i)
						list.Add (working);
				}
			}

			if (sinceCommit == null) {
				Annotation nextRev = new Annotation (null, GettextCatalog.GetString ("<uncommitted>"), DateTime.MinValue, null, GettextCatalog.GetString ("working copy"));
				foreach (var hunk in baseDocument.Diff (workingDocument, includeEol: false)) {
					list.RemoveRange (hunk.RemoveStart - 1, hunk.Removed);
					for (int i = 0; i < hunk.Inserted; ++i) {
						if (hunk.InsertStart + i >= list.Count)
							list.Add (nextRev);
						else
							list.Insert (hunk.InsertStart - 1, nextRev);
					}
				}
			}

			return list.ToArray ();
			*/
		}

		protected override void OnIgnore (FilePath[] localPath)
		{
			var ignored = new List<FilePath> ();
			string gitignore = RootPath + Path.DirectorySeparatorChar + ".gitignore";
			string txt;
			if (File.Exists (gitignore)) {
				using (var br = new StreamReader (gitignore)) {
					while ((txt = br.ReadLine ()) != null) {
						ignored.Add (txt);
					}
				}
			}

			var sb = new StringBuilder ();
			foreach (var path in localPath.Except (ignored))
				sb.AppendLine (RootRepository.ToGitPath (path));

			File.AppendAllText (RootPath + Path.DirectorySeparatorChar + ".gitignore", sb.ToString ());
			RootRepository.Stage (".gitignore");
		}

		protected override void OnUnignore (FilePath[] localPath)
		{
			var ignored = new List<string> ();
			string gitignore = RootPath + Path.DirectorySeparatorChar + ".gitignore";
			string txt;
			if (File.Exists (gitignore)) {
				using (var br = new StreamReader (RootPath + Path.DirectorySeparatorChar + ".gitignore")) {
					while ((txt = br.ReadLine ()) != null) {
						ignored.Add (txt);
					}
				}
			}

			var sb = new StringBuilder ();
			foreach (var path in ignored.Except (RootRepository.ToGitPath (localPath)))
				sb.AppendLine (path);

			File.WriteAllText (RootPath + Path.DirectorySeparatorChar + ".gitignore", sb.ToString ());
			RootRepository.Stage (".gitignore");
		}

		public override bool GetFileIsText (FilePath path)
		{
			ICommit c = GetHeadCommit (GetRepository (path));
			if (c == null)
				return base.GetFileIsText (path);

			var blob = GetBlob (c, path);
			if (blob == null)
				return base.GetFileIsText (path);

			return !blob.CanRead;
		}
	}

	public class GitRevision: Revision
	{
		readonly string rev;
		internal ICommit Commit { get; set; }
		internal FilePath FileForChanges { get; set; }

		public Microsoft.Alm.GitProcessManagement.IRepository GitRepository {
			get; private set;
		}

		public GitRevision (Repository repo, Microsoft.Alm.GitProcessManagement.IRepository gitRepository, ICommit commit) : base(repo)
		{
			GitRepository = gitRepository;
			Commit = commit;
			rev = Commit != null ? Commit.ObjectId.RevisionText : "";
		}

		public GitRevision (Repository repo, Microsoft.Alm.GitProcessManagement.IRepository gitRepository, ICommit commit, DateTime time, string author, string message) : base(repo, time, author, message)
		{
			GitRepository = gitRepository;
			Commit = commit;
			rev = Commit != null ? Commit.ObjectId.RevisionText : "";
		}

		public override string ToString ()
		{
			return rev;
		}

		public override string ShortName {
			get { return rev.Length > 10 ? rev.Substring (0, 10) : rev; }
		}

		public override Revision GetPrevious ()
		{
			var oid = Commit.ParentIdentities.FirstOrDefault ();
			if (oid == ObjectId.Zero)
				return null;
			
			var id = GitRepository.ReadObject<Commit> (oid);
			return id == null ? null : new GitRevision (Repository, GitRepository, id);
		}
	}
}
