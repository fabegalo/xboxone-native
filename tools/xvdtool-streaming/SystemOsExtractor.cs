// SPDX-License-Identifier: GPL-2.0-only
// External XvdTool.Streaming integration; not linked to the BSD runtime.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using DiscUtils;
using DiscUtils.Ntfs;
using DiscUtils.Partitions;
using LibXboxOne;

namespace XvdTool.Streaming;

internal static class SystemOsExtractor
{
    private static void NoLinks(string path)
    {
        if (path.Replace('\\', '/').Split('/').Contains(".."))
            throw new IOException("Parent traversal is not accepted.");
        for (var p = new FileInfo(Path.GetFullPath(path)) as System.IO.FileSystemInfo; p != null;
             p = p is DirectoryInfo d ? d.Parent : ((FileInfo)p).Directory)
            if (p.Exists && (p.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Linked source/output paths are not accepted.");
    }

    private static XvdHeader ReadHeader(Stream stream)
    {
        if (stream.Length < 0x3000) throw new InvalidDataException("Truncated XVD header.");
        stream.Position = 0;
        using var reader = new BinaryReader(stream, System.Text.Encoding.UTF8, leaveOpen: true);
        var header = reader.ReadStruct<XvdHeader>();
        if (new string(header.Magic) != "msft-xvd") throw new InvalidDataException("Invalid XVD magic.");
        if (header.FormatVersion != 3 || header.DriveSize == 0 || header.DriveSize > long.MaxValue
            || ((uint)header.VolumeFlags & ~0x1fu) != 0)
            throw new InvalidDataException("Unsupported XVD version, flags or disk size.");
        return header;
    }

    public static bool Handles(string path)
    {
        if (path.StartsWith("http", StringComparison.OrdinalIgnoreCase)) return false;
        NoLinks(path);
        using var stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return (uint)ReadHeader(stream).ContentType == 2;
    }

    private static string Destination(string root, string name)
    {
        var parts = name.Replace('\\', '/').Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0 || parts.Any(p => p is "." or ".." || p.Contains(':')))
            throw new IOException("Unsafe guest file path.");
        var path = Path.GetFullPath(Path.Combine(root, Path.Combine(parts)));
        if (!path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new IOException("Guest file path escapes output.");
        return path;
    }

    private static void Collect(DiscDirectoryInfo directory, List<DiscFileInfo> files, int depth,
                                HashSet<string> directories)
    {
        if (depth > 128 || directories.Count >= 100000 || !directories.Add(directory.FullName))
            throw new IOException("Filesystem directory limit/cycle detected.");
        if ((directory.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Guest reparse directories are not followed.");
        foreach (var file in directory.GetFiles())
        {
            if (files.Count >= 100000 || (file.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Filesystem file limit/reparse file detected.");
            files.Add(file);
        }
        foreach (var child in directory.GetDirectories()) Collect(child, files, depth + 1, directories);
    }

    public static int Extract(string source, string output)
    {
        NoLinks(source);
        NoLinks(output);
        output = Path.GetFullPath(output);
        if (File.Exists(output) || Directory.Exists(output))
            throw new IOException("Output must not already exist; nothing is replaced.");
        using var original = File.Open(source, FileMode.Open, FileAccess.Read, FileShare.Read);
        var header = ReadHeader(original);
        if ((uint)header.ContentType != 2) throw new InvalidDataException("SystemOS XVD required.");
        if (!header.VolumeFlags.HasFlag(XvdVolumeFlags.EncryptionDisabled))
        {
            Console.Error.WriteLine("SystemOS payload is encrypted; no readable disk/BAT is available. No key loading or output attempted.");
            return 3;
        }
        if (header.Type != XvdType.Fixed && header.Type != XvdType.Dynamic)
            throw new InvalidDataException("Unsupported XVD disk type.");
        var parent = Path.GetDirectoryName(output) ?? throw new IOException("Output parent required.");
        Directory.CreateDirectory(parent);
        var stage = Path.Combine(parent, ".systemos-extract-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(stage);
        var fileRoot = Path.Combine(stage, "files");
        Directory.CreateDirectory(fileRoot);
        long bytes = 0;
        var count = 0;
        try
        {
            // Upstream XvdFile requests read/write access. It only sees this private copy.
            var copy = Path.Combine(stage, "input.xvd");
            original.Position = 0;
            using (var target = File.Open(copy, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                original.CopyTo(target);
            using (var xvd = new XvdFile(copy))
            {
                if (!xvd.Load() || !xvd.HashTreeValid || !xvd.DataHashTreeValid || !xvd.XvcDataHashValid)
                    throw new InvalidDataException("XVD metadata/integrity validation failed.");
                if (header.Type == XvdType.Dynamic)
                {
                    var blocks = XvdMath.BytesToBlocks(header.DriveSize);
                    if (header.DynamicHeaderLength < blocks * sizeof(uint))
                        throw new InvalidDataException("Truncated SystemOS BAT.");
                    for (ulong block = 0; block < blocks; block++)
                    {
                        var page = xvd.ReadBat(block);
                        if (page != XvdFile.INVALID_SECTOR && page % XvdFile.PAGES_PER_BLOCK != 0)
                            throw new InvalidDataException("Invalid SystemOS BAT entry alignment.");
                    }
                }
                using var disk = new XvdFilesystemStream(xvd);
                var geometry = Geometry.FromCapacity(disk.Length, (int)header.SectorSize);
                PartitionTable table;
                try
                {
                    table = new GuidPartitionTable(disk, geometry);
                    if (table.Partitions.Count == 0) throw new InvalidDataException("Empty GPT.");
                }
                catch (InvalidDataException) { table = new BiosPartitionTable(disk, geometry); }
                catch (IOException) { table = new BiosPartitionTable(disk, geometry); }
                if (table.Partitions.Count == 0) throw new InvalidDataException("No disk partitions found.");
                var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                for (var partition = 0; partition < table.Partitions.Count; partition++)
                {
                    using var content = table.Partitions[partition].Open();
                    using var fs = new NtfsFileSystem(content);
                    var files = new List<DiscFileInfo>();
                    Collect(fs.Root, files, 0, new HashSet<string>(StringComparer.OrdinalIgnoreCase));
                    foreach (var file in files)
                    {
                        var relative = table.Partitions.Count == 1 ? file.FullName :
                            "partition-" + partition + "/" + file.FullName.TrimStart('\\', '/');
                        var path = Destination(fileRoot, relative);
                        if (!names.Add(path)) throw new IOException("Duplicate guest file destination.");
                        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                        using var input = file.OpenRead();
                        using var target = File.Open(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                        input.CopyTo(target);
                        if (target.Length != file.Length) throw new IOException("Incomplete guest file extraction.");
                        bytes = checked(bytes + target.Length);
                        count++;
                    }
                }
            }
            Directory.Move(fileRoot, output);
            Console.WriteLine($"Extracted SystemOS files={count}; bytes={bytes}; source_read_only=true");
            return 0;
        }
        finally
        {
            // Only this invocation's checked, randomly named staging directory is owned.
            if (Path.GetFullPath(stage).StartsWith(parent + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
                && Path.GetFileName(stage).StartsWith(".systemos-extract-", StringComparison.Ordinal))
                Directory.Delete(stage, recursive: true);
        }
    }
}
