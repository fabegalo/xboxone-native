// SPDX-License-Identifier: GPL-2.0-only
// Owned NTFS/XVD fixtures for the external extractor, not console software.
using System;
using System.Buffers.Binary;
using System.IO;
using System.Text;
using DiscUtils;
using DiscUtils.Ntfs;
using DiscUtils.Partitions;
using DiscUtils.Streams;
using LibXboxOne;

internal static class OwnedXvdFixture
{
    public static int Main(string[] args)
    {
        if (args.Length != 1) return 2;
        Directory.CreateDirectory(args[0]);
        const int size = 32 * 1024 * 1024;
        using var disk = new MemoryStream(new byte[size], writable: true);
        var geometry = Geometry.FromCapacity(size, 512);
        var table = BiosPartitionTable.Initialize(disk, geometry);
        var number = table.Create(WellKnownPartitionType.WindowsNtfs, false);
        var partition = table.Partitions[number];
        using (var content = partition.Open())
        using (var fs = NtfsFileSystem.Format(content, "OWNED", geometry,
                   partition.FirstSector, partition.SectorCount, new NtfsFormatOptions()))
        {
            fs.CreateDirectory("shell");
            using var file = fs.OpenFile("shell\\owned.txt", FileMode.Create, FileAccess.Write);
            file.Write(Encoding.UTF8.GetBytes("Owned fixture payload; not Xbox software.\n"));
        }
        foreach (var dynamic in new[] { false, true })
        {
            var header = new byte[0x3000];
            Encoding.ASCII.GetBytes("msft-xvd").CopyTo(header, 0x200);
            void U32(int offset, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(offset), value);
            U32(0x208, 14); // Plaintext, integrity disabled, 512-byte sectors.
            U32(0x20c, 3);
            BinaryPrimitives.WriteUInt64LittleEndian(header.AsSpan(0x218), size);
            U32(0x280, dynamic ? 1u : 0u);
            U32(0x284, 2);
            U32(0x298, 0xaa000);
            const int block = 0xaa000;
            const int staticBytes = 169 * 4096;
            var allocated = (size - staticBytes + block - 1) / block;
            var entries = (size + block - 1) / block;
            var dynamicBytes = dynamic ? entries * 4 : 0;
            U32(0x294, (uint)dynamicBytes);
            var path = Path.Combine(args[0], dynamic ? "dynamic.xvd" : "fixed.xvd");
            using var output = File.Open(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None);
            output.Write(header);
            if (dynamic)
            {
                var bat = new byte[4096];
                for (var i = 0; i < entries; i++)
                    BinaryPrimitives.WriteUInt32LittleEndian(bat.AsSpan(i * 4),
                        i < allocated ? (uint)(170 + i * 170) : 0xffffffff);
                output.Write(bat);
            }
            disk.Position = 0;
            disk.CopyTo(output);
            if (dynamic) output.SetLength(0x4000L + staticBytes + (long)allocated * block);
        }
        var hashed = Path.Combine(args[0], "hashed-fixed.xvd");
        File.Copy(Path.Combine(args[0], "fixed.xvd"), hashed, overwrite: false);
        using (var xvd = new XvdFile(hashed))
            if (!xvd.Load() || !xvd.AddHashTree()) throw new IOException("Owned hash fixture creation failed.");
        Console.WriteLine("Created fixed, dynamic and hashed owned plaintext SystemOS-type XVD fixtures.");
        return 0;
    }
}
