using MonoMod.Utils;
using System;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Linq;

namespace MonoMod.Core.Platforms
{
    /// <summary>
    /// An <see cref="IDetourFactory"/> implementation based on LibA.
    /// </summary>
    public sealed class WasmDetourFactory : IDetourFactory
    {
        private readonly PlatformTriple triple;

        /// <summary>
        /// Constructs a <see cref="WasmDetourFactory"/> based on the provided <see cref="PlatformTriple"/>.
        /// </summary>
        /// <param name="triple">The <see cref="PlatformTriple"/> to create a detour factory using.</param>
        public WasmDetourFactory(PlatformTriple triple)
        {
            MMDbgLog.Warning("RE'd by velzie and r58playz :33333");
            this.triple = triple;
        }

        /// <inheritdoc/>
        public ICoreDetour CreateDetour(CreateDetourRequest request)
        {
            Helpers.ThrowIfArgumentNull(request.Source);
            Helpers.ThrowIfArgumentNull(request.Target);

            if (!triple.TryDisableInlining(request.Source))
                MMDbgLog.Warning($"Could not disable inlining of method {request.Source}; detours may not be reliable");

            var detour = new Detour(triple, request.Source, request.Target);
            if (request.ApplyByDefault)
            {
                detour.Apply();
            }
            return detour;
        }

        /// <inheritdoc/>
        public ICoreNativeDetour CreateNativeDetour(CreateNativeDetourRequest request)
        {
            throw new NotSupportedException("Native detours are not supported on WASM.");
        }

        private static class LibA
        {
            [DllImport("liba")]
            public static extern IntPtr magictranslate(IntPtr ptr);
            [DllImport("liba")]
            public static extern void magicinvalidate(IntPtr ptr);
            [DllImport("liba")]
            public static extern UInt32 magictranslatelen(IntPtr ptr);
        }

        private sealed class Detour : ICoreDetourBase, ICoreDetour
        {
            public MethodBase Source { get; }

            public MethodBase Target { get; }

            public bool IsApplied { get; private set; }

            private byte[]? OldCode;
            private PlatformTriple triple;

            public Detour(PlatformTriple triple, MethodBase src, MethodBase dst)
            {
                Source = src; // triple.GetIdentifiable(src);
                Target = dst;

                this.triple = triple;

                IsApplied = false;
            }

            private static byte[] ReadCode(IntPtr ptr, UInt32 len)
            {
                byte[] code = new byte[len];
                for (int i = 0; i < len; i++)
                {
                    code[i] = Marshal.ReadByte(ptr + i);
                }
                return code;
            }
            private static void WriteCode(IntPtr ptr, byte[] code)
            {
                Marshal.Copy(code, 0, ptr, code.Length);
            }

            private static void WriteZeros(IntPtr ptr, UInt32 len)
            {
                for (int i = 0; i < len; i++)
                {
                    Marshal.WriteByte(ptr + i, 0x00);
                }
            }

            private byte[] BuildDetourBytes(IntPtr source, IntPtr target)
            {
                List<byte> il = new();

                int argCount = Source.GetParameters().Length;
                if (!Source.IsStatic)
                    argCount++; // this parameter

                foreach (var i in Enumerable.Range(0, argCount))
                {
                    if (i < 256)
                    {
                        il.Add(0x0E); // ldarg.s
                        il.Add((byte)i); // argument idx
                    }
                    else
                    {
                        il.AddRange([0xFE, 0x09]); // ldarg
                        il.AddRange(BitConverter.GetBytes((UInt16)i)); // argument idx
                    }
                }

                il.Add(0x20); // ldc.i4 (push int32 onto stack)
                il.AddRange(BitConverter.GetBytes((Int32)target)); // pointer to target
                //il.Add(0xD3); // conv.i (convert to native int)
                il.Add(0x29); // calli
                il.AddRange([0xF0, 0xF0, 0xF0, 0xF0]); // magic number that gets specialcased by patched runtime
                il.Add(0x2A); // ret

                return il.ToArray();
            }

            public void Apply()
            {
                IntPtr source = triple.Runtime.GetMethodHandle(Source).GetFunctionPointer();
                IntPtr target = triple.Runtime.GetMethodHandle(Target).GetFunctionPointer();
                MMDbgLog.Trace($"Applying managed IL detour from {Source} ({source:X}) to {Target} ({target:X})");

                IntPtr codeptr = LibA.magictranslate(source);
                UInt32 codelen = LibA.magictranslatelen(source);

                MMDbgLog.Trace($"Got Code ptr: {codeptr:X} {codelen}");

                byte[] jump = BuildDetourBytes(source, target);
                if (jump.Length > codelen) throw new Exception($"Jump patch was too big for code! (jump len {jump.Length} while code len {codelen})");

                OldCode = ReadCode(codeptr, codelen);
                WriteZeros(codeptr, codelen);
                WriteCode(codeptr, jump);

                MMDbgLog.Trace($"Wrote to code ptr: {codeptr:X} {codelen}");

                triple.PinMethodIfNeeded(Source);
                triple.PinMethodIfNeeded(Target);

                MMDbgLog.Trace($"Pinned {source:X} and {target:X}");

                LibA.magicinvalidate(source);
                MMDbgLog.Trace($"Invalidated {source:X}");
            }

            public void Undo()
            {
                if (OldCode == null) throw new Exception("Trying to Undo() a Detour that was not applied");
                IntPtr ptr = LibA.magictranslate(triple.Runtime.GetMethodHandle(Source).GetFunctionPointer());

                WriteCode(ptr, OldCode);

                OldCode = null;
            }

            private bool disposedValue;
            private void Dispose(bool disposing)
            {
                if (!disposedValue)
                {
                    disposedValue = true;
                }
            }

            ~Detour()
            {
                // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
                Dispose(disposing: false);
            }

            public void Dispose()
            {
                // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
                Dispose(disposing: true);
                GC.SuppressFinalize(this);
            }
        }
    }
}
