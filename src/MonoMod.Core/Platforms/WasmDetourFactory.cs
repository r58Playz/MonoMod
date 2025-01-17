using MonoMod.Utils;
using System;
using System.Reflection;
using System.Runtime.InteropServices;

namespace MonoMod.Core.Platforms
{
    /// <summary>
    /// An <see cref="IDetourFactory"/> implementation based on LibA.
    /// </summary>
    internal sealed class WasmDetourFactory : IDetourFactory
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

        public ICoreNativeDetour CreateNativeDetour(CreateNativeDetourRequest request)
        {
            throw new NotSupportedException("Native detours are not supported on WASM.");
        }

        public static class LibA
        {
            [DllImport("liba")]
            public static extern IntPtr magictranslate(IntPtr ptr);
            [DllImport("liba")]
            public static extern void magicinvalidate(IntPtr ptr);
            [DllImport("liba")]
            public static extern void magicwrap(IntPtr ptr);
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

            private byte[] ReadCode(IntPtr ptr, UInt32 len)
            {
                byte[] code = new byte[len];
                for (int i = 0; i < len; i++)
                {
                    code[i] = Marshal.ReadByte(ptr + i);
                }
                return code;
            }
            private void WriteCode(IntPtr ptr, byte[] code)
            {
                Marshal.Copy(code, 0, ptr, code.Length);
            }

            private void WriteZeros(IntPtr ptr, UInt32 len)
            {
                for (int i = 0; i < len; i++)
                {
                    Marshal.WriteByte(ptr + i, 0x00);
                }
            }

            public void Apply()
            {
                MMDbgLog.Trace($"Applying managed detour from {Source} to {Target}");

                IntPtr source = triple.Runtime.GetMethodHandle(Source).GetFunctionPointer();
                IntPtr codeptr = LibA.magictranslate(source);
                UInt32 codelen = LibA.magictranslatelen(source);

                IntPtr target = triple.Runtime.GetMethodHandle(Target).GetFunctionPointer();
                Int32 targetPtr = triple.Runtime.GetMethodHandle(Target).GetFunctionPointer().ToInt32();
                byte[] jump = {
                    0x20, // ldc.i4
                    (byte)(targetPtr & 0xFF),
                    (byte)((targetPtr & 0xFF00) >> 8),
                    (byte)((targetPtr & 0xFF0000) >> 16),
                    (byte)((targetPtr & 0xFF000000) >> 24), // fnptr
                    0xD3, // convert to native int?
                    0x29, 0x02, 0x00, 0x00, 0x00,
                    0x00,
                    0x2A,
                };

                if (jump.Length > codelen) throw new Exception($"Jump patch was too big for code! (jump len {jump.Length} while code len {codelen})");

                OldCode = ReadCode(codeptr, codelen);
                WriteZeros(codeptr, codelen);
                WriteCode(codeptr, jump);

                triple.PinMethodIfNeeded(Source);
                triple.PinMethodIfNeeded(Target);

                LibA.magicwrap(source);
                LibA.magicinvalidate(source);
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
