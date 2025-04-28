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
        private static class LibA
        {
            [DllImport("liba")]
            public static extern IntPtr magictranslate(IntPtr ptr);
            [DllImport("liba")]
            public static extern void magicinvalidate(IntPtr ptr);
            [DllImport("liba")]
            public static extern UInt32 magictranslatelen(IntPtr ptr);

            [DllImport("liba")]
            public static extern void magicdetour2(IntPtr ptr, IntPtr code);
            [DllImport("liba")]
            public static extern void magicundetour2(IntPtr ptr);
        }

        internal interface IWasmDetourStrategy
        {
            public abstract void ChangeMethodCode(IntPtr method, byte[] bytes);
            public abstract void RevertMethodCode(IntPtr method);
        }

        internal sealed class HotReloadDetourStrategy : IWasmDetourStrategy
        {
            GCHandle? Method;

            private void WriteFunc(IntPtr method, byte[] func)
            {
                Method = GCHandle.Alloc(func, GCHandleType.Pinned);

                LibA.magicdetour2(method, Method.Value.AddrOfPinnedObject());
                LibA.magicinvalidate(method);
            }

            private byte[] CreateFunc(byte[] code)
            {
                List<byte> func = new();
				if (code.Length < 0b00111111) {
					// tiny
					byte header = (byte) (0x2 | (code.Length << 2));
					func.Add(header);
					func.AddRange(code);
					return func.ToArray();
				} else {
					throw new NotImplementedException("TODO generate fat headers");
				}
            }

            public void ChangeMethodCode(IntPtr method, byte[] bytes)
            {
				MMDbgLog.Trace($"[HotReloadDetour] Detouring");
				WriteFunc(method, CreateFunc(bytes));
            }

            public void RevertMethodCode(IntPtr method)
            {
                if (!Method.HasValue) throw new Exception("Trying to Undo() a Detour that was not applied");

				MMDbgLog.Trace($"[HotReloadDetour] Undetouring");
                LibA.magicundetour2(method);

                Method.Value.Free();
				Method = null;
            }
        }

        internal sealed class MagicOverwriteDetourStrategy : IWasmDetourStrategy
        {
            private byte[]? OldCode;

            private static byte[] ReadCode(IntPtr ptr, UInt32 len)
            {
                byte[] code = new byte[len];
                for (int i = 0; i < len; i++)
                {
                    code[i] = Marshal.ReadByte(ptr + i);
                }
                return code;
            }

            private static byte[] OverwriteCode(IntPtr ptr, UInt32 len, byte[] code)
            {
                byte[] oldCode = ReadCode(ptr, len);

                for (int i = 0; i < len; i++)
                {
                    Marshal.WriteByte(ptr + i, 0x00);
                }
                Marshal.Copy(code, 0, ptr, code.Length);

                return oldCode;
            }

            public void ChangeMethodCode(IntPtr method, byte[] bytes)
            {
                IntPtr codeptr = LibA.magictranslate(method);
                UInt32 codelen = LibA.magictranslatelen(method);

                if (bytes.Length > codelen) throw new Exception($"Jump patch was too big for code! (jump len {bytes.Length} while code len {codelen})");

                MMDbgLog.Trace($"[MagicOverwriteDetour] Got Code ptr: {codeptr:X} {codelen}");

                byte[] oldCode = OverwriteCode(codeptr, codelen, bytes);

                MMDbgLog.Trace($"[MagicOverwriteDetour] Wrote to code ptr: {codeptr:X} {codelen}");

                OldCode = oldCode;
            }

            public void RevertMethodCode(IntPtr method)
            {
                if (OldCode == null) throw new Exception("Trying to Undo() a Detour that was not applied");
                ChangeMethodCode(method, OldCode);
                OldCode = null;
            }
        }

        private sealed class Detour : ICoreDetourBase, ICoreDetour
        {
            public MethodBase Source { get; }

            public MethodBase Target { get; }

            public bool IsApplied { get; private set; }

            private PlatformTriple triple;

            private IWasmDetourStrategy? Strategy;

            public Detour(PlatformTriple triple, MethodBase src, MethodBase dst)
            {
                Source = src; // triple.GetIdentifiable(src);
                Target = dst;

                this.triple = triple;

                IsApplied = false;
            }

            private byte[] BuildDetourBytes(IntPtr source, IntPtr target)
            {
                List<byte> il = new();

                int argCount = Source.GetParameters().Length;
                if (!Source.IsStatic)
                    argCount++; // this parameter

                foreach (var i in Enumerable.Range(0, argCount))
                {
                    if (i < 4)
                    {
                        il.Add((byte)(0x02 + i));
                    }
                    else if (i < 256)
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

			private void TryStrategies(IntPtr fn, byte[] jump) {
				Strategy = new MagicOverwriteDetourStrategy();
				try {
					MMDbgLog.Trace($"[WasmDetour] Trying MagicOverwriteDetourStrategy");
					Strategy.ChangeMethodCode(fn, jump);
				} catch (Exception e) {
					MMDbgLog.Trace($"[WasmDetour] Falling back to HotReloadDetourStrategy: {e.Message}");
					Strategy = new HotReloadDetourStrategy();
					Strategy.ChangeMethodCode(fn, jump);
				}
			}

            public void Apply()
            {
                if (Strategy != null) return;

                IntPtr source = triple.Runtime.GetMethodHandle(Source).GetFunctionPointer();
                IntPtr target = triple.Runtime.GetMethodHandle(Target).GetFunctionPointer();
                MMDbgLog.Trace($"[WasmDetour] Applying managed IL detour from {Source} ({source:X}) to {Target} ({target:X})");

                byte[] jump = BuildDetourBytes(source, target);
				TryStrategies(source, jump);

                triple.PinMethodIfNeeded(Source);
                triple.PinMethodIfNeeded(Target);

                MMDbgLog.Trace($"[WasmDetour] Pinned {source:X} and {target:X}");

                LibA.magicinvalidate(source);
                MMDbgLog.Trace($"[WasmDetour] Invalidated {source:X}");
            }

            public void Undo()
            {
                if (Strategy == null) return;

                IntPtr source = triple.Runtime.GetMethodHandle(Source).GetFunctionPointer();
                MMDbgLog.Trace($"[WasmDetour] Reverting managed IL detour on {Source} ({source:X}) ");
                Strategy.RevertMethodCode(source);
				Strategy = null;
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
    }
}
