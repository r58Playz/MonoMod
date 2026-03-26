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
        public static bool EnableTailCallDetours = false;
        public static HashSet<string> Blacklist = new();

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
            public static extern int magicdetour2allowed(IntPtr ptr);
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
            GCHandle? Code;

            private void WriteFunc(IntPtr method, byte[] func)
            {
                Code = GCHandle.Alloc(func, GCHandleType.Pinned);

                LibA.magicdetour2(method, Code.Value.AddrOfPinnedObject());
            }

            private byte[] CreateFunc(byte[] code)
            {
                // https://github.com/dotnet/runtime/blob/main/src/mono/mono/metadata/metadata.c#L4373-L4395
                List<byte> func = new();
				if (code.Length < 0b00111111) {
					byte header = (byte) (0x2 | (code.Length << 2)); // 0x2: tiny header
					func.Add(header);
					func.AddRange(code);
					return func.ToArray();
				} else {
					// currently hardcoding the stack size and locals which will probably cause mono to freak out
					MMDbgLog.Trace("[HotReloadDetour] Fat header needed, may fail");

					byte flags1 = (byte) (0x3); // 0x3: fat header
					byte flags2 = (byte) (0);

					UInt16 max_stack = (UInt16) (32);
					UInt32 code_size = (UInt32) (code.Length);
					UInt32 locals = (UInt32) (32);

					func.Add(flags1);
					func.Add(flags2);
					func.AddRange(BitConverter.GetBytes(max_stack));
					func.AddRange(BitConverter.GetBytes(code_size));
					func.AddRange(BitConverter.GetBytes(locals));
					func.AddRange(code);

					return func.ToArray();
				}
            }

            public void ChangeMethodCode(IntPtr method, byte[] bytes)
            {
                if (LibA.magicdetour2allowed(method) == 0)
					throw new NotSupportedException("HotReloadDetour is known to not work for this function type (magicdetour2NOTallowed!!)");

				MMDbgLog.Trace($"[HotReloadDetour] Detouring");
				WriteFunc(method, CreateFunc(bytes));
            }

            public void RevertMethodCode(IntPtr method)
            {
                if (!Code.HasValue) throw new Exception("Trying to Undo() a Detour that was not applied");

				MMDbgLog.Trace($"[HotReloadDetour] Undetouring");
                LibA.magicundetour2(method);

                Code.Value.Free();
				Code = null;
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

            private byte[] BuildDetourBytes(IntPtr source, IntPtr target, bool disableTailCalls = false)
            {
                List<byte> il = new();

                int argCount = Source.GetParameters().Length;
                if (!Source.IsStatic)
                    argCount++; // this parameter

                foreach (var i in Enumerable.Range(0, argCount))
                {
                    if (i < 4)
                    {
                        il.Add((byte)(0x02 + i)); // ldarg.{0,1,2,3}
                    }
                    else if (i < 256)
                    {
                        il.Add(0x0E); // ldarg.s
                        il.Add((byte)i);
                    }
                    else
                    {
                        il.AddRange([0xFE, 0x09]); // ldarg
                        il.AddRange(BitConverter.GetBytes((UInt16)i));
                    }
                }

                il.Add(0x20); // ldc.i4
                il.AddRange(BitConverter.GetBytes((Int32)target));

				// strictly worse for size but possibly faster?
                if (!disableTailCalls && WasmDetourFactory.EnableTailCallDetours) {
                    il.AddRange([0xFE, 0x14]); // tail.
				}

				il.Add(0x29); // calli
				il.AddRange([0xF0, 0xF0, 0xF0, 0xF0]); // magic number that gets specialcased by patched runtime
				il.Add(0x2A); // ret

                return il.ToArray();
            }

			private void TryStrategies(IntPtr fn, byte[] jump) {
				Strategy = new HotReloadDetourStrategy();
				try {
					MMDbgLog.Trace($"[WasmDetour] Trying HotReloadDetourStrategy");
					Strategy.ChangeMethodCode(fn, jump);
				} catch (Exception e) {
					MMDbgLog.Trace($"[WasmDetour] Falling back to MagicOverwriteDetourStrategy: {e.Message}");
					Strategy = new MagicOverwriteDetourStrategy();
					Strategy.ChangeMethodCode(fn, jump);
				}
			}

            public void Apply()
            {
                if (Strategy != null) return;

                IntPtr source = triple.Runtime.GetMethodHandle(Source).GetFunctionPointer();
                IntPtr target = triple.Runtime.GetMethodHandle(Target).GetFunctionPointer();
                MMDbgLog.Trace($"[WasmDetour] Applying managed IL detour from {Source} ({source:X}) to {Target} ({target:X})");

				try {
					TryStrategies(source, BuildDetourBytes(source, target));
				} catch(Exception e) {
					if (WasmDetourFactory.EnableTailCallDetours) {
						MMDbgLog.Trace($"[WasmDetour] tail call detour failed, trying without tail calls: {e.Message}");
						TryStrategies(source, BuildDetourBytes(source, target, true));
					} else {
						throw;
					}
				}

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

        private sealed class NullifiedDetour : ICoreDetourBase, ICoreDetour
        {
            public MethodBase Source { get; }
            public MethodBase Target { get; }
            public bool IsApplied => false;

            public NullifiedDetour(MethodBase src, MethodBase dst)
            {
                Source = src;
                Target = dst;
            }

            public void Apply() {}
            public void Undo() {}
            public void Dispose() {}
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

            string sourceAsm = request.Source.DeclaringType?.Assembly.GetName().Name ?? "Unknown";
            string targetAsm = request.Target.DeclaringType?.Assembly.GetName().Name ?? "Unknown";

            if (Blacklist.Contains(sourceAsm) || Blacklist.Contains(targetAsm))
            {
                MMDbgLog.Warning($"[WasmDetour] Skipping hook from \"{request.Source}\" to \"{request.Target}\" because containing assembly is blacklisted");
                return new NullifiedDetour(request.Source, request.Target);
            }

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
