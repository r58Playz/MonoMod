using Mono.Cecil;
using Mono.Cecil.Cil;
using MonoMod.Utils.Cil;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;
#if NETFRAMEWORK
using System.Diagnostics.SymbolStore;
#endif

namespace MonoMod.Utils
{
    internal static partial class _DMDEmit
    {

        private static readonly Dictionary<short, System.Reflection.Emit.OpCode> _ReflOpCodes = new Dictionary<short, System.Reflection.Emit.OpCode>();
        private static readonly Dictionary<short, Mono.Cecil.Cil.OpCode> _CecilOpCodes = new Dictionary<short, Mono.Cecil.Cil.OpCode>();

        static _DMDEmit()
        {
            foreach (var field in typeof(System.Reflection.Emit.OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static))
            {
                var reflOpCode = (System.Reflection.Emit.OpCode)field.GetValue(null)!;
                _ReflOpCodes[reflOpCode.Value] = reflOpCode;
            }

            foreach (var field in typeof(Mono.Cecil.Cil.OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static))
            {
                var cecilOpCode = (Mono.Cecil.Cil.OpCode)field.GetValue(null)!;
                _CecilOpCodes[cecilOpCode.Value] = cecilOpCode;
            }
        }

        public static void Generate(DynamicMethodDefinition dmd, MethodBase _mb, ILGenerator il)
        {
            var def = dmd.Definition ?? throw new InvalidOperationException();
            var dm = _mb as DynamicMethod;
#if NETFRAMEWORK
            var mb = _mb as MethodBuilder;
            var moduleBuilder = mb?.Module as ModuleBuilder;
            // moduleBuilder.Assembly sometimes avoids the .Assembly override under mysterious circumstances.
            var assemblyBuilder = (mb?.DeclaringType as TypeBuilder)?.Assembly as AssemblyBuilder;
            HashSet<Assembly>? accessChecksIgnored = null;
            if (mb != null) {
                accessChecksIgnored = new HashSet<Assembly>();
            }
#endif

#if !CECIL0_9
            var defInfo = dmd.Debug ? def.DebugInformation : null;
#endif

            if (dm != null)
            {
                foreach (var param in def.Parameters)
                {
                    dm.DefineParameter(param.Index + 1, (System.Reflection.ParameterAttributes)param.Attributes, param.Name);
                }
            }
#if NETFRAMEWORK
            if (mb != null) {
                foreach (var param in def.Parameters) {
                    mb.DefineParameter(param.Index + 1, (System.Reflection.ParameterAttributes) param.Attributes, param.Name);
                }
            }
#endif

            var locals = def.Body.Variables.Select(
                var =>
                {
                    var local = il.DeclareLocal(var.VariableType.ResolveReflection(), var.IsPinned);
#if NETFRAMEWORK && !CECIL0_9
                    if (mb != null && defInfo != null && defInfo.TryGetName(var, out var name)) {
                        local.SetLocalSymInfo(name);
                    }
#endif
                    return local;
                }
            ).ToArray();

            // Pre-pass - Set up label map.
            var labelMap = new Dictionary<Instruction, Label>();
            foreach (var instr in def.Body.Instructions)
            {
                if (instr.Operand is Instruction[] targets)
                {
                    foreach (var target in targets)
                        if (!labelMap.ContainsKey(target))
                            labelMap[target] = il.DefineLabel();

                }
                else if (instr.Operand is Instruction target)
                {
                    if (!labelMap.ContainsKey(target))
                        labelMap[target] = il.DefineLabel();
                }
            }

#if NETFRAMEWORK
            var infoDocCache = mb == null ? null : new Dictionary<Document, ISymbolDocumentWriter>();
#endif

            var paramOffs = def.HasThis ? 1 : 0;
            var emitArgs = new object?[2];
            var checkTryEndEarly = false;
            var skipInstrEmit = false;
            foreach (var instr in def.Body.Instructions)
            {
                if (labelMap.TryGetValue(instr, out var label))
                    il.MarkLabel(label);

#if NETFRAMEWORK
                var instrInfo = defInfo?.GetSequencePoint(instr);
                if (mb is not null && instrInfo is not null && infoDocCache is not null && moduleBuilder is not null) {
                    if (!infoDocCache.TryGetValue(instrInfo.Document, out var infoDoc)) {
                        infoDocCache[instrInfo.Document] = infoDoc = moduleBuilder.DefineDocument(
                            instrInfo.Document.Url,
                            instrInfo.Document.LanguageGuid,
                            instrInfo.Document.LanguageVendorGuid,
                            instrInfo.Document.TypeGuid
                        );
                    }
                    il.MarkSequencePoint(infoDoc, instrInfo.StartLine, instrInfo.StartColumn, instrInfo.EndLine, instrInfo.EndColumn);
                }
#endif

                foreach (var handler in def.Body.ExceptionHandlers)
                {
                    if (checkTryEndEarly && handler.HandlerEnd == instr)
                    {
                        il.EndExceptionBlock();
                    }

                    if (handler.TryStart == instr)
                    {
                        il.BeginExceptionBlock();
                    }
                    else if (handler.FilterStart == instr)
                    {
                        il.BeginExceptFilterBlock();
                    }
                    else if (handler.HandlerStart == instr)
                    {
                        switch (handler.HandlerType)
                        {
                            case ExceptionHandlerType.Filter:
                                il.BeginCatchBlock(null!); // This parameter should be null for filter blocks, even though the compiler doesn't thihnk so.
                                break;
                            case ExceptionHandlerType.Catch:
                                il.BeginCatchBlock(handler.CatchType.ResolveReflection());
                                break;
                            case ExceptionHandlerType.Finally:
                                il.BeginFinallyBlock();
                                break;
                            case ExceptionHandlerType.Fault:
                                il.BeginFaultBlock();
                                break;
                        }

                    }

                    // Avoid duplicate endfilter / endfinally when another handler starts next.
                    // ILGenerator.BeginFinallyBlock/BeginCatchBlock/BeginExceptFilterBlock call
                    // InternalEndClause() which emits an implicit endfinally/endfilter.
                    if (handler.HandlerStart == instr.Next)
                    {
                        switch (handler.HandlerType)
                        {
                            case ExceptionHandlerType.Filter:
                                if (instr.OpCode == Mono.Cecil.Cil.OpCodes.Endfilter)
                                    goto SkipEmit;
                                break;
                            case ExceptionHandlerType.Finally:
                                if (instr.OpCode == Mono.Cecil.Cil.OpCodes.Endfinally)
                                    goto SkipEmit;
                                break;
                        }
                    }

                    // Avoid duplicate leave when a handler starts next.
                    // ILGenerator.BeginFinallyBlock/BeginCatchBlock/BeginFaultBlock call
                    // InternalEndClause() which emits an implicit "leave end" when the
                    // last clause type is CATCH/FILTER (i.e., first handler in try block,
                    // or after a catch/filter handler). If the source IL has an explicit
                    // leave right before the handler start, we get two consecutive leave
                    // instructions. The second (implicit) one is dead code, but the v10
                    // Mono interpreter's BB_STATE system mishandles this pattern, causing
                    // infinite loops. Skip the explicit leave only when the implicit one
                    // targets the same destination (the end of the last handler in this
                    // exception block = HandlerEnd of the last handler sharing TryStart).
                    if (handler.HandlerStart == instr.Next
                        && (instr.OpCode == Mono.Cecil.Cil.OpCodes.Leave || instr.OpCode == Mono.Cecil.Cil.OpCodes.Leave_S))
                    {
                        // Determine what InternalEndClause would emit. It emits "leave end"
                        // when LastClauseType() returns CATCH or FILTER. For the first handler
                        // in a try block (no prior handlers), LastClauseType() returns CATCH.
                        // After a FINALLY/FAULT handler, it emits endfinally instead (already
                        // handled above). So we check: would InternalEndClause emit a leave?
                        bool wouldEmitLeave;
                        // Find the previous handler in the same exception block (same TryStart)
                        var prevHandler = def.Body.ExceptionHandlers
                            .Where(h => h.TryStart == handler.TryStart && h != handler
                                     && h.HandlerStart?.Offset < handler.HandlerStart?.Offset)
                            .OrderByDescending(h => h.HandlerStart?.Offset)
                            .FirstOrDefault();
                        if (prevHandler == null)
                        {
                            // First handler in try block: LastClauseType() returns CATCH → emits leave
                            wouldEmitLeave = true;
                        }
                        else
                        {
                            // After a handler: depends on its type
                            wouldEmitLeave = prevHandler.HandlerType == ExceptionHandlerType.Catch
                                          || prevHandler.HandlerType == ExceptionHandlerType.Filter;
                        }

                        if (wouldEmitLeave)
                        {
                            // The implicit "leave end" targets the end label, which gets marked
                            // at EndExceptionBlock at HandlerEnd of the last handler in this block.
                            var lastHandler = def.Body.ExceptionHandlers
                                .Where(h => h.TryStart == handler.TryStart)
                                .OrderByDescending(h => h.HandlerStart?.Offset)
                                .First();
                            var endTarget = lastHandler.HandlerEnd;
                            var explicitTarget = (Instruction)instr.Operand;

                            if (explicitTarget == endTarget)
                            {
                                // Both leave instructions target the same destination.
                                // Skip the explicit one to avoid dead code that confuses
                                // the v10 Mono interpreter.
                                skipInstrEmit = true;
                            }
                        }
                    }

                    // Avoid duplicate endfinally / endfault at end of handler.
                    // ILGenerator.EndExceptionBlock() calls InternalEndClause() which
                    // emits an implicit endfinally, so skip the explicit one from source IL.
                    // We use skipInstrEmit instead of goto SkipEmit here because SkipEmit
                    // defers EndExceptionBlock to the next iteration (via checkTryEndEarly),
                    // which would place it AFTER the next instruction's MarkLabel, corrupting
                    // branch targets. Instead, we skip only the emit and let EndExceptionBlock
                    // fire at its normal position (lines below), before the next MarkLabel.
                    if (handler.HandlerEnd == instr.Next)
                    {
                        switch (handler.HandlerType)
                        {
                            case ExceptionHandlerType.Finally:
                            case ExceptionHandlerType.Fault:
                                if (instr.OpCode == Mono.Cecil.Cil.OpCodes.Endfinally)
                                {
                                    skipInstrEmit = true;
                                }
                                break;
                        }
                    }
                }

                if (!skipInstrEmit)
                {
                if (instr.OpCode.OperandType == Mono.Cecil.Cil.OperandType.InlineNone)
                    il.Emit(_ReflOpCodes[instr.OpCode.Value]);
                else
                {
                    var opcode = instr.OpCode;
                    var operand = instr.Operand;

                    if (operand is Instruction[] targets)
                    {
                        operand = targets.Select(target => labelMap[target]).ToArray();
                        // Let's hope that the JIT treats the long forms identically to the short forms.
                        opcode = opcode.ToLongOp();

                    }
                    else if (operand is Instruction target)
                    {
                        operand = labelMap[target];
                        // Let's hope that the JIT treats the long forms identically to the short forms.
                        opcode = opcode.ToLongOp();

                    }
                    else if (operand is VariableDefinition var)
                    {
                        operand = locals[var.Index];

                    }
                    else if (operand is ParameterDefinition param)
                    {
                        operand = param.Index + paramOffs;

                    }
                    else if (operand is MemberReference mref)
                    {
                        var member = mref == def ? _mb : mref.ResolveReflection();
                        operand = member;
#if NETFRAMEWORK
                        if (mb != null && member != null) {
                            // See DMDGenerator.cs for the explanation of this forced .?
                            var module = member.Module;
                            if (module == null)
                                continue;
                            var asm = module.Assembly;
                            if (asm != null && accessChecksIgnored is not null && assemblyBuilder is not null && !accessChecksIgnored.Contains(asm)) {
                                // while (member.DeclaringType != null)
                                //     member = member.DeclaringType;
                                assemblyBuilder.SetCustomAttribute(new CustomAttributeBuilder(DynamicMethodDefinition.c_IgnoresAccessChecksToAttribute, new object[] {
                                    asm.GetName().Name
                                }));
                                accessChecksIgnored.Add(asm);
                            }
                        }
#endif

                    }
                    else if (operand is CallSite csite)
                    {
                        if (dm != null)
                        {
                            // SignatureHelper in unmanaged contexts cannot be fully made use of for DynamicMethods.
                            _EmitCallSite(dm, il, _ReflOpCodes[opcode.Value], csite);
                            continue;
                        }
#if NETFRAMEWORK
                        if (mb is not null) {
                            operand = csite.ResolveReflection(mb.Module);
                        } else
#endif
                        {
                            throw new NotSupportedException();
                        }
                    }

#if NETFRAMEWORK
                    if (mb != null && operand is MethodBase called && called.DeclaringType == null) {
                        // "Global" methods (f.e. DynamicMethods) cannot be tokenized.
                        if (opcode == Mono.Cecil.Cil.OpCodes.Call) {
                            if (called is MethodInfo target && target.IsDynamicMethod()) {
                                // This should be heavily optimizable.
                                operand = _CreateMethodProxy(mb, target);
                                // TODO: replace this with allocation of a reference and FastDelegateInvokers call, or similar invocation sequence
                            } else {
                                var ptr = called.GetLdftnPointer();
                                if (IntPtr.Size == 4)
                                    il.Emit(System.Reflection.Emit.OpCodes.Ldc_I4, (int) ptr);
                                else
                                    il.Emit(System.Reflection.Emit.OpCodes.Ldc_I8, (long) ptr);
                                il.Emit(System.Reflection.Emit.OpCodes.Conv_I);
                                opcode = Mono.Cecil.Cil.OpCodes.Calli;
                                operand = ((MethodReference) instr.Operand).ResolveReflectionSignature(mb.Module);
                            }
                        } else {
                            throw new NotSupportedException($"Unsupported global method operand on opcode {opcode.Name}");
                        }
                    }
#endif

                    if (operand == null)
                        throw new InvalidOperationException($"Unexpected null in {def} @ {instr}");

                    il.DynEmit(_ReflOpCodes[opcode.Value], operand);
                }
                } // !skipInstrEmit

                if (!checkTryEndEarly)
                {
                    foreach (var handler in def.Body.ExceptionHandlers)
                    {
                        if (handler.HandlerEnd == instr.Next)
                        {
                            il.EndExceptionBlock();
                        }
                    }
                }

                checkTryEndEarly = false;
                skipInstrEmit = false;
                continue;

                SkipEmit:
                checkTryEndEarly = true;
                skipInstrEmit = false;
                continue;
            }
        }

        public static void ResolveWithModifiers(TypeReference typeRef, out Type type, out Type[] typeModReq, out Type[] typeModOpt, List<Type>? modReq = null, List<Type>? modOpt = null)
        {
            if (modReq is null)
                modReq = new List<Type>();
            else
                modReq.Clear();

            if (modOpt is null)
                modOpt = new List<Type>();
            else
                modOpt.Clear();

            for (
                var mod = typeRef;
                mod is TypeSpecification modSpec;
                mod = modSpec.ElementType
            )
            {
                switch (mod)
                {
                    case RequiredModifierType paramTypeModReq:
                        modReq.Add(paramTypeModReq.ModifierType.ResolveReflection());
                        break;

                    case OptionalModifierType paramTypeOptReq:
                        modOpt.Add(paramTypeOptReq.ModifierType.ResolveReflection());
                        break;
                }
            }

            type = typeRef.ResolveReflection();
            typeModReq = modReq.ToArray();
            typeModOpt = modOpt.ToArray();
        }

    }
}
