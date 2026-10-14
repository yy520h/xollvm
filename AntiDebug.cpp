#include "llvm/Transforms/Obfuscator/AntiDebug.h"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/Transforms/Obfuscator/FunctionObfContextAnalysis.h"
#include "llvm/Transforms/Obfuscator/ObfuscationAnnotationAnalysis.h"
#include "llvm/Transforms/Obfuscator/ObfuscationConfig.h"
#include "llvm/Transforms/Obfuscator/Utils.h"
#include "llvm/Transforms/Obfuscator/VMPass_Plan.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

using namespace llvm;

namespace {

bool supportsAndroidArm64(const Module& M) {
	Triple T(M.getTargetTriple());
	return T.isAndroid() && T.getArch() == Triple::aarch64;
}

FunctionCallee symbol(Module& M, StringRef Name, Type* Ret,
	ArrayRef<Type*> Args, bool VarArgs = false) {
	return M.getOrInsertFunction(Name, FunctionType::get(Ret, Args, VarArgs));
}

Constant* nullPointer(LLVMContext& C) {
	return ConstantPointerNull::get(PointerType::getUnqual(C));
}

enum class Probe { Tracer, Maps, Injection, VPN, SELinux, Process, IPTables };

StringRef probeName(Probe Kind) {
	switch (Kind) {
	case Probe::Tracer: return "tracer";
	case Probe::Maps: return "maps";
	case Probe::Injection: return "injection";
	case Probe::VPN: return "vpn";
	case Probe::SELinux: return "selinux";
	case Probe::Process: return "process";
	case Probe::IPTables: return "iptables";
	}
	llvm_unreachable("unknown AntiDebug probe");
}

// 行解析统一返回：-2 无关行，-1 格式异常，0 正常，1 命中特征。
Function* lineParser(Module& M, Probe Kind) {
	std::string Name = ("__obf_ad_line_" + probeName(Kind)).str();
	if (auto* F = M.getFunction(Name)) return F;
	LLVMContext& C = M.getContext();
	Type* Ptr = PointerType::getUnqual(C);
	Type* I32 = Type::getInt32Ty(C);
	Type* I64 = Type::getInt64Ty(C);
	Function* F = Function::Create(FunctionType::get(I32, {Ptr}, false),
		GlobalValue::InternalLinkage, Name, M);
	IRBuilder<> B(BasicBlock::Create(C, "entry", F));
	Value* Line = F->getArg(0);
	auto span = [&](Value* Text, StringRef Set) {
		return B.CreateCall(symbol(M, "strspn", I64, {Ptr, Ptr}), {Text, B.CreateGlobalString(Set)});
	};
	auto trimmed = [&](Value* Text) {
		return B.CreateGEP(B.getInt8Ty(), Text, span(Text, " \t\r\n"));
	};
	auto prefix = [&](Value* Text, StringRef Token) {
		return B.CreateICmpEQ(B.CreateCall(symbol(M, "strncmp", I32, {Ptr, Ptr, I64}),
			{Text, B.CreateGlobalString(Token), B.getInt64(Token.size())}), B.getInt32(0));
	};
	auto contains = [&](Value* Text, StringRef Token) {
		return B.CreateICmpNE(B.CreateCall(symbol(M, "strstr", Ptr, {Ptr, Ptr}),
			{Text, B.CreateGlobalString(Token)}), nullPointer(C));
	};
	auto equal = [&](Value* Text, StringRef Token) {
		return B.CreateICmpEQ(B.CreateCall(symbol(M, "strcmp", I32, {Ptr, Ptr}),
			{Text, B.CreateGlobalString(Token)}), B.getInt32(0));
	};
	if (Kind == Probe::Tracer || Kind == Probe::SELinux) {
		Value* Relevant = Kind == Probe::Tracer ? prefix(Line, "TracerPid:") : B.getTrue();
		BasicBlock* Parse = BasicBlock::Create(C, "parse", F);
		BasicBlock* Ignore = BasicBlock::Create(C, "ignore", F);
		B.CreateCondBr(Relevant, Parse, Ignore);
		B.SetInsertPoint(Ignore);
		B.CreateRet(B.getInt32(-2));
		B.SetInsertPoint(Parse);
		Value* Start = trimmed(Kind == Probe::Tracer ? B.CreateGEP(B.getInt8Ty(), Line, B.getInt64(10)) : Line);
		Value* Digits = span(Start, "0123456789");
		Value* End = B.CreateAlloca(Ptr);
		Value* Number = B.CreateCall(symbol(M, "strtol", I64, {Ptr, Ptr, I32}), {Start, End, B.getInt32(10)});
		Value* ParsedEnd = B.CreateLoad(Ptr, End);
		Value* Valid = B.CreateAnd(B.CreateICmpUGT(Digits, B.getInt64(0)),
			B.CreateICmpEQ(ParsedEnd, B.CreateGEP(B.getInt8Ty(), Start, Digits)));
		Valid = B.CreateAnd(Valid, B.CreateICmpEQ(B.CreateLoad(B.getInt8Ty(), trimmed(ParsedEnd)), B.getInt8(0)));
		Valid = B.CreateAnd(Valid, B.CreateICmpULE(Number, B.getInt64(Kind == Probe::Tracer ? 2147483647 : 1)));
		Value* Hit = Kind == Probe::Tracer ? B.CreateICmpNE(Number, B.getInt64(0)) : B.CreateICmpEQ(Number, B.getInt64(0));
		B.CreateRet(B.CreateSelect(Valid, B.CreateZExt(Hit, I32), B.getInt32(-1)));
		return F;
	}
	if (Kind == Probe::Maps || Kind == Probe::Injection) {
		Value* Start = B.CreateAlloca(I64);
		Value* End = B.CreateAlloca(I64);
		Value* Perms = B.CreateAlloca(B.getInt8Ty(), B.getInt64(5));
		Value* Offset = B.CreateAlloca(I32);
		B.CreateStore(B.getInt64(0), Start);
		B.CreateStore(B.getInt64(0), End);
		B.CreateStore(B.getInt32(0), Offset);
		B.CreateMemSet(Perms, B.getInt8(0), 5, MaybeAlign(1));
		Value* Count = B.CreateCall(symbol(M, "sscanf", I32, {Ptr, Ptr}, true),
			{Line, B.CreateGlobalString("%lx-%lx %4s %*x %*x:%*x %*u %n"), Start, End, Perms, Offset});
		Value* Valid = B.CreateAnd(B.CreateICmpEQ(Count, B.getInt32(3)),
			B.CreateICmpULT(B.CreateLoad(I64, Start), B.CreateLoad(I64, End)));
		Value* Pos = B.CreateLoad(I32, Offset);
		Valid = B.CreateAnd(Valid, B.CreateICmpSGT(Pos, B.getInt32(0)));
		for (unsigned I = 0; I < 4; ++I) {
			Value* Ch = B.CreateLoad(B.getInt8Ty(), B.CreateGEP(B.getInt8Ty(), Perms, B.getInt64(I)));
			Value* Allowed = B.CreateICmpEQ(Ch, B.getInt8("rwxp"[I]));
			Allowed = B.CreateOr(Allowed, B.CreateICmpEQ(Ch, B.getInt8(I == 3 ? 's' : '-')));
			Valid = B.CreateAnd(Valid, Allowed);
		}
		Value* Path = B.CreateGEP(B.getInt8Ty(), Line, B.CreateZExt(Pos, I64));
		Value* Hit = B.getFalse();
		if (Kind == Probe::Maps) {
			for (StringRef Token : {"gdbserver", "lldb-server", "android_server", "idaserver"})
				Hit = B.CreateOr(Hit, contains(Path, Token));
		} else {
			for (StringRef Token : {"frida-agent", "frida-gadget", "libfrida.so", "gadget.so", "libxposed", "libsubstrate", "libriru", "liblsposed"})
				Hit = B.CreateOr(Hit, contains(Path, Token));
		}
		B.CreateRet(B.CreateSelect(Valid, B.CreateZExt(Hit, I32), B.getInt32(-1)));
		return F;
	}
	Value* Text = trimmed(Line);
	if (Kind == Probe::Process) {
		Value* Len = B.CreateCall(symbol(M, "strcspn", I64, {Ptr, Ptr}), {Text, B.CreateGlobalString("\r\n")});
		B.CreateStore(B.getInt8(0), B.CreateGEP(B.getInt8Ty(), Text, Len));
		Value* Hit = B.getFalse();
		for (StringRef Token : {"gdb", "gdbserver", "lldb-server", "android_server", "idaserver", "frida-server", "frida-helper", "memdumper64", "SoFixer64", "procdump", "linjector", "strace", "ltrace", "tcpdump", "mitmproxy"})
			Hit = B.CreateOr(Hit, equal(Text, Token));
		B.CreateRet(B.CreateSelect(B.CreateICmpNE(Len, B.getInt64(0)), B.CreateZExt(Hit, I32), B.getInt32(-1)));
		return F;
	}
	if (Kind == Probe::VPN) {
		BasicBlock* Ignore = BasicBlock::Create(C, "header", F);
		BasicBlock* Parse = BasicBlock::Create(C, "interface", F);
		B.CreateCondBr(B.CreateOr(prefix(Text, "Inter-"), prefix(Text, "face")), Ignore, Parse);
		B.SetInsertPoint(Ignore);
		B.CreateRet(B.getInt32(-2));
		B.SetInsertPoint(Parse);
		Value* IfName = B.CreateAlloca(B.getInt8Ty(), B.getInt64(16));
		Value* Offset = B.CreateAlloca(I32);
		B.CreateStore(B.getInt32(0), Offset);
		B.CreateMemSet(IfName, B.getInt8(0), 16, MaybeAlign(1));
		Value* Count = B.CreateCall(symbol(M, "sscanf", I32, {Ptr, Ptr}, true),
			{Text, B.CreateGlobalString("%15[^:]: %n"), IfName, Offset});
		Value* Pos = B.CreateLoad(I32, Offset);
		Value* Valid = B.CreateAnd(B.CreateICmpEQ(Count, B.getInt32(1)), B.CreateICmpSGT(Pos, B.getInt32(0)));
		Value* Cursor = B.CreateGEP(B.getInt8Ty(), Text, B.CreateZExt(Pos, I64));
		Value* End = B.CreateAlloca(Ptr);
		Value* Errno = B.CreateCall(symbol(M, "__errno", Ptr, {}));
		// 无符号 scanf 也接受负数；逐项解析并检查溢出及分隔符。
		for (unsigned I = 0; I < 16; ++I) {
			Value* Start = trimmed(Cursor);
			Value* Digits = span(Start, "0123456789");
			B.CreateStore(B.getInt32(0), Errno);
			B.CreateCall(symbol(M, "strtoull", I64, {Ptr, Ptr, I32}), {Start, End, B.getInt32(10)});
			Value* ParsedEnd = B.CreateLoad(Ptr, End);
			Value* NumberValid = B.CreateAnd(B.CreateICmpUGT(Digits, B.getInt64(0)),
				B.CreateICmpEQ(ParsedEnd, B.CreateGEP(B.getInt8Ty(), Start, Digits)));
			NumberValid = B.CreateAnd(NumberValid, B.CreateICmpEQ(B.CreateLoad(I32, Errno), B.getInt32(0)));
			Value* Spaces = span(ParsedEnd, " \t\r\n");
			if (I < 15) NumberValid = B.CreateAnd(NumberValid, B.CreateICmpUGT(Spaces, B.getInt64(0)));
			Valid = B.CreateAnd(Valid, NumberValid);
			Cursor = B.CreateGEP(B.getInt8Ty(), ParsedEnd, Spaces);
		}
		Valid = B.CreateAnd(Valid, B.CreateICmpEQ(B.CreateLoad(B.getInt8Ty(), Cursor), B.getInt8(0)));
		Value* Hit = B.getFalse();
		for (StringRef Token : {"tun", "ppp", "pptp", "ipsec"}) {
			// 只接受前缀后跟接口编号，避免名称中的普通子串误报。
			Value* Suffix = B.CreateGEP(B.getInt8Ty(), IfName, B.getInt64(Token.size()));
			Value* Digits = span(Suffix, "0123456789");
			Value* Numbered = B.CreateAnd(B.CreateICmpUGT(Digits, B.getInt64(0)),
				B.CreateICmpEQ(B.CreateLoad(B.getInt8Ty(), B.CreateGEP(B.getInt8Ty(), Suffix, Digits)), B.getInt8(0)));
			Hit = B.CreateOr(Hit, B.CreateAnd(prefix(IfName, Token), Numbered));
		}
		B.CreateRet(B.CreateSelect(Valid, B.CreateZExt(Hit, I32), B.getInt32(-1)));
		return F;
	}
	// iptables 的 REDIRECT 本身就是重定向；DNAT 仅检查本机目标。
	Value* Header = B.CreateOr(prefix(Text, "Chain "), prefix(Text, "target "));
	Value* Blank = B.CreateICmpEQ(B.CreateLoad(B.getInt8Ty(), Text), B.getInt8(0));
	Value* Target = B.CreateAlloca(B.getInt8Ty(), B.getInt64(64));
	Value* Word = B.CreateAlloca(B.getInt8Ty(), B.getInt64(64));
	B.CreateMemSet(Target, B.getInt8(0), 64, MaybeAlign(1));
	Value* Count = B.CreateCall(symbol(M, "sscanf", I32, {Ptr, Ptr}, true),
		{Text, B.CreateGlobalString("%63s %63s %63s %63s %63s"), Target, Word, Word, Word, Word});
	Value* Hit = B.CreateOr(equal(Target, "REDIRECT"), B.CreateAnd(equal(Target, "DNAT"),
		B.CreateOr(contains(Text, "to:127."), contains(Text, "to:::1"))));
	Value* Result = B.CreateSelect(B.CreateICmpEQ(Count, B.getInt32(5)), B.CreateZExt(Hit, I32), B.getInt32(-1));
	Result = B.CreateSelect(Header, B.getInt32(0), Result);
	B.CreateRet(B.CreateSelect(Blank, B.getInt32(-2), Result));
	return F;
}

// getline 读取完整行，避免固定 4 KiB 缓冲区截断路径或漏掉跨块特征。
// 返回 -2 表示进程在扫描中退出，只有进程枚举允许忽略此结果。
Function* fileProbe(Module& M, Probe Kind) {
	std::string Name = ("__obf_ad_file_" + probeName(Kind)).str();
	if (auto* F = M.getFunction(Name)) return F;
	LLVMContext& C = M.getContext();
	Type* Ptr = PointerType::getUnqual(C);
	Type* I32 = Type::getInt32Ty(C);
	Type* I64 = Type::getInt64Ty(C);
	Function* Parser = lineParser(M, Kind);
	Function* F = Function::Create(FunctionType::get(I32, {Ptr}, false),
		GlobalValue::InternalLinkage, Name, M);
	BasicBlock* Entry = BasicBlock::Create(C, "entry", F);
	BasicBlock* Failed = BasicBlock::Create(C, "open.failed", F);
	BasicBlock* Read = BasicBlock::Create(C, "read", F);
	BasicBlock* Parse = BasicBlock::Create(C, "parse", F);
	BasicBlock* Assess = BasicBlock::Create(C, "assess", F);
	BasicBlock* End = BasicBlock::Create(C, "eof", F);
	BasicBlock* Finish = BasicBlock::Create(C, "finish", F);
	IRBuilder<> B(Entry);
	Value* Buffer = B.CreateAlloca(Ptr);
	Value* Capacity = B.CreateAlloca(I64);
	Value* Seen = B.CreateAlloca(B.getInt1Ty());
	B.CreateStore(nullPointer(C), Buffer);
	B.CreateStore(B.getInt64(0), Capacity);
	B.CreateStore(B.getFalse(), Seen);
	const bool Pipe = Kind == Probe::IPTables;
	Value* Stream = B.CreateCall(symbol(M, Pipe ? "popen" : "fopen", Ptr, {Ptr, Ptr}),
		{F->getArg(0), B.CreateGlobalString("r")});
	B.CreateCondBr(B.CreateICmpEQ(Stream, nullPointer(C)), Failed, Read);
	B.SetInsertPoint(Failed);
	if (Kind == Probe::Process) {
		Value* Errno = B.CreateLoad(I32, B.CreateCall(symbol(M, "__errno", Ptr, {})));
		Value* Gone = B.CreateOr(B.CreateICmpEQ(Errno, B.getInt32(2)), B.CreateICmpEQ(Errno, B.getInt32(3)));
		B.CreateRet(B.CreateSelect(Gone, B.getInt32(-2), B.getInt32(-1)));
	} else {
		B.CreateRet(B.getInt32(-1));
	}
	B.SetInsertPoint(Read);
	Value* N = B.CreateCall(symbol(M, "getline", I64, {Ptr, Ptr, Ptr}), {Buffer, Capacity, Stream});
	B.CreateCondBr(B.CreateICmpSLT(N, B.getInt64(0)), End, Parse);
	B.SetInsertPoint(Parse);
	Value* Line = B.CreateLoad(Ptr, Buffer);
	// 内核文本不能带嵌入 NUL，否则会把尾部异常隐藏在 C 字符串之外。
	Value* TextLength = B.CreateCall(symbol(M, "strlen", I64, {Ptr}), {Line});
	Value* Status = B.CreateCall(Parser, {Line});
	Status = B.CreateSelect(B.CreateICmpEQ(TextLength, N), Status, B.getInt32(-1));
	B.CreateCondBr(B.CreateICmpEQ(Status, B.getInt32(-2)), Read, Assess);
	B.SetInsertPoint(Assess);
	Value* HadLine = B.CreateLoad(B.getInt1Ty(), Seen);
	B.CreateStore(B.getTrue(), Seen);
	if (Kind == Probe::SELinux)
		Status = B.CreateSelect(HadLine, B.getInt32(-1), Status);
	Value* Done = (Kind == Probe::Tracer || Kind == Probe::Process) ? B.getTrue() :
		B.CreateICmpNE(Status, B.getInt32(0));
	B.CreateCondBr(Done, Finish, Read);
	B.SetInsertPoint(End);
	Value* Error = B.CreateICmpNE(B.CreateCall(symbol(M, "ferror", I32, {Ptr}), {Stream}), B.getInt32(0));
	Value* Missing = B.CreateNot(B.CreateLoad(B.getInt1Ty(), Seen));
	Value* EOFStatus = B.CreateSelect(B.CreateOr(Error, Missing), B.getInt32(-1), B.getInt32(0));
	B.CreateBr(Finish);
	B.SetInsertPoint(Finish);
	PHINode* Result = B.CreatePHI(I32, 2);
	Result->addIncoming(Status, Assess);
	Result->addIncoming(EOFStatus, End);
	Value* CloseResult = B.CreateCall(symbol(M, Pipe ? "pclose" : "fclose", I32, {Ptr}), {Stream});
	B.CreateCall(symbol(M, "free", B.getVoidTy(), {Ptr}), {B.CreateLoad(Ptr, Buffer)});
	B.CreateRet(B.CreateSelect(B.CreateICmpEQ(CloseResult, B.getInt32(0)), Result, B.getInt32(-1)));
	return F;
}

Function* processProbe(Module& M) {
	if (auto* F = M.getFunction("__obf_ad_processes")) return F;
	LLVMContext& C = M.getContext();
	Type* Ptr = PointerType::getUnqual(C);
	Type* I32 = Type::getInt32Ty(C);
	Type* I64 = Type::getInt64Ty(C);
	Function* ProbeFn = fileProbe(M, Probe::Process);
	Function* F = Function::Create(FunctionType::get(I32, false),
		GlobalValue::InternalLinkage, "__obf_ad_processes", M);
	BasicBlock* Entry = BasicBlock::Create(C, "entry", F);
	BasicBlock* Fail = BasicBlock::Create(C, "fail", F);
	BasicBlock* Next = BasicBlock::Create(C, "next", F);
	BasicBlock* Check = BasicBlock::Create(C, "check", F);
	BasicBlock* Scan = BasicBlock::Create(C, "scan", F);
	BasicBlock* End = BasicBlock::Create(C, "end", F);
	BasicBlock* Finish = BasicBlock::Create(C, "finish", F);
	IRBuilder<> B(Entry);
	Value* Path = B.CreateAlloca(B.getInt8Ty(), B.getInt64(64));
	Value* Errno = B.CreateCall(symbol(M, "__errno", Ptr, {}));
	Value* Dir = B.CreateCall(symbol(M, "opendir", Ptr, {Ptr}), {B.CreateGlobalString("/proc")});
	B.CreateCondBr(B.CreateICmpEQ(Dir, nullPointer(C)), Fail, Next);
	B.SetInsertPoint(Fail);
	B.CreateRet(B.getInt32(-1));
	B.SetInsertPoint(Next);
	B.CreateStore(B.getInt32(0), Errno);
	Value* Ent = B.CreateCall(symbol(M, "readdir", Ptr, {Ptr}), {Dir});
	B.CreateCondBr(B.CreateICmpEQ(Ent, nullPointer(C)), End, Check);
	B.SetInsertPoint(Check);
	// Android arm64 的 dirent.d_name 位于第 19 字节，仅在该 ABI 下生成。
	Value* Name = B.CreateGEP(B.getInt8Ty(), Ent, B.getInt64(19));
	Value* Digits = B.CreateCall(symbol(M, "strspn", I64, {Ptr, Ptr}), {Name, B.CreateGlobalString("0123456789")});
	Value* IsPid = B.CreateAnd(B.CreateICmpUGT(Digits, B.getInt64(0)),
		B.CreateICmpEQ(B.CreateLoad(B.getInt8Ty(), B.CreateGEP(B.getInt8Ty(), Name, Digits)), B.getInt8(0)));
	B.CreateCondBr(IsPid, Scan, Next);
	B.SetInsertPoint(Scan);
	Value* Pid = B.CreateCall(symbol(M, "strtol", I64, {Ptr, Ptr, I32}), {Name, nullPointer(C), B.getInt32(10)});
	B.CreateCall(symbol(M, "snprintf", I32, {Ptr, I64, Ptr}, true),
		{Path, B.getInt64(64), B.CreateGlobalString("/proc/%d/comm"), B.CreateTrunc(Pid, I32)});
	Value* Status = B.CreateCall(ProbeFn, {Path});
	Value* Detected = B.CreateOr(B.CreateICmpEQ(Status, B.getInt32(1)), B.CreateICmpEQ(Status, B.getInt32(-1)));
	B.CreateCondBr(Detected, Finish, Next);
	B.SetInsertPoint(End);
	Value* EndStatus = B.CreateSelect(B.CreateICmpEQ(B.CreateLoad(I32, Errno), B.getInt32(0)), B.getInt32(0), B.getInt32(-1));
	B.CreateBr(Finish);
	B.SetInsertPoint(Finish);
	PHINode* Result = B.CreatePHI(I32, 2);
	Result->addIncoming(Status, Scan);
	Result->addIncoming(EndStatus, End);
	Value* CloseResult = B.CreateCall(symbol(M, "closedir", I32, {Ptr}), {Dir});
	B.CreateRet(B.CreateSelect(B.CreateICmpEQ(CloseResult, B.getInt32(0)), Result, B.getInt32(-1)));
	return F;
}

// 非阻塞本机连接不依赖 Android 受限的 /proc/net/tcp，也不会占用调试端口。
Function* portProbe(Module& M) {
	if (auto* F = M.getFunction("__obf_ad_port")) return F;
	LLVMContext& C = M.getContext();
	Type* Ptr = PointerType::getUnqual(C);
	Type* I32 = Type::getInt32Ty(C);
	Type* I16 = Type::getInt16Ty(C);
	Function* F = Function::Create(FunctionType::get(I32, {I16}, false),
		GlobalValue::InternalLinkage, "__obf_ad_port", M);
	BasicBlock* Entry = BasicBlock::Create(C, "entry", F);
	BasicBlock* Fail = BasicBlock::Create(C, "fail", F);
	BasicBlock* Connect = BasicBlock::Create(C, "connect", F);
	BasicBlock* Error = BasicBlock::Create(C, "connect.error", F);
	BasicBlock* Pending = BasicBlock::Create(C, "pending", F);
	BasicBlock* Poll = BasicBlock::Create(C, "poll", F);
	BasicBlock* SocketError = BasicBlock::Create(C, "socket.error", F);
	BasicBlock* Finish = BasicBlock::Create(C, "finish", F);
	IRBuilder<> B(Entry);
	Type* AddressTy = StructType::get(C, {I16, I16, I32, ArrayType::get(B.getInt8Ty(), 8)});
	Value* Address = B.CreateAlloca(AddressTy);
	Type* PollTy = StructType::get(C, {I32, I16, I16});
	Value* PollFD = B.CreateAlloca(PollTy);
	Value* Code = B.CreateAlloca(I32);
	Value* Length = B.CreateAlloca(I32);
	Value* FD = B.CreateCall(symbol(M, "socket", I32, {I32, I32, I32}),
		{B.getInt32(2), B.getInt32(1 | 2048 | 524288), B.getInt32(0)});
	B.CreateCondBr(B.CreateICmpSLT(FD, B.getInt32(0)), Fail, Connect);
	B.SetInsertPoint(Fail);
	B.CreateRet(B.getInt32(-1));
	B.SetInsertPoint(Connect);
	B.CreateStore(Constant::getNullValue(AddressTy), Address);
	B.CreateStore(B.getInt16(2), B.CreateStructGEP(AddressTy, Address, 0));
	Value* Port = F->getArg(0);
	Value* NetworkPort = B.CreateOr(B.CreateShl(Port, 8), B.CreateLShr(Port, 8));
	B.CreateStore(NetworkPort, B.CreateStructGEP(AddressTy, Address, 1));
	B.CreateStore(B.getInt32(0x0100007f), B.CreateStructGEP(AddressTy, Address, 2));
	Value* RC = B.CreateCall(symbol(M, "connect", I32, {I32, Ptr, I32}), {FD, Address, B.getInt32(16)});
	B.CreateCondBr(B.CreateICmpEQ(RC, B.getInt32(0)), Finish, Error);
	B.SetInsertPoint(Error);
	Value* Errno = B.CreateLoad(I32, B.CreateCall(symbol(M, "__errno", Ptr, {})));
	Value* Immediate = B.CreateSelect(B.CreateICmpEQ(Errno, B.getInt32(111)), B.getInt32(0), B.getInt32(-1));
	B.CreateCondBr(B.CreateICmpEQ(Errno, B.getInt32(115)), Pending, Finish);
	B.SetInsertPoint(Pending);
	B.CreateStore(Constant::getNullValue(PollTy), PollFD);
	B.CreateStore(FD, B.CreateStructGEP(PollTy, PollFD, 0));
	B.CreateStore(B.getInt16(4), B.CreateStructGEP(PollTy, PollFD, 1));
	Value* Ready = B.CreateCall(symbol(M, "poll", I32, {Ptr, Type::getInt64Ty(C), I32}), {PollFD, B.getInt64(1), B.getInt32(20)});
	B.CreateCondBr(B.CreateICmpSGT(Ready, B.getInt32(0)), Poll, Finish);
	B.SetInsertPoint(Poll);
	B.CreateStore(B.getInt32(0), Code);
	B.CreateStore(B.getInt32(4), Length);
	Value* Got = B.CreateCall(symbol(M, "getsockopt", I32, {I32, I32, I32, Ptr, Ptr}),
		{FD, B.getInt32(1), B.getInt32(4), Code, Length});
	B.CreateCondBr(B.CreateAnd(B.CreateICmpEQ(Got, B.getInt32(0)),
		B.CreateICmpEQ(B.CreateLoad(I32, Length), B.getInt32(4))), SocketError, Finish);
	B.SetInsertPoint(SocketError);
	Value* SOError = B.CreateLoad(I32, Code);
	Value* SOResult = B.CreateSelect(B.CreateICmpEQ(SOError, B.getInt32(0)), B.getInt32(1),
		B.CreateSelect(B.CreateICmpEQ(SOError, B.getInt32(111)), B.getInt32(0), B.getInt32(-1)));
	B.CreateBr(Finish);
	B.SetInsertPoint(Finish);
	PHINode* Result = B.CreatePHI(I32, 5);
	Result->addIncoming(B.getInt32(1), Connect);
	Result->addIncoming(Immediate, Error);
	// 超时无法确认连接结果，交由普通/严格模式决定跳过还是保护。
	Result->addIncoming(B.getInt32(-1), Pending);
	Result->addIncoming(B.getInt32(-1), Poll);
	Result->addIncoming(SOResult, SocketError);
	B.CreateCall(symbol(M, "close", I32, {I32}), {FD});
	B.CreateRet(Result);
	return F;
}

std::string configKey(const AntiDebugConfig& Cfg) {
	std::string Key;
	for (bool Flag : {Cfg.tracerPid || Cfg.ptrace, Cfg.timing, Cfg.maps, Cfg.injection,
		Cfg.debuggerProcess, Cfg.debugPorts, Cfg.vpn, Cfg.proxy, Cfg.iptables, Cfg.selinux, Cfg.rootRequired,
		Cfg.dynamic})
		Key += Flag ? '1' : '0';
	return Key + "." + std::to_string(Cfg.timing ? Cfg.thresholdNs : 0) +
		"." + std::to_string(Cfg.dynamic ? Cfg.intervalMs : 0);
}

AntiDebugConfig effectiveConfig(const Module& M, AntiDebugConfig Cfg) {
	if (!supportsAndroidArm64(M)) {
		Cfg.debuggerProcess = Cfg.injection = Cfg.debugPorts = Cfg.vpn = false;
		Cfg.proxy = Cfg.iptables = Cfg.selinux = Cfg.rootRequired = false;
	}
	if (!Cfg.rootRequired) Cfg.debuggerProcess = Cfg.iptables = false;
	return Cfg;
}

bool hasChecks(const AntiDebugConfig& Cfg) {
	return Cfg.tracerPid || Cfg.ptrace || Cfg.timing || Cfg.maps ||
		Cfg.debuggerProcess || Cfg.injection || Cfg.debugPorts || Cfg.vpn ||
		Cfg.proxy || Cfg.iptables || Cfg.selinux;
}

Function* checkFunction(Module& M, const AntiDebugConfig& Cfg, bool Monitor) {
	std::string Name = "__obf_ad_check." + configKey(Cfg) + (Monitor ? ".monitor" : ".entry");
	if (auto* F = M.getFunction(Name)) return F;
	LLVMContext& C = M.getContext();
	Type* Ptr = PointerType::getUnqual(C);
	Type* I32 = Type::getInt32Ty(C);
	Type* I64 = Type::getInt64Ty(C);
	Function* F = Function::Create(FunctionType::get(Type::getInt1Ty(C), false),
		GlobalValue::InternalLinkage, Name, M);
	IRBuilder<> B(BasicBlock::Create(C, "entry", F));
	if (Cfg.rootRequired) {
		BasicBlock* Checks = BasicBlock::Create(C, "root.checks", F);
		BasicBlock* Denied = BasicBlock::Create(C, "root.denied", F);
		Value* UID = B.CreateCall(symbol(M, "geteuid", I32, {}));
		B.CreateCondBr(B.CreateICmpEQ(UID, B.getInt32(0)), Checks, Denied);
		B.SetInsertPoint(Denied);
		B.CreateRet(B.getTrue());
		B.SetInsertPoint(Checks);
	}
	Value* Hit = B.getFalse();
	auto addStatus = [&](Value* Status) {
		Value* Found = B.CreateICmpEQ(Status, B.getInt32(1));
		if (Cfg.rootRequired) Found = B.CreateOr(Found, B.CreateICmpSLT(Status, B.getInt32(0)));
		Hit = B.CreateOr(Hit, Found);
	};
	auto file = [&](Probe Kind, StringRef Path) {
		addStatus(B.CreateCall(fileProbe(M, Kind), {B.CreateGlobalString(Path)}));
	};
	// ptrace 兼容项只读 TracerPid，入口和后台都不改变跟踪/信号关系。
	if (Cfg.tracerPid || Cfg.ptrace) file(Probe::Tracer, "/proc/self/status");
	if (Cfg.maps) file(Probe::Maps, "/proc/self/maps");
	if (Cfg.injection) file(Probe::Injection, "/proc/self/maps");
	if (Cfg.vpn) file(Probe::VPN, "/proc/net/dev");
	if (Cfg.selinux) file(Probe::SELinux, "/sys/fs/selinux/enforce");
	if (Cfg.debuggerProcess) addStatus(B.CreateCall(processProbe(M)));
	if (Cfg.debugPorts)
		for (unsigned Port : {23946, 23947, 27042})
			addStatus(B.CreateCall(portProbe(M), {B.getInt16(Port)}));
	if (Cfg.proxy) {
		for (StringRef Env : {"http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"}) {
			Value* ValuePtr = B.CreateCall(symbol(M, "getenv", Ptr, {Ptr}), {B.CreateGlobalString(Env)});
			Value* Safe = B.CreateSelect(B.CreateICmpEQ(ValuePtr, nullPointer(C)), B.CreateGlobalString(""), ValuePtr);
			Hit = B.CreateOr(Hit, B.CreateICmpNE(B.CreateLoad(B.getInt8Ty(), Safe), B.getInt8(0)));
		}
	}
	if (Cfg.iptables)
		for (StringRef Table : {"nat", "filter", "mangle"})
			file(Probe::IPTables, ("/system/bin/iptables -t " + Table + " -L -n").str());
	if (Cfg.timing) {
		Type* TS = StructType::get(C, {I64, I64});
		Value* A = B.CreateAlloca(TS);
		Value* Z = B.CreateAlloca(TS);
		B.CreateStore(Constant::getNullValue(TS), A);
		B.CreateStore(Constant::getNullValue(TS), Z);
		FunctionCallee Clock = symbol(M, "clock_gettime", I32, {I32, Ptr});
		Value* First = B.CreateCall(Clock, {B.getInt32(1), A});
		Value* Sink = B.CreateAlloca(I64);
		B.CreateStore(B.getInt64(1), Sink)->setVolatile(true);
		Value* Second = B.CreateCall(Clock, {B.getInt32(1), Z});
		Value* Sec = B.CreateSub(B.CreateLoad(I64, B.CreateStructGEP(TS, Z, 0)), B.CreateLoad(I64, B.CreateStructGEP(TS, A, 0)));
		Value* NSec = B.CreateSub(B.CreateLoad(I64, B.CreateStructGEP(TS, Z, 1)), B.CreateLoad(I64, B.CreateStructGEP(TS, A, 1)));
		Value* Delta = B.CreateAdd(B.CreateMul(Sec, B.getInt64(1000000000)), NSec);
		Value* Valid = B.CreateAnd(B.CreateICmpEQ(First, B.getInt32(0)), B.CreateICmpEQ(Second, B.getInt32(0)));
		Value* Slow = B.CreateICmpUGT(Delta, B.getInt64(Cfg.thresholdNs));
		Hit = B.CreateOr(Hit, B.CreateOr(B.CreateAnd(Valid, Slow), B.CreateAnd(B.getInt1(Cfg.rootRequired), B.CreateNot(Valid))));
	}
	B.CreateRet(Hit);
	return F;
}

GlobalVariable* responseState(Module& M, StringRef Key) {
	std::string Name = ("__obf_antidebug_response." + Key).str();
	if (auto* G = M.getGlobalVariable(Name, true)) return G;
	return new GlobalVariable(M, Type::getInt32Ty(M.getContext()), false,
		GlobalValue::InternalLinkage, ConstantInt::get(Type::getInt32Ty(M.getContext()), 0), Name);
}

void createMonitor(Module& M, const AntiDebugConfig& Cfg, GlobalVariable* Response) {
	const std::string Key = configKey(Cfg);
	const std::string Name = "__obf_antidebug_monitor." + Key;
	if (M.getFunction(Name)) return;
	LLVMContext& C = M.getContext();
	Type* Ptr = PointerType::getUnqual(C);
	Type* I32 = Type::getInt32Ty(C);
	Type* ThreadTy = M.getDataLayout().getIntPtrType(C);
	auto* StateTy = ArrayType::get(I32, 2);
	auto* State = new GlobalVariable(M, StateTy, false, GlobalValue::InternalLinkage,
		Constant::getNullValue(StateTy), "__obf_antidebug_monitor_state." + Key);
	auto* Thread = new GlobalVariable(M, ThreadTy, false, GlobalValue::InternalLinkage,
		ConstantInt::get(ThreadTy, 0), "__obf_antidebug_thread." + Key);
	Function* Check = checkFunction(M, Cfg, true);
	Function* Monitor = Function::Create(FunctionType::get(Ptr, {Ptr}, false), GlobalValue::InternalLinkage, Name, M);
	BasicBlock* Entry = BasicBlock::Create(C, "entry", Monitor);
	BasicBlock* Loop = BasicBlock::Create(C, "loop", Monitor);
	BasicBlock* Run = BasicBlock::Create(C, "check", Monitor);
	BasicBlock* Sleep = BasicBlock::Create(C, "sleep", Monitor);
	BasicBlock* Wait = BasicBlock::Create(C, "wait", Monitor);
	BasicBlock* Exit = BasicBlock::Create(C, "exit", Monitor);
	IRBuilder<> B(Entry);
	Value* Remaining = B.CreateAlloca(I32);
	Value* Stop = B.CreateGEP(StateTy, State, {B.getInt32(0), B.getInt32(0)});
	B.CreateBr(Loop);
	B.SetInsertPoint(Loop);
	auto* Stopped = B.CreateLoad(I32, Stop);
	Stopped->setAtomic(AtomicOrdering::Monotonic);
	B.CreateCondBr(B.CreateICmpEQ(Stopped, B.getInt32(0)), Run, Exit);
	B.SetInsertPoint(Run);
	Value* Hit = B.CreateZExt(B.CreateCall(Check), I32);
	// 异常状态锁存，避免下次入口检查把后台检测结果清零。
	B.CreateAtomicRMW(AtomicRMWInst::Or, Response, Hit, MaybeAlign(4), AtomicOrdering::Monotonic);
	B.CreateStore(B.getInt32(Cfg.intervalMs), Remaining);
	B.CreateBr(Sleep);
	B.SetInsertPoint(Sleep);
	auto* StopWait = B.CreateLoad(I32, Stop);
	StopWait->setAtomic(AtomicOrdering::Monotonic);
	B.CreateCondBr(B.CreateICmpNE(StopWait, B.getInt32(0)), Exit, Wait);
	B.SetInsertPoint(Wait);
	Value* MS = B.CreateLoad(I32, Remaining);
	Value* Chunk = B.CreateSelect(B.CreateICmpUGT(MS, B.getInt32(10)), B.getInt32(10), MS);
	B.CreateCall(symbol(M, "usleep", I32, {I32}), {B.CreateMul(Chunk, B.getInt32(1000))});
	Value* Rest = B.CreateSub(MS, Chunk);
	B.CreateStore(Rest, Remaining);
	B.CreateCondBr(B.CreateICmpEQ(Rest, B.getInt32(0)), Loop, Sleep);
	B.SetInsertPoint(Exit);
	B.CreateRet(nullPointer(C));
	Function* Ctor = Function::Create(FunctionType::get(B.getVoidTy(), false), GlobalValue::InternalLinkage,
		"__obf_antidebug_monitor_ctor." + Key, M);
	B.SetInsertPoint(BasicBlock::Create(C, "entry", Ctor));
	Value* RC = B.CreateCall(symbol(M, "pthread_create", I32, {Ptr, Ptr, Ptr, Ptr}), {Thread, nullPointer(C), Monitor, nullPointer(C)});
	Value* Started = B.CreateGEP(StateTy, State, {B.getInt32(0), B.getInt32(1)});
	B.CreateStore(B.CreateZExt(B.CreateICmpEQ(RC, B.getInt32(0)), I32), Started)->setAtomic(AtomicOrdering::Monotonic);
	// 启动失败始终锁存，不能因普通模式而悄悄失去监控。
	B.CreateAtomicRMW(AtomicRMWInst::Or, Response, B.CreateZExt(B.CreateICmpNE(RC, B.getInt32(0)), I32), MaybeAlign(4), AtomicOrdering::Monotonic);
	B.CreateRetVoid();
	appendToGlobalCtors(M, Ctor, 65535);
	Function* Dtor = Function::Create(FunctionType::get(B.getVoidTy(), false), GlobalValue::InternalLinkage,
		"__obf_antidebug_monitor_dtor." + Key, M);
	B.SetInsertPoint(BasicBlock::Create(C, "entry", Dtor));
	Stop = B.CreateGEP(StateTy, State, {B.getInt32(0), B.getInt32(0)});
	Started = B.CreateGEP(StateTy, State, {B.getInt32(0), B.getInt32(1)});
	B.CreateStore(B.getInt32(1), Stop)->setAtomic(AtomicOrdering::Monotonic);
	BasicBlock* Join = BasicBlock::Create(C, "join", Dtor);
	BasicBlock* Done = BasicBlock::Create(C, "done", Dtor);
	auto* HasThread = B.CreateLoad(I32, Started);
	HasThread->setAtomic(AtomicOrdering::Monotonic);
	B.CreateCondBr(B.CreateICmpNE(HasThread, B.getInt32(0)), Join, Done);
	B.SetInsertPoint(Join);
	B.CreateCall(symbol(M, "pthread_join", I32, {ThreadTy, Ptr}), {B.CreateLoad(ThreadTy, Thread), nullPointer(C)});
	B.CreateStore(B.getInt32(0), Started)->setAtomic(AtomicOrdering::Monotonic);
	B.CreateBr(Done);
	B.SetInsertPoint(Done);
	B.CreateRetVoid();
	appendToGlobalDtors(M, Dtor, 65535);
}

} // namespace

AntiDebugConfig llvm::effectiveAntiDebugConfig(const Module& M, AntiDebugConfig Cfg) {
	return effectiveConfig(M, Cfg);
}

bool llvm::hasAntiDebugDetectionSource(const AntiDebugConfig& Cfg) {
	return hasChecks(Cfg);
}

GlobalVariable* llvm::getOrCreateAntiDebugResponse(Module& M, const AntiDebugConfig& Cfg) {
	return responseState(M, configKey(effectiveConfig(M, Cfg)));
}

PreservedAnalyses AntiDebugPass::run(Function& F, FunctionAnalysisManager& AM) {
	if (F.isDeclaration() || F.getName().starts_with("__obf_ad_") ||
		F.getName().starts_with("__obf_antidebug_")) return PreservedAnalyses::all();
	auto PC = getObfConfig(F, AM).getPassConfig("antidebug");
	if (!PC) return PreservedAnalyses::all();
	AntiDebugConfig Cfg = AntiDebugConfig::fromPassConfig(*PC);
	std::string Reason;
	if (!Cfg.enabled || !Cfg.validate(&Reason)) return PreservedAnalyses::all();
	Module& M = *F.getParent();
	Triple T(M.getTargetTriple());
	Cfg = effectiveConfig(M, Cfg);
	if (!hasChecks(Cfg)) return PreservedAnalyses::all();
	if (!(T.isOSLinux() || T.isAndroid()) && (Cfg.tracerPid || Cfg.ptrace || Cfg.maps || Cfg.dynamic)) {
		auto& FOC = *AM.getResult<FunctionObfContextAnalysis>(F);
		obf::recordObfPassSkip(FOC, "antidebug", "target platform lacks Linux proc/pthread ABI");
		return PreservedAnalyses::all();
	}
	// 正式 wrapper 提交后再添加入口保护，避免被 VM 替换掉。
	if (VMPlanCoordinator::active() && F.getMetadata("obf.vm.caller")) {
		F.setMetadata("obf.antidebug.deferred", MDNode::get(M.getContext(), {}));
		return PreservedAnalyses::all();
	}
	return applyAntiDebug(F, Cfg) ? PreservedAnalyses::none() : PreservedAnalyses::all();
}

bool llvm::applyAntiDebug(Function& F, AntiDebugConfig Cfg) {
	if (F.isDeclaration() || !Cfg.enabled || !Cfg.validate()) return false;
	Module& M = *F.getParent();
	Cfg = effectiveConfig(M, Cfg);
	Triple T(M.getTargetTriple());
	if (!hasChecks(Cfg) || (!(T.isOSLinux() || T.isAndroid()) &&
		(Cfg.tracerPid || Cfg.ptrace || Cfg.maps || Cfg.dynamic))) return false;
	Function* Check = checkFunction(M, Cfg, false);
	GlobalVariable* Response = getOrCreateAntiDebugResponse(M, Cfg);
	if (Cfg.dynamic) createMonitor(M, Cfg, Response);
	BasicBlock* Entry = &F.getEntryBlock();
	IRBuilder<> B(&*Entry->getFirstInsertionPt());
	Value* Hit = B.CreateZExt(B.CreateCall(Check), B.getInt32Ty());
	B.CreateAtomicRMW(AtomicRMWInst::Or, Response, Hit, MaybeAlign(4), AtomicOrdering::Monotonic);
	if (!Cfg.responseCorrupt) return true;
	BasicBlock* Body = Entry->splitBasicBlock(B.GetInsertPoint(), "obf.ad.body");
	Entry->getTerminator()->eraseFromParent();
	IRBuilder<> Guard(Entry);
	auto* Flag = Guard.CreateLoad(Guard.getInt32Ty(), Response);
	Flag->setAtomic(AtomicOrdering::Monotonic);
	BasicBlock* Fail = BasicBlock::Create(M.getContext(), "obf.ad.fail", &F, Body);
	Guard.CreateCondBr(Guard.CreateICmpNE(Flag, Guard.getInt32(0)), Fail, Body);
	IRBuilder<> FailBuilder(Fail);
	Type* RT = F.getReturnType();
	if (RT->isVoidTy()) FailBuilder.CreateRetVoid();
	else FailBuilder.CreateRet(Constant::getNullValue(RT));
	return true;
}
