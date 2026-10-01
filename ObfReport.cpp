#include "llvm/Transforms/Obfuscator/ObfReport.h"

#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/StringRef.h"

#include "llvm/IR/CFG.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Constants.h"

#include "llvm/Support/JSON.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Obfuscator/IRBudget.h"
#include "llvm/Transforms/Obfuscator/ObfuscationOptions.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <limits>
#include <memory>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

using namespace llvm;

namespace llvm::obf {

	void ObfReportSink::add(FunctionReport&& R) { Functions.push_back(std::move(R)); }

	void GraphModel::addNode(GraphNode N) {
		for (GraphNode& Existing : Nodes)
			if (Existing.Id == N.Id) {
				if (Existing.Type == "source_function" || Existing.Type == "external_declaration")
					Existing.Type = N.Type;
				Existing.Generated |= N.Generated;
				return;
			}
		Nodes.push_back(std::move(N));
	}

	void GraphModel::addEdge(GraphEdge E) {
		for (const GraphEdge& Existing : Edges)
			if (Existing.Id == E.Id)
				return;
		Edges.push_back(std::move(E));
	}

	static std::string graphFunctionId(StringRef Name) {
		return (Twine("function:") + Name).str();
	}

	static std::string graphUnknownId(StringRef FunctionName) {
		return (Twine("unknown-indirect:") + FunctionName).str();
	}

	static bool containsBlockAddress(const Constant* C, const Function*& Target,
		const BasicBlock*& Block) {
		if (const auto* BA = dyn_cast<BlockAddress>(C)) {
			Target = BA->getFunction();
			Block = BA->getBasicBlock();
			return true;
		}
		if (const auto* Agg = dyn_cast<ConstantAggregate>(C))
			for (const Use& U : Agg->operands())
				if (containsBlockAddress(cast<Constant>(U.get()), Target, Block))
					return true;
		return false;
	}

	void collectFinalIRGraph(const Module& M, GraphModel& Model) {
		for (const Function& F : M) {
			if (F.isDeclaration() && F.use_empty())
				continue;
			const std::string Id = graphFunctionId(F.getName());
			const bool IsEngine = F.getName().starts_with("__vm_engine");
			Model.addNode({Id, F.getName().str(),
				F.isDeclaration() ? "external_declaration" :
				(IsEngine ? "vm_engine" : "source_function"), IsEngine});
		}
		for (const GlobalVariable& GV : M.globals()) {
			if (!GV.getName().contains(".vm.ophandlers") || !GV.hasInitializer())
				continue;
			const std::string TableId = (Twine("handler-table:") + GV.getName()).str();
			Model.addNode({TableId, GV.getName().str(), "vm_dispatcher", true});
			if (GV.getName().contains(".vm.ophandlers")) {
				for (const Function& F : M)
					if (F.getName().starts_with("__vm_engine")) {
						Model.addEdge({(Twine("dispatch:") + F.getName() + ":" + GV.getName()).str(),
							graphFunctionId(F.getName()), TableId, "vm_dispatch", false});
						break;
					}
			}
			if (const auto* Agg = dyn_cast<ConstantAggregate>(GV.getInitializer())) {
				for (const Use& U : Agg->operands()) {
					const Function* Target = nullptr;
					const BasicBlock* Block = nullptr;
					if (!containsBlockAddress(cast<Constant>(U.get()), Target, Block))
						continue;
					const std::string HandlerId =
						(Twine("handler:") + Target->getName() + ":" +
							(Block->hasName() ? Block->getName() : "unnamed")).str();
					Model.addNode({HandlerId, HandlerId, "vm_handler", true});
					Model.addEdge({(Twine("table:") + GV.getName() + ":" + HandlerId).str(),
						TableId, HandlerId, "handler_table", false});
				}
			}
		}
		for (const Function& F : M) {
			if (F.isDeclaration())
				continue;
			const std::string From = graphFunctionId(F.getName());
			for (const BasicBlock& BB : F) {
				for (const Instruction& I : BB) {
					if (const auto* Call = dyn_cast<CallBase>(&I)) {
						if (const Function* Callee = Call->getCalledFunction()) {
							const std::string To = graphFunctionId(Callee->getName());
							const bool IsZoneGate = Callee->getName() == "xollvm_zone_require";
							Model.addNode({To, Callee->getName().str(),
								IsZoneGate ? "zone_gate" :
								(Callee->isDeclaration() ? "external_declaration" : "source_function"), false});
							Model.addEdge({(Twine("direct:") + F.getName() + ":" +
								Callee->getName()).str(), From, To,
								IsZoneGate ? "zone_gate" : "direct_call", true});
						}
						else {
							const std::string To = graphUnknownId(F.getName());
							Model.addNode({To, "unknown indirect call", "unknown_indirect", false});
							Model.addEdge({(Twine("indirect:") + F.getName()).str(), From, To,
								"indirect_call", false});
						}
					}
					if (const auto* IBr = dyn_cast<IndirectBrInst>(&I)) {
						for (unsigned DestIndex = 0; DestIndex < IBr->getNumDestinations(); ++DestIndex) {
							const BasicBlock* Dest = IBr->getDestination(DestIndex);
							const std::string To = (Twine("block:") + F.getName() + ":" +
								(Dest->hasName() ? Dest->getName() : "unnamed")).str();
							Model.addNode({To, To, "indirect_target_set", false});
							Model.addEdge({(Twine("ibr:") + F.getName() + ":" + To).str(),
								From, To, "indirect_branch", false});
						}
					}
				}
			}
		}
		for (const Function& F : M) {
			MDNode* MD = F.getMetadata("obf.vm.engine");
			if (!MD || MD->getNumOperands() < 5)
				continue;
			auto ReadUInt = [&](unsigned Index) -> unsigned {
				const auto* Meta = dyn_cast<ConstantAsMetadata>(MD->getOperand(Index));
				const auto* CI = Meta ? dyn_cast<ConstantInt>(Meta->getValue()) : nullptr;
				return CI ? static_cast<unsigned>(CI->getZExtValue()) : 0;
			};
			GraphVMEngine Engine;
			Engine.FunctionId = graphFunctionId(F.getName());
			Engine.EngineId = ReadUInt(0);
			Engine.HandlerVariants = ReadUInt(1);
			Engine.Decoys = ReadUInt(2);
			Engine.HandlerTableEntries = ReadUInt(3);
			Engine.EncryptedDispatch = ReadUInt(4) != 0;
			const std::string DispatcherId = Engine.FunctionId + ":dispatcher";
			Model.addNode({DispatcherId, F.getName().str() + " dispatcher",
				"vm_dispatcher", true});
			Model.addEdge({Engine.FunctionId + ":vm-dispatch", Engine.FunctionId,
				DispatcherId, "vm_dispatch", false});
			for (unsigned Variant = 0; Variant < Engine.HandlerVariants; ++Variant) {
				const std::string VariantId = DispatcherId + ":variant:" +
					std::to_string(Variant);
				Model.addNode({VariantId, F.getName().str() + " handler variant " +
					std::to_string(Variant), "vm_handler_variant", true});
				Model.addEdge({VariantId + ":edge", DispatcherId, VariantId,
					"handler_variant", false});
			}
			for (unsigned Decoy = 0; Decoy < Engine.Decoys; ++Decoy) {
				const std::string DecoyId = DispatcherId + ":decoy:" +
					std::to_string(Decoy);
				Model.addNode({DecoyId, F.getName().str() + " decoy " +
					std::to_string(Decoy), "vm_handler", true});
				Model.addEdge({DecoyId + ":edge", DispatcherId, DecoyId,
					"handler_table", false});
			}
			Model.VMEngines.push_back(std::move(Engine));
		}
	}

	static double clamp01(double V) {
		if (V < 0.0)
			return 0.0;
		if (V > 1.0)
			return 1.0;
		return V;
	}

	bool isReportEnabled() {
		return !std::string(ObfReportDir).empty() || !std::string(ObfReportJson).empty();
	}

	bool isGraphReportEnabled() {
		return !std::string(ObfGraphDir).empty();
	}

	std::string getReportDir() {
		return std::string(ObfReportDir);
	}

	std::string getGraphReportDir() {
		return std::string(ObfGraphDir);
	}

	StringRef getGraphReportMode() {
		return ObfGraphMode;
	}

	std::string getReportJsonPath() {
		std::string J = std::string(ObfReportJson);
		if (!J.empty())
			return J;

		std::string D = std::string(ObfReportDir);
		if (D.empty())
			return "";

		SmallString<256> P(D);
		sys::path::append(P, "obf_report.json");
		return std::string(P.str());
	}

	std::string sanitizePathComponent(StringRef S) {
		std::string Out;
		Out.reserve(S.size());
		for (char C : S) {
			unsigned char UC = static_cast<unsigned char>(C);
			if (std::isalnum(UC) || C == '_' || C == '-' || C == '.')
				Out.push_back(C);
			else
				Out.push_back('_');
		}
		if (Out.empty())
			Out = "unnamed";
		return Out;
	}

	static bool isObfMarkedInst(const Instruction& I) {
		if (I.hasName() && I.getName().starts_with("obf."))
			return true;
		if (I.getMetadata("obf.shield"))
			return true;
		return false;
	}

	DifficultyComponents computeDifficultyComponents(const Function& F) {
		DifficultyComponents C;

		C.Insts = llvm::obf::countInstructions(F);

		unsigned Blocks = 0;
		unsigned Edges = 0;
		for (const BasicBlock& BB : F) {
			++Blocks;
			Edges += succ_size(&BB);

			if (const auto* Br = dyn_cast<BranchInst>(BB.getTerminator()))
				if (Br->isConditional())
					++C.ConditionalBranches;

			for (const Instruction& I : BB) {
				if (isa<ICmpInst>(I) && I.hasName() && I.getName().starts_with("obf."))
					++C.OpaquePredicates;

				if (isa<IndirectBrInst>(I))
					++C.IndirectBrs;
				if (isa<CallBrInst>(I))
					++C.CallBrs;

				if (const auto* CB = dyn_cast<CallBase>(&I)) {
					if (!CB->getCalledFunction())
						++C.IndirectCalls;
				}

				if (I.hasName() && I.getName().starts_with("obf.mba."))
					++C.MbaNodes;
			}
		}

		C.Blocks = Blocks;
		C.Edges = Edges;

		// Cyclomatic complexity: E - N + 2 (for a single-entry graph).
		if (Blocks == 0)
			C.Cyclomatic = 0;
		else {
			int64_t CC = (int64_t)Edges - (int64_t)Blocks + 2;
			C.Cyclomatic = (unsigned)std::max<int64_t>(1, CC);
		}

		// MBA depth: marker-based SSA expression depth among instructions whose names
		// start with "obf.mba.".
		DenseMap<const Instruction*, unsigned> Memo;

		auto Depth = [&](auto&& Self, const Instruction* I) -> unsigned {
			if (!I)
				return 0;
			if (!(I->hasName() && I->getName().starts_with("obf.mba.")))
				return 0;

			auto It = Memo.find(I);
			if (It != Memo.end())
				return It->second;

			unsigned D = 1;
			for (const Use& U : I->operands()) {
				if (const auto* OpI = dyn_cast<Instruction>(U.get())) {
					unsigned OD = Self(Self, OpI);
					if (OD)
						D = std::max(D, 1 + OD);
				}
			}

			Memo[I] = D;
			return D;
			};

		double SumDepth = 0.0;
		unsigned MaxDepth = 0;
		unsigned Count = 0;

		for (const BasicBlock& BB : F) {
			for (const Instruction& I : BB) {
				if (!(I.hasName() && I.getName().starts_with("obf.mba.")))
					continue;
				unsigned D = Depth(Depth, &I);
				MaxDepth = std::max(MaxDepth, D);
				SumDepth += (double)D;
				++Count;
			}
		}

		C.MbaMaxDepth = MaxDepth;
		C.MbaAvgDepth = Count ? (SumDepth / (double)Count) : 0.0;

		return C;
	}

	DifficultyScore scoreDifficulty(const DifficultyComponents& Before,
		const DifficultyComponents& After) {
		DifficultyScore S;

		S.CyclomaticBefore = Before.Cyclomatic;
		S.CyclomaticAfter = After.Cyclomatic;
		S.CyclomaticDelta = (int64_t)After.Cyclomatic - (int64_t)Before.Cyclomatic;

		S.OpaquePredicates = After.OpaquePredicates;
		S.OpaquePer100Insts = After.Insts ? (After.OpaquePredicates * 100.0) / (double)After.Insts
			: 0.0;

		S.MbaNodes = After.MbaNodes;
		S.MbaMaxDepth = After.MbaMaxDepth;
		S.MbaAvgDepth = After.MbaAvgDepth;

		S.IndirectBrs = After.IndirectBrs;
		S.CallBrs = After.CallBrs;
		S.IndirectCalls = After.IndirectCalls;

		// Heuristic score: [0,100]. Tune for monotonicity and stability.
		double CCInc = std::max<int64_t>(0, S.CyclomaticDelta);
		double CC = clamp01(CCInc / 40.0);

		double Opaque = clamp01(S.OpaquePer100Insts / 8.0);

		double Mba = clamp01((double)S.MbaMaxDepth / 12.0);

		double Ind = clamp01((double)S.IndirectBrs / 8.0);

		S.Score = 100.0 * (0.30 * CC + 0.25 * Opaque + 0.25 * Mba + 0.20 * Ind);
		return S;
	}

	static std::string dotEscapeLabel(StringRef S) {
		std::string Out;
		Out.reserve(S.size());
		for (char C : S) {
			switch (C) {
			case '\\': Out += "\\\\"; break;
			case '"':  Out += "\\\""; break;
			case '\n': Out += "\\n"; break;
			case '\r': break;
			case '\t': Out += "\\t"; break;
			default:    Out += C; break;
			}
		}
		return Out;
	}

	static std::string svgEscape(StringRef S) {
		std::string Out;
		Out.reserve(S.size());
		for (char C : S) {
			switch (C) {
			case '&': Out += "&amp;"; break;
			case '<': Out += "&lt;"; break;
			case '>': Out += "&gt;"; break;
			case '"': Out += "&quot;"; break;
			case '\'': Out += "&apos;"; break;
			default: Out += C; break;
			}
		}
		return Out;
	}

	static std::string svgTextLabel(StringRef S, size_t MaxLength = 42) {
		std::string Text = S.str();
		if (Text.size() > MaxLength)
			Text = Text.substr(0, MaxLength - 3) + "...";
		return svgEscape(Text);
	}

	static void writeSvgHeader(raw_fd_ostream& OS, unsigned Width, unsigned Height,
		StringRef Title) {
		OS << "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"" << Width
			<< "\" height=\"" << Height << "\" viewBox=\"0 0 " << Width
			<< " " << Height << "\">\n";
		OS << "<defs><marker id=\"arrow\" markerWidth=\"10\" markerHeight=\"7\" "
			"refX=\"9\" refY=\"3.5\" orient=\"auto\"><path d=\"M0,0 L10,3.5 L0,7 z\" "
			"fill=\"#475569\"/></marker></defs>\n";
		OS << "<rect width=\"100%\" height=\"100%\" fill=\"#f8fafc\"/>\n";
		OS << "<text x=\"28\" y=\"34\" font-family=\"monospace\" font-size=\"20\" "
			"font-weight=\"bold\" fill=\"#0f172a\">" << svgEscape(Title)
			<< "</text>\n";
	}

	static Error openSvg(StringRef Path, unsigned Width, unsigned Height,
		StringRef Title, std::unique_ptr<raw_fd_ostream>& Out) {
		std::error_code EC;
		Out = std::make_unique<raw_fd_ostream>(Path, EC, sys::fs::OF_Text);
		if (EC)
			return createStringError(EC, "open('%s')", Path.str().c_str());
		writeSvgHeader(*Out, Width, Height, Title);
		return Error::success();
	}

	struct SvgNodePosition {
		double X = 0.0;
		double Y = 0.0;
	};

	static Error writeFunctionSvg(const Function& F, StringRef Path) {
		constexpr unsigned NodeW = 190;
		constexpr unsigned NodeH = 58;
		constexpr unsigned HGap = 42;
		constexpr unsigned VGap = 74;
		constexpr unsigned Margin = 28;
		std::vector<const BasicBlock*> Blocks;
		DenseMap<const BasicBlock*, unsigned> Index;
		for (const BasicBlock& BB : F) {
			Index[&BB] = Blocks.size();
			Blocks.push_back(&BB);
		}
		if (Blocks.empty())
			return Error::success();

		DenseMap<const BasicBlock*, unsigned> Rank;
		std::vector<const BasicBlock*> Queue;
		Rank[Blocks.front()] = 0;
		Queue.push_back(Blocks.front());
		for (size_t Q = 0; Q < Queue.size(); ++Q) {
			const BasicBlock* BB = Queue[Q];
			for (const BasicBlock* Succ : successors(BB)) {
				if (!Rank.count(Succ)) {
					Rank[Succ] = Rank[BB] + 1;
					Queue.push_back(Succ);
				}
			}
		}
		for (const BasicBlock* BB : Blocks)
			if (!Rank.count(BB))
				Rank[BB] = 0;

		std::map<unsigned, std::vector<const BasicBlock*>> Layers;
		for (const BasicBlock* BB : Blocks)
			Layers[Rank[BB]].push_back(BB);
		unsigned MaxCols = 1;
		for (const auto& Layer : Layers)
			MaxCols = std::max<unsigned>(MaxCols, Layer.second.size());
		const unsigned Width = Margin * 2 + MaxCols * NodeW + (MaxCols - 1) * HGap;
		const unsigned Height = Margin + 54 + Layers.size() * NodeH +
			(Layers.size() ? (Layers.size() - 1) * VGap : 0) + Margin;

		SmallString<256> Parent(sys::path::parent_path(Path));
		if (!Parent.empty()) {
			if (std::error_code EC = sys::fs::create_directories(Parent))
				return createStringError(EC, "create_directories('%s')", Parent.c_str());
		}
		std::unique_ptr<raw_fd_ostream> Out;
		if (Error E = openSvg(Path, Width, Height, (Twine("CFG: ") + F.getName()).str(), Out))
			return E;
		raw_fd_ostream& OS = *Out;
		DenseMap<const BasicBlock*, SvgNodePosition> Positions;
		unsigned LayerIndex = 0;
		for (auto& Layer : Layers) {
			const auto& Nodes = Layer.second;
			const double RowWidth = Nodes.size() * NodeW + (Nodes.size() - 1) * HGap;
			const double X0 = (Width - RowWidth) / 2.0;
			for (size_t Col = 0; Col < Nodes.size(); ++Col) {
				const BasicBlock* BB = Nodes[Col];
				Positions[BB] = {X0 + Col * (NodeW + HGap),
					static_cast<double>(Margin + 54 + LayerIndex * (NodeH + VGap))};
			}
			++LayerIndex;
		}
		for (const BasicBlock* From : Blocks) {
			for (const BasicBlock* To : successors(From)) {
				const auto A = Positions[From];
				const auto B = Positions[To];
				OS << "<path d=\"M " << A.X + NodeW / 2 << " " << A.Y + NodeH
					<< " L " << B.X + NodeW / 2 << " " << B.Y
					<< "\" stroke=\"#64748b\" stroke-width=\"1.5\" fill=\"none\" marker-end=\"url(#arrow)\"/>\n";
			}
		}
		for (size_t I = 0; I < Blocks.size(); ++I) {
			const BasicBlock* BB = Blocks[I];
			const auto P = Positions[BB];
			const bool HasObf = [&] {
				for (const Instruction& Inst : *BB)
					if (isObfMarkedInst(Inst))
						return true;
				return false;
			}();
			OS << "<rect x=\"" << P.X << "\" y=\"" << P.Y << "\" width=\""
				<< NodeW << "\" height=\"" << NodeH << "\" rx=\"8\" fill=\""
				<< (I == 0 ? "#d1fae5" : "#e0e7ff") << "\" stroke=\""
				<< (HasObf ? "#0891b2" : "#64748b") << "\" stroke-width=\""
				<< (HasObf ? 2 : 1) << "\"/>\n";
			const std::string BlockName = BB->hasName() ? BB->getName().str()
				: (Twine("bb") + Twine(I)).str();
			OS << "<text x=\"" << P.X + 12 << "\" y=\"" << P.Y + 24
				<< "\" font-family=\"monospace\" font-size=\"13\" fill=\"#0f172a\">"
				<< svgTextLabel(BlockName)
				<< "</text>\n";
			OS << "<text x=\"" << P.X + 12 << "\" y=\"" << P.Y + 44
				<< "\" font-family=\"monospace\" font-size=\"11\" fill=\"#475569\">insts: "
				<< BB->size() << "</text>\n";
		}
		OS << "</svg>\n";
		return Error::success();
	}

	static std::string graphModuleKey(const Module& M) {
		StringRef Identifier = M.getModuleIdentifier();
		if (Identifier.empty())
			Identifier = "module";
		return sanitizePathComponent(Identifier);
	}

	static json::Object graphModelJson(const GraphModel& Model, StringRef Mode);

	static void restrictToDirectGraph(GraphModel& Model) {
		std::set<std::string> Used;
		std::vector<GraphEdge> Edges;
		for (const GraphEdge& E : Model.Edges) {
			if (E.Type != "direct_call")
				continue;
			Edges.push_back(E);
			Used.insert(E.From);
			Used.insert(E.To);
		}
		std::vector<GraphNode> Nodes;
		for (const GraphNode& N : Model.Nodes)
			if (Used.count(N.Id) || N.Type == "source_function" ||
				N.Type == "external_declaration")
				Nodes.push_back(N);
		Model.Nodes = std::move(Nodes);
		Model.Edges = std::move(Edges);
	}

	static Error writeGraphFragment(const Module& M, StringRef Path) {
		SmallString<256> Parent(sys::path::parent_path(Path));
		if (!Parent.empty()) {
			if (std::error_code EC = sys::fs::create_directories(Parent))
				return createStringError(EC, "create_directories('%s')", Parent.c_str());
		}
		std::error_code EC;
		raw_fd_ostream OS(Path, EC, sys::fs::OF_Text);
		if (EC)
			return createStringError(EC, "open('%s')", Path.str().c_str());
		GraphModel Model;
		collectFinalIRGraph(M, Model);
		if (getGraphReportMode() == "direct")
			restrictToDirectGraph(Model);
		json::OStream J(OS, 2);
		J.value(graphModelJson(Model, getGraphReportMode()));
		OS << "\n";
		return Error::success();
	}

	static Error writeAggregatedCallGraphSvg(StringRef Root, StringRef OutputPath) {
		SmallString<256> FragmentDir(Root);
		sys::path::append(FragmentDir, "modules");
		std::error_code EC;
		sys::fs::directory_iterator It(FragmentDir, EC);
		if (EC && EC != std::errc::no_such_file_or_directory)
			return createStringError(EC, "iterate('%s')", FragmentDir.c_str());
		std::set<std::string> Nodes;
		std::set<std::pair<std::string, std::string>> Edges;
		for (; !EC && It != sys::fs::directory_iterator(); It.increment(EC)) {
			if (!StringRef(It->path()).ends_with(".graph"))
				continue;
			auto BufferOrErr = MemoryBuffer::getFile(It->path());
			if (!BufferOrErr)
				continue;
			SmallVector<StringRef, 32> Lines;
			(*BufferOrErr)->getBuffer().split(Lines, '\n');
			for (StringRef Line : Lines) {
				SmallVector<StringRef, 4> Parts;
				Line.split(Parts, '\t');
				if (Parts.size() == 2 && Parts[0] == "N")
					Nodes.insert(Parts[1].str());
				else if (Parts.size() == 3 && Parts[0] == "E")
					Edges.insert({Parts[1].str(), Parts[2].str()});
			}
		}
		if (EC)
			return createStringError(EC, "iterate('%s')", FragmentDir.c_str());

		constexpr unsigned NodeW = 220;
		constexpr unsigned NodeH = 58;
		constexpr unsigned HGap = 34;
		constexpr unsigned VGap = 42;
		constexpr unsigned Margin = 28;
		std::vector<std::string> Names(Nodes.begin(), Nodes.end());
		const unsigned Columns = Names.empty() ? 1 : std::min<unsigned>(4, Names.size());
		const unsigned Rows = (Names.size() + Columns - 1) / Columns;
		const unsigned Width = Margin * 2 + Columns * NodeW + (Columns - 1) * HGap;
		const unsigned Height = Margin + 54 + std::max<unsigned>(1, Rows) * NodeH +
			(Rows ? (Rows - 1) * VGap : 0) + Margin;
		std::unique_ptr<raw_fd_ostream> Out;
		if (Error E = openSvg(OutputPath, Width, Height, "Program call graph", Out))
			return E;
		raw_fd_ostream& OS = *Out;
		std::map<std::string, SvgNodePosition> Positions;
		for (size_t I = 0; I < Names.size(); ++I) {
			Positions[Names[I]] = {
				static_cast<double>(Margin + (I % Columns) * (NodeW + HGap)),
				static_cast<double>(Margin + 54 + (I / Columns) * (NodeH + VGap))};
		}
		for (const auto& Edge : Edges) {
			const auto A = Positions[Edge.first];
			const auto B = Positions[Edge.second];
			OS << "<path d=\"M " << A.X + NodeW / 2 << " " << A.Y + NodeH / 2
				<< " L " << B.X + NodeW / 2 << " " << B.Y + NodeH / 2
				<< "\" stroke=\"#64748b\" stroke-width=\"1.5\" fill=\"none\" marker-end=\"url(#arrow)\"/>\n";
		}
		for (const std::string& Name : Names) {
			const auto P = Positions[Name];
			OS << "<rect x=\"" << P.X << "\" y=\"" << P.Y << "\" width=\""
				<< NodeW << "\" height=\"" << NodeH << "\" rx=\"8\" fill=\"#dbeafe\" stroke=\"#475569\"/>\n";
			OS << "<text x=\"" << P.X + 12 << "\" y=\"" << P.Y + 34
				<< "\" font-family=\"monospace\" font-size=\"13\" fill=\"#0f172a\">"
				<< svgTextLabel(Name) << "</text>\n";
		}
		OS << "</svg>\n";
		return Error::success();
	}

	static json::Object graphModelJson(const GraphModel& Model, StringRef Mode) {
		json::Object Root;
		Root["schema"] = "llvm_obfuscator.graph";
		Root["schema_version"] = 1;
		Root["graph_mode"] = Mode;
		json::Array Nodes;
		for (const GraphNode& N : Model.Nodes) {
			json::Object Value;
			Value["id"] = N.Id;
			Value["label"] = N.Label;
			Value["type"] = N.Type;
			Value["generated"] = N.Generated;
			Nodes.push_back(std::move(Value));
		}
		json::Array Edges;
		for (const GraphEdge& E : Model.Edges) {
			json::Object Value;
			Value["id"] = E.Id;
			Value["from"] = E.From;
			Value["to"] = E.To;
			Value["type"] = E.Type;
			Value["static_exact"] = E.StaticExact;
			Edges.push_back(std::move(Value));
		}
		Root["nodes"] = std::move(Nodes);
		Root["edges"] = std::move(Edges);
		json::Array Engines;
		for (const GraphVMEngine& Engine : Model.VMEngines) {
			json::Object Value;
			Value["function_id"] = Engine.FunctionId;
			Value["engine_id"] = Engine.EngineId;
			Value["handler_variants"] = Engine.HandlerVariants;
			Value["decoys"] = Engine.Decoys;
			Value["handler_table_entries"] = Engine.HandlerTableEntries;
			Value["encrypted_dispatch"] = Engine.EncryptedDispatch;
			Engines.push_back(std::move(Value));
		}
		Root["vm_engines"] = std::move(Engines);
		return Root;
	}

	static Error writeGraphModelJson(const GraphModel& Model, StringRef Mode,
		StringRef OutputPath) {
		std::error_code EC;
		raw_fd_ostream OS(OutputPath, EC, sys::fs::OF_Text);
		if (EC)
			return createStringError(EC, "open('%s')", OutputPath.str().c_str());
		json::OStream J(OS, 2);
		J.value(graphModelJson(Model, Mode));
		OS << "\n";
		return Error::success();
	}

	static Error writeGraphModelSvg(const GraphModel& Model, StringRef Mode,
		StringRef OutputPath) {
		const unsigned NodeW = 230;
		const unsigned NodeH = 64;
		const unsigned Gap = 36;
		const unsigned Margin = 28;
		std::vector<GraphNode> Nodes = Model.Nodes;
		std::sort(Nodes.begin(), Nodes.end(), [](const GraphNode& A, const GraphNode& B) {
			return A.Id < B.Id;
		});
		const unsigned Columns = Nodes.empty() ? 1 : std::min<unsigned>(4, Nodes.size());
		const unsigned Rows = Nodes.empty() ? 1 : (Nodes.size() + Columns - 1) / Columns;
		const unsigned Width = Margin * 2 + Columns * NodeW + (Columns - 1) * Gap;
		const unsigned Height = Margin * 2 + 34 + Rows * NodeH + (Rows - 1) * Gap;
		std::unique_ptr<raw_fd_ostream> Out;
		if (Error E = openSvg(OutputPath, Width, Height,
			(Twine("Obfuscated graph (") + Mode + ")").str(), Out))
			return E;
		raw_fd_ostream& OS = *Out;
		std::map<std::string, SvgNodePosition> Positions;
		for (size_t I = 0; I < Nodes.size(); ++I)
			Positions[Nodes[I].Id] = {static_cast<double>(Margin + (I % Columns) * (NodeW + Gap)),
				static_cast<double>(Margin + 34 + (I / Columns) * (NodeH + Gap))};
		for (const GraphEdge& E : Model.Edges) {
			auto A = Positions.find(E.From);
			auto B = Positions.find(E.To);
			if (A == Positions.end() || B == Positions.end())
				continue;
			OS << "<path d=\"M " << A->second.X + NodeW / 2 << " " << A->second.Y + NodeH / 2
				<< " L " << B->second.X + NodeW / 2 << " " << B->second.Y + NodeH / 2
				<< "\" stroke=\"" << (E.StaticExact ? "#64748b" : "#dc2626")
				<< "\" stroke-width=\"1.5\" fill=\"none\" marker-end=\"url(#arrow)\"/>\n";
		}
		for (const GraphNode& N : Nodes) {
			const auto P = Positions[N.Id];
			OS << "<rect x=\"" << P.X << "\" y=\"" << P.Y << "\" width=\""
				<< NodeW << "\" height=\"" << NodeH << "\" rx=\"8\" fill=\"#dbeafe\" stroke=\"#475569\"/>\n";
			OS << "<text x=\"" << P.X + 12 << "\" y=\"" << P.Y + 26
				<< "\" font-family=\"monospace\" font-size=\"12\" fill=\"#0f172a\">"
				<< svgTextLabel(N.Label) << "</text>\n";
			OS << "<text x=\"" << P.X + 12 << "\" y=\"" << P.Y + 46
				<< "\" font-family=\"monospace\" font-size=\"10\" fill=\"#475569\">"
				<< svgTextLabel(N.Type) << "</text>\n";
		}
		OS << "</svg>\n";
		return Error::success();
	}

	static Error readAggregatedGraphModel(StringRef Root, StringRef Mode,
		GraphModel& Model) {
		SmallString<256> FragmentDir(Root);
		sys::path::append(FragmentDir, "modules");
		std::error_code EC;
		sys::fs::directory_iterator It(FragmentDir, EC);
		if (EC == std::errc::no_such_file_or_directory)
			return Error::success();
		if (EC)
			return createStringError(EC, "iterate('%s')", FragmentDir.c_str());
		for (; It != sys::fs::directory_iterator(); It.increment(EC)) {
			if (!StringRef(It->path()).ends_with((Twine(".") + Mode + ".graph").str()))
				continue;
			auto BufferOrErr = MemoryBuffer::getFile(It->path());
			if (!BufferOrErr)
				continue;
			auto Parsed = json::parse((*BufferOrErr)->getBuffer());
			if (!Parsed)
				continue;
			json::Object* RootObject = Parsed->getAsObject();
			if (!RootObject)
				continue;
			if (auto Nodes = RootObject->getArray("nodes")) {
				for (const json::Value& Value : *Nodes) {
					const json::Object* Node = Value.getAsObject();
					if (!Node)
						continue;
					auto Id = Node->getString("id");
					auto Label = Node->getString("label");
					auto Type = Node->getString("type");
					if (!Id || !Label || !Type)
						continue;
					Model.addNode({Id->str(), Label->str(), Type->str(),
						Node->getBoolean("generated").value_or(false)});
				}
			}
			if (auto Edges = RootObject->getArray("edges")) {
				for (const json::Value& Value : *Edges) {
					const json::Object* Edge = Value.getAsObject();
					if (!Edge)
						continue;
					auto Id = Edge->getString("id");
					auto From = Edge->getString("from");
					auto To = Edge->getString("to");
					auto Type = Edge->getString("type");
					if (!Id || !From || !To || !Type)
						continue;
					Model.addEdge({Id->str(), From->str(), To->str(), Type->str(),
						Edge->getBoolean("static_exact").value_or(false)});
				}
			}
		}
		if (EC)
			return createStringError(EC, "iterate('%s')", FragmentDir.c_str());
		return Error::success();
	}

	Error writeGraphReport(Module& M) {
		if (!isGraphReportEnabled())
			return Error::success();
		if (getGraphReportMode() != "direct" && getGraphReportMode() != "obfuscated")
			return createStringError(inconvertibleErrorCode(),
				"invalid -obf-graph-mode='%s' (expected direct or obfuscated)",
				getGraphReportMode().str().c_str());
		const std::string Root = getGraphReportDir();
		if (std::error_code EC = sys::fs::create_directories(Root))
			return createStringError(EC, "create_directories('%s')", Root.c_str());
		SmallString<256> ModuleDir(Root);
		sys::path::append(ModuleDir, "modules");
		if (std::error_code EC = sys::fs::create_directories(ModuleDir))
			return createStringError(EC, "create_directories('%s')", ModuleDir.c_str());
		SmallString<256> LockPath(Root);
		sys::path::append(LockPath, ".graph.lock");
		int LockFD = -1;
		if (std::error_code EC = sys::fs::openFileForWrite(LockPath, LockFD,
			sys::fs::CD_CreateAlways, sys::fs::OF_None, sys::fs::all_read | sys::fs::all_write))
			return createStringError(EC, "open('%s')", LockPath.c_str());
		if (std::error_code EC = sys::fs::lockFile(LockFD)) {
			sys::fs::closeFile(LockFD);
			return createStringError(EC, "lock('%s')", LockPath.c_str());
		}
		SmallString<256> FragmentPath(ModuleDir);
		sys::path::append(FragmentPath,
			graphModuleKey(M) + "." + getGraphReportMode().str() + ".graph");
		Error FragmentError = writeGraphFragment(M, FragmentPath);
		if (FragmentError) {
			sys::fs::unlockFile(LockFD);
			sys::fs::closeFile(LockFD);
			return FragmentError;
		}
		GraphModel Model;
		collectFinalIRGraph(M, Model);
		if (getGraphReportMode() == "direct")
			restrictToDirectGraph(Model);
		SmallString<256> JsonPath(Root);
		sys::path::append(JsonPath, "obfuscated_callgraph.json");
		Error GraphError = readAggregatedGraphModel(Root, getGraphReportMode(), Model);
		if (!GraphError)
			GraphError = writeGraphModelJson(Model, getGraphReportMode(), JsonPath);
		if (!GraphError) {
			SmallString<256> CallGraph(Root);
			sys::path::append(CallGraph, getGraphReportMode() == "direct"
				? "program_callgraph.svg" : "obfuscated_callgraph.svg");
			GraphError = writeGraphModelSvg(Model, getGraphReportMode(), CallGraph);
		}
		sys::fs::unlockFile(LockFD);
		sys::fs::closeFile(LockFD);
		if (GraphError)
			return GraphError;
		for (const Function& F : M) {
			if (F.isDeclaration() || F.empty())
				continue;
			SmallString<256> FunctionPath(Root);
			sys::path::append(FunctionPath, "functions");
			sys::path::append(FunctionPath, sanitizePathComponent(F.getName()) + ".svg");
			if (Error E = writeFunctionSvg(F, FunctionPath))
				return E;
		}
		return Error::success();
	}

	Error writeCfgDotSnapshot(const Function& F, StringRef AbsDotPath,
		const DenseMap<const BasicBlock*, unsigned>* PrevInsts,
		DenseMap<const BasicBlock*, unsigned>& OutInsts) {
		// Ensure parent directory exists.
		SmallString<256> Parent(sys::path::parent_path(AbsDotPath));
		if (!Parent.empty()) {
			if (std::error_code EC = sys::fs::create_directories(Parent))
				return createStringError(EC, "create_directories('%s')", Parent.c_str());
		}

		std::error_code EC;
		raw_fd_ostream OS(AbsDotPath, EC, sys::fs::OF_Text);
		if (EC)
			return createStringError(EC, "open('%s')", AbsDotPath.str().c_str());

		// Assign deterministic node IDs (bb0, bb1, ...).
		DenseMap<const BasicBlock*, unsigned> Idx;
		unsigned I = 0;
		for (const BasicBlock& BB : F)
			Idx[&BB] = I++;

		auto NodeId = [&](const BasicBlock* BB) -> std::string {
			return ("bb" + std::to_string(Idx.lookup(BB)));
			};

		auto BlockLabel = [&](const BasicBlock& BB) -> std::string {
			std::string Name = BB.hasName() ? BB.getName().str() : NodeId(&BB);
			return dotEscapeLabel(Name) + "\\ninsts: " + std::to_string(BB.size());
			};

		auto BlockHasObf = [&](const BasicBlock& BB) -> bool {
			for (const Instruction& Inst : BB)
				if (isObfMarkedInst(Inst))
					return true;
			return false;
			};

		OS << "digraph \"cfg.\" {\n";
		OS << "  graph [fontname=\"monospace\", labelloc=t, label=\"CFG: "
			<< dotEscapeLabel(F.getName()) << "\"];\n";
		OS << "  node  [shape=box, style=\"rounded,filled\", fontname=\"monospace\"];\n";
		OS << "  edge  [fontname=\"monospace\"];\n\n";

		for (const BasicBlock& BB : F) {
			const BasicBlock* BBP = &BB;
			unsigned Insts = BB.size();
			OutInsts[BBP] = Insts;

			bool IsNew = false;
			bool IsChanged = false;
			if (PrevInsts) {
				auto It = PrevInsts->find(BBP);
				if (It == PrevInsts->end())
					IsNew = true;
				else if (It->second != Insts)
					IsChanged = true;
			}

			bool HasObf = BlockHasObf(BB);

			// Visual encoding (simple, stable):
			// - new blocks: palegreen fill
			// - changed blocks: khaki fill
			// - blocks containing obf-marked instructions: blue border
			std::string Fill = "white";
			if (IsNew)
				Fill = "palegreen";
			else if (IsChanged)
				Fill = "khaki";

			std::string Border = HasObf ? "deepskyblue4" : "gray50";
			unsigned PenW = HasObf ? 2 : 1;

			OS << "  " << NodeId(BBP)
				<< " [label=\"" << BlockLabel(BB) << "\""
				<< ", fillcolor=\"" << Fill << "\""
				<< ", color=\"" << Border << "\""
				<< ", penwidth=" << PenW
				<< "];\n";
		}

		OS << "\n";

		for (const BasicBlock& BB : F) {
			const BasicBlock* From = &BB;
			for (const BasicBlock* To : successors(From)) {
				OS << "  " << NodeId(From) << " -> " << NodeId(To) << ";\n";
			}
		}

		OS << "}\n";
		return Error::success();
	}

	static json::Object toJson(const DifficultyScore& D) {
		json::Object O;
		O["score"] = D.Score;
		O["cyclomatic_before"] = D.CyclomaticBefore;
		O["cyclomatic_after"] = D.CyclomaticAfter;
		O["cyclomatic_delta"] = D.CyclomaticDelta;
		O["opaque_predicates"] = D.OpaquePredicates;
		O["opaque_per_100_insts"] = D.OpaquePer100Insts;
		O["mba_nodes"] = D.MbaNodes;
		O["mba_max_depth"] = D.MbaMaxDepth;
		O["mba_avg_depth"] = D.MbaAvgDepth;
		O["indirect_branches"] = D.IndirectBrs;
		O["callbrs"] = D.CallBrs;
		O["indirect_calls"] = D.IndirectCalls;
		return O;
	}

	static json::Object toJson(const PassReport& P) {
		json::Object O;
		O["id"] = P.Id;
		O["seed"] = (int64_t)P.Seed;
		O["status"] = P.Skipped ? "skipped" : "ran";
		if (P.Skipped) {
			if (!P.SkipReason.empty())
				O["skip_reason"] = P.SkipReason;
		}
		else {
			O["changed"] = P.Changed;
		}
		O["insts_before"] = (int64_t)P.InstsBefore;
		O["insts_after"] = (int64_t)P.InstsAfter;
		O["delta_insts"] = (int64_t)P.InstsAfter - (int64_t)P.InstsBefore;
		O["budget_util_after"] = P.BudgetUtilAfter;
		return O;
	}

	static json::Object toJson(const FunctionReport& R) {
		json::Object O;

		O["name"] = R.Name;
		O["declaration"] = R.Declaration;

		if (R.Skipped) {
			O["skipped"] = true;
			if (!R.SkipReason.empty())
				O["skip_reason"] = R.SkipReason;
		}
		else {
			O["skipped"] = false;
		}

		json::Object Seed;
		Seed["base"] = (int64_t)R.BaseSeed;
		Seed["module"] = (int64_t)R.ModuleSeed;
		Seed["function"] = (int64_t)R.FunctionSeed;
		O["seed"] = std::move(Seed);

		json::Object Insts;
		Insts["before"] = (int64_t)R.InstsBefore;
		Insts["after"] = (int64_t)R.InstsAfter;
		O["insts"] = std::move(Insts);

		json::Object Budget;
		Budget["enabled"] = R.BudgetEnabled;
		if (R.BudgetEnabled) {
			Budget["limit"] = (int64_t)R.BudgetLimit;
			Budget["remaining"] = (int64_t)R.BudgetRemaining;
			Budget["utilization"] = R.BudgetUtilization;
		}
		O["budget"] = std::move(Budget);

		json::Array Passes;
		for (const auto& P : R.Passes)
			Passes.push_back(toJson(P));
		O["passes"] = std::move(Passes);
		if (R.VM) O["vm"] = R.VM->toJson();
		json::Object AntiDebug;
		AntiDebug["enabled"] = R.AntiDebugEnabled;
		json::Array Detectors;
		for (const auto& D : R.AntiDebugDetectors) Detectors.push_back(D);
		AntiDebug["detectors"] = std::move(Detectors);
		AntiDebug["dynamic"] = R.AntiDebugDynamic;
		AntiDebug["response"] = R.AntiDebugResponse;
		O["anti_debug"] = std::move(AntiDebug);

		O["difficulty"] = toJson(R.Difficulty);

		// Artifacts
		if (!R.CfgBeforeDot.empty() || !R.CfgAfterDot.empty() || !R.CfgPerPass.empty()) {
			json::Object Art;
			json::Object Cfg;
			if (!R.CfgBeforeDot.empty())
				Cfg["before_dot"] = R.CfgBeforeDot;
			if (!R.CfgAfterDot.empty())
				Cfg["after_dot"] = R.CfgAfterDot;
			if (!R.CfgPerPass.empty()) {
				json::Array Stages;
				for (const auto& S : R.CfgPerPass) {
					json::Object SO;
					SO["pass"] = S.Pass;
					SO["after_dot"] = S.DotAfter;
					if (!S.DotDiff.empty())
						SO["diff_dot"] = S.DotDiff;
					Stages.push_back(std::move(SO));
				}
				Cfg["per_pass"] = std::move(Stages);
			}
			Art["cfg"] = std::move(Cfg);
			O["artifacts"] = std::move(Art);
		}

		return O;
	}

	Error maybeWriteObfReportJson(Module& M, ModuleAnalysisManager& MAM) {
		std::string JsonPath = getReportJsonPath();
		if (JsonPath.empty())
			return Error::success();

		auto& Sink = MAM.getResult<ObfReportAnalysis>(M);

		// Sort functions by name for deterministic output.
		std::vector<const FunctionReport*> Sorted;
		Sorted.reserve(Sink.Functions.size());
		for (const auto& FR : Sink.Functions)
			Sorted.push_back(&FR);
		std::sort(Sorted.begin(), Sorted.end(), [](const FunctionReport* A, const FunctionReport* B) {
			return A->Name < B->Name;
			});

		json::Object Root;
		Root["schema"] = "llvm_obfuscator.obf_map";
		Root["schema_version"] = (int64_t)kObfReportSchemaVersion;

		json::Object Mod;
		Mod["identifier"] = M.getModuleIdentifier();
		if (!M.getSourceFileName().empty())
			Mod["source_file"] = M.getSourceFileName();
		if (!M.getTargetTriple().empty())
			Mod["target_triple"] = M.getTargetTriple().getTriple();
		if (!M.getDataLayoutStr().empty())
			Mod["data_layout"] = M.getDataLayoutStr();
		Root["module"] = std::move(Mod);

		json::Array Funcs;
		for (const FunctionReport* FR : Sorted)
			Funcs.push_back(toJson(*FR));
		Root["functions"] = std::move(Funcs);

		// Ensure parent directory exists.
		if (JsonPath != "-") {
			SmallString<256> Parent(sys::path::parent_path(JsonPath));
			if (!Parent.empty()) {
				if (std::error_code EC = sys::fs::create_directories(Parent))
					return createStringError(EC, "create_directories('%s')", Parent.c_str());
			}
		}

		if (JsonPath == "-") {
			json::OStream J(outs(), 2);
			J.value(std::move(Root));
			outs() << "\n";
			return Error::success();
		}

		std::error_code EC;
		raw_fd_ostream OS(JsonPath, EC, sys::fs::OF_Text);
		if (EC)
			return createStringError(EC, "open('%s')", JsonPath.c_str());

		json::OStream J(OS, 2);
		J.value(std::move(Root));
		OS << "\n";
		return Error::success();
	}

} // namespace llvm::obf

namespace llvm {

	AnalysisKey ObfReportAnalysis::Key;

	ObfReportAnalysis::Result ObfReportAnalysis::run(Module&, ModuleAnalysisManager&) {
		// Start empty. Function passes append to the sink via the MAM proxy.
		return obf::ObfReportSink();
	}

} // namespace llvm
