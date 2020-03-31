#include "plugin.h"
#include <zydis_wrapper.h>
#include <set>
#include <queue>

bool MemIsCanonicalAddress(duint Address)
{
#ifndef _WIN64
	// 32-bit mode only supports 4GB max, so limits are
	// not an issue
	return true;
#else
	// The most-significant 16 bits must be all 1 or all 0.
	// (64 - 16) = 48bit linear address range.
	//
	// 0xFFFF800000000000 = Significant 16 bits set
	// 0x0000800000000000 = 48th bit set
	return (((Address & 0xFFFF800000000000) + 0x800000000000) & ~0x800000000000) == 0;
#endif //_WIN64
}

static bool MemReadDumb(duint BaseAddress, void* Buffer, duint Size)
{
	if (!MemIsCanonicalAddress(BaseAddress) || !Buffer || !Size)
		return false;

	duint offset = 0;
	duint requestedSize = Size;
	duint sizeLeftInFirstPage = PAGE_SIZE - (BaseAddress & (PAGE_SIZE - 1));
	duint readSize = min(sizeLeftInFirstPage, requestedSize);
	auto hProcess = DbgGetProcessHandle();
	bool success = true;
	while (readSize)
	{
		SIZE_T bytesRead = 0;
		if (!MemoryReadSafe(hProcess, (PVOID)(BaseAddress + offset), (PBYTE)Buffer + offset, readSize, &bytesRead))
			success = false;
		offset += readSize;
		requestedSize -= readSize;
		readSize = min(PAGE_SIZE, requestedSize);
	}
	return success;
}

struct ModuleCache
{
	duint base = 0;
	std::vector<unsigned char> data;

	void init(duint addr)
	{
		Script::Module::ModuleInfo info;
		Script::Module::InfoFromAddr(addr, &info);
		base = info.base;
		data.resize(info.size);
		MemReadDumb(info.base, data.data(), info.size);
	}

	bool read(duint va, void* dest, duint size)
	{
		if (inrange(va))
		{
			memcpy(dest, data.data() + (va - base), size);
			return true;
		}
		return DbgMemRead(va, dest, size);
	}

	bool disasm(Zydis& zydis, duint va)
	{
		unsigned char data[16] = { 0 };
		return read(va, data, sizeof(data)) && zydis.Disassemble(va, data);
	}

	bool inrange(duint va)
	{
		return va >= base && va < base + data.size();
	}
};

struct InstrInfo
{
	duint addr = 0;
	duint size = 0;
	ZydisMnemonic id = ZYDIS_MNEMONIC_INVALID;
};

static bool isCmov(ZydisMnemonic id)
{
	switch (id)
	{
	case ZYDIS_MNEMONIC_CMOVB:
	case ZYDIS_MNEMONIC_CMOVBE:
	case ZYDIS_MNEMONIC_CMOVL:
	case ZYDIS_MNEMONIC_CMOVLE:
	case ZYDIS_MNEMONIC_CMOVNB:
	case ZYDIS_MNEMONIC_CMOVNBE:
	case ZYDIS_MNEMONIC_CMOVNL:
	case ZYDIS_MNEMONIC_CMOVNLE:
	case ZYDIS_MNEMONIC_CMOVNO:
	case ZYDIS_MNEMONIC_CMOVNP:
	case ZYDIS_MNEMONIC_CMOVNS:
	case ZYDIS_MNEMONIC_CMOVNZ:
	case ZYDIS_MNEMONIC_CMOVO:
	case ZYDIS_MNEMONIC_CMOVP:
	case ZYDIS_MNEMONIC_CMOVS:
	case ZYDIS_MNEMONIC_CMOVZ:
		return true;
	}
	return false;
}

static bool cbExplore(int argc, char* argv[])
{
	if (argc < 2)
	{
		dputs("Usage: arxan_explore vm_enter");
		return false;
	}
	char filename[MAX_PATH] = "";
	sprintf_s(filename, "arxan_%s.log", argv[1]);
	FILE* fLog = nullptr;
	fopen_s(&fLog, filename, "w");
	if (!fLog)
	{
		dprintf("Failed to open log %s\n", filename);
		return false;
	}
	auto vm_enter = DbgValFromString(argv[1]);
	ModuleCache mod;
	mod.init(vm_enter);
	std::set<duint> visited, handlers;
	std::queue<duint> queue;
	std::vector<InstrInfo> instrInfo;
	queue.emplace(vm_enter);
	Zydis zydis;
	int count = 0, disasmCount = 0;
	int cmovCount = 0, cmovHandled = 0;
	for(int count = 0; !queue.empty();)
	{
		if (count >= 1000)
		{
			fprintf(fLog, "reached limit %d\n", count);
			break;
		}
		auto block_va = queue.front();
		if (!mod.inrange(block_va))
		{
			fprintf(fLog, "out of range block address: %p\n", block_va);
			break;
		}
		queue.pop();
		if (visited.count(block_va))
			continue;
		visited.emplace(block_va);
		count++;

		fprintf(fLog, "visiting block %p\n", block_va);

		auto cur_va = block_va;
		bool hasPushedHandler = false;

		while (true)
		{
			if (!mod.disasm(zydis, cur_va))
			{
				fprintf(fLog, "failed to disassemble %p (block: %p)\n", cur_va, block_va);
				break;
			}
			disasmCount++;
			if (disasmCount >= 100000)
			{
				fprintf(fLog, "reached disasm limit %d\n", disasmCount);
				break;
			}
				

			visited.emplace(cur_va);

			InstrInfo info;
			info.addr = cur_va;
			info.size = zydis.Size();
			info.id = zydis.GetId();

			if (isCmov(info.id))
			{
				fprintf(fLog, "cmov spotted at %p in block %p\n", info.addr, block_va);
				cmovCount++;
			}

			if (info.id == ZYDIS_MNEMONIC_LEA
				&& zydis[0].type == ZYDIS_OPERAND_TYPE_REGISTER
				&& zydis[0].reg.value == ZYDIS_REGISTER_RSP
				&& zydis[1].type == ZYDIS_OPERAND_TYPE_MEMORY
				&& (zydis[1].mem.base == ZYDIS_REGISTER_RSP || zydis[1].mem.index == ZYDIS_REGISTER_RSP)
				&& zydis[1].mem.disp.hasDisplacement
				&& std::abs(zydis[1].mem.disp.value) == 0x100)
			{
				auto isEnter = zydis[1].mem.disp.value < 0;
				fprintf(fLog, "detected vm %s at %p in block %p\n", isEnter ? "enter" : "exit", info.addr, block_va);
				DbgSetAutoCommentAt(info.addr, isEnter ? "context save" : "context restore");
			}

			bool isRet = zydis.IsRet();
			if (zydis.IsJump())
			{
				auto dest1 = zydis.BranchDestination();
				if (dest1 == 0) // jmp [mem] (like ret anyway)
				{
					fprintf(fLog, "assuming ret at %p\n", cur_va);
					isRet = true; // TODO: better heuristics
				}
				else
				{
					fprintf(fLog, "jump dest %p -> %p\n", cur_va, dest1);
					if (zydis.IsBranchType(Zydis::BranchType::BTCondJmp))
					{
						auto dest2 = cur_va + zydis.Size();
						fprintf(fLog, "cond fallthrough %p -> %p\n", cur_va, dest2);
						queue.emplace(dest1);
						queue.emplace(dest2);
					}
					else
					{
						if (visited.count(dest1))
						{
							fprintf(fLog, "fuckup %p\n", cur_va);
							break;
						}
						cur_va = dest1;
						continue;
					}
				}
			}
			else if (zydis.GetId() == ZYDIS_MNEMONIC_XCHG && instrInfo.back().id == ZYDIS_MNEMONIC_LEA) // lea rbp, [handleraddr]; xchg [rsp], rbp
			{
				if (zydis[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
				{
					mod.disasm(zydis, instrInfo.back().addr);
					bool fucked = false;
					auto dest = zydis.ResolveOpValue(1, [&fucked](ZydisRegister r) -> duint
					{
						fucked = true;
						return 0;
					});
					if (!fucked)
					{
						hasPushedHandler = true;
						char msg[256] = "";
						sprintf_s(msg, "handler push %p", dest);
						DbgSetAutoCommentAt(zydis.Address(), msg);
						DbgSetAutoCommentAt(info.addr, msg);
						fprintf(fLog, "potential pushed handler candidate %p -> %p\n", zydis.Address(), dest);
						queue.emplace(dest);
						handlers.emplace(dest);
					}
				}
			}

			if(isRet)
			{
				auto oldInstrInfo = instrInfo;
				instrInfo.clear();
				std::reverse(oldInstrInfo.begin(), oldInstrInfo.end());

				//TODO: write a proper matching algorithm for:
				// mov rdx,rdr2.7FF63798DE6D
				// cmove rcx,rdx
				// mov qword ptr ss:[rsp+10],rcx
				auto cmovItr = std::find_if(oldInstrInfo.begin(), oldInstrInfo.end(), [](const InstrInfo& info)
				{
					return isCmov(info.id);
				});

				if (cmovItr == oldInstrInfo.end() || cmovItr == oldInstrInfo.begin())
				{
					fprintf(fLog, "%s ret detected at %p!\n", hasPushedHandler ? "fake" : "unhandled", cur_va);
				}
				else
				{
					auto nextInstr = cmovItr - 1;
					if (nextInstr->id == ZYDIS_MNEMONIC_MOV)
					{
						mod.disasm(zydis, nextInstr->addr);
						if (zydis[0].type == ZYDIS_OPERAND_TYPE_MEMORY
							&& (zydis[0].mem.base == ZYDIS_REGISTER_RSP || zydis[0].mem.index == ZYDIS_REGISTER_RSP)
							&& zydis[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
						{

							std::vector<std::pair<duint, duint>> dests;
							for (auto itr = cmovItr; itr != oldInstrInfo.end() && dests.size() < 2; ++itr)
							{
								const InstrInfo& info = *itr;
								if (info.id == ZYDIS_MNEMONIC_MOV)
								{
									mod.disasm(zydis, info.addr);
									if (zydis[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
									{
										bool fucked = false;
										auto dest = zydis.ResolveOpValue(1, [&fucked](ZydisRegister r) -> duint
										{
											fucked = true;
											return 0;
										});
										if (mod.inrange(dest) && !fucked)
										{
											dests.push_back({ info.addr, dest });
										}
									}
								}
							}
							if (dests.size() != 2)
							{
								fprintf(fLog, "unhandled cmov handler at %p\n", cur_va);
							}
							else
							{
								DbgSetAutoCommentAt(dests[0].first, "cmov handler candidate 1");
								auto dest1 = dests[0].second;
								DbgSetAutoCommentAt(dests[1].first, "cmov handler candidate 2");
								auto dest2 = dests[1].second;
								fprintf(fLog, "cmov %p candidates: (%p -> %p), (%p -> %p)\n", cmovItr->addr, dests[0].first, dest1, dests[1].first, dest2);
								queue.emplace(dest1);
								handlers.emplace(dest1);
								queue.emplace(dest2);
								handlers.emplace(dest2);
								cmovHandled++;
							}
						}
					}
				}
				
				break;
			}

			instrInfo.push_back(info);
			cur_va += info.size;
		}

		if (disasmCount >= 100000)
			break;
	}
	fprintf(fLog, "cmov handled: %d/%d\n", cmovHandled, cmovCount);
	fclose(fLog);

	GuiReferenceInitialize("Arxan handlers");
	GuiReferenceAddColumn(16, "Addr");
	GuiReferenceAddColumn(0, "Disam");
	GuiReferenceSetRowCount((int)handlers.size());
	int idx = 0;
	for (duint addr : handlers)
	{
		char str[256] = "";
		sprintf_s(str, "%p", addr);
		GuiReferenceSetCellContent(idx, 0, str);
		mod.disasm(zydis, addr);
		GuiReferenceSetCellContent(idx, 1, zydis.InstructionText().c_str());
		idx++;
	}
	GuiReferenceReloadData();
	GuiUpdateAllViews();
	dprintf("done, see %s for details...\n", filename);

	return true;
}

static DWORD pidCache = 0;
static std::vector<Script::Module::ModuleSectionInfo> sectionsCache;

static size_t findSection(duint addr)
{
	auto curPid = DbgGetProcessId();
	if (curPid != pidCache)
	{
		BridgeList<Script::Module::ModuleSectionInfo> sections;
		if (Script::Module::SectionListFromAddr(Script::Module::GetMainModuleBase(), &sections))
		{
			for (int i = 0; i < sections.Count(); i++)
				sectionsCache.push_back(sections[i]);
			pidCache = curPid;
		}
	}

	for (size_t i = 0; i < sectionsCache.size(); i++)
	{
		const auto& section = sectionsCache[i];
		if (addr >= section.addr && addr < section.addr + section.size)
			return i;
	}
	return sectionsCache.size();
}

static void cbSelChanged(CBTYPE cbType, LPVOID generic_param)
{
	PLUG_CB_SELCHANGED* info = (PLUG_CB_SELCHANGED*)generic_param;
	if (info->hWindow == GUI_DISASSEMBLY)
	{
		auto addr = info->VA;
		auto base = Script::Module::BaseFromAddr(addr);
		if (base == Script::Module::GetMainModuleBase() && !sectionsCache.empty())
		{
			std::string info;
			auto selSectionIdx = findSection(addr);
			if (selSectionIdx + 1 == sectionsCache.size())
				info = "Arxan section";

			auto dest = DbgGetBranchDestination(addr);
			if (dest)
			{
				auto destSectionIdx = findSection(dest);
				if (destSectionIdx != sectionsCache.size() && destSectionIdx != selSectionIdx)
				{
					if (!info.empty())
						info += ", ";
					info += "Cross section branch";
				}
			}

			if (!info.empty())
				GuiAddInfoLine(info.c_str());
		}
	}
}

static size_t resolveRegister(ZydisRegister reg)
{
	if (reg == ZYDIS_REGISTER_NONE)
		return 0;
	auto regname = ZydisRegisterGetString(reg);
	if (!regname)
		__debugbreak();
	return DbgValFromString(regname);
}

static bool cbEmulate(int argc, char* argv[])
{
	if (argc < 2)
	{
		dputs("usage: arxan_emulate addr");
		return false;
	}
	auto addr = DbgValFromString(argv[1]);
	unsigned char data[16] = { 0 };
	if (!DbgMemRead(addr, data, sizeof(data)))
	{
		dputs("failed to read memory!");
		return false;
	}
	Zydis zydis;
	if (!zydis.Disassemble(addr, data))
	{
		dputs("failed to disassemble!");
		return false;
	}

	switch (zydis.GetId())
	{
	case ZYDIS_MNEMONIC_MOV:
	{
		if (zydis[0].type == ZYDIS_OPERAND_TYPE_MEMORY && zydis[0].size <= 64 && zydis[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
		{
			auto destAddr = zydis.ResolveOpValue(0, resolveRegister);
			auto srcValue = resolveRegister(zydis[1].reg.value);
			dprintf("write 0x%llX (%u bits) to 0x%p\n", srcValue, zydis[0].size, destAddr);
			DbgMemWrite(destAddr, &srcValue, zydis[0].size / 8);
		}
		else
		{
			dputs("unsupported mov variant");
			return false;
		}
	}
	break;

	default:
	{
		dprintf("unsupported mnemonic %s (%u)\n", zydis.Mnemonic().c_str(), zydis.GetId());
		return false;
	}
	}

	return true;
}

static bool cbProtect(int argc, char* argv[])
{
	if (argc < 3)
	{
		dputs("usage: arxan_protect section_addr, r/rw/rx/rwx");
		return false;
	}
	auto sectionAddr = DbgValFromString(argv[1]);
	auto sectionIdx = findSection(sectionAddr);
	if (sectionIdx == sectionsCache.size())
	{
		dprintf("failed to find section for %p\n", sectionAddr);
		return false;
	}
	DWORD dwProtect = 0;
	std::string prot = argv[2];
	for (char& ch : prot)
		ch = tolower(ch);
	if (prot == "r")
		dwProtect = PAGE_READONLY;
	else if (prot == "rw")
		dwProtect = PAGE_READWRITE;
	else if (prot == "rx")
		dwProtect = PAGE_EXECUTE_READ;
	else if (prot == "rwx")
		dwProtect = PAGE_EXECUTE_READWRITE;
	else
	{
		dprintf("unknown protection '%s'\n", prot.c_str());
		return false;
	}
	DWORD dwOldProtect = 0;
	const auto& section = sectionsCache[sectionIdx];
	dprintf("VirtualProtect(%p, %p, %X)\n", section.addr, section.size, dwProtect);
	if (!VirtualProtectEx(DbgGetProcessHandle(), (LPVOID)section.addr, section.size, dwProtect, &dwOldProtect))
	{
		dprintf("VirtualProtect failed, error %d\n", GetLastError());
		return false;
	}
	return true;
}

//Initialize your plugin data here.
bool pluginInit(PLUG_INITSTRUCT* initStruct)
{
    _plugin_registercommand(pluginHandle, "arxan_explore", cbExplore, true);
	_plugin_registercommand(pluginHandle, "arxan_emulate", cbEmulate, true);
	_plugin_registercommand(pluginHandle, "arxan_protect", cbProtect, true);
    return true; //Return false to cancel loading the plugin.
}

//Deinitialize your plugin data here.
void pluginStop()
{
}

//Do GUI/Menu related things here.
void pluginSetup()
{
	_plugin_registercallback(pluginHandle, CB_SELCHANGED, &cbSelChanged);
}
