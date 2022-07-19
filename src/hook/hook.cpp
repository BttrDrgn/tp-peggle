#include "hook.hpp"

namespace utils
{
	void hook::nop(std::uint32_t address, std::uint32_t size)
	{
		DWORD protecc;
		VirtualProtect(reinterpret_cast<void*>(address), size, PAGE_EXECUTE_READWRITE, &protecc);
		for (auto i = 0u; i < size; ++i)
		{
			hook::set<hook::instr>(address + i, instr::nop);
		}
		VirtualProtect(reinterpret_cast<void*>(address), size, protecc, &protecc);
	}

	void hook::write(std::uint32_t address, const std::initializer_list<std::uint8_t>& bytes)
	{
		DWORD protecc;
		VirtualProtect(reinterpret_cast<void*>(address), bytes.size(), PAGE_EXECUTE_READWRITE, &protecc);
		std::memcpy(reinterpret_cast<std::uint8_t*>(address), bytes.begin(), bytes.size());
		VirtualProtect(reinterpret_cast<void*>(address), bytes.size(), protecc, &protecc);
	}

	void hook::retn(std::uint32_t address)
	{
		DWORD protecc;
		VirtualProtect(reinterpret_cast<void*>(address), 1, PAGE_EXECUTE_READWRITE, &protecc);
		utils::hook::set<hook::instr>(address, instr::retn);
		VirtualProtect(reinterpret_cast<void*>(address), 1, protecc, &protecc);
	}
}
