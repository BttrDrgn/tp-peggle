#pragma once

#include <functional>

namespace utils
{
	template <typename t> class function final
	{
	public:
		function() : function_(reinterpret_cast<t*>(nullptr))
		{

		}

		function(t* ptr) : function_(ptr)
		{

		}

		function(std::uint32_t address) : function_(reinterpret_cast<t*>(address))
		{

		}

		function(const utils::function<t>& other) : function_(other.function_)
		{

		}

		auto operator=(std::uint32_t address) -> utils::function<t>&
		{
			this->function_ = reinterpret_cast<t*>(address);

			return *this;
		}

		auto operator=(const utils::function<t>& function) -> utils::function<t>&
		{
			this->function_ = function.function_;

			return *this;
		}

		template <typename... v> auto operator()(v&& ...args) const -> decltype(auto)
		{
			return this->function_(args...);
		}

	private:
		t* function_;
	};

	template <typename t> class vtable final
	{
	public:
		vtable() : table_(nullptr)
		{

		}

		vtable(std::uint32_t address) : table_(reinterpret_cast<t*>(address))
		{

		}

		vtable(const utils::vtable<t>& other) : table_(other.table_)
		{

		}

		auto get() -> t*
		{
			return reinterpret_cast<t*>(*reinterpret_cast<std::uint32_t**>(this->table_));
		}

		auto get(std::uint32_t index) -> std::uint32_t
		{
			return (**reinterpret_cast<std::uint32_t***>(this->table_))[index];
		}

		template <typename f> auto call(std::uint32_t index) -> utils::function<f>
		{
			return utils::function<f>((**reinterpret_cast<std::uint32_t***>(this->table_))[index]);
		}

		template <typename f> auto hook(std::uint32_t index, f function) -> std::uint32_t
		{
			const auto result = **reinterpret_cast<std::uint32_t***>(this->table_);
			const auto original = result[index];

			set<std::uint32_t>(std::uint32_t(&result[index]), std::uint32_t(function));

			return original;
		}

		auto operator->() -> t*
		{
			return reinterpret_cast<t*>(*reinterpret_cast<std::uint32_t**>(this->table_));
		}

	private:
		t* table_;
	};

	namespace hook
	{
		enum class instr : std::uint8_t
		{
			nop = 0x90,
			mov = 0xB8,
			jmp = 0xE9,
			retn = 0xC3,
			call = 0xE8,
		};

		void nop(std::uint32_t address, std::uint32_t size);

		void write(std::uint32_t address, const std::initializer_list<std::uint8_t>& bytes);
		void retn(std::uint32_t address);

		template <typename T> auto get(std::uint32_t address)
		{
			return *reinterpret_cast<T*>(address);
		}

		template <typename T> void set(std::uint32_t address, T value)
		{
			DWORD protecc;
			VirtualProtect(reinterpret_cast<void*>(address), sizeof(T), PAGE_EXECUTE_READWRITE, &protecc);
			*reinterpret_cast<T*>(address) = value;
			VirtualProtect(reinterpret_cast<void*>(address), sizeof(T), protecc, &protecc);
		}

		template <typename T> void jump(std::uint32_t address, T function)
		{
			DWORD protecc;
			VirtualProtect(reinterpret_cast<void*>(address), 5, PAGE_EXECUTE_READWRITE, &protecc);
			hook::set<hook::instr>(address, instr::jmp);
			hook::set<std::uint32_t>(address + 1, std::uint32_t(function) - address - 5);
			VirtualProtect(reinterpret_cast<void*>(address), 5, protecc, &protecc);
		}

		template <typename T> void call(std::uint32_t address, T function)
		{
			DWORD protecc;
			VirtualProtect(reinterpret_cast<void*>(address), 5, PAGE_EXECUTE_READWRITE, &protecc);
			hook::set<hook::instr>(address, instr::call);
			hook::set<std::uint32_t>(address + 1, std::uint32_t(function) - address - 5);
			VirtualProtect(reinterpret_cast<void*>(address), 5, protecc, &protecc);
		}

		template <typename T> void return_value(std::uint32_t address, T value)
		{
			DWORD protecc;
			VirtualProtect(reinterpret_cast<void*>(address), 5, PAGE_EXECUTE_READWRITE, &protecc);
			hook::set<hook::instr>(address, instr::mov);
			hook::set<std::uint32_t>(address + 1, std::uint32_t(value));
			hook::set<hook::instr>(address + 5, instr::retn);
			VirtualProtect(reinterpret_cast<void*>(address), 5, protecc, &protecc);
		}

		template <typename T> auto detour(std::uint32_t source, const T& destination, std::uint32_t size) ->utils::function<T>
		{
			DWORD protecc;
			VirtualProtect(reinterpret_cast<void*>(source), size + 5, PAGE_EXECUTE_READWRITE, &protecc);

			const auto address = ::VirtualAlloc(nullptr, size + 5, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

			std::memcpy(address, reinterpret_cast<std::uint8_t*>(source), size + 5);

			hook::jump(source, destination);
			hook::jump(reinterpret_cast<std::uint32_t>(address) + size, source + size);

			VirtualProtect(reinterpret_cast<void*>(source), size + 5, protecc, &protecc);

			return utils::function<T>(reinterpret_cast<T*>(address));
		}
	}
}
