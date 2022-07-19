#define SDL_MAIN_HANDLED
#include <SDL.h>
#include <SDL_syswm.h>
#include <MinHook.h>
#include "hook/hook.hpp"

SDL_Window* window;

typedef LRESULT(__stdcall* def_window_proc_a_t)(HWND, UINT, WPARAM, LPARAM);
def_window_proc_a_t fpDefWidowProcA = NULL;
LRESULT __stdcall def_window_proc_a(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
	switch (Msg)
	{
		case 3:
		{
			SDL_DestroyWindow(window);
		}
		break;

		case 7:
		{
			window = SDL_CreateWindowFrom(hWnd);
			SDL_SetWindowGrab(window, SDL_TRUE);
		}
		break;

		case 8:
		{
			SDL_DestroyWindow(window);
		}
		break;
	}

	return fpDefWidowProcA(hWnd, Msg, wParam, lParam);
}

void init()
{
	SDL_SetMainReady();
	if (SDL_Init(SDL_INIT_EVERYTHING) != 0)
	{
		SDL_ShowSimpleMessageBox(0, "TP Peggle", "An error occurred when starting SDL2.", window);
	}

	MH_Initialize();
	MH_CreateHook(&DefWindowProcA, &def_window_proc_a, reinterpret_cast<LPVOID*>(&fpDefWidowProcA));
	MH_EnableHook(MH_ALL_HOOKS);
}

DWORD WINAPI OnAttachImpl(LPVOID lpParameter)
{
	init();
	return 0;
}

DWORD WINAPI OnAttach(LPVOID lpParameter)
{
	__try
	{
		return OnAttachImpl(lpParameter);
	}
	__except (0)
	{
		FreeLibraryAndExitThread((HMODULE)lpParameter, 0xDECEA5ED);
	}

	return 0;
}

BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hModule);
		CreateThread(nullptr, 0, OnAttach, hModule, 0, nullptr);
		return true;
	}

	return false;
}
