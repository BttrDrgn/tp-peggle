workspace "tp-peggle"
	startproject "tp-peggle"
	location "../build/"
	targetdir "%{wks.location}/bin/%{cfg.buildcfg}-%{cfg.platform}/"
	objdir "%{wks.location}/obj/%{prj.name}/%{cfg.buildcfg}-%{cfg.platform}/"
	buildlog "%{wks.location}/obj/%{cfg.platform}/%{cfg.buildcfg}-%{prj.name}.log"

	largeaddressaware "on"
	editandcontinue "off"
	staticruntime "on"

	systemversion "latest"
	characterset "unicode"
	warnings "extra"

	flags {
		"noincrementallink",
		"no64bitchecks",
		"shadowedvariables",
		"undefinedidentifiers",
		"multiprocessorcompile",
	}

	platforms {
		"x86",
	}

	configurations {
		"Release",
		"Debug",
	}

	defines {
		"NOMINMAX",
		"WIN32_LEAN_AND_MEAN",
		"_CRT_SECURE_NO_WARNINGS",
		"_SILENCE_ALL_CXX17_DEPRECATION_WARNINGS",
	}

	--x86
	filter "platforms:x86"	
		architecture "x86"
	--end

	filter "Release"
		defines "NDEBUG"
		optimize "full"
		runtime "release"
		symbols "off"

	filter "Debug"
		defines "DEBUG"
		optimize "debug"
		runtime "debug"
		symbols "on"

	project "tp-peggle"
		targetname "tp-peggle"
		language "c++"
		cppdialect "c++17"
		kind "sharedlib"
		warnings "off"

		pchheader "stdafx.hpp"
		pchsource "../src/stdafx.cpp"
		forceincludes "stdafx.hpp"

		dependson {
			"SDL2",
			"MinHook",
		}

		links {
			"SDL2",
			"MinHook",
		}

		includedirs {
			"../src/",
			"../deps/minhook/include/",
			"../deps/SDL/include/",
		}

		files {
			"../src/**",
		}

	group "Dependencies"

	project "SDL2"
		language "c"
		kind "staticlib"

		defines {
			"HAVE_LIBC=1",
			"_WINDOWS",
		}

		links {
			"setupapi.lib",
			"winmm.lib",
			"imm32.lib",
			"version.lib",
		}

		files {
			"../deps/SDL/include/**",

			"../deps/SDL/include/begin_code.h",
			"../deps/SDL/include/close_code.h",
			"../deps/SDL/include/SDL.h",
			"../deps/SDL/include/SDL_assert.h",
			"../deps/SDL/include/SDL_atomic.h",
			"../deps/SDL/include/SDL_audio.h",
			"../deps/SDL/include/SDL_bits.h",
			"../deps/SDL/include/SDL_blendmode.h",
			"../deps/SDL/include/SDL_clipboard.h",
			"../deps/SDL/include/SDL_config.h",
			"../deps/SDL/include/SDL_config_windows.h",
			"../deps/SDL/include/SDL_copying.h",
			"../deps/SDL/include/SDL_cpuinfo.h",
			"../deps/SDL/include/SDL_egl.h",
			"../deps/SDL/include/SDL_endian.h",
			"../deps/SDL/include/SDL_error.h",
			"../deps/SDL/include/SDL_events.h",
			"../deps/SDL/include/SDL_filesystem.h",
			"../deps/SDL/include/SDL_gamecontroller.h",
			"../deps/SDL/include/SDL_gesture.h",
			"../deps/SDL/include/SDL_guid.h",
			"../deps/SDL/include/SDL_haptic.h",
			"../deps/SDL/include/SDL_hints.h",
			"../deps/SDL/include/SDL_hidapi.h",
			"../deps/SDL/include/SDL_joystick.h",
			"../deps/SDL/include/SDL_keyboard.h",
			"../deps/SDL/include/SDL_keycode.h",
			"../deps/SDL/include/SDL_loadso.h",
			"../deps/SDL/include/SDL_locale.h",
			"../deps/SDL/include/SDL_log.h",
			"../deps/SDL/include/SDL_main.h",
			"../deps/SDL/include/SDL_messagebox.h",
			"../deps/SDL/include/SDL_metal.h",
			"../deps/SDL/include/SDL_misc.h",
			"../deps/SDL/include/SDL_mouse.h",
			"../deps/SDL/include/SDL_mutex.h",
			"../deps/SDL/include/SDL_name.h",
			"../deps/SDL/include/SDL_opengl.h",
			"../deps/SDL/include/SDL_opengl_glext.h",
			"../deps/SDL/include/SDL_opengles.h",
			"../deps/SDL/include/SDL_opengles2.h",
			"../deps/SDL/include/SDL_opengles2_gl2.h",
			"../deps/SDL/include/SDL_opengles2_gl2ext.h",
			"../deps/SDL/include/SDL_opengles2_gl2platform.h",
			"../deps/SDL/include/SDL_opengles2_khrplatform.h",
			"../deps/SDL/include/SDL_pixels.h",
			"../deps/SDL/include/SDL_platform.h",
			"../deps/SDL/include/SDL_power.h",
			"../deps/SDL/include/SDL_quit.h",
			"../deps/SDL/include/SDL_rect.h",
			"../deps/SDL/include/SDL_render.h",
			"../deps/SDL/include/SDL_revision.h",
			"../deps/SDL/include/SDL_rwops.h",
			"../deps/SDL/include/SDL_scancode.h",
			"../deps/SDL/include/SDL_sensor.h",
			"../deps/SDL/include/SDL_shape.h",
			"../deps/SDL/include/SDL_stdinc.h",
			"../deps/SDL/include/SDL_surface.h",
			"../deps/SDL/include/SDL_system.h",
			"../deps/SDL/include/SDL_syswm.h",
			"../deps/SDL/include/SDL_test.h",
			"../deps/SDL/include/SDL_test_assert.h",
			"../deps/SDL/include/SDL_test_common.h",
			"../deps/SDL/include/SDL_test_compare.h",
			"../deps/SDL/include/SDL_test_crc32.h",
			"../deps/SDL/include/SDL_test_font.h",
			"../deps/SDL/include/SDL_test_fuzzer.h",
			"../deps/SDL/include/SDL_test_harness.h",
			"../deps/SDL/include/SDL_test_images.h",
			"../deps/SDL/include/SDL_test_log.h",
			"../deps/SDL/include/SDL_test_md5.h",
			"../deps/SDL/include/SDL_test_memory.h",
			"../deps/SDL/include/SDL_test_random.h",
			"../deps/SDL/include/SDL_thread.h",
			"../deps/SDL/include/SDL_timer.h",
			"../deps/SDL/include/SDL_touch.h",
			"../deps/SDL/include/SDL_types.h",
			"../deps/SDL/include/SDL_version.h",
			"../deps/SDL/include/SDL_video.h",
			"../deps/SDL/include/SDL_vulkan.h",
			"../deps/SDL/src/audio/directsound/SDL_directsound.h",
			"../deps/SDL/src/audio/disk/SDL_diskaudio.h",
			"../deps/SDL/src/audio/dummy/SDL_dummyaudio.h",
			"../deps/SDL/src/audio/SDL_audio_c.h",
			"../deps/SDL/src/audio/SDL_audiodev_c.h",
			"../deps/SDL/src/audio/SDL_sysaudio.h",
			"../deps/SDL/src/audio/SDL_wave.h",
			"../deps/SDL/src/audio/wasapi/SDL_wasapi.h",
			"../deps/SDL/src/audio/winmm/SDL_winmm.h",
			"../deps/SDL/src/core/windows/SDL_directx.h",
			"../deps/SDL/src/core/windows/SDL_hid.h",
			"../deps/SDL/src/core/windows/SDL_immdevice.h",
			"../deps/SDL/src/core/windows/SDL_windows.h",
			"../deps/SDL/src/core/windows/SDL_xinput.h",
			"../deps/SDL/src/dynapi/SDL_dynapi.h",
			"../deps/SDL/src/dynapi/SDL_dynapi_overrides.h",
			"../deps/SDL/src/dynapi/SDL_dynapi_procs.h",
			"../deps/SDL/src/events/blank_cursor.h",
			"../deps/SDL/src/events/default_cursor.h",
			"../deps/SDL/src/events/scancodes_windows.h",
			"../deps/SDL/src/events/SDL_clipboardevents_c.h",
			"../deps/SDL/src/events/SDL_displayevents_c.h",
			"../deps/SDL/src/events/SDL_dropevents_c.h",
			"../deps/SDL/src/events/SDL_events_c.h",
			"../deps/SDL/src/events/SDL_gesture_c.h",
			"../deps/SDL/src/events/SDL_keyboard_c.h",
			"../deps/SDL/src/events/SDL_mouse_c.h",
			"../deps/SDL/src/events/SDL_touch_c.h",
			"../deps/SDL/src/events/SDL_windowevents_c.h",
			"../deps/SDL/src/haptic/SDL_haptic_c.h",
			"../deps/SDL/src/haptic/SDL_syshaptic.h",
			"../deps/SDL/src/haptic/windows/SDL_dinputhaptic_c.h",
			"../deps/SDL/src/haptic/windows/SDL_windowshaptic_c.h",
			"../deps/SDL/src/haptic/windows/SDL_xinputhaptic_c.h",
			"../deps/SDL/src/hidapi/hidapi/hidapi.h",
			"../deps/SDL/src/hidapi/SDL_hidapi_c.h",
			"../deps/SDL/src/joystick/controller_type.h",
			"../deps/SDL/src/joystick/hidapi/SDL_hidapijoystick_c.h",
			"../deps/SDL/src/joystick/hidapi/SDL_hidapi_rumble.h",
			"../deps/SDL/src/joystick/SDL_gamecontrollerdb.h",
			"../deps/SDL/src/joystick/SDL_joystick_c.h",
			"../deps/SDL/src/joystick/SDL_sysjoystick.h",
			"../deps/SDL/src/joystick/usb_ids.h",
			"../deps/SDL/src/joystick/virtual/SDL_virtualjoystick_c.h",
			"../deps/SDL/src/joystick/windows/SDL_dinputjoystick_c.h",
			"../deps/SDL/src/joystick/windows/SDL_rawinputjoystick_c.h",
			"../deps/SDL/src/joystick/windows/SDL_windowsjoystick_c.h",
			"../deps/SDL/src/joystick/windows/SDL_xinputjoystick_c.h",
			"../deps/SDL/src/libm/math_libm.h",
			"../deps/SDL/src/libm/math_private.h",
			"../deps/SDL/src/locale/SDL_syslocale.h",
			"../deps/SDL/src/misc/SDL_sysurl.h",
			"../deps/SDL/src/power/SDL_syspower.h",
			"../deps/SDL/src/render/direct3d11/SDL_shaders_d3d11.h",
			"../deps/SDL/src/render/direct3d12/SDL_shaders_d3d12.h",
			"../deps/SDL/src/render/direct3d/SDL_shaders_d3d.h",
			"../deps/SDL/src/render/opengles2/SDL_gles2funcs.h",
			"../deps/SDL/src/render/opengles2/SDL_shaders_gles2.h",
			"../deps/SDL/src/render/opengl/SDL_glfuncs.h",
			"../deps/SDL/src/render/opengl/SDL_shaders_gl.h",
			"../deps/SDL/src/render/SDL_d3dmath.h",
			"../deps/SDL/src/render/SDL_sysrender.h",
			"../deps/SDL/src/render/SDL_yuv_sw_c.h",
			"../deps/SDL/src/render/software/SDL_blendfillrect.h",
			"../deps/SDL/src/render/software/SDL_blendline.h",
			"../deps/SDL/src/render/software/SDL_blendpoint.h",
			"../deps/SDL/src/render/software/SDL_draw.h",
			"../deps/SDL/src/render/software/SDL_drawline.h",
			"../deps/SDL/src/render/software/SDL_drawpoint.h",
			"../deps/SDL/src/render/software/SDL_render_sw_c.h",
			"../deps/SDL/src/render/software/SDL_rotate.h",
			"../deps/SDL/src/render/software/SDL_triangle.h",
			"../deps/SDL/src/SDL_assert_c.h",
			"../deps/SDL/src/SDL_dataqueue.h",
			"../deps/SDL/src/SDL_error_c.h",
			"../deps/SDL/src/SDL_guid.c",
			"../deps/SDL/src/SDL_hints_c.h",
			"../deps/SDL/src/SDL_internal.h",
			"../deps/SDL/src/SDL_list.h",
			"../deps/SDL/src/SDL_log_c.h",
			"../deps/SDL/src/sensor/dummy/SDL_dummysensor.h",
			"../deps/SDL/src/sensor/SDL_sensor_c.h",
			"../deps/SDL/src/sensor/SDL_syssensor.h",
			"../deps/SDL/src/sensor/windows/SDL_windowssensor.h",
			"../deps/SDL/src/thread/SDL_systhread.h",
			"../deps/SDL/src/thread/SDL_thread_c.h",
			"../deps/SDL/src/thread/generic/SDL_syscond_c.h",
			"../deps/SDL/src/thread/windows/SDL_sysmutex_c.h",
			"../deps/SDL/src/thread/windows/SDL_systhread_c.h",
			"../deps/SDL/src/timer/SDL_timer_c.h",
			"../deps/SDL/src/video/dummy/SDL_nullevents_c.h",
			"../deps/SDL/src/video/dummy/SDL_nullframebuffer_c.h",
			"../deps/SDL/src/video/dummy/SDL_nullvideo.h",
			"../deps/SDL/src/video/khronos/vulkan/vk_icd.h",
			"../deps/SDL/src/video/khronos/vulkan/vk_layer.h",
			"../deps/SDL/src/video/khronos/vulkan/vk_platform.h",
			"../deps/SDL/src/video/khronos/vulkan/vk_sdk_platform.h",
			"../deps/SDL/src/video/khronos/vulkan/vulkan.h",
			"../deps/SDL/src/video/khronos/vulkan/vulkan.hpp",
			"../deps/SDL/src/video/khronos/vulkan/vulkan_android.h",
			"../deps/SDL/src/video/khronos/vulkan/vulkan_beta.h",
			"../deps/SDL/src/video/khronos/vulkan/vulkan_core.h",
			"../deps/SDL/src/video/khronos/vulkan/vulkan_directfb.h",
			"../deps/SDL/src/video/khronos/vulkan/vulkan_fuchsia.h",
			"../deps/SDL/src/video/khronos/vulkan/vulkan_ggp.h",
			"../deps/SDL/src/video/khronos/vulkan/vulkan_ios.h",
			"../deps/SDL/src/video/khronos/vulkan/vulkan_macos.h",
			"../deps/SDL/src/video/khronos/vulkan/vulkan_metal.h",
			"../deps/SDL/src/video/khronos/vulkan/vulkan_vi.h",
			"../deps/SDL/src/video/khronos/vulkan/vulkan_wayland.h",
			"../deps/SDL/src/video/khronos/vulkan/vulkan_win32.h",
			"../deps/SDL/src/video/khronos/vulkan/vulkan_xcb.h",
			"../deps/SDL/src/video/khronos/vulkan/vulkan_xlib.h",
			"../deps/SDL/src/video/khronos/vulkan/vulkan_xlib_xrandr.h",
			"../deps/SDL/src/video/SDL_blit.h",
			"../deps/SDL/src/video/SDL_blit_auto.h",
			"../deps/SDL/src/video/SDL_blit_copy.h",
			"../deps/SDL/src/video/SDL_blit_slow.h",
			"../deps/SDL/src/video/SDL_egl_c.h",
			"../deps/SDL/src/video/SDL_pixels_c.h",
			"../deps/SDL/src/video/SDL_rect_c.h",
			"../deps/SDL/src/video/SDL_RLEaccel_c.h",
			"../deps/SDL/src/video/SDL_shape_internals.h",
			"../deps/SDL/src/video/SDL_sysvideo.h",
			"../deps/SDL/src/video/SDL_vulkan_internal.h",
			"../deps/SDL/src/video/SDL_yuv_c.h",
			"../deps/SDL/src/video/windows/SDL_msctf.h",
			"../deps/SDL/src/video/windows/SDL_vkeys.h",
			"../deps/SDL/src/video/windows/SDL_windowsclipboard.h",
			"../deps/SDL/src/video/windows/SDL_windowsevents.h",
			"../deps/SDL/src/video/windows/SDL_windowsframebuffer.h",
			"../deps/SDL/src/video/windows/SDL_windowskeyboard.h",
			"../deps/SDL/src/video/windows/SDL_windowsmessagebox.h",
			"../deps/SDL/src/video/windows/SDL_windowsmodes.h",
			"../deps/SDL/src/video/windows/SDL_windowsmouse.h",
			"../deps/SDL/src/video/windows/SDL_windowsopengl.h",
			"../deps/SDL/src/video/windows/SDL_windowsopengles.h",
			"../deps/SDL/src/video/windows/SDL_windowsshape.h",
			"../deps/SDL/src/video/windows/SDL_windowstaskdialog.h",
			"../deps/SDL/src/video/windows/SDL_windowsvideo.h",
			"../deps/SDL/src/video/windows/SDL_windowsvulkan.h",
			"../deps/SDL/src/video/windows/SDL_windowswindow.h",
			"../deps/SDL/src/video/windows/wmmsg.h",
			"../deps/SDL/src/video/yuv2rgb/yuv_rgb.h",
			"../deps/SDL/src/video/yuv2rgb/yuv_rgb_sse_func.h",
			"../deps/SDL/src/video/yuv2rgb/yuv_rgb_std_func.h",

			"../deps/SDL/src/atomic/SDL_atomic.c",
			"../deps/SDL/src/atomic/SDL_spinlock.c",
			"../deps/SDL/src/audio/directsound/SDL_directsound.c",
			"../deps/SDL/src/audio/disk/SDL_diskaudio.c",
			"../deps/SDL/src/audio/dummy/SDL_dummyaudio.c",
			"../deps/SDL/src/audio/SDL_audio.c",
			"../deps/SDL/src/audio/SDL_audiocvt.c",
			"../deps/SDL/src/audio/SDL_audiodev.c",
			"../deps/SDL/src/audio/SDL_audiotypecvt.c",
			"../deps/SDL/src/audio/SDL_mixer.c",
			"../deps/SDL/src/audio/SDL_wave.c",
			"../deps/SDL/src/audio/winmm/SDL_winmm.c",
			"../deps/SDL/src/audio/wasapi/SDL_wasapi.c",
			"../deps/SDL/src/audio/wasapi/SDL_wasapi_win32.c",
			"../deps/SDL/src/core/windows/SDL_hid.c",
			"../deps/SDL/src/core/windows/SDL_immdevice.c",
			"../deps/SDL/src/core/windows/SDL_windows.c",
			"../deps/SDL/src/core/windows/SDL_xinput.c",
			"../deps/SDL/src/cpuinfo/SDL_cpuinfo.c",
			"../deps/SDL/src/dynapi/SDL_dynapi.c",
			"../deps/SDL/src/events/SDL_clipboardevents.c",
			"../deps/SDL/src/events/SDL_displayevents.c",
			"../deps/SDL/src/events/SDL_dropevents.c",
			"../deps/SDL/src/events/SDL_events.c",
			"../deps/SDL/src/events/SDL_gesture.c",
			"../deps/SDL/src/events/SDL_keyboard.c",
			"../deps/SDL/src/events/SDL_mouse.c",
			"../deps/SDL/src/events/SDL_quit.c",
			"../deps/SDL/src/events/SDL_touch.c",
			"../deps/SDL/src/events/SDL_windowevents.c",
			"../deps/SDL/src/file/SDL_rwops.c",
			"../deps/SDL/src/filesystem/windows/SDL_sysfilesystem.c",
			"../deps/SDL/src/haptic/dummy/SDL_syshaptic.c",
			"../deps/SDL/src/haptic/SDL_haptic.c",
			"../deps/SDL/src/haptic/windows/SDL_dinputhaptic.c",
			"../deps/SDL/src/haptic/windows/SDL_windowshaptic.c",
			"../deps/SDL/src/haptic/windows/SDL_xinputhaptic.c",
			"../deps/SDL/src/hidapi/SDL_hidapi.c",
			"../deps/SDL/src/joystick/controller_type.c",
			"../deps/SDL/src/joystick/dummy/SDL_sysjoystick.c",
			"../deps/SDL/src/joystick/hidapi/SDL_hidapijoystick.c",
			"../deps/SDL/src/joystick/hidapi/SDL_hidapi_gamecube.c",
			"../deps/SDL/src/joystick/hidapi/SDL_hidapi_luna.c",
			"../deps/SDL/src/joystick/hidapi/SDL_hidapi_ps4.c",
			"../deps/SDL/src/joystick/hidapi/SDL_hidapi_ps5.c",
			"../deps/SDL/src/joystick/hidapi/SDL_hidapi_rumble.c",
			"../deps/SDL/src/joystick/hidapi/SDL_hidapi_shield.c",
			"../deps/SDL/src/joystick/hidapi/SDL_hidapi_stadia.c",
			"../deps/SDL/src/joystick/hidapi/SDL_hidapi_switch.c",
			"../deps/SDL/src/joystick/hidapi/SDL_hidapi_xbox360.c",
			"../deps/SDL/src/joystick/hidapi/SDL_hidapi_xbox360w.c",
			"../deps/SDL/src/joystick/hidapi/SDL_hidapi_xboxone.c",
			"../deps/SDL/src/joystick/SDL_gamecontroller.c",
			"../deps/SDL/src/joystick/SDL_joystick.c",
			"../deps/SDL/src/joystick/virtual/SDL_virtualjoystick.c",
			"../deps/SDL/src/joystick/windows/SDL_dinputjoystick.c",
			"../deps/SDL/src/joystick/windows/SDL_rawinputjoystick.c",
			"../deps/SDL/src/joystick/windows/SDL_windowsjoystick.c",
			"../deps/SDL/src/joystick/windows/SDL_windows_gaming_input.c",
			"../deps/SDL/src/joystick/windows/SDL_xinputjoystick.c",
			"../deps/SDL/src/libm/e_atan2.c",
			"../deps/SDL/src/libm/e_exp.c",
			"../deps/SDL/src/libm/e_fmod.c",
			"../deps/SDL/src/libm/e_log.c",
			"../deps/SDL/src/libm/e_log10.c",
			"../deps/SDL/src/libm/e_pow.c",
			"../deps/SDL/src/libm/e_rem_pio2.c",
			"../deps/SDL/src/libm/e_sqrt.c",
			"../deps/SDL/src/libm/k_cos.c",
			"../deps/SDL/src/libm/k_rem_pio2.c",
			"../deps/SDL/src/libm/k_sin.c",
			"../deps/SDL/src/libm/k_tan.c",
			"../deps/SDL/src/libm/s_atan.c",
			"../deps/SDL/src/libm/s_copysign.c",
			"../deps/SDL/src/libm/s_cos.c",
			"../deps/SDL/src/libm/s_fabs.c",
			"../deps/SDL/src/libm/s_floor.c",
			"../deps/SDL/src/libm/s_scalbn.c",
			"../deps/SDL/src/libm/s_sin.c",
			"../deps/SDL/src/libm/s_tan.c",
			"../deps/SDL/src/loadso/windows/SDL_sysloadso.c",
			"../deps/SDL/src/locale/SDL_locale.c",
			"../deps/SDL/src/locale/windows/SDL_syslocale.c",
			"../deps/SDL/src/misc/SDL_url.c",
			"../deps/SDL/src/misc/windows/SDL_sysurl.c",
			"../deps/SDL/src/power/SDL_power.c",
			"../deps/SDL/src/power/windows/SDL_syspower.c",
			"../deps/SDL/src/render/direct3d11/SDL_shaders_d3d11.c",
			"../deps/SDL/src/render/direct3d12/SDL_render_d3d12.c",
			"../deps/SDL/src/render/direct3d12/SDL_shaders_d3d12.c",
			"../deps/SDL/src/render/direct3d/SDL_render_d3d.c",
			"../deps/SDL/src/render/direct3d11/SDL_render_d3d11.c",
			"../deps/SDL/src/render/direct3d/SDL_shaders_d3d.c",
			"../deps/SDL/src/render/opengl/SDL_render_gl.c",
			"../deps/SDL/src/render/opengl/SDL_shaders_gl.c",
			"../deps/SDL/src/render/opengles2/SDL_render_gles2.c",
			"../deps/SDL/src/render/opengles2/SDL_shaders_gles2.c",
			"../deps/SDL/src/render/SDL_d3dmath.c",
			"../deps/SDL/src/render/SDL_render.c",
			"../deps/SDL/src/render/SDL_yuv_sw.c",
			"../deps/SDL/src/render/software/SDL_blendfillrect.c",
			"../deps/SDL/src/render/software/SDL_blendline.c",
			"../deps/SDL/src/render/software/SDL_blendpoint.c",
			"../deps/SDL/src/render/software/SDL_drawline.c",
			"../deps/SDL/src/render/software/SDL_drawpoint.c",
			"../deps/SDL/src/render/software/SDL_render_sw.c",
			"../deps/SDL/src/render/software/SDL_rotate.c",
			"../deps/SDL/src/render/software/SDL_triangle.c",
			"../deps/SDL/src/SDL.c",
			"../deps/SDL/src/SDL_assert.c",
			"../deps/SDL/src/SDL_dataqueue.c",
			"../deps/SDL/src/SDL_list.c",
			"../deps/SDL/src/SDL_error.c",
			"../deps/SDL/src/SDL_hints.c",
			"../deps/SDL/src/SDL_log.c",
			"../deps/SDL/src/sensor/dummy/SDL_dummysensor.c",
			"../deps/SDL/src/sensor/SDL_sensor.c",
			"../deps/SDL/src/sensor/windows/SDL_windowssensor.c",
			"../deps/SDL/src/stdlib/SDL_crc32.c",
			"../deps/SDL/src/stdlib/SDL_getenv.c",
			"../deps/SDL/src/stdlib/SDL_iconv.c",
			"../deps/SDL/src/stdlib/SDL_malloc.c",
			"../deps/SDL/src/stdlib/SDL_memcpy.c",
			"../deps/SDL/src/stdlib/SDL_memset.c",
			"../deps/SDL/src/stdlib/SDL_qsort.c",
			"../deps/SDL/src/stdlib/SDL_stdlib.c",
			"../deps/SDL/src/stdlib/SDL_string.c",
			"../deps/SDL/src/stdlib/SDL_strtokr.c",
			"../deps/SDL/src/thread/generic/SDL_syscond.c",
			"../deps/SDL/src/thread/SDL_thread.c",
			"../deps/SDL/src/thread/windows/SDL_syscond_cv.c",
			"../deps/SDL/src/thread/windows/SDL_sysmutex.c",
			"../deps/SDL/src/thread/windows/SDL_syssem.c",
			"../deps/SDL/src/thread/windows/SDL_systhread.c",
			"../deps/SDL/src/thread/windows/SDL_systls.c",
			"../deps/SDL/src/timer/SDL_timer.c",
			"../deps/SDL/src/timer/windows/SDL_systimer.c",
			"../deps/SDL/src/video/dummy/SDL_nullevents.c",
			"../deps/SDL/src/video/dummy/SDL_nullframebuffer.c",
			"../deps/SDL/src/video/dummy/SDL_nullvideo.c",
			"../deps/SDL/src/video/SDL_blit.c",
			"../deps/SDL/src/video/SDL_blit_0.c",
			"../deps/SDL/src/video/SDL_blit_1.c",
			"../deps/SDL/src/video/SDL_blit_A.c",
			"../deps/SDL/src/video/SDL_blit_auto.c",
			"../deps/SDL/src/video/SDL_blit_copy.c",
			"../deps/SDL/src/video/SDL_blit_N.c",
			"../deps/SDL/src/video/SDL_blit_slow.c",
			"../deps/SDL/src/video/SDL_bmp.c",
			"../deps/SDL/src/video/SDL_clipboard.c",
			"../deps/SDL/src/video/SDL_egl.c",
			"../deps/SDL/src/video/SDL_fillrect.c",
			"../deps/SDL/src/video/SDL_pixels.c",
			"../deps/SDL/src/video/SDL_rect.c",
			"../deps/SDL/src/video/SDL_RLEaccel.c",
			"../deps/SDL/src/video/SDL_shape.c",
			"../deps/SDL/src/video/SDL_stretch.c",
			"../deps/SDL/src/video/SDL_surface.c",
			"../deps/SDL/src/video/SDL_video.c",
			"../deps/SDL/src/video/SDL_vulkan_utils.c",
			"../deps/SDL/src/video/SDL_yuv.c",
			"../deps/SDL/src/video/windows/SDL_windowsclipboard.c",
			"../deps/SDL/src/video/windows/SDL_windowsevents.c",
			"../deps/SDL/src/video/windows/SDL_windowsframebuffer.c",
			"../deps/SDL/src/video/windows/SDL_windowskeyboard.c",
			"../deps/SDL/src/video/windows/SDL_windowsmessagebox.c",
			"../deps/SDL/src/video/windows/SDL_windowsmodes.c",
			"../deps/SDL/src/video/windows/SDL_windowsmouse.c",
			"../deps/SDL/src/video/windows/SDL_windowsopengl.c",
			"../deps/SDL/src/video/windows/SDL_windowsopengles.c",
			"../deps/SDL/src/video/windows/SDL_windowsshape.c",
			"../deps/SDL/src/video/windows/SDL_windowsvideo.c",
			"../deps/SDL/src/video/windows/SDL_windowsvulkan.c",
			"../deps/SDL/src/video/windows/SDL_windowswindow.c",
			"../deps/SDL/src/video/yuv2rgb/yuv_rgb.c",
		}

		includedirs {
			"../deps/SDL/include/",
		}

	project "MinHook"
		targetname "MinHook"

		language "c++"
		kind "staticlib"

		files {
			"../deps/minhook/src/**",
		}

		includedirs {
			"../deps/minhook/include/",
		}