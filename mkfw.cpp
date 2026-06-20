#include <phnt_windows.h>
#include <phnt.h>

#include <CommCtrl.h>
#include <fwpmu.h>

#include <algorithm>
#include <array>
#include <tuple>

#if defined DEBUG || defined _DEBUG
void mk_crash(void){ int volatile* volatile ptr; ptr = NULL; *ptr = 0; }
#define mk_assert(x) (((x)) ? ((void)(0)) : ((void)(__debugbreak(), mk_crash())))
#else
#define mk_assert(x)
#endif

// fnv1a begin

struct fnv1a_state
{
	DWORD m_sum;
};

constexpr static inline void fnv1a_init(fnv1a_state& state)
{
	state.m_sum = 0x811c9dc5;
}

constexpr static inline void fnv1a_append(fnv1a_state& state, BYTE const& val)
{
	state.m_sum ^= ((DWORD)(val));
	state.m_sum *= 0x01000193;
}

constexpr static inline void fnv1a_append(fnv1a_state& state, CHAR const& val)
{
	fnv1a_append(state, ((BYTE)(val)));
}

constexpr static inline void fnv1a_append(fnv1a_state& state, LPCCH const& str, DWORD const& len)
{
	DWORD n;
	DWORD i;

	n = len;
	for(i = 0; i != n; ++i)
	{
		fnv1a_append(state, str[i]);
	}
}

constexpr static inline DWORD fnv1a_finish(fnv1a_state const& state)
{
	return state.m_sum;
}

constexpr static inline DWORD fnv1a(LPCCH const& str, DWORD const& len)
{
	fnv1a_state hasher;

	fnv1a_init(hasher);
	fnv1a_append(hasher, str, len);
	return fnv1a_finish(hasher);
}

constexpr static inline DWORD fnv1alcdll(LPCSTR const& str, DWORD const& len)
{
	fnv1a_state hasher;
	DWORD n;
	DWORD i;
	UCHAR uchar;

	fnv1a_init(hasher);
	n = len;
	for(i = 0; i != n; ++i)
	{
		uchar = (str[i] >= 'A' && str[i] <= 'Z') ? ((UCHAR)(str[i] + ('a' - 'A'))) : ((UCHAR)(str[i]));
		fnv1a_append(hasher, uchar);
	}
	fnv1a_append(hasher, '.');
	fnv1a_append(hasher, 'd');
	fnv1a_append(hasher, 'l');
	fnv1a_append(hasher, 'l');
	return fnv1a_finish(hasher);
}

constexpr static inline DWORD fnv1a(PWCHAR const& str, DWORD const& len)
{
	fnv1a_state hasher;
	DWORD n;
	DWORD i;
	UCHAR uchar;

	fnv1a_init(hasher);
	n = len;
	for(i = 0; i != n; ++i)
	{
		uchar = (str[i] >= L'A' && str[i] <= L'Z') ? ((UCHAR)(str[i] + (L'a' - L'A'))) : ((UCHAR)(str[i]));
		fnv1a_append(hasher, uchar);
	}
	return fnv1a_finish(hasher);
}

static inline DWORD fnv1a(LPCVOID const& str, DWORD const& len)
{
	return fnv1a(((LPCCH)(str)), len);
}

template<typename t>
static inline DWORD fnv1a(t const&) = delete;

template<>
constexpr static inline DWORD fnv1a<LPCCH>(LPCCH const& str)
{
	LPCCH txt;
	fnv1a_state hasher;

	txt = str;
	fnv1a_init(hasher);
	while(*txt)
	{
		fnv1a_append(hasher, *txt++);
	}
	return fnv1a_finish(hasher);
}

template<DWORD N>
constexpr static inline DWORD fnv1a(CHAR const(&str)[N]) noexcept
{
	return fnv1a(str, N - 1);
}

// fnv1a end

template<typename t, size_t n>
constexpr static inline auto make_zstr(t const(&name)[n])
{
	std::array<t, n - 1> arr{};

	mk_assert(name[n - 1] == '\0');

	std::copy(name, name + arr.size(), arr.data());
	return arr;
}

static inline HMODULE find_module(PPEB const& peb, DWORD const& k_hash)
{
	HMODULE mod;
	PPEB_LDR_DATA ldr;
	PLDR_DATA_TABLE_ENTRY list;
	PLDR_DATA_TABLE_ENTRY entry;
	SHORT len;
	PWCHAR name;
	DWORD sum;

	mod = NULL;
	ldr = peb->Ldr;
	list = ((PLDR_DATA_TABLE_ENTRY)(((PBYTE)(&ldr->InLoadOrderModuleList)) - offsetof(LDR_DATA_TABLE_ENTRY, InLoadOrderLinks)));
	entry = ((PLDR_DATA_TABLE_ENTRY)(((PBYTE)(list->InLoadOrderLinks.Flink)) - offsetof(LDR_DATA_TABLE_ENTRY, InLoadOrderLinks)));
	while(entry != list)
	{
		len = entry->BaseDllName.Length;
		name = entry->BaseDllName.Buffer;
		sum = fnv1a(name, len / sizeof(WCHAR));
		if(sum == k_hash)
		{
			mod = ((HMODULE)(entry->DllBase));
			break;
		}
		entry = ((PLDR_DATA_TABLE_ENTRY)(((PBYTE)(entry->InLoadOrderLinks.Flink)) - offsetof(LDR_DATA_TABLE_ENTRY, InLoadOrderLinks)));
	}
	return mod;
}

static inline LPVOID va_to_real(HMODULE const& mod, PIMAGE_SECTION_HEADER const& sections, WORD const& count, DWORD const& va, DWORD const& sz)
{
	LPVOID real;
	LPBYTE base;
	WORD n;
	WORD i;
	DWORD sec_va;
	DWORD raw;

	real = NULL;
	base = ((LPBYTE)(mod));
	n = count;
	for(i = 0; i != n; ++i)
	{
		sec_va = sections[i].VirtualAddress;
		if(va >= sec_va && va + sz <= sec_va + sections->SizeOfRawData)
		{
			raw = sections[i].PointerToRawData + (va - sec_va);
			real = base + raw;
			break;
		}
	}
	return real;
}

[[nodiscard]] static inline int mk_str_len(LPCSTR const str)
{
	LPCSTR s;
	int len;

	mk_assert(str);

	s = str;
	while(*s != '\0')
	{
		++s;
	}
	len = ((int)(s - str));
	return len;
}

[[nodiscard]] static inline int find_dot(LPCSTR const str)
{
	LPCSTR s;
	int len;

	mk_assert(str);

	s = str;
	while(*s != '.')
	{
		++s;
	}
	len = ((int)(s - str));
	return len;
}

static inline FARPROC find_proc(PPEB const peb, HMODULE const& mod, DWORD const& k_hash)
{
	FARPROC proc;
	PIMAGE_DOS_HEADER dos;
	PIMAGE_NT_HEADERS nt;
	PIMAGE_DATA_DIRECTORY arr_dirs;
	DWORD n_dirs;
	DWORD exp_dir_va;
	DWORD exp_dir_sz;
	PIMAGE_SECTION_HEADER arr_sections;
	WORD n_sections;
	PIMAGE_EXPORT_DIRECTORY exp_dir_real;
	DWORD n_names;
	LPDWORD arr_names;
	DWORD i_names;
	DWORD name_va;
	LPCCH name_real;
	DWORD sum;
	LPWORD arr_ordinals;
	WORD ordinal;
	LPDWORD arr_functions;
	DWORD func_va;
	bool is_fwd;
	LPCSTR fwd_str;
	int dot_pos;
	HMODULE fwd_mod;

	mk_assert(peb);

	proc = NULL;
	dos = ((PIMAGE_DOS_HEADER)(mod));
	nt = ((PIMAGE_NT_HEADERS)(((LPBYTE)(mod)) + dos->e_lfanew));
	arr_dirs = ((PIMAGE_DATA_DIRECTORY)(((LPBYTE)(&nt->OptionalHeader.NumberOfRvaAndSizes)) + sizeof(nt->OptionalHeader.NumberOfRvaAndSizes)));
	n_dirs = nt->OptionalHeader.NumberOfRvaAndSizes;
	mk_assert(n_dirs > IMAGE_DIRECTORY_ENTRY_EXPORT);
	exp_dir_va = arr_dirs[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	exp_dir_sz = arr_dirs[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	arr_sections = ((PIMAGE_SECTION_HEADER)(((LPBYTE)(arr_dirs)) + n_dirs * sizeof(IMAGE_DATA_DIRECTORY)));
	n_sections = nt->FileHeader.NumberOfSections;
	exp_dir_real = ((PIMAGE_EXPORT_DIRECTORY)(va_to_real(mod, arr_sections, n_sections, exp_dir_va, exp_dir_sz)));
	n_names = exp_dir_real->NumberOfNames;
	arr_names = ((LPDWORD)(va_to_real(mod, arr_sections, n_sections, exp_dir_real->AddressOfNames, n_names * sizeof(DWORD))));
	for(i_names = 0; i_names != n_names; ++i_names)
	{
		name_va = arr_names[i_names];
		name_real = ((LPCCH)(va_to_real(mod, arr_sections, n_sections, name_va, 1)));
		sum = fnv1a(name_real);
		if(sum == k_hash)
		{
			arr_ordinals = ((LPWORD)(va_to_real(mod, arr_sections, n_sections, exp_dir_real->AddressOfNameOrdinals, exp_dir_real->NumberOfNames * sizeof(arr_ordinals[0]))));
			ordinal = arr_ordinals[i_names];
			arr_functions = ((LPDWORD)(va_to_real(mod, arr_sections, n_sections, exp_dir_real->AddressOfFunctions, exp_dir_real->NumberOfFunctions * sizeof(arr_functions[0]))));
			func_va = arr_functions[ordinal];
			is_fwd = func_va >= exp_dir_va && func_va < exp_dir_va + exp_dir_sz;
			if(!is_fwd)
			{
				proc = ((FARPROC)(va_to_real(mod, arr_sections, n_sections, func_va, sizeof(DWORD))));
			}
			else
			{
				fwd_str = ((LPCSTR)(va_to_real(mod, arr_sections, n_sections, func_va, sizeof(DWORD))));
				dot_pos = find_dot(fwd_str); mk_assert(dot_pos >= 1); mk_assert(dot_pos < mk_str_len(fwd_str) - 1);
				fwd_mod = find_module(peb, fnv1alcdll(fwd_str, dot_pos)); mk_assert(fwd_mod);
				proc = find_proc(peb, fwd_mod, fnv1a(fwd_str + dot_pos + 1));
			}
			break;
		}
	}
	return proc;
}

#define mk_x_dlls_to_load() \
	x(combase)\
	x(fwpuclnt)\
	x(user32)\
	x(comctl32)\

#define mk_x_kernel_funcs() \
	x(ExitProcess) \
	x(GetModuleHandleW) \
	x(LoadLibraryExA) \

#define mk_x_combase_funcs() \
	x(StringFromGUID2) \

#define mk_x_fw_funcs() \
	x(FwpmEngineClose0) \
	x(FwpmEngineOpen0) \
	x(FwpmFilterCreateEnumHandle0) \
	x(FwpmFilterDestroyEnumHandle0) \
	x(FwpmFilterEnum0) \
	x(FwpmFreeMemory0) \

#define mk_x_user_funcs() \
	x(CreateWindowExW) \
	x(DefWindowProcW) \
	x(DispatchMessageW) \
	x(GetClientRect) \
	x(GetMessageW) \
	x(GetWindowLongPtrW) \
	x(LoadCursorW) \
	x(LoadIconW) \
	x(MoveWindow) \
	x(PostQuitMessage) \
	x(RegisterClassExW) \
	x(SendMessageW) \
	x(SetWindowLongPtrW) \
	x(ShowWindow) \
	x(TranslateMessage) \

#define mk_x_comctl_funcs() \
	x(InitCommonControls) \

#define mk_x_all_funcs() \
	mk_x_kernel_funcs() \
	mk_x_combase_funcs() \
	mk_x_fw_funcs() \
	mk_x_user_funcs() \
	mk_x_comctl_funcs() \

#define mk_x_hash_strings() \
	x(kernel32dll, "kernel32.dll") \

#define mk_x_nstrings() \
	x(description, "Description") \
	x(empty, "") \
	x(fire_wall, "FireWall") \
	x(mkfw, "mkfw") \
	x(name, "Name") \
	x(none, "[ none ]") \
	x(provider, "Provider") \
	x(layer, "Layer") \
	x(wnd_cls_name_list_view, "SysListView32") \

#define mk_x_guids_2() \
	x(0xc38d57d1, 0x05a7, 0x4c33, 0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82, FWPM_LAYER_ALE_AUTH_CONNECT_V4) \
	x(0xd632a801, 0xf5ba, 0x4ad6, 0x96, 0xe3, 0x60, 0x70, 0x17, 0xd9, 0x83, 0x6a, FWPM_LAYER_ALE_AUTH_CONNECT_V4_DISCARD) \
	x(0x4a72393b, 0x319f, 0x44bc, 0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4, FWPM_LAYER_ALE_AUTH_CONNECT_V6) \
	x(0xc97bc3b8, 0xc9a3, 0x4e33, 0x86, 0x95, 0x8e, 0x17, 0xaa, 0xd4, 0xde, 0x09, FWPM_LAYER_ALE_AUTH_CONNECT_V6_DISCARD) \
	x(0x88bb5dad, 0x76d7, 0x4227, 0x9c, 0x71, 0xdf, 0x0a, 0x3e, 0xd7, 0xbe, 0x7e, FWPM_LAYER_ALE_AUTH_LISTEN_V4) \
	x(0x371dfada, 0x9f26, 0x45fd, 0xb4, 0xeb, 0xc2, 0x9e, 0xb2, 0x12, 0x89, 0x3f, FWPM_LAYER_ALE_AUTH_LISTEN_V4_DISCARD) \
	x(0x7ac9de24, 0x17dd, 0x4814, 0xb4, 0xbd, 0xa9, 0xfb, 0xc9, 0x5a, 0x32, 0x1b, FWPM_LAYER_ALE_AUTH_LISTEN_V6) \
	x(0x60703b07, 0x63c8, 0x48e9, 0xad, 0xa3, 0x12, 0xb1, 0xaf, 0x40, 0xa6, 0x17, FWPM_LAYER_ALE_AUTH_LISTEN_V6_DISCARD) \
	x(0xe1cd9fe7, 0xf4b5, 0x4273, 0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4) \
	x(0x9eeaa99b, 0xbd22, 0x4227, 0x91, 0x9f, 0x00, 0x73, 0xc6, 0x33, 0x57, 0xb1, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4_DISCARD) \
	x(0xa3b42c97, 0x9f04, 0x4672, 0xb8, 0x7e, 0xce, 0xe9, 0xc4, 0x83, 0x25, 0x7f, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6) \
	x(0x89455b97, 0xdbe1, 0x453f, 0xa2, 0x24, 0x13, 0xda, 0x89, 0x5a, 0xf3, 0x96, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6_DISCARD) \
	x(0x66978cad, 0xc704, 0x42ac, 0x86, 0xac, 0x7c, 0x1a, 0x23, 0x1b, 0xd2, 0x53, FWPM_LAYER_ALE_BIND_REDIRECT_V4) \
	x(0xbef02c9c, 0x606b, 0x4536, 0x8c, 0x26, 0x1c, 0x2f, 0xc7, 0xb6, 0x31, 0xd4, FWPM_LAYER_ALE_BIND_REDIRECT_V6) \
	x(0xc6e63c8c, 0xb784, 0x4562, 0xaa, 0x7d, 0x0a, 0x67, 0xcf, 0xca, 0xf9, 0xa3, FWPM_LAYER_ALE_CONNECT_REDIRECT_V4) \
	x(0x587e54a7, 0x8046, 0x42ba, 0xa0, 0xaa, 0xb7, 0x16, 0x25, 0x0f, 0xc7, 0xfd, FWPM_LAYER_ALE_CONNECT_REDIRECT_V6) \
	x(0xb4766427, 0xe2a2, 0x467a, 0xbd, 0x7e, 0xdb, 0xcd, 0x1b, 0xd8, 0x5a, 0x09, FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V4) \
	x(0xbb536ccd, 0x4755, 0x4ba9, 0x9f, 0xf7, 0xf9, 0xed, 0xf8, 0x69, 0x9c, 0x7b, FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V6) \
	x(0xaf80470a, 0x5596, 0x4c13, 0x99, 0x92, 0x53, 0x9e, 0x6f, 0xe5, 0x79, 0x67, FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4) \
	x(0x146ae4a9, 0xa1d2, 0x4d43, 0xa3, 0x1a, 0x4c, 0x42, 0x68, 0x2b, 0x8e, 0x4f, FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4_DISCARD) \
	x(0x7021d2b3, 0xdfa4, 0x406e, 0xaf, 0xeb, 0x6a, 0xfa, 0xf7, 0xe7, 0x0e, 0xfd, FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6) \
	x(0x46928636, 0xbbca, 0x4b76, 0x94, 0x1d, 0x0f, 0xa7, 0xf5, 0xd7, 0xd3, 0x72, FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6_DISCARD) \
	x(0x1247d66d, 0x0b60, 0x4a15, 0x8d, 0x44, 0x71, 0x55, 0xd0, 0xf5, 0x3a, 0x0c, FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4) \
	x(0x0b5812a2, 0xc3ff, 0x4eca, 0xb8, 0x8d, 0xc7, 0x9e, 0x20, 0xac, 0x63, 0x22, FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4_DISCARD) \
	x(0x55a650e1, 0x5f0a, 0x4eca, 0xa6, 0x53, 0x88, 0xf5, 0x3b, 0x26, 0xaa, 0x8c, FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6) \
	x(0xcbc998bb, 0xc51f, 0x4c1a, 0xbb, 0x4f, 0x97, 0x75, 0xfc, 0xac, 0xab, 0x2f, FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6_DISCARD) \
	x(0x74365cce, 0xccb0, 0x401a, 0xbf, 0xc1, 0xb8, 0x99, 0x34, 0xad, 0x7e, 0x15, FWPM_LAYER_ALE_RESOURCE_RELEASE_V4) \
	x(0xf4e5ce80, 0xedcc, 0x4e13, 0x8a, 0x2f, 0xb9, 0x14, 0x54, 0xbb, 0x05, 0x7b, FWPM_LAYER_ALE_RESOURCE_RELEASE_V6) \
	x(0x3d08bf4e, 0x45f6, 0x4930, 0xa9, 0x22, 0x41, 0x70, 0x98, 0xe2, 0x00, 0x27, FWPM_LAYER_DATAGRAM_DATA_V4) \
	x(0x18e330c6, 0x7248, 0x4e52, 0xaa, 0xab, 0x47, 0x2e, 0xd6, 0x77, 0x04, 0xfd, FWPM_LAYER_DATAGRAM_DATA_V4_DISCARD) \
	x(0xfa45fe2f, 0x3cba, 0x4427, 0x87, 0xfc, 0x57, 0xb9, 0xa4, 0xb1, 0x0d, 0x00, FWPM_LAYER_DATAGRAM_DATA_V6) \
	x(0x09d1dfe1, 0x9b86, 0x4a42, 0xbe, 0x9d, 0x8c, 0x31, 0x5b, 0x92, 0xa5, 0xd0, FWPM_LAYER_DATAGRAM_DATA_V6_DISCARD) \
	x(0x86c872b0, 0x76fa, 0x4b79, 0x93, 0xa4, 0x07, 0x50, 0x53, 0x0a, 0xe2, 0x92, FWPM_LAYER_EGRESS_VSWITCH_ETHERNET) \
	x(0xb92350b6, 0x91f0, 0x46b6, 0xbd, 0xc4, 0x87, 0x1d, 0xfd, 0x4a, 0x7c, 0x98, FWPM_LAYER_EGRESS_VSWITCH_TRANSPORT_V4) \
	x(0x1b2def23, 0x1881, 0x40bd, 0x82, 0xf4, 0x42, 0x54, 0xe6, 0x31, 0x41, 0xcb, FWPM_LAYER_EGRESS_VSWITCH_TRANSPORT_V6) \
	x(0xb14b7bdb, 0xdbbd, 0x473e, 0xbe, 0xd4, 0x8b, 0x47, 0x08, 0xd4, 0xf2, 0x70, FWPM_LAYER_IKEEXT_V4) \
	x(0xb64786b3, 0xf687, 0x4eb9, 0x89, 0xd2, 0x8e, 0xf3, 0x2a, 0xcd, 0xab, 0xe2, FWPM_LAYER_IKEEXT_V6) \
	x(0x61499990, 0x3cb6, 0x4e84, 0xb9, 0x50, 0x53, 0xb9, 0x4b, 0x69, 0x64, 0xf3, FWPM_LAYER_INBOUND_ICMP_ERROR_V4) \
	x(0xa6b17075, 0xebaf, 0x4053, 0xa4, 0xe7, 0x21, 0x3c, 0x81, 0x21, 0xed, 0xe5, FWPM_LAYER_INBOUND_ICMP_ERROR_V4_DISCARD) \
	x(0x65f9bdff, 0x3b2d, 0x4e5d, 0xb8, 0xc6, 0xc7, 0x20, 0x65, 0x1f, 0xe8, 0x98, FWPM_LAYER_INBOUND_ICMP_ERROR_V6) \
	x(0xa6e7ccc0, 0x08fb, 0x468d, 0xa4, 0x72, 0x97, 0x71, 0xd5, 0x59, 0x5e, 0x09, FWPM_LAYER_INBOUND_ICMP_ERROR_V6_DISCARD) \
	x(0xc86fd1bf, 0x21cd, 0x497e, 0xa0, 0xbb, 0x17, 0x42, 0x5c, 0x88, 0x5c, 0x58, FWPM_LAYER_INBOUND_IPPACKET_V4) \
	x(0xb5a230d0, 0xa8c0, 0x44f2, 0x91, 0x6e, 0x99, 0x1b, 0x53, 0xde, 0xd1, 0xf7, FWPM_LAYER_INBOUND_IPPACKET_V4_DISCARD) \
	x(0xf52032cb, 0x991c, 0x46e7, 0x97, 0x1d, 0x26, 0x01, 0x45, 0x9a, 0x91, 0xca, FWPM_LAYER_INBOUND_IPPACKET_V6) \
	x(0xbb24c279, 0x93b4, 0x47a2, 0x83, 0xad, 0xae, 0x16, 0x98, 0xb5, 0x08, 0x85, FWPM_LAYER_INBOUND_IPPACKET_V6_DISCARD) \
	x(0xeffb7edb, 0x0055, 0x4f9a, 0xa2, 0x31, 0x4f, 0xf8, 0x13, 0x1a, 0xd1, 0x91, FWPM_LAYER_INBOUND_MAC_FRAME_ETHERNET) \
	x(0xd4220bd3, 0x62ce, 0x4f08, 0xae, 0x88, 0xb5, 0x6e, 0x85, 0x26, 0xdf, 0x50, FWPM_LAYER_INBOUND_MAC_FRAME_NATIVE) \
	x(0x853aaa8e, 0x2b78, 0x4d24, 0xa8, 0x04, 0x36, 0xdb, 0x08, 0xb2, 0x97, 0x11, FWPM_LAYER_INBOUND_MAC_FRAME_NATIVE_FAST) \
	x(0xf4fb8d55, 0xc076, 0x46d8, 0xa2, 0xc7, 0x6a, 0x4c, 0x72, 0x2c, 0xa4, 0xed, FWPM_LAYER_INBOUND_RESERVED2) \
	x(0xe41d2719, 0x05c7, 0x40f0, 0x89, 0x83, 0xea, 0x8d, 0x17, 0xbb, 0xc2, 0xf6, FWPM_LAYER_INBOUND_TRANSPORT_FAST) \
	x(0x5926dfc8, 0xe3cf, 0x4426, 0xa2, 0x83, 0xdc, 0x39, 0x3f, 0x5d, 0x0f, 0x9d, FWPM_LAYER_INBOUND_TRANSPORT_V4) \
	x(0xac4a9833, 0xf69d, 0x4648, 0xb2, 0x61, 0x6d, 0xc8, 0x48, 0x35, 0xef, 0x39, FWPM_LAYER_INBOUND_TRANSPORT_V4_DISCARD) \
	x(0x634a869f, 0xfc23, 0x4b90, 0xb0, 0xc1, 0xbf, 0x62, 0x0a, 0x36, 0xae, 0x6f, FWPM_LAYER_INBOUND_TRANSPORT_V6) \
	x(0x2a6ff955, 0x3b2b, 0x49d2, 0x98, 0x48, 0xad, 0x9d, 0x72, 0xdc, 0xaa, 0xb7, FWPM_LAYER_INBOUND_TRANSPORT_V6_DISCARD) \
	x(0x7d98577a, 0x9a87, 0x41ec, 0x97, 0x18, 0x7c, 0xf5, 0x89, 0xc9, 0xf3, 0x2d, FWPM_LAYER_INGRESS_VSWITCH_ETHERNET) \
	x(0xb2696ff6, 0x774f, 0x4554, 0x9f, 0x7d, 0x3d, 0xa3, 0x94, 0x5f, 0x8e, 0x85, FWPM_LAYER_INGRESS_VSWITCH_TRANSPORT_V4) \
	x(0x5ee314fc, 0x7d8a, 0x47f4, 0xb7, 0xe3, 0x29, 0x1a, 0x36, 0xda, 0x4e, 0x12, FWPM_LAYER_INGRESS_VSWITCH_TRANSPORT_V6) \
	x(0xa82acc24, 0x4ee1, 0x4ee1, 0xb4, 0x65, 0xfd, 0x1d, 0x25, 0xcb, 0x10, 0xa4, FWPM_LAYER_IPFORWARD_V4) \
	x(0x9e9ea773, 0x2fae, 0x4210, 0x8f, 0x17, 0x34, 0x12, 0x9e, 0xf3, 0x69, 0xeb, FWPM_LAYER_IPFORWARD_V4_DISCARD) \
	x(0x7b964818, 0x19c7, 0x493a, 0xb7, 0x1f, 0x83, 0x2c, 0x36, 0x84, 0xd2, 0x8c, FWPM_LAYER_IPFORWARD_V6) \
	x(0x31524a5d, 0x1dfe, 0x472f, 0xbb, 0x93, 0x51, 0x8e, 0xe9, 0x45, 0xd8, 0xa2, FWPM_LAYER_IPFORWARD_V6_DISCARD) \
	x(0xf02b1526, 0xa459, 0x4a51, 0xb9, 0xe3, 0x75, 0x9d, 0xe5, 0x2b, 0x9d, 0x2c, FWPM_LAYER_IPSEC_KM_DEMUX_V4) \
	x(0x2f755cf6, 0x2fd4, 0x4e88, 0xb3, 0xe4, 0xa9, 0x1b, 0xca, 0x49, 0x52, 0x35, FWPM_LAYER_IPSEC_KM_DEMUX_V6) \
	x(0xeda65c74, 0x610d, 0x4bc5, 0x94, 0x8f, 0x3c, 0x4f, 0x89, 0x55, 0x68, 0x67, FWPM_LAYER_IPSEC_V4) \
	x(0x13c48442, 0x8d87, 0x4261, 0x9a, 0x29, 0x59, 0xd2, 0xab, 0xc3, 0x48, 0xb4, FWPM_LAYER_IPSEC_V6) \
	x(0x4aa226e9, 0x9020, 0x45fb, 0x95, 0x6a, 0xc0, 0x24, 0x9d, 0x84, 0x11, 0x95, FWPM_LAYER_KM_AUTHORIZATION) \
	x(0x0c2aa681, 0x905b, 0x4ccd, 0xa4, 0x67, 0x4d, 0xd8, 0x11, 0xd0, 0x7b, 0x7b, FWPM_LAYER_NAME_RESOLUTION_CACHE_V4) \
	x(0x92d592fa, 0x6b01, 0x434a, 0x9d, 0xea, 0xd1, 0xe9, 0x6e, 0xa9, 0x7d, 0xa9, FWPM_LAYER_NAME_RESOLUTION_CACHE_V6) \
	x(0x41390100, 0x564c, 0x4b32, 0xbc, 0x1d, 0x71, 0x80, 0x48, 0x35, 0x4d, 0x7c, FWPM_LAYER_OUTBOUND_ICMP_ERROR_V4) \
	x(0xb3598d36, 0x0561, 0x4588, 0xa6, 0xbf, 0xe9, 0x55, 0xe3, 0xf6, 0x26, 0x4b, FWPM_LAYER_OUTBOUND_ICMP_ERROR_V4_DISCARD) \
	x(0x7fb03b60, 0x7b8d, 0x4dfa, 0xba, 0xdd, 0x98, 0x01, 0x76, 0xfc, 0x4e, 0x12, FWPM_LAYER_OUTBOUND_ICMP_ERROR_V6) \
	x(0x65f2e647, 0x8d0c, 0x4f47, 0xb1, 0x9b, 0x33, 0xa4, 0xd3, 0xf1, 0x35, 0x7c, FWPM_LAYER_OUTBOUND_ICMP_ERROR_V6_DISCARD) \
	x(0x1e5c9fae, 0x8a84, 0x4135, 0xa3, 0x31, 0x95, 0x0b, 0x54, 0x22, 0x9e, 0xcd, FWPM_LAYER_OUTBOUND_IPPACKET_V4) \
	x(0x08e4bcb5, 0xb647, 0x48f3, 0x95, 0x3c, 0xe5, 0xdd, 0xbd, 0x03, 0x93, 0x7e, FWPM_LAYER_OUTBOUND_IPPACKET_V4_DISCARD) \
	x(0xa3b3ab6b, 0x3564, 0x488c, 0x91, 0x17, 0xf3, 0x4e, 0x82, 0x14, 0x27, 0x63, FWPM_LAYER_OUTBOUND_IPPACKET_V6) \
	x(0x9513d7c4, 0xa934, 0x49dc, 0x91, 0xa7, 0x6c, 0xcb, 0x80, 0xcc, 0x02, 0xe3, FWPM_LAYER_OUTBOUND_IPPACKET_V6_DISCARD) \
	x(0x694673bc, 0xd6db, 0x4870, 0xad, 0xee, 0x0a, 0xcd, 0xbd, 0xb7, 0xf4, 0xb2, FWPM_LAYER_OUTBOUND_MAC_FRAME_ETHERNET) \
	x(0x94c44912, 0x9d6f, 0x4ebf, 0xb9, 0x95, 0x05, 0xab, 0x8a, 0x08, 0x8d, 0x1b, FWPM_LAYER_OUTBOUND_MAC_FRAME_NATIVE) \
	x(0x470df946, 0xc962, 0x486f, 0x94, 0x46, 0x82, 0x93, 0xcb, 0xc7, 0x5e, 0xb8, FWPM_LAYER_OUTBOUND_MAC_FRAME_NATIVE_FAST) \
	x(0x037f317a, 0xd696, 0x494a, 0xbb, 0xa5, 0xbf, 0xfc, 0x26, 0x5e, 0x60, 0x52, FWPM_LAYER_OUTBOUND_NETWORK_CONNECTION_POLICY_V4) \
	x(0x22a4fdb1, 0x6d7e, 0x48ae, 0xae, 0x77, 0x37, 0x42, 0x52, 0x5c, 0x31, 0x19, FWPM_LAYER_OUTBOUND_NETWORK_CONNECTION_POLICY_V6) \
	x(0x13ed4388, 0xa070, 0x4815, 0x99, 0x35, 0x7a, 0x9b, 0xe6, 0x40, 0x8b, 0x78, FWPM_LAYER_OUTBOUND_TRANSPORT_FAST) \
	x(0x09e61aea, 0xd214, 0x46e2, 0x9b, 0x21, 0xb2, 0x6b, 0x0b, 0x2f, 0x28, 0xc8, FWPM_LAYER_OUTBOUND_TRANSPORT_V4) \
	x(0xc5f10551, 0xbdb0, 0x43d7, 0xa3, 0x13, 0x50, 0xe2, 0x11, 0xf4, 0xd6, 0x8a, FWPM_LAYER_OUTBOUND_TRANSPORT_V4_DISCARD) \
	x(0xe1735bde, 0x013f, 0x4655, 0xb3, 0x51, 0xa4, 0x9e, 0x15, 0x76, 0x2d, 0xf0, FWPM_LAYER_OUTBOUND_TRANSPORT_V6) \
	x(0xf433df69, 0xccbd, 0x482e, 0xb9, 0xb2, 0x57, 0x16, 0x56, 0x58, 0xc3, 0xb3, FWPM_LAYER_OUTBOUND_TRANSPORT_V6_DISCARD) \
	x(0x618dffc7, 0xc450, 0x4943, 0x95, 0xdb, 0x99, 0xb4, 0xc1, 0x6a, 0x55, 0xd4, FWPM_LAYER_RPC_EP_ADD) \
	x(0x9247bc61, 0xeb07, 0x47ee, 0x87, 0x2c, 0xbf, 0xd7, 0x8b, 0xfd, 0x16, 0x16, FWPM_LAYER_RPC_EPMAP) \
	x(0x94a4b50b, 0xba5c, 0x4f27, 0x90, 0x7a, 0x22, 0x9f, 0xac, 0x0c, 0x2a, 0x7a, FWPM_LAYER_RPC_PROXY_CONN) \
	x(0xf8a38615, 0xe12c, 0x41ac, 0x98, 0xdf, 0x12, 0x1a, 0xd9, 0x81, 0xaa, 0xde, FWPM_LAYER_RPC_PROXY_IF) \
	x(0x75a89dda, 0x95e4, 0x40f3, 0xad, 0xc7, 0x76, 0x88, 0xa9, 0xc8, 0x47, 0xe1, FWPM_LAYER_RPC_UM) \
	x(0xaf52d8ec, 0xcb2d, 0x44e5, 0xad, 0x92, 0xf8, 0xdc, 0x38, 0xd2, 0xeb, 0x29, FWPM_LAYER_STREAM_PACKET_V4) \
	x(0x779a8ca3, 0xf099, 0x468f, 0xb5, 0xd4, 0x83, 0x53, 0x5c, 0x46, 0x1c, 0x02, FWPM_LAYER_STREAM_PACKET_V6) \
	x(0x3b89653c, 0xc170, 0x49e4, 0xb1, 0xcd, 0xe0, 0xee, 0xee, 0xe1, 0x9a, 0x3e, FWPM_LAYER_STREAM_V4) \
	x(0x25c4c2c2, 0x25ff, 0x4352, 0x82, 0xf9, 0xc5, 0x4a, 0x4a, 0x47, 0x26, 0xdc, FWPM_LAYER_STREAM_V4_DISCARD) \
	x(0x47c9137a, 0x7ec4, 0x46b3, 0xb6, 0xe4, 0x48, 0xe9, 0x26, 0xb1, 0xed, 0xa4, FWPM_LAYER_STREAM_V6) \
	x(0x10a59fc7, 0xb628, 0x4c41, 0x9e, 0xb8, 0xcf, 0x37, 0xd5, 0x51, 0x03, 0xcf, FWPM_LAYER_STREAM_V6_DISCARD) \
	x(0xb25ea800, 0x0d02, 0x46ed, 0x92, 0xbd, 0x7f, 0xa8, 0x4b, 0xb7, 0x3e, 0x9d, FWPM_PROVIDER_CONTEXT_SECURE_SOCKET_AUTHIP) \
	x(0x8c2d4144, 0xf8e0, 0x42c0, 0x94, 0xce, 0x7c, 0xcf, 0xc6, 0x3b, 0x2f, 0x9b, FWPM_PROVIDER_CONTEXT_SECURE_SOCKET_IPSEC) \
	x(0x10ad9216, 0xccde, 0x456c, 0x8b, 0x16, 0xe9, 0xf0, 0x4e, 0x60, 0xa9, 0x0b, FWPM_PROVIDER_IKEEXT) \
	x(0x3c6c05a9, 0xc05c, 0x4bb9, 0x83, 0x38, 0x23, 0x27, 0x81, 0x4c, 0xe8, 0xbf, FWPM_PROVIDER_IPSEC_DOSP_CONFIG) \
	x(0x3cc2631f, 0x2d5d, 0x43a0, 0xb1, 0x74, 0x61, 0x48, 0x37, 0xd8, 0x63, 0xa1, FWPM_PROVIDER_MPSSVC_APP_ISOLATION) \
	x(0xa90296f7, 0x46b8, 0x4457, 0x8f, 0x84, 0xb0, 0x5e, 0x05, 0xd3, 0xc6, 0x22, FWPM_PROVIDER_MPSSVC_EDP) \
	x(0xd0718ff9, 0x44da, 0x4f50, 0x9d, 0xc2, 0xc9, 0x63, 0xa4, 0x24, 0x76, 0x13, FWPM_PROVIDER_MPSSVC_TENANT_RESTRICTIONS) \
	x(0xdecc16ca, 0x3f33, 0x4346, 0xbe, 0x1e, 0x8f, 0xb4, 0xae, 0x0f, 0x3d, 0x62, FWPM_PROVIDER_MPSSVC_WF) \
	x(0x4b153735, 0x1049, 0x4480, 0xaa, 0xb4, 0xd1, 0xb9, 0xbd, 0xc0, 0x37, 0x10, FWPM_PROVIDER_MPSSVC_WSH) \
	x(0x896aa19e, 0x9a34, 0x4bcb, 0xae, 0x79, 0xbe, 0xb9, 0x12, 0x7c, 0x84, 0xb9, FWPM_PROVIDER_TCP_CHIMNEY_OFFLOAD) \
	x(0x76cfcd30, 0x3394, 0x432d, 0xbe, 0xd3, 0x44, 0x1a, 0xe5, 0x0e, 0x63, 0xc3, FWPM_PROVIDER_TCP_TEMPLATES) \

template<typename t, size_t n>
struct mk_view_t
{
	t const* m_buf;
};

template<typename t, size_t n>
[[nodiscard]] bool operator==(mk_view_t<t, n> const& a, mk_view_t<t, n> const& b)
{
	bool eq;
	int i;
	
	eq = true;
	for(i = 0; i != n; ++i)
	{
		eq &= a.m_buf[i] == b.m_buf[i];
	}
	return eq;
}

template<typename t, size_t n>
[[nodiscard]] static inline auto c_arr_to_view(t const(&c_arr)[n])
{
	mk_view_t<t, n> view;

	view.m_buf = c_arr + 0;
	return view;
}

[[nodiscard]] static inline bool guid_eq(GUID const* const a, GUID const* const b)
{
	bool eq;

	if(!a && !b)
	{
		eq = true;
	}
	else if(!a && b)
	{
		eq = false;
	}
	else if(a && !b)
	{
		eq = false;
	}
	else
	{
		auto const& view_a = c_arr_to_view(a->Data4);
		auto const& view_b = c_arr_to_view(b->Data4);
		eq = std::tie(a->Data1, a->Data2, a->Data3, view_a) == std::tie(b->Data1, b->Data2, b->Data3, view_b);
	}
	return eq;
}

[[nodiscard]] constexpr static inline int guids_2_count(void)
{
	int i;
	
	i = 0;

	#define x(d1, d2, d3, dd1, dd2, dd3, dd4, dd5, dd6, dd7, dd8, name) \
		++i;
	mk_x_guids_2()
	#undef x

	return i;
}

[[nodiscard]] constexpr static inline int guids_2_strs_len(void)
{
	int len;

	len = 0;

	#define x(d1, d2, d3, dd1, dd2, dd3, dd4, dd5, dd6, dd7, dd8, name) \
		len += _countof(#name) - 1;
	mk_x_guids_2()
	#undef x

	return len;
}

[[nodiscard]] constexpr static inline int guids_2_longest(void)
{
	int mx;
	int len;

	mx = 0;
	#define x(d1, d2, d3, dd1, dd2, dd3, dd4, dd5, dd6, dd7, dd8, name) \
		len = _countof(#name) - 1; \
		mx = len > mx ? len : mx;
	mk_x_guids_2()
	#undef x
	return mx;
}

struct guid_2_s
{
	unsigned char m_bytes[16];
};
typedef struct guid_2_s guid_2_t;

struct guids_2_s
{
	guid_2_t m_guids[guids_2_count()];
};
typedef struct guids_2_s guids_2_t;

[[nodiscard]] constexpr static inline guids_2_t guids_2_get_all(void)
{
	int i;
	guids_2_t guids;

	i = 0;

	#define x(d1, d2, d3, dd1, dd2, dd3, dd4, dd5, dd6, dd7, dd8, name) \
		guids.m_guids[i].m_bytes[ 0] = ((unsigned char)(d1 >> (0 * 8))); \
		guids.m_guids[i].m_bytes[ 1] = ((unsigned char)(d1 >> (1 * 8))); \
		guids.m_guids[i].m_bytes[ 2] = ((unsigned char)(d1 >> (2 * 8))); \
		guids.m_guids[i].m_bytes[ 3] = ((unsigned char)(d1 >> (3 * 8))); \
		guids.m_guids[i].m_bytes[ 4] = ((unsigned char)(d2 >> (0 * 8))); \
		guids.m_guids[i].m_bytes[ 5] = ((unsigned char)(d2 >> (1 * 8))); \
		guids.m_guids[i].m_bytes[ 6] = ((unsigned char)(d3 >> (0 * 8))); \
		guids.m_guids[i].m_bytes[ 7] = ((unsigned char)(d3 >> (1 * 8))); \
		guids.m_guids[i].m_bytes[ 8] = ((unsigned char)(dd1)); \
		guids.m_guids[i].m_bytes[ 9] = ((unsigned char)(dd2)); \
		guids.m_guids[i].m_bytes[10] = ((unsigned char)(dd3)); \
		guids.m_guids[i].m_bytes[11] = ((unsigned char)(dd4)); \
		guids.m_guids[i].m_bytes[12] = ((unsigned char)(dd5)); \
		guids.m_guids[i].m_bytes[13] = ((unsigned char)(dd6)); \
		guids.m_guids[i].m_bytes[14] = ((unsigned char)(dd7)); \
		guids.m_guids[i].m_bytes[15] = ((unsigned char)(dd8)); \
		++i;
	mk_x_guids_2()
	#undef x

	return guids;
}

[[nodiscard]] static inline bool guids_2_test(void)
{
	bool gud;
	int i;
	guids_2_t guids_2;

	gud = true;
	i = 0;
	guids_2 = guids_2_get_all();

	#define x(d1, d2, d3, dd1, dd2, dd3, dd4, dd5, dd6, dd7, dd8, name) \
		gud &= guid_eq(&name, ((GUID*)(&guids_2.m_guids[i]))); \
		++i;
	mk_x_guids_2()
	#undef x

	return gud;
}

struct mk_guids_s
{
	guids_2_t m_guids;
	int m_desc_lens[guids_2_count()];
	int m_desc_offs[guids_2_count()];
	char m_descs_str[guids_2_strs_len()];
};
typedef struct mk_guids_s mk_guids_t;

[[nodiscard]] constexpr static inline mk_guids_t make_guids(void)
{
	int i;
	mk_guids_t guids;

	i = 0;
	guids.m_guids = guids_2_get_all();

	#define x(d1, d2, d3, dd1, dd2, dd3, dd4, dd5, dd6, dd7, dd8, name) \
		guids.m_desc_lens[i] = _countof(#name) - 1; \
		guids.m_desc_offs[i] = ((i == 0) ? (0) : (guids.m_desc_offs[i - 1] + guids.m_desc_lens[i - 1])); \
		std::copy(&#name[0], &#name[0] + _countof(#name) - 1, &guids.m_descs_str[0] + guids.m_desc_offs[i]); \
		++i;
	mk_x_guids_2()
	#undef x

	return guids;
}

#define x(name) typedef decltype(&name) tfn_##name;
mk_x_all_funcs()
#undef x

struct mk_konst_s
{
	#define x(name) DWORD m_hash_##name;
	mk_x_all_funcs()
	#undef x

	#define x(name, value) DWORD m_hash_##name;
	mk_x_hash_strings()
	#undef x

	#define x(name, value) decltype(make_zstr(value)) m_nstr_##name;
	mk_x_nstrings()
	#undef x

	#define x(name) decltype(make_zstr(#name)) m_nstr_##name;
	mk_x_dlls_to_load()
	#undef x

	mk_guids_t m_guids;
};
typedef struct mk_konst_s mk_konst_t;

[[nodiscard]] constexpr static inline mk_konst_t make_konst(void)
{
	mk_konst_t konst{};

	#define x(name) konst.m_hash_##name = fnv1a(#name);
	mk_x_all_funcs()
	#undef x

	#define x(name, value) konst.m_hash_##name = fnv1a(value);
	mk_x_hash_strings()
	#undef x

	#define x(name, value) konst.m_nstr_##name = make_zstr(value);
	mk_x_nstrings()
	#undef x

	#define x(name) konst.m_nstr_##name = make_zstr(#name);
	mk_x_dlls_to_load()
	#undef x

	konst.m_guids = make_guids();
	return konst;
}

struct mk_fw_s
{
	HANDLE m_eng;
	FWPM_FILTER0** m_entries;
	UINT32 m_count;
};
typedef struct mk_fw_s mk_fw_t;

struct mk_wnd_s
{
	HWND m_hwnd;
	HWND m_list;
	mk_fw_t* m_fw;
};
typedef struct mk_wnd_s mk_wnd_t;

struct mk_app_s
{
	PPEB m_peb;
	HMODULE m_dll_exe;
	HMODULE m_dll_kernel;
	#define x(name) HMODULE m_dll_##name;
	mk_x_dlls_to_load()
	#undef x
	#define x(name) tfn_##name m_pfn_##name;
	mk_x_all_funcs()
	#undef x
	mk_fw_t m_fw;
	mk_wnd_t m_fw_wnd;
	UINT m_tmps_nstr_idx;
	UINT m_tmps_wstr_idx;
	CHAR m_tmp_nstrs[8][64];
	WCHAR m_tmp_wstrs[8][guids_2_longest()];
};
typedef struct mk_app_s mk_app_t;


static constexpr mk_konst_t const k_konst = make_konst();;
static mk_app_t g_app;


static inline void fw_construct(mk_fw_t* const fw)
{
	#define k_count (1 * 1024 * 1024)

	DWORD dw;
	HANDLE enm;

	mk_assert(fw);

	dw = g_app.m_pfn_FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &fw->m_eng); mk_assert(dw == ERROR_SUCCESS);
	dw = g_app.m_pfn_FwpmFilterCreateEnumHandle0(fw->m_eng, NULL, &enm); mk_assert(dw == ERROR_SUCCESS);
	dw = g_app.m_pfn_FwpmFilterEnum0(fw->m_eng, enm, k_count, &fw->m_entries, &fw->m_count); mk_assert(dw == ERROR_SUCCESS);
	dw = g_app.m_pfn_FwpmFilterDestroyEnumHandle0(fw->m_eng, enm); mk_assert(dw == ERROR_SUCCESS);
}

static inline void fw_destroy(mk_fw_t* const fw)
{
	DWORD dw;

	mk_assert(fw);

	g_app.m_pfn_FwpmFreeMemory0(((void**)(&fw->m_entries)));
	dw = g_app.m_pfn_FwpmEngineClose0(fw->m_eng); mk_assert(dw == ERROR_SUCCESS);
}

[[nodiscard]] static inline auto nstr_to_nstr(LPCSTR const nstr, int const len)
{
	LPSTR pstr;
	int n;
	int i;

	mk_assert(len < _countof(g_app.m_tmp_nstrs[0]));

	pstr = &g_app.m_tmp_nstrs[g_app.m_tmps_nstr_idx++ % _countof(g_app.m_tmp_nstrs)][0];
	n = len;
	for(i = 0; i != n; ++i)
	{
		pstr[i] = ((CHAR)(nstr[i]));
	}
	pstr[i] = '\0';
	return pstr;
}

template<size_t n>
[[nodiscard]] static inline auto nstr_to_nstr(std::array<char, n> const& arr)
{
	return nstr_to_nstr(arr.data(), ((int)(arr.size())));
}

[[nodiscard]] static inline auto nstr_to_wstr(LPCSTR const nstr, int const len)
{
	LPWSTR wstr;
	int n;
	int i;

	wstr = &g_app.m_tmp_wstrs[g_app.m_tmps_wstr_idx++ % _countof(g_app.m_tmp_wstrs)][0];
	n = len;
	for(i = 0; i != n; ++i)
	{
		wstr[i] = ((WCHAR)(nstr[i]));
	}
	wstr[i] = L'\0';
	return wstr;
}

template<size_t n>
[[nodiscard]] static inline LPWSTR nstr_to_wstr(std::array<char, n> const& arr)
{
	return nstr_to_wstr(arr.data(), ((int)(arr.size())));
}

[[nodiscard]] static inline auto guid_to_wstr(GUID const* const guid)
{
	int cap;
	LPWSTR wstr;
	int len;

	mk_assert(guid);

	cap = _countof(g_app.m_tmp_wstrs[0]);
	wstr = &g_app.m_tmp_wstrs[g_app.m_tmps_wstr_idx++ % _countof(g_app.m_tmp_wstrs)][0];
	len = g_app.m_pfn_StringFromGUID2(*guid, wstr, cap); mk_assert(len >= 1); mk_assert(len < cap);
	return wstr;
}

static inline void mkfw_load_all(PPEB const peb)
{
	mk_assert(peb);

	g_app.m_peb = peb;
	g_app.m_dll_kernel = find_module(peb, k_konst.m_hash_kernel32dll); mk_assert(g_app.m_dll_kernel);

	#define x(name) g_app.m_pfn_##name = ((tfn_##name)(find_proc(peb, g_app.m_dll_kernel, k_konst.m_hash_##name))); mk_assert(g_app.m_pfn_##name);
	mk_x_kernel_funcs()
	#undef x

	#define x(name) g_app.m_dll_##name = g_app.m_pfn_LoadLibraryExA(nstr_to_nstr(k_konst.m_nstr_##name), NULL, LOAD_LIBRARY_SEARCH_SYSTEM32); mk_assert(g_app.m_dll_##name);
	mk_x_dlls_to_load()
	#undef x

	#define x(name) g_app.m_pfn_##name = ((tfn_##name)(find_proc(peb, g_app.m_dll_combase, k_konst.m_hash_##name))); mk_assert(g_app.m_pfn_##name);
	mk_x_combase_funcs()
	#undef x

	#define x(name) g_app.m_pfn_##name = ((tfn_##name)(find_proc(peb, g_app.m_dll_fwpuclnt, k_konst.m_hash_##name))); mk_assert(g_app.m_pfn_##name);
	mk_x_fw_funcs()
	#undef x

	#define x(name) g_app.m_pfn_##name = ((tfn_##name)(find_proc(peb, g_app.m_dll_user32, k_konst.m_hash_##name))); mk_assert(g_app.m_pfn_##name);
	mk_x_user_funcs()
	#undef x

	#define x(name) g_app.m_pfn_##name = ((tfn_##name)(find_proc(peb, g_app.m_dll_comctl32, k_konst.m_hash_##name))); mk_assert(g_app.m_pfn_##name);
	mk_x_comctl_funcs()
	#undef x

	g_app.m_pfn_InitCommonControls();
	g_app.m_dll_exe = g_app.m_pfn_GetModuleHandleW(NULL);
}

[[nodiscard]] static inline LPCWSTR guid_to_text(GUID const* const guid)
{
	LPCWSTR wstr;
	int n;
	int i;
	GUID const* ggg;

	static_assert(std::size(k_konst.m_guids.m_desc_lens) == std::size(k_konst.m_guids.m_desc_offs));
	
	wstr = NULL;
	if(guid)
	{
		n = std::size(k_konst.m_guids.m_desc_lens);
		for(i = 0; i != n; ++i)
		{
			ggg = ((GUID*)(&k_konst.m_guids.m_guids.m_guids[i]));
			auto const& view_a = c_arr_to_view(guid->Data4);
			auto const& view_b = c_arr_to_view(ggg->Data4);
			if(std::tie(guid->Data1, guid->Data2, guid->Data3, view_a) == std::tie(ggg->Data1, ggg->Data2, ggg->Data3, view_b))
			{
				break;
			}
		}
		if(i != n)
		{
			wstr = nstr_to_wstr(&k_konst.m_guids.m_descs_str[k_konst.m_guids.m_desc_offs[i]], k_konst.m_guids.m_desc_lens[i]);
		}
		else
		{
			wstr = guid_to_wstr(guid);
		}
	}
	else
	{
		wstr = nstr_to_wstr(k_konst.m_nstr_none);
	}
	return wstr;
}

static LRESULT CALLBACK mkfw_wnd_proc(HWND const hwnd, UINT const msg, WPARAM const wparam, LPARAM const lparam)
{
	bool call_def;
	LRESULT lres;
	LONG_PTR ptr;
	mk_wnd_t* self;
	CREATESTRUCTW* crt;
	LVCOLUMNW col;
	LRESULT lr;
	BOOL b;
	RECT rect;
	NMHDR* nm;
	NMLVDISPINFOW* disp_info;
	UINT mask;

	call_def = true;
	lres = 0;
	ptr = g_app.m_pfn_GetWindowLongPtrW(hwnd, GWLP_USERDATA);
	self = ((mk_wnd_t*)(ptr));
	switch(msg)
	{
		case WM_CREATE:
			mk_assert(lparam);
			crt = ((CREATESTRUCTW*)(lparam));
			self = ((mk_wnd_t*)(crt->lpCreateParams));
			self->m_hwnd = hwnd;
			ptr = g_app.m_pfn_SetWindowLongPtrW(self->m_hwnd, GWLP_USERDATA, ((LONG_PTR)(self))); mk_assert(ptr == 0);
			self->m_list = g_app.m_pfn_CreateWindowExW(WS_EX_LEFT | WS_EX_LTRREADING | WS_EX_RIGHTSCROLLBAR, nstr_to_wstr(k_konst.m_nstr_wnd_cls_name_list_view), nstr_to_wstr(k_konst.m_nstr_empty), WS_VISIBLE | WS_CHILD | LVS_REPORT | LVS_OWNERDATA, 10, 10, 800, 600, self->m_hwnd, NULL, g_app.m_dll_exe, NULL); mk_assert(self->m_list);
			lr = g_app.m_pfn_SendMessageW(self->m_list, LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_DOUBLEBUFFER | LVS_EX_FULLROWSELECT, LVS_EX_DOUBLEBUFFER | LVS_EX_FULLROWSELECT); ((void)(lr));
			col.mask = LVCF_WIDTH | LVCF_TEXT; col.pszText = ((LPWSTR)(nstr_to_wstr(k_konst.m_nstr_name))); col.cx = 80;
			lr = g_app.m_pfn_SendMessageW(self->m_list, LVM_INSERTCOLUMN, 0, ((LPARAM)(&col))); mk_assert(lr == 0);
			col.mask = LVCF_WIDTH | LVCF_TEXT; col.pszText = ((LPWSTR)(nstr_to_wstr(k_konst.m_nstr_description))); col.cx = 180;
			lr = g_app.m_pfn_SendMessageW(self->m_list, LVM_INSERTCOLUMN, 1, ((LPARAM)(&col))); mk_assert(lr == 1);
			col.mask = LVCF_WIDTH | LVCF_TEXT; col.pszText = ((LPWSTR)(nstr_to_wstr(k_konst.m_nstr_provider))); col.cx = 80;
			lr = g_app.m_pfn_SendMessageW(self->m_list, LVM_INSERTCOLUMN, 2, ((LPARAM)(&col))); mk_assert(lr == 2);
			col.mask = LVCF_WIDTH | LVCF_TEXT; col.pszText = ((LPWSTR)(nstr_to_wstr(k_konst.m_nstr_layer))); col.cx = 80;
			lr = g_app.m_pfn_SendMessageW(self->m_list, LVM_INSERTCOLUMN, 3, ((LPARAM)(&col))); mk_assert(lr == 3);
			lr = g_app.m_pfn_SendMessageW(self->m_list, LVM_SETITEMCOUNT, self->m_fw->m_count, LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL); mk_assert(lr != 0);
			lr = g_app.m_pfn_SendMessageW(self->m_list, LVM_SETCOLUMNWIDTH, 2, LVSCW_AUTOSIZE); mk_assert(lr != 0);
			lr = g_app.m_pfn_SendMessageW(self->m_list, LVM_SETCOLUMNWIDTH, 3, LVSCW_AUTOSIZE); mk_assert(lr != 0);
		break;
		case WM_DESTROY:
			g_app.m_pfn_PostQuitMessage(0);
		break;
		case WM_SIZE:
			b = g_app.m_pfn_GetClientRect(self->m_hwnd, &rect); mk_assert(b);
			b = g_app.m_pfn_MoveWindow(self->m_list, 0, 0, rect.right, rect.bottom, TRUE); mk_assert(b);
		break;
		case WM_NOTIFY:
			nm = ((NMHDR*)(lparam));
			if(nm->hwndFrom == self->m_list)
			{
				if(nm->code == LVN_GETDISPINFOW)
				{
					disp_info = ((NMLVDISPINFOW*)(lparam));
					mask = disp_info->item.mask;
					if((mask & LVIF_TEXT) != 0)
					{
						mask &=~ LVIF_TEXT;
						if(disp_info->item.iSubItem == 0)
						{
							mk_assert(disp_info->item.iItem >= 0);
							mk_assert(disp_info->item.iItem < ((int)(self->m_fw->m_count)));
							disp_info->item.pszText = self->m_fw->m_entries[disp_info->item.iItem]->displayData.name;
						}
						else if(disp_info->item.iSubItem == 1)
						{
							mk_assert(disp_info->item.iItem >= 0);
							mk_assert(disp_info->item.iItem < ((int)(self->m_fw->m_count)));
							disp_info->item.pszText = self->m_fw->m_entries[disp_info->item.iItem]->displayData.description;
						}
						else if(disp_info->item.iSubItem == 2)
						{
							mk_assert(disp_info->item.iItem >= 0);
							mk_assert(disp_info->item.iItem < ((int)(self->m_fw->m_count)));
							disp_info->item.pszText = ((LPWSTR)(guid_to_text(self->m_fw->m_entries[disp_info->item.iItem]->providerKey)));
						}
						else if(disp_info->item.iSubItem == 3)
						{
							mk_assert(disp_info->item.iItem >= 0);
							mk_assert(disp_info->item.iItem < ((int)(self->m_fw->m_count)));
							disp_info->item.pszText = ((LPWSTR)(guid_to_text(&self->m_fw->m_entries[disp_info->item.iItem]->layerKey)));
						}
						else
						{
							mk_assert(false);
						}
						if(!disp_info->item.pszText)
						{
							disp_info->item.pszText = ((LPWSTR)(nstr_to_wstr(k_konst.m_nstr_empty)));
						}
					}
					if((mask & LVIF_INDENT) != 0)
					{
						mask &=~ LVIF_INDENT;
						disp_info->item.iIndent = 0;
					}
					if((mask & LVIF_IMAGE) != 0)
					{
						mask &=~ LVIF_IMAGE;
						disp_info->item.iImage = 0;
					}
					if((mask & LVIF_STATE) != 0)
					{
						mask &=~ LVIF_STATE;
						disp_info->item.state = 0;
					}
					if(mask != 0)
					{
						mk_assert(false);
					}
				}
			}
		break;
	}
	if(call_def)
	{
		lres = g_app.m_pfn_DefWindowProcW(hwnd, msg, wparam, lparam);
	}
	return lres;
}


extern "C" DWORD __stdcall mk_entry(PPEB const peb)
{
	WNDCLASSEXW wnd_cls_info;
	ATOM wnd_cls_atom;
	HWND hwnd;
	BOOL b;
	MSG msg;
	LRESULT lr;

	mk_assert(guids_2_test());

	mkfw_load_all(peb);
	fw_construct(&g_app.m_fw);
	wnd_cls_info.cbSize = sizeof(wnd_cls_info);
	wnd_cls_info.style = CS_VREDRAW | CS_HREDRAW;
	wnd_cls_info.lpfnWndProc = &mkfw_wnd_proc;
	wnd_cls_info.cbClsExtra = 0;
	wnd_cls_info.cbWndExtra = sizeof(mk_wnd_t*);
	wnd_cls_info.hInstance = g_app.m_dll_exe;
	wnd_cls_info.hIcon = g_app.m_pfn_LoadIconW(NULL, IDI_APPLICATION);
	wnd_cls_info.hCursor = g_app.m_pfn_LoadCursorW(NULL, IDC_ARROW);
	wnd_cls_info.hbrBackground = ((HBRUSH)(COLOR_APPWORKSPACE + 1));
	wnd_cls_info.lpszMenuName = NULL;
	wnd_cls_info.lpszClassName = nstr_to_wstr(k_konst.m_nstr_mkfw);
	wnd_cls_info.hIconSm = g_app.m_pfn_LoadIconW(NULL, IDI_APPLICATION);
	wnd_cls_atom = g_app.m_pfn_RegisterClassExW(&wnd_cls_info); mk_assert(wnd_cls_atom);
	g_app.m_fw_wnd.m_fw = &g_app.m_fw;
	hwnd = g_app.m_pfn_CreateWindowExW(WS_EX_APPWINDOW, ((LPCWSTR)(wnd_cls_atom)), nstr_to_wstr(k_konst.m_nstr_fire_wall), WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, NULL, NULL, g_app.m_dll_exe, &g_app.m_fw_wnd); mk_assert(hwnd);
	b = g_app.m_pfn_ShowWindow(hwnd, SW_SHOWDEFAULT); ((void)(b));
	for(;;)
	{
		b = g_app.m_pfn_GetMessageW(&msg, NULL, 0, 0); mk_assert((b == TRUE) || (b == FALSE && msg.message == WM_QUIT));
		if(!b)
		{
			break;
		}
		b = g_app.m_pfn_TranslateMessage(&msg); ((void)(b));
		lr = g_app.m_pfn_DispatchMessageW(&msg); ((void)(lr));
	}
	fw_destroy(&g_app.m_fw);
	g_app.m_pfn_ExitProcess(((UINT)(msg.wParam)));
	return 0;
}

/*
int main()
{
	mk_entry(((PPEB)(__readgsqword(0x60))));
}
*/
