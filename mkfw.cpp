#include <phnt_windows.h>
#include <phnt.h>

#include <CommCtrl.h>
#include <fwpmu.h>
#include <sddl.h>
#include <commdlg.h>

#include <algorithm>
#include <array>
#include <climits>
#include <tuple>

#if defined _MSC_VER && defined _M_X64 && defined _M_AMD64
#define mk_arch_is_i386 0
#define mk_arch_is_amd64 1
#elif defined _MSC_VER && defined _M_IX86 && !defined _M_I86 && !defined M_I86
#define mk_arch_is_i386 1
#define mk_arch_is_amd64 0
#endif

#if mk_arch_is_i386
#define m_pfn_GetWindowLongPtrW m_pfn_GetWindowLongW
#define m_pfn_SetWindowLongPtrW m_pfn_SetWindowLongW
#elif mk_arch_is_amd64
#define m_pfn_GetWindowLongPtrW m_pfn_GetWindowLongPtrW
#define m_pfn_SetWindowLongPtrW m_pfn_SetWindowLongPtrW
#endif

#if defined DEBUG || defined _DEBUG
#define mk_is_debug 1
void mk_crash(void){ int volatile* volatile ptr; ptr = NULL; *ptr = 0; }
void mk_msg(char const* const msg){ MessageBoxA(NULL, msg, "Assert!", MB_ICONERROR); }
#define stringify2(x) #x
#define stringify(x) stringify2(x)
#define mk_assert(x) (((x)) ? ((void)(0)) : ((void)(mk_msg("Assert in file `" __FILE__ "' line `" stringify(__LINE__) "' expression `" #x "'!"), __debugbreak(), mk_crash())))
#define my_MessageBoxA(parent, msg, title, icon) MessageBoxA(parent, msg, title, icon)
#else
#define mk_is_debug 0
#define mk_assert(x)
#define my_MessageBoxA(parent, msg, title, icon)
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
	std::array<t, n - 1> arr;

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
	return ((LPVOID)(((LPBYTE)(mod)) + va));
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
	exp_dir_real = ((PIMAGE_EXPORT_DIRECTORY)(va_to_real(mod, arr_sections, n_sections, exp_dir_va, exp_dir_sz))); mk_assert(exp_dir_real);
	n_names = exp_dir_real->NumberOfNames;
	arr_names = ((LPDWORD)(va_to_real(mod, arr_sections, n_sections, exp_dir_real->AddressOfNames, n_names * sizeof(DWORD)))); mk_assert(arr_names);
	for(i_names = 0; i_names != n_names; ++i_names)
	{
		name_va = arr_names[i_names];
		name_real = ((LPCCH)(va_to_real(mod, arr_sections, n_sections, name_va, 1))); mk_assert(name_real);
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

#define mk_min(a, b)((b)<(a)?(b):(a))
#define mk_max(a, b)((b)<(a)?(a):(b))
#define mk_clamp(x, lo, hi)mk_min(mk_max((lo),(x)),(hi))

extern "C" [[nodiscard]] void* __cdecl mk_memcpy_asm(void* const dst, void const* const src, size_t const cnt) noexcept;
extern "C" void __cdecl mk_memclr_asm(void* const dst, size_t const cnt) noexcept;
extern "C" [[nodiscard]] size_t __cdecl mk_wcslen_asm(wchar_t const* const str) noexcept;
extern "C" [[nodiscard]] int __cdecl wcsncmp_asm(wchar_t const* const stra, wchar_t const* const strb, size_t const cnt) noexcept;

static inline void* mk_memcpy_c(void* const dst, void const* const src, size_t const cnt) noexcept
{
	mk_assert(dst || cnt == 0);
	mk_assert(src || cnt == 0);
	mk_assert(cnt >= 0);
	mk_assert((((unsigned char*)(dst)) + cnt <= ((unsigned char*)(src))) || (((unsigned char*)(dst)) >= ((unsigned char*)(src)) + cnt));
	mk_assert((((unsigned char*)(src)) + cnt <= ((unsigned char*)(dst))) || (((unsigned char*)(src)) >= ((unsigned char*)(dst)) + cnt));

	return mk_memcpy_asm(dst, src, cnt);
}

static inline void mk_memclr_c(void* const dst, size_t const cnt) noexcept
{
	mk_assert(dst || cnt == 0);
	mk_assert(cnt >= 0);

	mk_memclr_asm(dst, cnt);
}

[[nodiscard]] static inline size_t mk_wcslen_c(wchar_t const* const str) noexcept
{
	size_t len;

	mk_assert(str);
	mk_assert(((uintptr_t)(str)) % sizeof(*str) == 0);

	len = mk_wcslen_asm(str);
	mk_assert(((int(__cdecl*)(wchar_t const*))(GetProcAddress(GetModuleHandleA("ntdll.dll"), "wcslen")))(str) == len);
	return len;
}

[[nodiscard]] static inline int wcsncmp_c(wchar_t const* const stra, wchar_t const* const strb, size_t const cnt) noexcept
{
	int cmp;

	mk_assert(stra);
	mk_assert(strb);
	mk_assert(cnt >= 1);
	mk_assert(stra[cnt - 1] == L'\0' || strb[cnt - 1] == L'\0');

	cmp = wcsncmp_asm(stra, strb, cnt);
	mk_assert(((int(__cdecl*)(wchar_t const*, wchar_t const*, size_t))(GetProcAddress(GetModuleHandleA("ntdll.dll"), "wcsncmp")))(stra, strb, cnt) == cmp);
	return cmp;
}

template<typename t>
struct mk_defer_t
{
	template<typename u>
	mk_defer_t(u&& fnc) noexcept :
		m_fnc(std::forward<u>(fnc))
	{
	}
	~mk_defer_t() noexcept
	{
		m_fnc();
	}
	t m_fnc;
};
template<typename t> [[nodiscard]] mk_defer_t<t> mk_defer_make(t&& fnc){ return mk_defer_t<t>{std::move(fnc)}; }
#define mk_concat2(a, b) a ## b
#define mk_concat(a, b) mk_concat2(a, b)
#define mk_make_defer(x) auto const mk_concat(defer_, __LINE__) = mk_defer_make(x)

template<typename t, size_t n>
struct mk_view_t
{
	t const* m_buf;
};

template<typename t>
struct mk_view_t<t, -1>
{
	t const* m_buf;
	size_t m_len;
};

template<typename t>
struct mk_view_t<t, -2>
{
	t const* m_buf;
	size_t m_len;
};

typedef typename mk_view_t<CHAR, -1> mk_view_nstr_t;
typedef typename mk_view_t<WCHAR, -1> mk_view_wstr_t;
typedef typename mk_view_t<CHAR, -2> mk_view_nstr_nz_t;
typedef typename mk_view_t<WCHAR, -2> mk_view_wstr_nz_t;

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

[[nodiscard]] static inline LPWSTR mk_memcpy(LPWSTR const dst, LPCWSTR const src, SIZE_T const cnt)
{
	LPWSTR end;

	mk_assert(dst);
	mk_assert(src);
	mk_assert(cnt >= 0);
	mk_assert((dst + cnt <= src) || (dst >= src + cnt));
	mk_assert((src + cnt <= dst) || (src >= dst + cnt));

	mk_memcpy_c(dst, src, cnt * sizeof(*dst));
	end = dst + cnt;
	return end;
}

[[nodiscard]] static inline LPWSTR mk_memcpy(LPWSTR const dst, mk_view_wstr_t const& src)
{
	return mk_memcpy(dst, src.m_buf, src.m_len);
}

#define mk_x_dlls_all() \
	x(exe)\
	x(ntdll)\
	x(kernel32)\
	x(advapi32)\
	x(combase)\
	x(fwpuclnt)\
	x(user32)\
	x(comctl32)\
	x(comdlg32)\

#define mk_x_dlls_to_load() \
	x(advapi32)\
	x(combase)\
	x(fwpuclnt)\
	x(user32)\
	x(comctl32)\
	x(comdlg32)\

#define mk_x_ntdll_funcs() \
	x(_snprintf) \
	x(qsort) \

int __cdecl mk_fn_swprintf(wchar_t*, wchar_t const*, ...);

#define mk_x_ntdll2_funcs() \
	x(swprintf, mk_fn_swprintf) \

#define mk_x_kernel_funcs() \
	x(CloseHandle) \
	x(CreateFileW) \
	x(ExitProcess) \
	x(GetFinalPathNameByHandleW) \
	x(GetModuleHandleW) \
	x(GetProcessHeap) \
	x(GlobalAlloc) \
	x(GlobalLock) \
	x(GlobalUnlock) \
	x(HeapAlloc) \
	x(HeapFree) \
	x(HeapReAlloc) \
	x(LoadLibraryExA) \
	x(LocalFree) \

#define mk_x_advapi_funcs() \
	x(ConvertSecurityDescriptorToStringSecurityDescriptorW) \
	x(ConvertSidToStringSidW) \

#define mk_x_combase_funcs() \
	x(StringFromGUID2) \

#define mk_x_fw_funcs() \
	x(FwpmEngineClose0) \
	x(FwpmEngineOpen0) \
	x(FwpmFilterAdd0) \
	x(FwpmFilterCreateEnumHandle0) \
	x(FwpmFilterDeleteByKey0) \
	x(FwpmFilterDestroyEnumHandle0) \
	x(FwpmFilterEnum0) \
	x(FwpmFreeMemory0) \
	x(FwpmTransactionAbort0) \
	x(FwpmTransactionBegin0) \
	x(FwpmTransactionCommit0) \

#if mk_arch_is_i386
#define mk_x_user_funcs() \
	x(ClientToScreen) \
	x(CloseClipboard) \
	x(CreatePopupMenu) \
	x(CreateWindowExW) \
	x(DefWindowProcW) \
	x(DestroyMenu) \
	x(DispatchMessageW) \
	x(EmptyClipboard) \
	x(GetClientRect) \
	x(GetMessageW) \
	x(GetWindowLongW) \
	x(InsertMenuItemW) \
	x(InvalidateRect) \
	x(LoadCursorW) \
	x(LoadIconW) \
	x(MessageBoxW) \
	x(MoveWindow) \
	x(OpenClipboard) \
	x(PeekMessageW) \
	x(PostMessageW) \
	x(PostQuitMessage) \
	x(RegisterClassExW) \
	x(SendMessageW) \
	x(SetClipboardData) \
	x(SetFocus) \
	x(SetWindowLongW) \
	x(ShowWindow) \
	x(TrackPopupMenu) \
	x(TranslateMessage) \
	x(UpdateWindow) \

#elif mk_arch_is_amd64
#define mk_x_user_funcs() \
	x(ClientToScreen) \
	x(CloseClipboard) \
	x(CreatePopupMenu) \
	x(CreateWindowExW) \
	x(DefWindowProcW) \
	x(DestroyMenu) \
	x(DispatchMessageW) \
	x(EmptyClipboard) \
	x(GetClientRect) \
	x(GetMessageW) \
	x(GetWindowLongPtrW) \
	x(InsertMenuItemW) \
	x(InvalidateRect) \
	x(LoadCursorW) \
	x(LoadIconW) \
	x(MessageBoxW) \
	x(MoveWindow) \
	x(OpenClipboard) \
	x(PeekMessageW) \
	x(PostMessageW) \
	x(PostQuitMessage) \
	x(RegisterClassExW) \
	x(SendMessageW) \
	x(SetClipboardData) \
	x(SetFocus) \
	x(SetWindowLongPtrW) \
	x(ShowWindow) \
	x(TrackPopupMenu) \
	x(TranslateMessage) \
	x(UpdateWindow) \

#endif

#define mk_x_comctl_funcs() \
	x(InitCommonControls) \

#define mk_x_comdlg_funcs() \
	x(GetOpenFileNameW) \

#define mk_x_all_funcs() \
	mk_x_ntdll_funcs() \
	mk_x_kernel_funcs() \
	mk_x_advapi_funcs() \
	mk_x_combase_funcs() \
	mk_x_fw_funcs() \
	mk_x_user_funcs() \
	mk_x_comctl_funcs() \
	mk_x_comdlg_funcs() \

#define mk_x_hash_strings() \
	x(ntdll, "ntdll.dll") \
	x(kernel32dll, "kernel32.dll") \

#define mk_x_nstrings() \
	x(action, "Action") \
	x(block_added, "Filters succesfully added.") \
	x(delete_caption, "Delete?") \
	x(delete_fmt, "Do you want to delete this FireWall filter?\x0d\x0a%s") \
	x(delete_ok_caption, "Delete.") \
	x(delete_ok_text, "Succesfully deleted FireWall filter.") \
	x(description, "Description") \
	x(effective_weight, "Effective Weight") \
	x(empty, "") \
	x(every_ipv4, "Every single one IPv4 address.") \
	x(field, "Field") \
	x(filter, "Filter") \
	x(filter_id, "Filter ID") \
	x(filter_type_callout, "Filter Type / Callout") \
	x(fire_wall, "FireWall") \
	x(fmt_arr16, "[%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x]") \
	x(fmt_block_ipv4_desc, "zzz Block IPv4 %s.") \
	x(fmt_block_ipv4_name, "zzz Block IPv4 %s.") \
	x(fmt_block_ipv6_desc, "zzz Block IPv6 %s.") \
	x(fmt_block_ipv6_name, "zzz Block IPv6 %s.") \
	x(fmt_ipv4, "%d.%d.%d.%d") \
	x(fmt_ipv4_mask_08, "%d.%d.%d.%d - %d.%d.%d.%d") \
	x(fmt_ipv4_mask_16, "%d.%d.%d.%d - %d.%d.%d.%d") \
	x(fmt_ipv4_mask_24, "%d.%d.%d.%d - %d.%d.%d.%d") \
	x(fmt_ipv4_mask_32, "%d.%d.%d.%d - %d.%d.%d.%d") \
	x(fmt_ipv6_mask_128, "%x:%x:%x:%x:%x:%x:%x:%x/%d") \
	x(fmt_ipv6_mask_32, "%x:%x::/%d") \
	x(fmt_ipv6_mask_48, "%x:%x:%x::/%d") \
	x(fmt_u16, "0x%04x (%d)") \
	x(fmt_u32, "0x%08x (%d)") \
	x(fmt_u64, "0x%016llx (%lld)") \
	x(fmt_u8, "0x%02x (%d)") \
	x(icmp_address_mask_request, "Address Mask Request") \
	x(icmp_destination_unreachable, "Destination Unreachable") \
	x(icmp_echo_request, "Echo Request (ping)") \
	x(icmp_multicast_listener_done, "Multicast Listener Done") \
	x(icmp_multicast_listener_query, "Multicast Listener Query") \
	x(icmp_multicast_listener_report, "Multicast Listener Report") \
	x(icmp_multicast_listener_report_v2, "Multicast Listener Report V2") \
	x(icmp_neighbor_discovery_advertisement, "Neighbor Discovery Advertisement") \
	x(icmp_neighbor_discovery_solicitation, "Neighbor Discovery Solicitation") \
	x(icmp_packet_too_big, "Packet Too Big") \
	x(icmp_parameter_problem, "Parameter Problem") \
	x(icmp_redirect, "Redirect") \
	x(icmp_router_advertisement, "Router Advertisement") \
	x(icmp_router_solicitation, "Router Solicitation") \
	x(icmp_source_quench, "Source Quench") \
	x(icmp_time_exceeded, "Time Exceeded") \
	x(icmp_timestamp_request, "Timestamp Request") \
	x(layer, "Layer") \
	x(match_type, "Match Type") \
	x(menu_copy_line, "Copy Row") \
	x(menu_copy_name, "Copy Name") \
	x(menu_copy_table, "Copy Table") \
	x(menu_copy_value, "Copy Value") \
	x(mkfw, "mkfw") \
	x(name, "Name") \
	x(nl, "\x0d\x0a") \
	x(none, "[ none ]") \
	x(note, "Note") \
	x(open_filter, "Executable files.\0*.exe\0All files.\0*\0") \
	x(open_title, "Select executable file to block.") \
	x(protocol_gre, "GRE") \
	x(protocol_icmpv4, "ICMPv4") \
	x(protocol_icmpv6, "ICMPv6") \
	x(protocol_igmp, "IGMP") \
	x(protocol_ipv6frag, "IPv6-Frag") \
	x(protocol_ipv6generic, "IPv6") \
	x(protocol_ipv6nonxt, "IPv6-NoNxt") \
	x(protocol_ipv6opts, "IPv6-Opts") \
	x(protocol_ipv6route, "IPv6-Route") \
	x(protocol_l2tp, "L2TP") \
	x(protocol_pgm, "PGM") \
	x(protocol_tcp, "TCP") \
	x(protocol_udp, "UDP") \
	x(protocol_vrrp, "VRRP") \
	x(provider, "Provider") \
	x(questions, "???") \
	x(range_from, "From: ") \
	x(range_to, " To: ") \
	x(sublayer, "Sub Layer") \
	x(tab, "\x09") \
	x(type, "Type") \
	x(value, "Value") \
	x(weight, "Weight") \
	x(wnd_cls_name_list_view, "SysListView32") \

#define mk_x_matches() \
	x(FWP_MATCH_EQUAL                 , "FWP_MATCH_EQUAL"                 ) \
	x(FWP_MATCH_GREATER               , "FWP_MATCH_GREATER"               ) \
	x(FWP_MATCH_LESS                  , "FWP_MATCH_LESS"                  ) \
	x(FWP_MATCH_GREATER_OR_EQUAL      , "FWP_MATCH_GREATER_OR_EQUAL"      ) \
	x(FWP_MATCH_LESS_OR_EQUAL         , "FWP_MATCH_LESS_OR_EQUAL"         ) \
	x(FWP_MATCH_RANGE                 , "FWP_MATCH_RANGE"                 ) \
	x(FWP_MATCH_FLAGS_ALL_SET         , "FWP_MATCH_FLAGS_ALL_SET"         ) \
	x(FWP_MATCH_FLAGS_ANY_SET         , "FWP_MATCH_FLAGS_ANY_SET"         ) \
	x(FWP_MATCH_FLAGS_NONE_SET        , "FWP_MATCH_FLAGS_NONE_SET"        ) \
	x(FWP_MATCH_EQUAL_CASE_INSENSITIVE, "FWP_MATCH_EQUAL_CASE_INSENSITIVE") \
	x(FWP_MATCH_NOT_EQUAL             , "FWP_MATCH_NOT_EQUAL"             ) \
	x(FWP_MATCH_PREFIX                , "FWP_MATCH_PREFIX"                ) \
	x(FWP_MATCH_NOT_PREFIX            , "FWP_MATCH_NOT_PREFIX"            ) \

#define mk_x_types() \
	x(FWP_EMPTY                        , "FWP_EMPTY"                        ) \
	x(FWP_UINT8                        , "FWP_UINT8"                        ) \
	x(FWP_UINT16                       , "FWP_UINT16"                       ) \
	x(FWP_UINT32                       , "FWP_UINT32"                       ) \
	x(FWP_UINT64                       , "FWP_UINT64"                       ) \
	x(FWP_INT8                         , "FWP_INT8"                         ) \
	x(FWP_INT16                        , "FWP_INT16"                        ) \
	x(FWP_INT32                        , "FWP_INT32"                        ) \
	x(FWP_INT64                        , "FWP_INT64"                        ) \
	x(FWP_FLOAT                        , "FWP_FLOAT"                        ) \
	x(FWP_DOUBLE                       , "FWP_DOUBLE"                       ) \
	x(FWP_BYTE_ARRAY16_TYPE            , "FWP_BYTE_ARRAY16_TYPE"            ) \
	x(FWP_BYTE_BLOB_TYPE               , "FWP_BYTE_BLOB_TYPE"               ) \
	x(FWP_SID                          , "FWP_SID"                          ) \
	x(FWP_SECURITY_DESCRIPTOR_TYPE     , "FWP_SECURITY_DESCRIPTOR_TYPE"     ) \
	x(FWP_TOKEN_INFORMATION_TYPE       , "FWP_TOKEN_INFORMATION_TYPE"       ) \
	x(FWP_TOKEN_ACCESS_INFORMATION_TYPE, "FWP_TOKEN_ACCESS_INFORMATION_TYPE") \
	x(FWP_UNICODE_STRING_TYPE          , "FWP_UNICODE_STRING_TYPE"          ) \
	x(FWP_BYTE_ARRAY6_TYPE             , "FWP_BYTE_ARRAY6_TYPE"             ) \
	x(FWP_V4_ADDR_MASK                 , "FWP_V4_ADDR_MASK"                 ) \
	x(FWP_V6_ADDR_MASK                 , "FWP_V6_ADDR_MASK"                 ) \
	x(FWP_RANGE_TYPE                   , "FWP_RANGE_TYPE"                   ) \

#define mk_x_action_types() \
	x(FWP_ACTION_BLOCK_              , FWP_ACTION_BLOCK              , "FWP_ACTION_BLOCK"              ) \
	x(FWP_ACTION_CALLOUT_INSPECTION_ , FWP_ACTION_CALLOUT_INSPECTION , "FWP_ACTION_CALLOUT_INSPECTION" ) \
	x(FWP_ACTION_CALLOUT_TERMINATING_, FWP_ACTION_CALLOUT_TERMINATING, "FWP_ACTION_CALLOUT_TERMINATING") \
	x(FWP_ACTION_CALLOUT_UNKNOWN_    , FWP_ACTION_CALLOUT_UNKNOWN    , "FWP_ACTION_CALLOUT_UNKNOWN"    ) \
	x(FWP_ACTION_CONTINUE_           , FWP_ACTION_CONTINUE           , "FWP_ACTION_CONTINUE"           ) \
	x(FWP_ACTION_NONE_               , FWP_ACTION_NONE               , "FWP_ACTION_NONE"               ) \
	x(FWP_ACTION_NONE_NO_MATCH_      , FWP_ACTION_NONE_NO_MATCH      , "FWP_ACTION_NONE_NO_MATCH"      ) \
	x(FWP_ACTION_PERMIT_             , FWP_ACTION_PERMIT             , "FWP_ACTION_PERMIT"             ) \

enum mk_net_icmp_v4_e
{
	mk_net_icmp_v4_e_packet_too_big          =  2,
	mk_net_icmp_v4_e_destination_unreachable =  3,
	mk_net_icmp_v4_e_source_quench           =  4,
	mk_net_icmp_v4_e_redirect                =  5,
	mk_net_icmp_v4_e_echo_request            =  8,
	mk_net_icmp_v4_e_router_advertisement    =  9,
	mk_net_icmp_v4_e_router_solicitation     = 10,
	mk_net_icmp_v4_e_time_exceeded           = 11,
	mk_net_icmp_v4_e_parameter_problem       = 12,
	mk_net_icmp_v4_e_timestamp_request       = 13,
	mk_net_icmp_v4_e_address_mask_request    = 17,
	mk_net_icmp_v4_e_dummy_end
};
typedef enum mk_net_icmp_v4_e mk_net_icmp_v4_t;

enum mk_net_icmp_6_e
{
	mk_net_icmp_v6_e_destination_unreachable          =   1,
	mk_net_icmp_v6_e_packet_too_big                   =   2,
	mk_net_icmp_v6_e_time_exceeded                    =   3,
	mk_net_icmp_v6_e_parameter_problem                =   4,
	mk_net_icmp_v6_e_echo_request                     = 128,
	mk_net_icmp_v6_e_multicast_listener_query         = 130,
	mk_net_icmp_v6_e_multicast_listener_report        = 131,
	mk_net_icmp_v6_e_multicast_listener_done          = 132,
	mk_net_icmp_v6_e_router_solicitation              = 133,
	mk_net_icmp_v6_e_router_advertisement             = 134,
	mk_net_icmp_v6_e_neighbor_discovery_solicitation  = 135,
	mk_net_icmp_v6_e_neighbor_discovery_advertisement = 136,
	mk_net_icmp_v6_e_redirect                         = 137,
	mk_net_icmp_v6_e_multicast_listener_report_v2     = 143,
	mk_net_icmp_v6_e_dummy_end
};
typedef enum mk_net_icmp_v6_e mk_net_icmp_v6_t;

#define mk_x_guids() \
	x(0x779719a4, 0xe695, 0x47b6, 0xa1, 0x99, 0x79, 0x99, 0xfe, 0xc9, 0x16, 0x3b, FWPM_CALLOUT_BUILT_IN_RESERVED_1) \
	x(0xef9661b6, 0x7c5e, 0x48fd, 0xa1, 0x30, 0x96, 0x67, 0x8c, 0xea, 0xcc, 0x41, FWPM_CALLOUT_BUILT_IN_RESERVED_2) \
	x(0x18729c7a, 0x2f62, 0x4be0, 0x96, 0x6f, 0x97, 0x4b, 0x21, 0xb8, 0x6d, 0xf1, FWPM_CALLOUT_BUILT_IN_RESERVED_3) \
	x(0x6c3fb801, 0xdaff, 0x40e9, 0x91, 0xe6, 0xf7, 0xff, 0x7e, 0x52, 0xf7, 0xd9, FWPM_CALLOUT_BUILT_IN_RESERVED_4) \
	x(0x33486ab5, 0x6d5e, 0x4e65, 0xa0, 0x0b, 0xa7, 0xaf, 0xed, 0x0b, 0xa9, 0xa1, FWPM_CALLOUT_EDGE_TRAVERSAL_ALE_LISTEN_V4) \
	x(0x079b1010, 0xf1c5, 0x4fcd, 0xae, 0x05, 0xda, 0x41, 0x10, 0x7a, 0xbd, 0x0b, FWPM_CALLOUT_EDGE_TRAVERSAL_ALE_RESOURCE_ASSIGNMENT_V4) \
	x(0xb3423249, 0x8d09, 0x4858, 0x92, 0x10, 0x95, 0xc7, 0xfd, 0xa8, 0xe3, 0x0f, FWPM_CALLOUT_HTTP_TEMPLATE_SSL_HANDSHAKE) \
	x(0x6ac141fc, 0xf75d, 0x4203, 0xb9 ,0xc8 ,0x48, 0xe6, 0x14, 0x9c, 0x27, 0x12, FWPM_CALLOUT_IPSEC_ALE_CONNECT_V4) \
	x(0x4c0dda05, 0xe31f, 0x4666, 0x90, 0xb0, 0xb3, 0xdf, 0xad, 0x34, 0x12, 0x9a, FWPM_CALLOUT_IPSEC_ALE_CONNECT_V6) \
	x(0x2fcb56ec, 0xcd37, 0x4b4f, 0xb1, 0x08, 0x62, 0xc2, 0xb1, 0x85, 0x0a, 0x0c, FWPM_CALLOUT_IPSEC_DOSP_FORWARD_V4) \
	x(0x6d08a342, 0xdb9e, 0x4fbe, 0x9e, 0xd2, 0x57, 0x37, 0x4c, 0xe8, 0x9f, 0x79, FWPM_CALLOUT_IPSEC_DOSP_FORWARD_V6) \
	x(0x28829633, 0xc4f0, 0x4e66, 0x87, 0x3f, 0x84, 0x4d, 0xb2, 0xa8, 0x99, 0xc7, FWPM_CALLOUT_IPSEC_FORWARD_INBOUND_TUNNEL_V4) \
	x(0xaf50bec2, 0xc686, 0x429a, 0x88, 0x4d, 0xb7, 0x44, 0x43, 0xe7, 0xb0, 0xb4, FWPM_CALLOUT_IPSEC_FORWARD_INBOUND_TUNNEL_V6) \
	x(0xfb532136, 0x15cb, 0x440b, 0x93, 0x7c, 0x17, 0x17, 0xca, 0x32, 0x0c, 0x40, FWPM_CALLOUT_IPSEC_FORWARD_OUTBOUND_TUNNEL_V4) \
	x(0xdae640cc, 0xe021, 0x4bee, 0x9e, 0xb6, 0xa4, 0x8b, 0x27, 0x5c, 0x8c, 0x1d, FWPM_CALLOUT_IPSEC_FORWARD_OUTBOUND_TUNNEL_V6) \
	x(0x7dff309b, 0xba7d, 0x4aba, 0x91, 0xaa, 0xae, 0x5c, 0x66, 0x40, 0xc9, 0x44, FWPM_CALLOUT_IPSEC_INBOUND_INITIATE_SECURE_V4) \
	x(0xa9a0d6d9, 0xc58c, 0x474e, 0x8a, 0xeb, 0x3c, 0xfe, 0x99, 0xd6, 0xd5, 0x3d, FWPM_CALLOUT_IPSEC_INBOUND_INITIATE_SECURE_V6) \
	x(0x5132900d, 0x5e84, 0x4b5f, 0x80, 0xe4, 0x01, 0x74, 0x1e, 0x81, 0xff, 0x10, FWPM_CALLOUT_IPSEC_INBOUND_TRANSPORT_V4) \
	x(0x49d3ac92, 0x2a6c, 0x4dcf, 0x95, 0x5f, 0x1c, 0x3b, 0xe0, 0x09, 0xdd, 0x99, FWPM_CALLOUT_IPSEC_INBOUND_TRANSPORT_V6) \
	x(0x3df6e7de, 0xfd20, 0x48f2, 0x9f, 0x26, 0xf8, 0x54, 0x44, 0x4c, 0xba, 0x79, FWPM_CALLOUT_IPSEC_INBOUND_TUNNEL_ALE_ACCEPT_V4) \
	x(0xa1e392d3, 0x72ac, 0x47bb, 0x87, 0xa7, 0x01, 0x22, 0xc6, 0x94, 0x34, 0xab, FWPM_CALLOUT_IPSEC_INBOUND_TUNNEL_ALE_ACCEPT_V6) \
	x(0x191a8a46, 0x0bf8, 0x46cf, 0xb0, 0x45, 0x4b, 0x45, 0xdf, 0xa6, 0xa3, 0x24, FWPM_CALLOUT_IPSEC_INBOUND_TUNNEL_V4) \
	x(0x80c342e3, 0x1e53, 0x4d6f, 0x9b, 0x44, 0x03, 0xdf, 0x5a, 0xee, 0xe1, 0x54, FWPM_CALLOUT_IPSEC_INBOUND_TUNNEL_V6) \
	x(0x4b46bf0a, 0x4523, 0x4e57, 0xaa, 0x38, 0xa8, 0x79, 0x87, 0xc9, 0x10, 0xd9, FWPM_CALLOUT_IPSEC_OUTBOUND_TRANSPORT_V4) \
	x(0x38d87722, 0xad83, 0x4f11, 0xa9, 0x1f, 0xdf, 0x0f, 0xb0, 0x77, 0x22, 0x5b, FWPM_CALLOUT_IPSEC_OUTBOUND_TRANSPORT_V6) \
	x(0x70a4196c, 0x835b, 0x4fb0, 0x98, 0xe8, 0x07, 0x5f, 0x4d, 0x97, 0x7d, 0x46, FWPM_CALLOUT_IPSEC_OUTBOUND_TUNNEL_V4) \
	x(0xf1835363, 0xa6a5, 0x4e62, 0xb1, 0x80, 0x23, 0xdb, 0x78, 0x9d, 0x8d, 0xa6, FWPM_CALLOUT_IPSEC_OUTBOUND_TUNNEL_V6) \
	x(0x103090d4, 0x8e28, 0x4fd6, 0x98, 0x94, 0xd1, 0xd6, 0x7d, 0x6b, 0x10, 0xc9, FWPM_CALLOUT_OUTBOUND_NETWORK_CONNECTION_POLICY_LAYER_V4) \
	x(0x4ed3446d, 0x8dc7, 0x459b, 0xb0, 0x9f, 0xc1, 0xcb, 0x7a, 0x8f, 0x86, 0x89, FWPM_CALLOUT_OUTBOUND_NETWORK_CONNECTION_POLICY_LAYER_V6) \
	x(0x5fbfc31d, 0xa51c, 0x44dc, 0xac, 0xb6, 0x06, 0x24, 0xa0, 0x30, 0xa7, 0x00, FWPM_CALLOUT_POLICY_SILENT_MODE_AUTH_CONNECT_LAYER_V4) \
	x(0x5fbfc31d, 0xa51c, 0x44dc, 0xac, 0xb6, 0x06, 0x24, 0xa0, 0x30, 0xa7, 0x01, FWPM_CALLOUT_POLICY_SILENT_MODE_AUTH_CONNECT_LAYER_V6) \
	x(0x5fbfc31d, 0xa51c, 0x44dc, 0xac, 0xb6, 0x06, 0x24, 0xa0, 0x30, 0xa7, 0x02, FWPM_CALLOUT_POLICY_SILENT_MODE_AUTH_RECV_ACCEPT_LAYER_V4) \
	x(0x5fbfc31d, 0xa51c, 0x44dc, 0xac, 0xb6, 0x06, 0x24, 0xa0, 0x30, 0xa7, 0x03, FWPM_CALLOUT_POLICY_SILENT_MODE_AUTH_RECV_ACCEPT_LAYER_V6) \
	x(0x288b524d, 0x0566, 0x4e19, 0xb6, 0x12, 0x8f, 0x44, 0x1a, 0x2e, 0x59, 0x49, FWPM_CALLOUT_RESERVED_AUTH_CONNECT_LAYER_V4) \
	x(0x00b84b92, 0x2b5e, 0x4b71, 0xab, 0x0e, 0xaa, 0xca, 0x43, 0xe3, 0x87, 0xe6, FWPM_CALLOUT_RESERVED_AUTH_CONNECT_LAYER_V6) \
	x(0xbc582280, 0x1677, 0x41e9, 0x94, 0xab, 0xc2, 0xfc, 0xb1, 0x5c, 0x2e, 0xeb, FWPM_CALLOUT_SET_OPTIONS_AUTH_CONNECT_LAYER_V4) \
	x(0x98e5373c, 0xb884, 0x490f, 0xb6, 0x5f, 0x2f, 0x6a, 0x4a, 0x57, 0x51, 0x95, FWPM_CALLOUT_SET_OPTIONS_AUTH_CONNECT_LAYER_V6) \
	x(0x2d55f008, 0x0c01, 0x4f92, 0xb2, 0x6e, 0xa0, 0x8a, 0x94, 0x56, 0x9b, 0x8d, FWPM_CALLOUT_SET_OPTIONS_AUTH_RECV_ACCEPT_LAYER_V4) \
	x(0x63018537, 0xf281, 0x4dc4, 0x83, 0xd3, 0x8d, 0xec, 0x18, 0xb7, 0xad, 0xe2, FWPM_CALLOUT_SET_OPTIONS_AUTH_RECV_ACCEPT_LAYER_V6) \
	x(0xe183ecb2, 0x3a7f, 0x4b54, 0x8a, 0xd9, 0x76, 0x05, 0x0e, 0xd8, 0x80, 0xca, FWPM_CALLOUT_TCP_CHIMNEY_ACCEPT_LAYER_V4) \
	x(0x0378cf41, 0xbf98, 0x4603, 0x81, 0xf2, 0x7f, 0x12, 0x58, 0x60, 0x79, 0xf6, FWPM_CALLOUT_TCP_CHIMNEY_ACCEPT_LAYER_V6) \
	x(0xf3e10ab3, 0x2c25, 0x4279, 0xac, 0x36, 0xc3, 0x0f, 0xc1, 0x81, 0xbe, 0xc4, FWPM_CALLOUT_TCP_CHIMNEY_CONNECT_LAYER_V4) \
	x(0x39e22085, 0xa341, 0x42fc, 0xa2, 0x79, 0xae, 0xc9, 0x4e, 0x68, 0x9c, 0x56, FWPM_CALLOUT_TCP_CHIMNEY_CONNECT_LAYER_V6) \
	x(0x2f23f5d0, 0x40c4, 0x4c41, 0xa2, 0x54, 0x46, 0xd8, 0xdb, 0xa8, 0x95, 0x7c, FWPM_CALLOUT_TCP_TEMPLATES_ACCEPT_LAYER_V4) \
	x(0xb25152f0, 0x991c, 0x4f53, 0xbb, 0xe7, 0xd2, 0x4b, 0x45, 0xfe, 0x63, 0x2c, FWPM_CALLOUT_TCP_TEMPLATES_ACCEPT_LAYER_V6) \
	x(0x215a0b39, 0x4b7e, 0x4eda, 0x8c, 0xe4, 0x17, 0x96, 0x79, 0xdf, 0x62, 0x24, FWPM_CALLOUT_TCP_TEMPLATES_CONNECT_LAYER_V4) \
	x(0x838b37a1, 0x5c12, 0x4d34, 0x8b, 0x38, 0x07, 0x87, 0x28, 0xb2, 0xd2, 0x5c, FWPM_CALLOUT_TCP_TEMPLATES_CONNECT_LAYER_V6) \
	x(0x81a434e7, 0xf60c, 0x4378, 0xba, 0xb8, 0xc6, 0x25, 0xa3, 0x0f, 0x01, 0x97, FWPM_CALLOUT_TEREDO_ALE_LISTEN_V6) \
	x(0x31b95392, 0x066e, 0x42a2, 0xb7, 0xdb, 0x92, 0xf8, 0xac, 0xdd, 0x56, 0xf9, FWPM_CALLOUT_TEREDO_ALE_RESOURCE_ASSIGNMENT_V6) \
	x(0xeda08606, 0x2494, 0x4d78, 0x89, 0xbc, 0x67, 0x83, 0x7c, 0x03, 0xb9, 0x69, FWPM_CALLOUT_WFP_TRANSPORT_LAYER_V4_SILENT_DROP) \
	x(0x8693cc74, 0xa075, 0x4156, 0xb4, 0x76, 0x92, 0x86, 0xee, 0xce, 0x81, 0x4e, FWPM_CALLOUT_WFP_TRANSPORT_LAYER_V6_SILENT_DROP) \
	x(0xd78e1e87, 0x8644, 0x4ea5, 0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71, FWPM_CONDITION_ALE_APP_ID) \
	x(0xb1277b9a, 0xb781, 0x40fc, 0x96, 0x71, 0xe5, 0xf1, 0xb9, 0x89, 0xf3, 0x4e, FWPM_CONDITION_ALE_EFFECTIVE_NAME) \
	x(0x46275a9d, 0xc03f, 0x4d77, 0xb7, 0x84, 0x1c, 0x57, 0xf4, 0xd0, 0x27, 0x53, FWPM_CONDITION_ALE_NAP_CONTEXT) \
	x(0x0e6cd086, 0xe1fb, 0x4212, 0x84, 0x2f, 0x8a, 0x9f, 0x99, 0x3f, 0xb3, 0xf6, FWPM_CONDITION_ALE_ORIGINAL_APP_ID) \
	x(0x81bc78fb, 0xf28d, 0x4886, 0xa6, 0x04, 0x6a, 0xcc, 0x26, 0x1f, 0x26, 0x1b, FWPM_CONDITION_ALE_PACKAGE_FAMILY_NAME) \
	x(0x71bc78fa, 0xf17c, 0x4997, 0xa6, 0x02, 0x6a, 0xbb, 0x26, 0x1f, 0x35, 0x1c, FWPM_CONDITION_ALE_PACKAGE_ID) \
	x(0x1c974776, 0x7182, 0x46e9, 0xaf, 0xd3, 0xb0, 0x29, 0x10, 0xe3, 0x03, 0x34, FWPM_CONDITION_ALE_PROMISCUOUS_MODE) \
	x(0xb482d227, 0x1979, 0x4a98, 0x80, 0x44, 0x18, 0xbb, 0xe6, 0x23, 0x75, 0x42, FWPM_CONDITION_ALE_REAUTH_REASON) \
	x(0x1aa47f51, 0x7f93, 0x4508, 0xa2, 0x71, 0x81, 0xab, 0xb0, 0x0c, 0x9c, 0xab, FWPM_CONDITION_ALE_REMOTE_MACHINE_ID) \
	x(0xf63073b7, 0x0189, 0x4ab0, 0x95, 0xa4, 0x61, 0x23, 0xcb, 0xfa, 0xb8, 0x62, FWPM_CONDITION_ALE_REMOTE_USER_ID) \
	x(0x37a57699, 0x5883, 0x4963, 0x92, 0xb8, 0x3e, 0x70, 0x46, 0x88, 0xb0, 0xad, FWPM_CONDITION_ALE_SECURITY_ATTRIBUTE_FQBN_VALUE) \
	x(0xb9f4e088, 0xcb98, 0x4efb, 0xa2, 0xc7, 0xad, 0x07, 0x33, 0x26, 0x43, 0xdb, FWPM_CONDITION_ALE_SIO_FIREWALL_SYSTEM_PORT) \
	x(0xaf043a0a, 0xb34d, 0x4f86, 0x97, 0x9c, 0xc9, 0x03, 0x71, 0xaf, 0x6e, 0x66, FWPM_CONDITION_ALE_USER_ID) \
	x(0xcc088db3, 0x1792, 0x4a71, 0xb0, 0xf9, 0x03, 0x7d, 0x21, 0xcd, 0x82, 0x8b, FWPM_CONDITION_ARRIVAL_INTERFACE_INDEX) \
	x(0xcdfe6aab, 0xc083, 0x4142, 0x86, 0x79, 0xc0, 0x8f, 0x95, 0x32, 0x9c, 0x61, FWPM_CONDITION_ARRIVAL_INTERFACE_PROFILE_ID) \
	x(0x89f990de, 0xe798, 0x4e6d, 0xab, 0x76, 0x7c, 0x95, 0x58, 0x29, 0x2e, 0x6f, FWPM_CONDITION_ARRIVAL_INTERFACE_TYPE) \
	x(0x511166dc, 0x7a8c, 0x4aa7, 0xb5, 0x33, 0x95, 0xab, 0x59, 0xfb, 0x03, 0x40, FWPM_CONDITION_ARRIVAL_TUNNEL_TYPE) \
	x(0xeb458cd5, 0xda7b, 0x4ef9, 0x8d, 0x43, 0x7b, 0x0a, 0x84, 0x03, 0x32, 0xf2, FWPM_CONDITION_AUTHENTICATION_TYPE) \
	x(0xa3ec00c7, 0x05f4, 0x4df7, 0x91, 0xf2, 0x5f, 0x60, 0xd9, 0x1f, 0xf4, 0x43, FWPM_CONDITION_CLIENT_CERT_KEY_LENGTH) \
	x(0xc491ad5e, 0xf882, 0x4283, 0xb9, 0x16, 0x43, 0x6b, 0x10, 0x3f, 0xf4, 0xad, FWPM_CONDITION_CLIENT_CERT_OID) \
	x(0xc228fc1e, 0x403a, 0x4478, 0xbe, 0x05, 0xc9, 0xba, 0xa4, 0xc0, 0x5a, 0xce, FWPM_CONDITION_CLIENT_TOKEN) \
	x(0x35a791ab, 0x04ac, 0x4ff2, 0xa6, 0xbb, 0xda, 0x6c, 0xfa, 0xc7, 0x18, 0x06, FWPM_CONDITION_COMPARTMENT_ID) \
	x(0xab3033c9, 0xc0e3, 0x4759, 0x93, 0x7d, 0x57, 0x58, 0xc6, 0x5d, 0x4a, 0xe3, FWPM_CONDITION_CURRENT_PROFILE_ID) \
	x(0xff2e7b4d, 0x3112, 0x4770, 0xb6, 0x36, 0x4d, 0x24, 0xae, 0x3a, 0x6a, 0xf2, FWPM_CONDITION_DCOM_APP_ID) \
	x(0x35cf6522, 0x4139, 0x45ee, 0xa0, 0xd5, 0x67, 0xb8, 0x09, 0x49, 0xd8, 0x79, FWPM_CONDITION_DESTINATION_INTERFACE_INDEX) \
	x(0x2b7d4399, 0xd4c7, 0x4738, 0xa2, 0xf5, 0xe9, 0x94, 0xb4, 0x3d, 0xa3, 0x88, FWPM_CONDITION_DESTINATION_SUB_INTERFACE_INDEX) \
	x(0x8784c146, 0xca97, 0x44d6, 0x9f, 0xd1, 0x19, 0xfb, 0x18, 0x40, 0xcb, 0xf7, FWPM_CONDITION_DIRECTION) \
	x(0x4672a468, 0x8a0a, 0x4202, 0xab, 0xb4, 0x84, 0x9e, 0x92, 0xe6, 0x68, 0x09, FWPM_CONDITION_EMBEDDED_LOCAL_ADDRESS_TYPE) \
	x(0xbfca394d, 0xacdb, 0x484e, 0xb8, 0xe6, 0x2a, 0xff, 0x79, 0x75, 0x73, 0x45, FWPM_CONDITION_EMBEDDED_LOCAL_PORT) \
	x(0x07784107, 0xa29e, 0x4c7b, 0x9e, 0xc7, 0x29, 0xc4, 0x4a, 0xfa, 0xfd, 0xbc, FWPM_CONDITION_EMBEDDED_PROTOCOL) \
	x(0x77ee4b39, 0x3273, 0x4671, 0xb6, 0x3b, 0xab, 0x6f, 0xeb, 0x66, 0xee, 0xb6, FWPM_CONDITION_EMBEDDED_REMOTE_ADDRESS) \
	x(0xcae4d6a1, 0x2968, 0x40ed, 0xa4, 0xce, 0x54, 0x71, 0x60, 0xdd, 0xa8, 0x8d, FWPM_CONDITION_EMBEDDED_REMOTE_PORT) \
	x(0xfd08948d, 0xa219, 0x4d52, 0xbb, 0x98, 0x1a, 0x55, 0x40, 0xee, 0x7b, 0x4e, FWPM_CONDITION_ETHER_TYPE) \
	x(0x632ce23b, 0x5167, 0x435c, 0x86, 0xd7, 0xe9, 0x03, 0x68, 0x4a, 0xa8, 0x0c, FWPM_CONDITION_FLAGS) \
	x(0xd024de4d, 0xdeaa, 0x4317, 0x9c, 0x85, 0xe4, 0x0e, 0xf6, 0xe1, 0x40, 0xc3, FWPM_CONDITION_IMAGE_NAME) \
	x(0x667fd755, 0xd695, 0x434a, 0x8a, 0xf5, 0xd3, 0x83, 0x5a, 0x12, 0x59, 0xbc, FWPM_CONDITION_INTERFACE_INDEX) \
	x(0xf6e63dce, 0x1f4b, 0x4c6b, 0xb6, 0xef, 0x11, 0x65, 0xe7, 0x1f, 0x8e, 0xe7, FWPM_CONDITION_INTERFACE_MAC_ADDRESS) \
	x(0xcce68d5e, 0x053b, 0x43a8, 0x9a, 0x6f, 0x33, 0x38, 0x4c, 0x28, 0xe4, 0xf6, FWPM_CONDITION_INTERFACE_QUARANTINE_EPOCH) \
	x(0xdaf8cd14, 0xe09e, 0x4c93, 0xa5, 0xae, 0xc5, 0xc1, 0x3b, 0x73, 0xff, 0xca, FWPM_CONDITION_INTERFACE_TYPE) \
	x(0x618a9b6d, 0x386b, 0x4136, 0xad, 0x6e, 0xb5, 0x15, 0x87, 0xcf, 0xb1, 0xcd, FWPM_CONDITION_IP_ARRIVAL_INTERFACE) \
	x(0x2d79133b, 0xb390, 0x45c6, 0x86, 0x99, 0xac, 0xac, 0xea, 0xaf, 0xed, 0x33, FWPM_CONDITION_IP_DESTINATION_ADDRESS) \
	x(0x1ec1b7c9, 0x4eea, 0x4f5e, 0xb9, 0xef, 0x76, 0xbe, 0xaa, 0xaf, 0x17, 0xee, FWPM_CONDITION_IP_DESTINATION_ADDRESS_TYPE) \
	x(0xce6def45, 0x60fb, 0x4a7b, 0xa3, 0x04, 0xaf, 0x30, 0xa1, 0x17, 0x00, 0x0e, FWPM_CONDITION_IP_DESTINATION_PORT) \
	x(0x1076b8a5, 0x6323, 0x4c5e, 0x98, 0x10, 0xe8, 0xd3, 0xfc, 0x9e, 0x61, 0x36, FWPM_CONDITION_IP_FORWARD_INTERFACE) \
	x(0xd9ee00de, 0xc1ef, 0x4617, 0xbf, 0xe3, 0xff, 0xd8, 0xf5, 0xa0, 0x89, 0x57, FWPM_CONDITION_IP_LOCAL_ADDRESS) \
	x(0x6ec7f6c4, 0x376b, 0x45d7, 0x9e, 0x9c, 0xd3, 0x37, 0xce, 0xdc, 0xd2, 0x37, FWPM_CONDITION_IP_LOCAL_ADDRESS_TYPE) \
	x(0x03a629cb, 0x6e52, 0x49f8, 0x9c, 0x41, 0x57, 0x09, 0x63, 0x3c, 0x09, 0xcf, FWPM_CONDITION_IP_LOCAL_ADDRESS_V4) \
	x(0x2381be84, 0x7524, 0x45b3, 0xa0, 0x5b, 0x1e, 0x63, 0x7d, 0x9c, 0x7a, 0x6a, FWPM_CONDITION_IP_LOCAL_ADDRESS_V6) \
	x(0x4cd62a49, 0x59c3, 0x4969, 0xb7, 0xf3, 0xbd, 0xa5, 0xd3, 0x28, 0x90, 0xa4, FWPM_CONDITION_IP_LOCAL_INTERFACE) \
	x(0x0c1ba1af, 0x5765, 0x453f, 0xaf, 0x22, 0xa8, 0xf7, 0x91, 0xac, 0x77, 0x5b, FWPM_CONDITION_IP_LOCAL_PORT) \
	x(0xeabe448a, 0xa711, 0x4d64, 0x85, 0xb7, 0x3f, 0x76, 0xb6, 0x52, 0x99, 0xc7, FWPM_CONDITION_IP_NEXTHOP_ADDRESS) \
	x(0x93ae8f5b, 0x7f6f, 0x4719, 0x98, 0xc8, 0x14, 0xe9, 0x74, 0x29, 0xef, 0x04, FWPM_CONDITION_IP_NEXTHOP_INTERFACE) \
	x(0xda50d5c8, 0xfa0d, 0x4c89, 0xb0, 0x32, 0x6e, 0x62, 0x13, 0x6d, 0x1e, 0x96, FWPM_CONDITION_IP_PHYSICAL_ARRIVAL_INTERFACE) \
	x(0xf09bd5ce, 0x5150, 0x48be, 0xb0, 0x98, 0xc2, 0x51, 0x52, 0xfb, 0x1f, 0x92, FWPM_CONDITION_IP_PHYSICAL_NEXTHOP_INTERFACE) \
	x(0x3971ef2b, 0x623e, 0x4f9a, 0x8c, 0xb1, 0x6e, 0x79, 0xb8, 0x06, 0xb9, 0xa7, FWPM_CONDITION_IP_PROTOCOL) \
	x(0xb235ae9a, 0x1d64, 0x49b8, 0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45, FWPM_CONDITION_IP_REMOTE_ADDRESS) \
	x(0x1febb610, 0x3bcc, 0x45e1, 0xbc, 0x36, 0x2e, 0x06, 0x7e, 0x2c, 0xb1, 0x86, FWPM_CONDITION_IP_REMOTE_ADDRESS_V4) \
	x(0x246e1d8c, 0x8bee, 0x4018, 0x9b, 0x98, 0x31, 0xd4, 0x58, 0x2f, 0x33, 0x61, FWPM_CONDITION_IP_REMOTE_ADDRESS_V6) \
	x(0xc35a604d, 0xd22b, 0x4e1a, 0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b, FWPM_CONDITION_IP_REMOTE_PORT) \
	x(0xae96897e, 0x2e94, 0x4bc9, 0xb3, 0x13, 0xb2, 0x7e, 0xe8, 0x0e, 0x57, 0x4d, FWPM_CONDITION_IP_SOURCE_ADDRESS) \
	x(0xa6afef91, 0x3df4, 0x4730, 0xa2, 0x14, 0xf5, 0x42, 0x6a, 0xeb, 0xf8, 0x21, FWPM_CONDITION_IP_SOURCE_PORT) \
	x(0xad37dee3, 0x722f, 0x45cc, 0xa4, 0xe3, 0x06, 0x80, 0x48, 0x12, 0x44, 0x52, FWPM_CONDITION_IPSEC_POLICY_KEY) \
	x(0x37a57700, 0x5884, 0x4964, 0x92, 0xb8, 0x3e, 0x70, 0x46, 0x88, 0xb0, 0xad, FWPM_CONDITION_IPSEC_SECURITY_REALM_ID) \
	x(0x35d0ea0e, 0x15ca, 0x492b, 0x90, 0x0e, 0x97, 0xfd, 0x46, 0x35, 0x2c, 0xce, FWPM_CONDITION_KM_AUTH_NAP_CONTEXT) \
	x(0xfeef4582, 0xef8f, 0x4f7b, 0x85, 0x8b, 0x90, 0x77, 0xd1, 0x22, 0xde, 0x47, FWPM_CONDITION_KM_MODE) \
	x(0xff0f5f49, 0x0ceb, 0x481b, 0x86, 0x38, 0x14, 0x79, 0x79, 0x1f, 0x3f, 0x2c, FWPM_CONDITION_KM_TYPE) \
	x(0x7bc43cbf, 0x37ba, 0x45f1, 0xb7, 0x4a, 0x82, 0xff, 0x51, 0x8e, 0xeb, 0x10, FWPM_CONDITION_L2_FLAGS) \
	x(0x4ebf7562, 0x9f18, 0x4d06, 0x99, 0x41, 0xa7, 0xa6, 0x25, 0x74, 0x4d, 0x71, FWPM_CONDITION_LOCAL_INTERFACE_PROFILE_ID) \
	x(0x04ea2a93, 0x858c, 0x4027, 0xb6, 0x13, 0xb4, 0x31, 0x80, 0xc7, 0x85, 0x9e, FWPM_CONDITION_MAC_DESTINATION_ADDRESS) \
	x(0xae052932, 0xef42, 0x4e99, 0xb1, 0x29, 0xf3, 0xb3, 0x13, 0x9e, 0x34, 0xf7, FWPM_CONDITION_MAC_DESTINATION_ADDRESS_TYPE) \
	x(0xd999e981, 0x7948, 0x4c83, 0xb7, 0x42, 0xc8, 0x4e, 0x3b, 0x67, 0x8f, 0x8f, FWPM_CONDITION_MAC_LOCAL_ADDRESS) \
	x(0xcc31355c, 0x3073, 0x4ffb, 0xa1, 0x4f, 0x79, 0x41, 0x5c, 0xb1, 0xea, 0xd1, FWPM_CONDITION_MAC_LOCAL_ADDRESS_TYPE) \
	x(0x408f2ed4, 0x3a70, 0x4b4d, 0x92, 0xa6, 0x41, 0x5a, 0xc2, 0x0e, 0x2f, 0x12, FWPM_CONDITION_MAC_REMOTE_ADDRESS) \
	x(0x027fedb4, 0xf1c1, 0x4030, 0xb5, 0x64, 0xee, 0x77, 0x7f, 0xd8, 0x67, 0xea, FWPM_CONDITION_MAC_REMOTE_ADDRESS_TYPE) \
	x(0x7b795451, 0xf1f6, 0x4d05, 0xb7, 0xcb, 0x21, 0x77, 0x9d, 0x80, 0x23, 0x36, FWPM_CONDITION_MAC_SOURCE_ADDRESS) \
	x(0x5c1b72e4, 0x299e, 0x4437, 0xa2, 0x98, 0xbc, 0x3f, 0x01, 0x4b, 0x3d, 0xc2, FWPM_CONDITION_MAC_SOURCE_ADDRESS_TYPE) \
	x(0xcb31cef1, 0x791d, 0x473b, 0x89, 0xd1, 0x61, 0xc5, 0x98, 0x43, 0x04, 0xa0, FWPM_CONDITION_NDIS_MEDIA_TYPE) \
	x(0x34c79823, 0xc229, 0x44f2, 0xb8, 0x3c, 0x74, 0x02, 0x08, 0x82, 0xae, 0x77, FWPM_CONDITION_NDIS_PHYSICAL_MEDIA_TYPE) \
	x(0xdb7bb42b, 0x2dac, 0x4cd4, 0xa5, 0x9a, 0xe0, 0xbd, 0xce, 0x1e, 0x68, 0x34, FWPM_CONDITION_NDIS_PORT) \
	x(0x206e9996, 0x490e, 0x40cf, 0xb8, 0x31, 0xb3, 0x86, 0x41, 0xeb, 0x6f, 0xcb, FWPM_CONDITION_NET_EVENT_TYPE) \
	x(0x138e6888, 0x7ab8, 0x4d65, 0x9e, 0xe8, 0x05, 0x91, 0xbc, 0xf6, 0xa4, 0x94, FWPM_CONDITION_NEXTHOP_INTERFACE_INDEX) \
	x(0xd7ff9a56, 0xcdaa, 0x472b, 0x84, 0xdb, 0xd2, 0x39, 0x63, 0xc1, 0xd1, 0xbf, FWPM_CONDITION_NEXTHOP_INTERFACE_PROFILE_ID) \
	x(0x97537c6c, 0xd9a3, 0x4767, 0xa3, 0x81, 0xe9, 0x42, 0x67, 0x5c, 0xd9, 0x20, FWPM_CONDITION_NEXTHOP_INTERFACE_TYPE) \
	x(0xef8a6122, 0x0577, 0x45a7, 0x9a, 0xaf, 0x82, 0x5f, 0xbe, 0xb4, 0xfb, 0x95, FWPM_CONDITION_NEXTHOP_SUB_INTERFACE_INDEX) \
	x(0x72b1a111, 0x987b, 0x4720, 0x99, 0xdd, 0xc7, 0xc5, 0x76, 0xfa, 0x2d, 0x4c, FWPM_CONDITION_NEXTHOP_TUNNEL_TYPE) \
	x(0x076dfdbe, 0xc56c, 0x4f72, 0xae, 0x8a, 0x2c, 0xfe, 0x7e, 0x5c, 0x82, 0x86, FWPM_CONDITION_ORIGINAL_ICMP_TYPE) \
	x(0x46ea1551, 0x2255, 0x492b, 0x80, 0x19, 0xaa, 0xbe, 0xee, 0x34, 0x9f, 0x40, FWPM_CONDITION_ORIGINAL_PROFILE_ID) \
	x(0x9b539082, 0xeb90, 0x4186, 0xa6, 0xcc, 0xde, 0x5b, 0x63, 0x23, 0x50, 0x16, FWPM_CONDITION_PEER_NAME) \
	x(0x1bd0741d, 0xe3df, 0x4e24, 0x86, 0x34, 0x76, 0x20, 0x46, 0xee, 0xf6, 0xeb, FWPM_CONDITION_PIPE) \
	x(0xe31180a8, 0xbbbd, 0x4d14, 0xa6, 0x5e, 0x71, 0x57, 0xb0, 0x62, 0x33, 0xbb, FWPM_CONDITION_PROCESS_WITH_RPC_IF_UUID) \
	x(0xf64fc6d1, 0xf9cb, 0x43d2, 0x8a, 0x5f, 0xe1, 0x3b, 0xc8, 0x94, 0xf2, 0x65, FWPM_CONDITION_QM_MODE) \
	x(0x11205e8c, 0x11ae, 0x457a, 0x8a, 0x44, 0x47, 0x70, 0x26, 0xdd, 0x76, 0x4a, FWPM_CONDITION_REAUTHORIZE_REASON) \
	x(0xf68166fd, 0x0682, 0x4c89, 0xb8, 0xf5, 0x86, 0x43, 0x6c, 0x7e, 0xf9, 0xb7, FWPM_CONDITION_REMOTE_ID) \
	x(0x9bf0ee66, 0x06c9, 0x41b9, 0x84, 0xda, 0x28, 0x8c, 0xb4, 0x3a, 0xf5, 0x1f, FWPM_CONDITION_REMOTE_USER_TOKEN) \
	x(0x678f4deb, 0x45af, 0x4882, 0x93, 0xfe, 0x19, 0xd4, 0x72, 0x9d, 0x98, 0x34, FWPM_CONDITION_RESERVED0) \
	x(0xd818f827, 0x5c69, 0x48eb, 0xbf, 0x80, 0xd8, 0x6b, 0x17, 0x75, 0x5f, 0x97, FWPM_CONDITION_RESERVED1) \
	x(0xb979e282, 0xd621, 0x4c8c, 0xb1, 0x84, 0xb1, 0x05, 0xa6, 0x1c, 0x36, 0xce, FWPM_CONDITION_RESERVED10) \
	x(0x2d62ee4d, 0x023d, 0x411f, 0x95, 0x82, 0x43, 0xac, 0xbb, 0x79, 0x59, 0x75, FWPM_CONDITION_RESERVED11) \
	x(0xa3677c32, 0x7e35, 0x4ddc, 0x93, 0xda, 0xe8, 0xc3, 0x3f, 0xc9, 0x23, 0xc7, FWPM_CONDITION_RESERVED12) \
	x(0x335a3e90, 0x84aa, 0x42f5, 0x9e, 0x6f, 0x59, 0x30, 0x95, 0x36, 0xa4, 0x4c, FWPM_CONDITION_RESERVED13) \
	x(0x30e44da2, 0x2f1a, 0x4116, 0xa5, 0x59, 0xf9, 0x07, 0xde, 0x83, 0x60, 0x4a, FWPM_CONDITION_RESERVED14) \
	x(0xbab8340f, 0xafe0, 0x43d1, 0x80, 0xd8, 0x5c, 0xa4, 0x56, 0x96, 0x2d, 0xe3, FWPM_CONDITION_RESERVED15) \
	x(0x53d4123d, 0xe15b, 0x4e84, 0xb7, 0xa8, 0xdc, 0xe1, 0x6f, 0x7b, 0x62, 0xd9, FWPM_CONDITION_RESERVED2) \
	x(0x7f6e8ca3, 0x6606, 0x4932, 0x97, 0xc7, 0xe1, 0xf2, 0x07, 0x10, 0xaf, 0x3b, FWPM_CONDITION_RESERVED3) \
	x(0x5f58e642, 0xb937, 0x495e, 0xa9, 0x4b, 0xf6, 0xb0, 0x51, 0xa4, 0x92, 0x50, FWPM_CONDITION_RESERVED4) \
	x(0x9ba8f6cd, 0xf77c, 0x43e6, 0x88, 0x47, 0x11, 0x93, 0x9d, 0xc5, 0xdb, 0x5a, FWPM_CONDITION_RESERVED5) \
	x(0xf13d84bd, 0x59d5, 0x44c4, 0x88, 0x17, 0x5e, 0xcd, 0xae, 0x18, 0x05, 0xbd, FWPM_CONDITION_RESERVED6) \
	x(0x65a0f930, 0x45dd, 0x4983, 0xaa, 0x33, 0xef, 0xc7, 0xb6, 0x11, 0xaf, 0x08, FWPM_CONDITION_RESERVED7) \
	x(0x4f424974, 0x0c12, 0x4816, 0x9b, 0x47, 0x9a, 0x54, 0x7d, 0xb3, 0x9a, 0x32, FWPM_CONDITION_RESERVED8) \
	x(0xce78e10f, 0x13ff, 0x4c70, 0x86, 0x43, 0x36, 0xad, 0x18, 0x79, 0xaf, 0xa3, FWPM_CONDITION_RESERVED9) \
	x(0xe5a0aed5, 0x59ac, 0x46ea, 0xbe, 0x05, 0xa5, 0xf0, 0x5e, 0xcf, 0x44, 0x6e, FWPM_CONDITION_RPC_AUTH_LEVEL) \
	x(0xdaba74ab, 0x0d67, 0x43e7, 0x98, 0x6e, 0x75, 0xb8, 0x4f, 0x82, 0xf5, 0x94, FWPM_CONDITION_RPC_AUTH_TYPE) \
	x(0x218b814a, 0x0a39, 0x49b8, 0x8e, 0x71, 0xc2, 0x0c, 0x39, 0xc7, 0xdd, 0x2e, FWPM_CONDITION_RPC_EP_FLAGS) \
	x(0xdccea0b9, 0x0886, 0x4360, 0x9c, 0x6a, 0xab, 0x04, 0x3a, 0x24, 0xfb, 0xa9, FWPM_CONDITION_RPC_EP_VALUE) \
	x(0x238a8a32, 0x3199, 0x467d, 0x87, 0x1c, 0x27, 0x26, 0x21, 0xab, 0x38, 0x96, FWPM_CONDITION_RPC_IF_FLAG) \
	x(0x7c9c7d9f, 0x0075, 0x4d35, 0xa0, 0xd1, 0x83, 0x11, 0xc4, 0xcf, 0x6a, 0xf1, FWPM_CONDITION_RPC_IF_UUID) \
	x(0xeabfd9b7, 0x1262, 0x4a2e, 0xad, 0xaa, 0x5f, 0x96, 0xf6, 0xfe, 0x32, 0x6d, FWPM_CONDITION_RPC_IF_VERSION) \
	x(0xd58efb76, 0xaab7, 0x4148, 0xa8, 0x7e, 0x95, 0x81, 0x13, 0x41, 0x29, 0xb9, FWPM_CONDITION_RPC_OPNUM) \
	x(0x2717bc74, 0x3a35, 0x4ce7, 0xb7, 0xef, 0xc8, 0x38, 0xfa, 0xbd, 0xec, 0x45, FWPM_CONDITION_RPC_PROTOCOL) \
	x(0x40953fe2, 0x8565, 0x4759, 0x84, 0x88, 0x17, 0x71, 0xb4, 0xb4, 0xb5, 0xdb, FWPM_CONDITION_RPC_PROXY_AUTH_TYPE) \
	x(0xb605a225, 0xc3b3, 0x48c7, 0x98, 0x33, 0x7a, 0xef, 0xa9, 0x52, 0x75, 0x46, FWPM_CONDITION_RPC_SERVER_NAME) \
	x(0x8090f645, 0x9ad5, 0x4e3b, 0x9f, 0x9f, 0x80, 0x23, 0xca, 0x09, 0x79, 0x09, FWPM_CONDITION_RPC_SERVER_PORT) \
	x(0x0d306ef0, 0xe974, 0x4f74, 0xb5, 0xc7, 0x59, 0x1b, 0x0d, 0xa7, 0xd5, 0x62, FWPM_CONDITION_SEC_ENCRYPT_ALGORITHM) \
	x(0x4772183b, 0xccf8, 0x4aeb, 0xbc, 0xe1, 0xc6, 0xc6, 0x16, 0x1c, 0x8f, 0xe4, FWPM_CONDITION_SEC_KEY_SIZE) \
	x(0x2311334d, 0xc92d, 0x45bf, 0x94, 0x96, 0xed, 0xf4, 0x47, 0x82, 0x0e, 0x2d, FWPM_CONDITION_SOURCE_INTERFACE_INDEX) \
	x(0x055edd9d, 0xacd2, 0x4361, 0x8d, 0xab, 0xf9, 0x52, 0x5d, 0x97, 0x66, 0x2f, FWPM_CONDITION_SOURCE_SUB_INTERFACE_INDEX) \
	x(0x0cd42473, 0xd621, 0x4be3, 0xae, 0x8c, 0x72, 0xa3, 0x48, 0xd2, 0x83, 0xe1, FWPM_CONDITION_SUB_INTERFACE_INDEX) \
	x(0x77a40437, 0x8779, 0x4868, 0xa2, 0x61, 0xf5, 0xa9, 0x02, 0xf1, 0xc0, 0xcd, FWPM_CONDITION_TUNNEL_TYPE) \
	x(0x938eab21, 0x3618, 0x4e64, 0x9c, 0xa5, 0x21, 0x41, 0xeb, 0xda, 0x1c, 0xa2, FWPM_CONDITION_VLAN_ID) \
	x(0x8ed48be4, 0xc926, 0x49f6, 0xa4, 0xf6, 0xef, 0x30, 0x30, 0xe3, 0xfc, 0x16, FWPM_CONDITION_VSWITCH_DESTINATION_INTERFACE_ID) \
	x(0xfa9b3f06, 0x2f1a, 0x4c57, 0x9e, 0x68, 0xa7, 0x09, 0x8b, 0x28, 0xdb, 0xfe, FWPM_CONDITION_VSWITCH_DESTINATION_INTERFACE_TYPE) \
	x(0x6106aace, 0x4de1, 0x4c84, 0x96, 0x71, 0x36, 0x37, 0xf8, 0xbc, 0xf7, 0x31, FWPM_CONDITION_VSWITCH_DESTINATION_VM_ID) \
	x(0xc4a414ba, 0x437b, 0x4de6, 0x99, 0x46, 0xd9, 0x9c, 0x1b, 0x95, 0xb3, 0x12, FWPM_CONDITION_VSWITCH_ID) \
	x(0x11d48b4b, 0xe77a, 0x40b4, 0x91, 0x55, 0x39, 0x2c, 0x90, 0x6c, 0x26, 0x08, FWPM_CONDITION_VSWITCH_NETWORK_TYPE) \
	x(0x7f4ef24b, 0xb2c1, 0x4938, 0xba, 0x33, 0xa1, 0xec, 0xbe, 0xd5, 0x12, 0xba, FWPM_CONDITION_VSWITCH_SOURCE_INTERFACE_ID) \
	x(0xe6b040a2, 0xedaf, 0x4c36, 0x90, 0x8b, 0xf2, 0xf5, 0x8a, 0xe4, 0x38, 0x07, FWPM_CONDITION_VSWITCH_SOURCE_INTERFACE_TYPE) \
	x(0x9c2a9ec2, 0x9fc6, 0x42bc, 0xbd, 0xd8, 0x40, 0x6d, 0x4d, 0xa0, 0xbe, 0x64, FWPM_CONDITION_VSWITCH_SOURCE_VM_ID) \
	x(0xdc04843c, 0x79e6, 0x4e44, 0xa0, 0x25, 0x65, 0xb9, 0xbb, 0x0f, 0x9f, 0x94, FWPM_CONDITION_VSWITCH_TENANT_NETWORK_ID) \
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
	x(0x877519e1, 0xe6a9, 0x41a5, 0x81, 0xb4, 0x8c, 0x4f, 0x11, 0x8e, 0x4a, 0x60, FWPM_SUBLAYER_INSPECTION) \
	x(0xe076d572, 0x5d3d, 0x48ef, 0x80, 0x2b, 0x90, 0x9e, 0xdd, 0xb0, 0x98, 0xbd, FWPM_SUBLAYER_IPSEC_DOSP) \
	x(0xa5082e73, 0x8f71, 0x4559, 0x8a, 0x9a, 0x10, 0x1c, 0xea, 0x04, 0xef, 0x87, FWPM_SUBLAYER_IPSEC_FORWARD_OUTBOUND_TUNNEL) \
	x(0x37a57701, 0x5884, 0x4964, 0x92, 0xb8, 0x3e, 0x70, 0x46, 0x88, 0xb0, 0xad, FWPM_SUBLAYER_IPSEC_SECURITY_REALM) \
	x(0x83f299ed, 0x9ff4, 0x4967, 0xaf, 0xf4, 0xc3, 0x09, 0xf4, 0xda, 0xb8, 0x27, FWPM_SUBLAYER_IPSEC_TUNNEL) \
	x(0x1b75c0ce, 0xff60, 0x4711, 0xa7, 0x0f, 0xb4, 0x95, 0x8c, 0xc3, 0xb2, 0xd0, FWPM_SUBLAYER_LIPS) \
	x(0xffe221c3, 0x92a8, 0x4564, 0xa5, 0x9f, 0xda, 0xfb, 0x70, 0x75, 0x60, 0x20, FWPM_SUBLAYER_MPSSVC_APP_ISOLATION) \
	x(0x09a47e38, 0xfa97, 0x471b, 0xb1, 0x23, 0x18, 0xbc, 0xd7, 0xe6, 0x50, 0x71, FWPM_SUBLAYER_MPSSVC_EDP) \
	x(0xb3cdd441, 0xaf90, 0x41ba, 0xa7, 0x45, 0x7c, 0x60, 0x08, 0xff, 0x23, 0x02, FWPM_SUBLAYER_MPSSVC_QUARANTINE) \
	x(0x1ec6c7e1, 0xfdd9, 0x478a, 0xb5, 0x5f, 0xff, 0x8b, 0xa1, 0xd2, 0xc1, 0x7d, FWPM_SUBLAYER_MPSSVC_TENANT_RESTRICTIONS) \
	x(0xb3cdd441, 0xaf90, 0x41ba, 0xa7, 0x45, 0x7c, 0x60, 0x08, 0xff, 0x23, 0x01, FWPM_SUBLAYER_MPSSVC_WF) \
	x(0xb3cdd441, 0xaf90, 0x41ba, 0xa7, 0x45, 0x7c, 0x60, 0x08, 0xff, 0x23, 0x00, FWPM_SUBLAYER_MPSSVC_WSH) \
	x(0x758c84f4, 0xfb48, 0x4de9, 0x9a, 0xeb, 0x3e, 0xd9, 0x55, 0x1a, 0xb1, 0xfd, FWPM_SUBLAYER_RPC_AUDIT) \
	x(0x15a66e17, 0x3f3c, 0x4f7b, 0xaa, 0x6c, 0x81, 0x2a, 0xa6, 0x13, 0xdd, 0x82, FWPM_SUBLAYER_SECURE_SOCKET) \
	x(0x337608b9, 0xb7d5, 0x4d5f, 0x82, 0xf9, 0x36, 0x18, 0x61, 0x8b, 0xc0, 0x58, FWPM_SUBLAYER_TCP_CHIMNEY_OFFLOAD) \
	x(0x24421dcf, 0x0ac5, 0x4caa, 0x9e, 0x14, 0x50, 0xf6, 0xe3, 0x63, 0x6a, 0xf0, FWPM_SUBLAYER_TCP_TEMPLATES) \
	x(0xba69dc66, 0x5176, 0x4979, 0x9c, 0x89, 0x26, 0xa7, 0xb4, 0x6a, 0x83, 0x27, FWPM_SUBLAYER_TEREDO) \
	x(0xeebecc03, 0xced4, 0x4380, 0x81, 0x9a, 0x27, 0x34, 0x39, 0x7b, 0x2b, 0x74, FWPM_SUBLAYER_UNIVERSAL) \

[[nodiscard]] static inline bool mk_guid_eq(GUID const* const a, GUID const* const b)
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

enum mk_guid_id_e
{
	#define x(d1, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8, name) guid_id_e_##name,
	mk_x_guids()
	#undef x
	guid_id_e_dummy_end
};
typedef enum mk_guid_id_e mk_guid_id_t;

[[nodiscard]] constexpr static inline int mk_guids_get_count(void)
{
	int i;
	
	i = 0;

	#define x(d1, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8, name) ++i;
	mk_x_guids()
	#undef x

	return i;
}

struct mk_guid_s
{
	unsigned char m_bytes[16];
};
typedef struct mk_guid_s mk_guid_t;

struct mk_guids_s
{
	mk_guid_t m_guids[mk_guids_get_count()];
};
typedef struct mk_guids_s mk_guids_t;

[[nodiscard]] constexpr static inline mk_guids_t mk_guids_get_all(void)
{
	int i;
	mk_guids_t guids;

	i = 0;
	#define x(d1, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8, name) \
	{ \
		guids.m_guids[i].m_bytes[ 0] = ((unsigned char)(d1 >> (0 * 8))); \
		guids.m_guids[i].m_bytes[ 1] = ((unsigned char)(d1 >> (1 * 8))); \
		guids.m_guids[i].m_bytes[ 2] = ((unsigned char)(d1 >> (2 * 8))); \
		guids.m_guids[i].m_bytes[ 3] = ((unsigned char)(d1 >> (3 * 8))); \
		guids.m_guids[i].m_bytes[ 4] = ((unsigned char)(w1 >> (0 * 8))); \
		guids.m_guids[i].m_bytes[ 5] = ((unsigned char)(w1 >> (1 * 8))); \
		guids.m_guids[i].m_bytes[ 6] = ((unsigned char)(w2 >> (0 * 8))); \
		guids.m_guids[i].m_bytes[ 7] = ((unsigned char)(w2 >> (1 * 8))); \
		guids.m_guids[i].m_bytes[ 8] = ((unsigned char)(b1)); \
		guids.m_guids[i].m_bytes[ 9] = ((unsigned char)(b2)); \
		guids.m_guids[i].m_bytes[10] = ((unsigned char)(b3)); \
		guids.m_guids[i].m_bytes[11] = ((unsigned char)(b4)); \
		guids.m_guids[i].m_bytes[12] = ((unsigned char)(b5)); \
		guids.m_guids[i].m_bytes[13] = ((unsigned char)(b6)); \
		guids.m_guids[i].m_bytes[14] = ((unsigned char)(b7)); \
		guids.m_guids[i].m_bytes[15] = ((unsigned char)(b8)); \
		++i; \
	}
	mk_x_guids()
	#undef x
	return guids;
}

[[nodiscard]] static inline bool mk_guids_test(void)
{
	bool gud;
	int i;
	mk_guids_t guids_2;

	gud = true;
	i = 0;
	guids_2 = mk_guids_get_all();
	#define x(d1, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8, name) \
	{ \
		gud &= mk_guid_eq(&name, ((GUID*)(&guids_2.m_guids[i]))); \
		++i; \
	}
	mk_x_guids()
	#undef x
	return gud;
}

[[nodiscard]] static inline bool mk_guid_eq(GUID const* const a, mk_guid_t const* const b)
{
	return mk_guid_eq(a, ((GUID const*)(b)));
}

[[nodiscard]] static inline bool matches_test(void)
{
	bool gud;
	int i;

	gud = true;
	i = 0;

	#define x(enm, txt) \
		gud &= (((int)(enm)) == i); \
		++i;
	mk_x_matches()
	#undef x

	return gud;
}

[[nodiscard]] constexpr static inline int matches_get_count(void)
{
	int cnt;

	cnt = 0;

	#define x(enm, txt) \
		++cnt;
	mk_x_matches()
	#undef x

	return cnt;
}

enum matches_get_count_e { matches_get_count_v = matches_get_count() };

[[nodiscard]] static inline bool types_test(void)
{
	bool gud;
	int i;

	gud = true;
	i = 0;
	#define x(name, value) ++i;
	mk_x_types()
	#undef x
	return gud;
}

[[nodiscard]] constexpr static inline int types_get_count(void)
{
	int cnt;

	cnt = 0;
	#define x(name, value) ++cnt;
	mk_x_types()
	#undef x
	return cnt;
}

enum types_get_count_e { types_get_count_v = types_get_count() };

[[nodiscard]] constexpr static inline int action_types_get_count(void)
{
	int cnt;

	cnt = 0;

	#define x(name, value, str) \
		++cnt;
	mk_x_action_types()
	#undef x

	return cnt;
}

[[nodiscard]] constexpr static inline int action_types_get_texts_len(void)
{
	int total;
	int len;

	total = 0;

	#define x(name, value, str) \
		len = _countof(str) - 1; \
		total += len;
	mk_x_action_types()
	#undef x

	return total;
}

enum action_types_get_count_e { action_types_get_count_v = action_types_get_count() };

#define x(name) typedef decltype(&name) tfn_##name;
mk_x_all_funcs()
#undef x
#define x(namea, nameb) typedef decltype(&nameb) tfn_##namea;
mk_x_ntdll2_funcs()
#undef x

template<std::size_t t_strings_cnt, std::size_t t_bytes_cnt>
struct mk_strings
{
public:
	static constexpr std::size_t const s_strings_cnt = t_strings_cnt;
	static constexpr std::size_t const s_offsets_cnt = t_strings_cnt - 1;
	static constexpr std::size_t const s_bytes_cnt = t_bytes_cnt;
public:
	enum string_id : std::size_t
	{
		#define xx(name, value) mk_concat(id_, name),
		#define x(name, value) xx(name, value)
		mk_x_nstrings()
		#undef x
		#define x(name) xx(name, #name)
		mk_x_dlls_to_load()
		#undef x
		#define x(d1, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8, name) xx(name, #name)
		mk_x_guids()
		#undef x
		#define x(name, value) xx(name, value)
		mk_x_matches()
		#undef x
		#define x(name, value, str) xx(name, str)
		mk_x_action_types()
		#undef x
		#define x(name, value) xx(name, value)
		mk_x_types()
		#undef x
		#undef xx
	};
public:
	[[nodiscard]] constexpr char const* get_str_ptr(string_id const& id) const noexcept
	{
		char const* str_ptr;

		mk_assert(id >= 0);
		mk_assert(id < s_strings_cnt);

		if(id == 0)
		{
			str_ptr = &m_bytes_buf[0];
		}
		else
		{
			str_ptr = &m_bytes_buf[0] + m_offsets_buf[id - 1];
		}
		return str_ptr;
	}
	[[nodiscard]] constexpr int get_str_len(string_id const& id) const noexcept
	{
		int str_len;

		mk_assert(id >= 0);
		mk_assert(id < s_strings_cnt);

		if(id == 0)
		{
			str_len = m_offsets_buf[0];
		}
		else if(id == s_strings_cnt - 1)
		{
			str_len = s_bytes_cnt - m_offsets_buf[id - 1];
		}
		else
		{
			str_len = m_offsets_buf[id - 0] - m_offsets_buf[id - 1];
		}
		return str_len;
	}
	[[nodiscard]] constexpr mk_view_nstr_nz_t get_nstr(string_id const& id) const noexcept
	{
		mk_view_nstr_nz_t nstr;

		mk_assert(id >= 0);
		mk_assert(id < s_strings_cnt);

		nstr.m_buf = get_str_ptr(id);
		nstr.m_len = get_str_len(id);
		return nstr;
	}
	[[nodiscard]] constexpr mk_view_nstr_nz_t get_nstr(int const& id) const noexcept
	{
		return get_nstr(((string_id)(id)));
	}
public:
	std::uint16_t m_offsets_buf[s_offsets_cnt];
	char m_bytes_buf[s_bytes_cnt];
};

[[nodiscard]] constexpr static inline auto mk_strings_count(void) noexcept
{
	int i;

	i = 0;
	#define xx(name, value) ++i;
	#define x(name, value) xx(name, value)
	mk_x_nstrings()
	#undef x
	#define x(name) xx(name, #name)
	mk_x_dlls_to_load()
	#undef x
	#define x(d1, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8, name) xx(name, #name)
	mk_x_guids()
	#undef x
	#define x(name, value) xx(name, value)
	mk_x_matches()
	#undef x
	#define x(name, value, str) xx(name, str)
	mk_x_action_types()
	#undef x
	#define x(name, value) xx(name, value)
	mk_x_types()
	#undef x
	#undef xx
	return i;
}

[[nodiscard]] constexpr static inline auto mk_strings_bytes_count(void) noexcept
{
	int i;

	i = 0;
	#define xx(name, value) i += std::size(value) - 1;
	#define x(name, value) xx(name, value)
	mk_x_nstrings()
	#undef x
	#define x(name) xx(name, #name)
	mk_x_dlls_to_load()
	#undef x
	#define x(d1, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8, name) xx(name, #name)
	mk_x_guids()
	#undef x
	#define x(name, value) xx(name, value)
	mk_x_matches()
	#undef x
	#define x(name, value, str) xx(name, str)
	mk_x_action_types()
	#undef x
	#define x(name, value) xx(name, value)
	mk_x_types()
	#undef x
	#undef xx
	return i;
}

[[nodiscard]] constexpr static inline auto mk_strings_make(void) noexcept
{
	mk_strings<mk_strings_count(), mk_strings_bytes_count()> strings;
	int i;
	std::uint16_t offset;
	std::uint16_t cur_len;
	char const* begin;

	i = 0;
	offset = 0;
	#define xx(name, value) \
	{ \
		cur_len = std::size(value) - 1; \
		begin = value; \
		if(i != 0) \
		{ \
			strings.m_offsets_buf[i - 1] = offset; \
		} \
		std::copy(begin + 0, begin + cur_len, &strings.m_bytes_buf[offset]); \
		mk_assert(((std::size_t)(offset)) + ((std::size_t)(cur_len)) <= std::numeric_limits<std::uint16_t>::max()); \
		offset += cur_len; \
		++i; \
	}
	#define x(name, value) xx(name, value)
	mk_x_nstrings()
	#undef x
	#define x(name) xx(name, #name)
	mk_x_dlls_to_load()
	#undef x
	#define x(d1, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8, name) xx(name, #name)
	mk_x_guids()
	#undef x
	#define x(name, value) xx(name, value)
	mk_x_matches()
	#undef x
	#define x(name, value, str) xx(name, str)
	mk_x_action_types()
	#undef x
	#define x(name, value) xx(name, value)
	mk_x_types()
	#undef x
	#undef xx
	return strings;
}

struct mk_konst_s
{
	#define x(name) DWORD m_hash_##name;
	mk_x_all_funcs()
	#undef x
	#define x(namea, nameb) DWORD m_hash_##namea;
	mk_x_ntdll2_funcs()
	#undef x

	#define x(name, value) DWORD m_hash_##name;
	mk_x_hash_strings()
	#undef x

	mk_guids_t m_guids;
	decltype(mk_strings_make()) m_strings;
};
typedef struct mk_konst_s mk_konst_t;

[[nodiscard]] constexpr static inline mk_konst_t make_konst(void)
{
	mk_konst_t konst;

	#define x(name) konst.m_hash_##name = fnv1a(#name);
	mk_x_all_funcs()
	#undef x
	#define x(namea, nameb) konst.m_hash_##namea = fnv1a(#namea);
	mk_x_ntdll2_funcs()
	#undef x

	#define x(name, value) konst.m_hash_##name = fnv1a(value);
	mk_x_hash_strings()
	#undef x

	konst.m_guids = mk_guids_get_all();
	konst.m_strings = mk_strings_make();
	return konst;
}

struct mk_fw_s
{
	HANDLE m_eng;
	FWPM_FILTER0** m_entries;
	UINT32 m_count;
};
typedef struct mk_fw_s mk_fw_t;

enum mk_col_id_entry_e
{
	mk_col_id_entry_e_filter,
	mk_col_id_entry_e_name,
	mk_col_id_entry_e_description,
	mk_col_id_entry_e_provider,
	mk_col_id_entry_e_layer,
	mk_col_id_entry_e_sub_layer,
	mk_col_id_entry_e_action,
	mk_col_id_entry_e_callout,
	mk_col_id_entry_e_id,
	mk_col_id_entry_e_weight,
	mk_col_id_entry_e_effective_weight,
	mk_col_id_entry_e_dummy_end
};
typedef enum mk_col_id_entry_e mk_col_id_entry_t;

enum mk_col_id_condition_e
{
	mk_col_id_condition_e_field,
	mk_col_id_condition_e_match_type,
	mk_col_id_condition_e_value_type,
	mk_col_id_condition_e_value_data,
	mk_col_id_condition_e_note,
	mk_col_id_condition_e_dummy_end
};
typedef enum mk_col_id_condition_e mk_col_id_condition_t;

enum mk_wnd_sub_window_id_e
{
	mk_wnd_sub_window_id_e_entries,
	mk_wnd_sub_window_id_e_conditions,
	mk_wnd_sub_window_id_e_dummy_end
};
typedef enum mk_wnd_sub_window_id_e mk_wnd_sub_window_id_t;

enum menu_id_e
{
	menu_id_e_copy_cell,
	menu_id_e_copy_line,
	menu_id_e_copy_table,
	menu_id_e_dummy_end
};
typedef enum menu_id_e menu_id_t;

struct mk_max_width_cols_entries_s
{
	int m_filter;
	int m_provider;
	int m_layer;
	int m_sub_layer;
	int m_action;
	int m_callout;
	int m_id;
	int m_weight;
	int m_effective_weight;
};
typedef struct mk_max_width_cols_entries_s mk_max_width_cols_entries_t;

struct mk_max_width_cols_conditions_s
{
	int m_field;
	int m_match_type;
	int m_value_type;
	int m_note;
};
typedef struct mk_max_width_cols_conditions_s mk_max_width_cols_conditions_t;

struct mk_wnd_s
{
	HWND m_hwnd;
	HWND m_entries;
	HWND m_conditions;
	HMENU m_menu;
	HWND m_list_view_for_menu;
	int m_row_idx_for_menu;
	int m_col_idx_for_menu;
	mk_fw_t* m_fw;
	mk_wnd_sub_window_id_t m_last_sub_window_focus;
	int m_entry_idx_sorted;
	int m_entries_sort_col;
	int* m_sort_ints;
	int m_condition_row;
	mk_max_width_cols_entries_t m_max_entries;
	mk_max_width_cols_conditions_t m_max_conditions;
};
typedef struct mk_wnd_s mk_wnd_t;

struct mk_funcs_ntdll_s
{
	#define x(name) tfn_##name m_pfn_##name;
	mk_x_ntdll_funcs()
	#undef x
	#define x(namea, nameb) tfn_##namea m_pfn_##namea;
	mk_x_ntdll2_funcs()
	#undef x

};
typedef struct mk_funcs_ntdll_s mk_funcs_ntdll_t;

struct mk_funcs_kernel_s
{
	#define x(name) tfn_##name m_pfn_##name;
	mk_x_kernel_funcs()
	#undef x
};
typedef struct mk_funcs_kernel_s mk_funcs_kernel_t;

struct mk_funcs_advapi_s
{
	#define x(name) tfn_##name m_pfn_##name;
	mk_x_advapi_funcs()
	#undef x
};
typedef struct mk_funcs_advapi_s mk_funcs_advapi_t;

struct mk_funcs_combase_s
{
	#define x(name) tfn_##name m_pfn_##name;
	mk_x_combase_funcs()
	#undef x
};
typedef struct mk_funcs_combase_s mk_funcs_combase_t;

struct mk_funcs_fw_s
{
	#define x(name) tfn_##name m_pfn_##name;
	mk_x_fw_funcs()
	#undef x
};
typedef struct mk_funcs_fw_s mk_funcs_fw_t;

struct mk_funcs_user_s
{
	#define x(name) tfn_##name m_pfn_##name;
	mk_x_user_funcs()
	#undef x
};
typedef struct mk_funcs_user_s mk_funcs_user_t;

struct mk_funcs_comctl_s
{
	#define x(name) tfn_##name m_pfn_##name;
	mk_x_comctl_funcs()
	#undef x
};
typedef struct mk_funcs_comctl_s mk_funcs_comctl_t;

struct mk_funcs_comdlg_s
{
	#define x(name) tfn_##name m_pfn_##name;
	mk_x_comdlg_funcs()
	#undef x
};
typedef struct mk_funcs_comdlg_s mk_funcs_comdlg_t;

struct mk_dlls_s
{
	#define x(name) HMODULE m_##name;
	mk_x_dlls_all()
	#undef x
};
typedef struct mk_dlls_s mk_dlls_t;

struct mk_app_s
{
	PPEB m_peb;
	mk_dlls_t m_dlls;
	mk_funcs_ntdll_t m_funcs_ntdll;
	mk_funcs_kernel_t m_funcs_kernel;
	mk_funcs_advapi_t m_funcs_advapi;
	mk_funcs_combase_t m_funcs_combase;
	mk_funcs_fw_t m_funcs_fw;
	mk_funcs_user_t m_funcs_user;
	mk_funcs_comctl_t m_funcs_comctl;
	mk_funcs_comdlg_t m_funcs_comdlg;
	mk_fw_t m_fw;
	mk_wnd_t m_fw_wnd;
	UINT m_tmps_nstr_idx;
	UINT m_tmps_wstr_idx;
	CHAR m_tmp_nstrs[64][32 * 1024];
	WCHAR m_tmp_wstrs[64][32 * 1024];
};
typedef struct mk_app_s mk_app_t;


static constexpr mk_konst_t const k_konst = make_konst();;
static constexpr bool const k_debug = mk_is_debug;
static mk_app_t g_app;


static inline void fw_construct(mk_fw_t* const fw)
{
	#define k_count (1 * 1024 * 1024)

	DWORD dw;
	HANDLE enm;

	mk_assert(fw);

	dw = g_app.m_funcs_fw.m_pfn_FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &fw->m_eng); mk_assert(dw == ERROR_SUCCESS);
	dw = g_app.m_funcs_fw.m_pfn_FwpmFilterCreateEnumHandle0(fw->m_eng, NULL, &enm); mk_assert(dw == ERROR_SUCCESS);
	dw = g_app.m_funcs_fw.m_pfn_FwpmFilterEnum0(fw->m_eng, enm, k_count, &fw->m_entries, &fw->m_count); mk_assert(dw == ERROR_SUCCESS);
	dw = g_app.m_funcs_fw.m_pfn_FwpmFilterDestroyEnumHandle0(fw->m_eng, enm); mk_assert(dw == ERROR_SUCCESS);
}

static inline void fw_destroy(mk_fw_t* const fw)
{
	DWORD dw;

	mk_assert(fw);

	g_app.m_funcs_fw.m_pfn_FwpmFreeMemory0(((void**)(&fw->m_entries)));
	dw = g_app.m_funcs_fw.m_pfn_FwpmEngineClose0(fw->m_eng); mk_assert(dw == ERROR_SUCCESS);
}

[[nodiscard]] static inline mk_view_nstr_t nstr_to_nstr(LPCSTR const win_str, int const len)
{
	LPSTR buf;
	int n;
	int i;
	mk_view_nstr_t nstr;

	mk_assert(len < _countof(g_app.m_tmp_nstrs[0]));

	buf = &g_app.m_tmp_nstrs[g_app.m_tmps_nstr_idx++ % _countof(g_app.m_tmp_nstrs)][0];
	n = len;
	for(i = 0; i != n; ++i)
	{
		buf[i] = ((CHAR)(win_str[i]));
	}
	buf[i] = '\0';
	nstr.m_buf = buf;
	nstr.m_len = len;
	mk_assert(nstr.m_len >= 0);
	mk_assert(nstr.m_buf[nstr.m_len] == '\0');
	return nstr;
}

[[nodiscard]] static inline mk_view_nstr_t nstr_to_nstr(mk_view_nstr_nz_t const nstr_nz)
{
	LPSTR buf;
	int n;
	int i;
	mk_view_nstr_t nstr;

	mk_assert(nstr_nz.m_len < _countof(g_app.m_tmp_nstrs[0]));

	buf = &g_app.m_tmp_nstrs[g_app.m_tmps_nstr_idx++ % _countof(g_app.m_tmp_nstrs)][0];
	n = ((int)(nstr_nz.m_len));
	for(i = 0; i != n; ++i)
	{
		buf[i] = ((CHAR)(nstr_nz.m_buf[i]));
	}
	buf[i] = '\0';
	nstr.m_buf = buf;
	nstr.m_len = nstr_nz.m_len;
	mk_assert(nstr.m_len >= 0);
	mk_assert(nstr.m_buf[nstr.m_len] == '\0');
	return nstr;
}

template<size_t n>
[[nodiscard]] static inline mk_view_nstr_t nstr_to_nstr(std::array<char, n> const& arr)
{
	return nstr_to_nstr(arr.data(), ((int)(arr.size())));
}

[[nodiscard]] static inline mk_view_wstr_t nstr_to_wstr(mk_view_nstr_t const& nstr)
{
	LPWSTR buf;
	SIZE_T n;
	SIZE_T i;
	mk_view_wstr_t wstr;

	mk_assert(nstr.m_len >= 0);
	mk_assert(nstr.m_len < _countof(g_app.m_tmp_wstrs[0]));
	mk_assert(nstr.m_buf[nstr.m_len] == '\0');

	buf = &g_app.m_tmp_wstrs[g_app.m_tmps_wstr_idx++ % _countof(g_app.m_tmp_wstrs)][0];
	n = nstr.m_len + 1;
	for(i = 0; i != n; ++i)
	{
		buf[i] = ((WCHAR)(nstr.m_buf[i]));
	}
	wstr.m_buf = buf;
	wstr.m_len = nstr.m_len;
	mk_assert(wstr.m_len >= 0);
	mk_assert(wstr.m_buf[wstr.m_len] == L'\0');
	return wstr;
}

[[nodiscard]] static inline mk_view_wstr_t nstr_to_wstr(mk_view_nstr_nz_t const& nstr)
{
	LPWSTR buf;
	SIZE_T n;
	SIZE_T i;
	mk_view_wstr_t wstr;

	mk_assert(nstr.m_len >= 0);
	mk_assert(nstr.m_len < _countof(g_app.m_tmp_wstrs[0]));

	buf = &g_app.m_tmp_wstrs[g_app.m_tmps_wstr_idx++ % _countof(g_app.m_tmp_wstrs)][0];
	n = nstr.m_len;
	for(i = 0; i != n; ++i)
	{
		buf[i] = ((WCHAR)(nstr.m_buf[i]));
	}
	buf[i] = L'\0';
	wstr.m_buf = buf;
	wstr.m_len = nstr.m_len;
	mk_assert(wstr.m_len >= 0);
	mk_assert(wstr.m_buf[wstr.m_len] == L'\0');
	return wstr;
}

[[nodiscard]] static inline mk_view_wstr_t nstr_to_wstr(LPCSTR const nstr, int const len)
{
	LPWSTR buf;
	int n;
	int i;
	mk_view_wstr_t wstr;

	buf = &g_app.m_tmp_wstrs[g_app.m_tmps_wstr_idx++ % _countof(g_app.m_tmp_wstrs)][0];
	n = len;
	for(i = 0; i != n; ++i)
	{
		buf[i] = ((WCHAR)(nstr[i]));
	}
	buf[i] = L'\0';
	wstr.m_buf = buf;
	wstr.m_len = len;
	mk_assert(wstr.m_len >= 0);
	mk_assert(wstr.m_buf[wstr.m_len] == L'\0');
	return wstr;
}

template<size_t nn>
[[nodiscard]] static inline mk_view_wstr_t nstr_to_wstr(std::array<char, nn> const& arr)
{
	LPWSTR buf;
	int n;
	int i;
	mk_view_wstr_t wstr;

	buf = &g_app.m_tmp_wstrs[g_app.m_tmps_wstr_idx++ % _countof(g_app.m_tmp_wstrs)][0];
	n = nn;
	for(i = 0; i != n; ++i)
	{
		buf[i] = ((WCHAR)(arr[i]));
	}
	buf[i] = L'\0';
	wstr.m_buf = buf;
	wstr.m_len = n;
	mk_assert(wstr.m_len >= 0);
	mk_assert(wstr.m_buf[wstr.m_len] == L'\0');
	return wstr;
}

[[nodiscard]] static inline mk_view_wstr_t wstr_to_wstr(LPCWSTR const win_str)
{
	mk_view_wstr_t wstr;

	if(win_str)
	{
		wstr.m_buf = win_str;
		wstr.m_len = mk_wcslen_c(win_str);
	}
	else
	{
		wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_empty));
	}
	mk_assert(wstr.m_len >= 0);
	mk_assert(wstr.m_buf[wstr.m_len] == L'\0');
	return wstr;
}

template<typename t, size_t n>
[[nodiscard]] static inline LPWSTR nstr_to_wstr(mk_view_t<t, n> const& view)
{
	return nstr_to_wstr(view.m_buf, ((int)(n)));
}

[[nodiscard]] static inline mk_view_wstr_t mk_guid_to_wstr_raw(GUID const* const guid)
{
	int cap;
	LPWSTR buf;
	mk_view_wstr_t wstr;
	int len;

	mk_assert(guid);

	cap = _countof(g_app.m_tmp_wstrs[0]);
	buf = &g_app.m_tmp_wstrs[g_app.m_tmps_wstr_idx++ % _countof(g_app.m_tmp_wstrs)][0];
	len = g_app.m_funcs_combase.m_pfn_StringFromGUID2(*guid, buf, cap); mk_assert(len >= 1); mk_assert(len < cap);
	buf[len] = L'\0';
	wstr.m_buf = buf;
	wstr.m_len = len - 1;
	mk_assert(wstr.m_len >= 0);
	mk_assert(wstr.m_buf[wstr.m_len] == L'\0');
	return wstr;
}

static inline void mkfw_load_all(PPEB const peb)
{
	mk_assert(peb);

	g_app.m_peb = peb;
	g_app.m_dlls.m_ntdll = find_module(peb, k_konst.m_hash_ntdll); mk_assert(g_app.m_dlls.m_ntdll);
	g_app.m_dlls.m_kernel32 = find_module(peb, k_konst.m_hash_kernel32dll); mk_assert(g_app.m_dlls.m_kernel32);

	#define x(name) g_app.m_funcs_ntdll.m_pfn_##name = ((tfn_##name)(find_proc(peb, g_app.m_dlls.m_ntdll, k_konst.m_hash_##name))); mk_assert(g_app.m_funcs_ntdll.m_pfn_##name); if(k_debug){ if(!g_app.m_funcs_ntdll.m_pfn_##name){ my_MessageBoxA(0, "Could not find `" #name "'.", 0, 0); } }
	mk_x_ntdll_funcs()
	#undef x
	#define x(namea, nameb) g_app.m_funcs_ntdll.m_pfn_##namea = ((tfn_##namea)(find_proc(peb, g_app.m_dlls.m_ntdll, k_konst.m_hash_##namea))); mk_assert(g_app.m_funcs_ntdll.m_pfn_##namea); if(k_debug){ if(!g_app.m_funcs_ntdll.m_pfn_##namea){ my_MessageBoxA(0, "Could not find `" ## #namea ## "'.", 0, 0); } }
	mk_x_ntdll2_funcs()
	#undef x

	#define x(name) g_app.m_funcs_kernel.m_pfn_##name = ((tfn_##name)(find_proc(peb, g_app.m_dlls.m_kernel32, k_konst.m_hash_##name))); mk_assert(g_app.m_funcs_kernel.m_pfn_##name); if(k_debug){ if(!g_app.m_funcs_kernel.m_pfn_##name){ my_MessageBoxA(0, "Could not find `" #name "'.", 0, 0); } }
	mk_x_kernel_funcs()
	#undef x

	#define x(name) g_app.m_dlls.m_##name = g_app.m_funcs_kernel.m_pfn_LoadLibraryExA(nstr_to_nstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_##name)).m_buf, NULL, LOAD_LIBRARY_SEARCH_SYSTEM32); mk_assert(g_app.m_dlls.m_##name);
	mk_x_dlls_to_load()
	#undef x

	#define x(name) g_app.m_funcs_advapi.m_pfn_##name = ((tfn_##name)(find_proc(peb, g_app.m_dlls.m_advapi32, k_konst.m_hash_##name))); mk_assert(g_app.m_funcs_advapi.m_pfn_##name); if(k_debug){ if(!g_app.m_funcs_advapi.m_pfn_##name){ my_MessageBoxA(0, "Could not find `" #name "'.", 0, 0); } }
	mk_x_advapi_funcs()
	#undef x

	#define x(name) g_app.m_funcs_combase.m_pfn_##name = ((tfn_##name)(find_proc(peb, g_app.m_dlls.m_combase, k_konst.m_hash_##name))); mk_assert(g_app.m_funcs_combase.m_pfn_##name); if(k_debug){ if(!g_app.m_funcs_combase.m_pfn_##name){ my_MessageBoxA(0, "Could not find `" #name "'.", 0, 0); } }
	mk_x_combase_funcs()
	#undef x

	#define x(name) g_app.m_funcs_fw.m_pfn_##name = ((tfn_##name)(find_proc(peb, g_app.m_dlls.m_fwpuclnt, k_konst.m_hash_##name))); mk_assert(g_app.m_funcs_fw.m_pfn_##name); if(k_debug){ if(!g_app.m_funcs_fw.m_pfn_##name){ my_MessageBoxA(0, "Could not find `" #name "'.", 0, 0); } }
	mk_x_fw_funcs()
	#undef x

	#define x(name) g_app.m_funcs_user.m_pfn_##name = ((tfn_##name)(find_proc(peb, g_app.m_dlls.m_user32, k_konst.m_hash_##name))); mk_assert(g_app.m_funcs_user.m_pfn_##name); if(k_debug){ if(!g_app.m_funcs_user.m_pfn_##name){ my_MessageBoxA(0, "Could not find `" #name "'.", 0, 0); } }
	mk_x_user_funcs()
	#undef x

	#define x(name) g_app.m_funcs_comctl.m_pfn_##name = ((tfn_##name)(find_proc(peb, g_app.m_dlls.m_comctl32, k_konst.m_hash_##name))); mk_assert(g_app.m_funcs_comctl.m_pfn_##name); if(k_debug){ if(!g_app.m_funcs_comctl.m_pfn_##name){ my_MessageBoxA(0, "Could not find `" #name "'.", 0, 0); } }
	mk_x_comctl_funcs()
	#undef x

	#define x(name) g_app.m_funcs_comdlg.m_pfn_##name = ((tfn_##name)(find_proc(peb, g_app.m_dlls.m_comdlg32, k_konst.m_hash_##name))); mk_assert(g_app.m_funcs_comdlg.m_pfn_##name); if(k_debug){ if(!g_app.m_funcs_comdlg.m_pfn_##name){ my_MessageBoxA(0, "Could not find `" #name "'.", 0, 0); } }
	mk_x_comdlg_funcs()
	#undef x

	g_app.m_funcs_comctl.m_pfn_InitCommonControls();
	g_app.m_dlls.m_exe = g_app.m_funcs_kernel.m_pfn_GetModuleHandleW(NULL);

	mk_memclr_c(g_app.m_tmp_nstrs, sizeof(g_app.m_tmp_nstrs));
	mk_memclr_c(g_app.m_tmp_wstrs, sizeof(g_app.m_tmp_wstrs));
}

[[nodiscard]] static inline mk_view_wstr_t mk_guid_to_wstr_nice(GUID const* const guid)
{
	int n;
	int i;
	GUID const* ggg;
	mk_view_wstr_t wstr;

	if(guid)
	{
		n = std::size(k_konst.m_guids.m_guids);
		for(i = 0; i != n; ++i)
		{
			ggg = ((GUID*)(&k_konst.m_guids.m_guids[i]));
			auto const& view_a = c_arr_to_view(guid->Data4);
			auto const& view_b = c_arr_to_view(ggg->Data4);
			if(std::tie(guid->Data1, guid->Data2, guid->Data3, view_a) == std::tie(ggg->Data1, ggg->Data2, ggg->Data3, view_b))
			{
				break;
			}
		}
		if(i != n)
		{
			wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_FWPM_CALLOUT_BUILT_IN_RESERVED_1 + i));
		}
		else
		{
			wstr = mk_guid_to_wstr_raw(guid);
		}
	}
	else
	{
		wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_none));
	}
	mk_assert(wstr.m_len >= 0);
	mk_assert(wstr.m_buf[wstr.m_len] == L'\0');
	return wstr;
}

[[nodiscard]] static inline bool mk_guid_is_null(GUID const* const guid)
{
	GUID guid_null;
	bool eq;
	bool is;

	mk_assert(guid);

	mk_memclr_c(&guid_null, sizeof(guid_null));
	eq = mk_guid_eq(guid, &guid_null);
	is = eq;
	return is;
}

[[nodiscard]] static inline mk_view_wstr_t mk_guid_to_text_not_null(GUID const* const guid)
{
	mk_view_wstr_t wstr;

	mk_assert(guid);

	if(!mk_guid_is_null(guid))
	{
		wstr = mk_guid_to_wstr_nice(guid);
	}
	else
	{
		wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_empty));
	}
	mk_assert(wstr.m_len >= 0);
	mk_assert(wstr.m_buf[wstr.m_len] == L'\0');
	return wstr;
}

[[nodiscard]] static inline mk_view_wstr_t type_to_text(FWP_DATA_TYPE const type)
{
	int idx;
	int i;
	mk_view_wstr_t wstr;

	idx = 0;
	i = 0;
	#define x(name, value) \
	{ \
		if(type == name){ idx = i; } \
		++i; \
	}
	mk_x_types()
	#undef x
	if(idx != 0)
	{
		wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_FWP_EMPTY + idx));
	}
	else
	{
		wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_questions));
	}
	mk_assert(wstr.m_len >= 0);
	mk_assert(wstr.m_buf[wstr.m_len] == L'\0');
	return wstr;
}

[[nodiscard]] static inline mk_view_nstr_t value_to_nstr_uint8(UINT8 const u8)
{
	char* fmt;
	char* buf;
	int cap;
	int len;
	mk_view_nstr_t view;

	fmt = &g_app.m_tmp_nstrs[g_app.m_tmps_nstr_idx++ % _countof(g_app.m_tmp_nstrs)][0];
	buf = &g_app.m_tmp_nstrs[g_app.m_tmps_nstr_idx++ % _countof(g_app.m_tmp_nstrs)][0];
	cap = _countof(g_app.m_tmp_nstrs[0]);
	mk_memcpy_c(&fmt[0], k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_fmt_u8).m_buf, k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_fmt_u8).m_len);
	fmt[k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_fmt_u8).m_len] = '\0';
	len = g_app.m_funcs_ntdll.m_pfn__snprintf(buf, cap, fmt, ((int)(u8)), ((int)(u8))); mk_assert(len >= 1); mk_assert(len < cap);
	view.m_buf = buf;
	view.m_len = len;
	return view;
}

[[nodiscard]] static inline mk_view_nstr_t value_to_nstr_uint16(UINT16 const u16)
{
	char* fmt;
	char* buf;
	int cap;
	int len;
	mk_view_nstr_t view;

	fmt = &g_app.m_tmp_nstrs[g_app.m_tmps_nstr_idx++ % _countof(g_app.m_tmp_nstrs)][0];
	buf = &g_app.m_tmp_nstrs[g_app.m_tmps_nstr_idx++ % _countof(g_app.m_tmp_nstrs)][0];
	cap = _countof(g_app.m_tmp_nstrs[0]);
	mk_memcpy_c(&fmt[0], k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_fmt_u16).m_buf, k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_fmt_u16).m_len);
	fmt[k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_fmt_u16).m_len] = '\0';
	len = g_app.m_funcs_ntdll.m_pfn__snprintf(buf, cap, fmt, ((int)(u16)), ((int)(u16))); mk_assert(len >= 1); mk_assert(len < cap);
	buf[len] = '\0';
	view.m_buf = buf;
	view.m_len = len;
	mk_assert(view.m_len >= 0);
	mk_assert(view.m_buf[view.m_len] == '\0');
	return view;
}

[[nodiscard]] static inline mk_view_nstr_t value_to_nstr_uint32(UINT32 const u32)
{
	char* fmt;
	char* buf;
	int cap;
	int len;
	mk_view_nstr_t view;

	fmt = &g_app.m_tmp_nstrs[g_app.m_tmps_nstr_idx++ % _countof(g_app.m_tmp_nstrs)][0];
	buf = &g_app.m_tmp_nstrs[g_app.m_tmps_nstr_idx++ % _countof(g_app.m_tmp_nstrs)][0];
	cap = _countof(g_app.m_tmp_nstrs[0]);
	mk_memcpy_c(&fmt[0], k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_fmt_u32).m_buf, k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_fmt_u32).m_len);
	fmt[k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_fmt_u32).m_len] = '\0';
	len = g_app.m_funcs_ntdll.m_pfn__snprintf(buf, cap, fmt, *((unsigned int*)(&u32)), *((unsigned int*)(&u32))); mk_assert(len >= 1); mk_assert(len < cap);
	view.m_buf = buf;
	view.m_len = len;
	return view;
}

[[nodiscard]] static inline mk_view_nstr_t value_to_nstr_uint64(UINT64 const* const u64)
{
	char* fmt;
	char* buf;
	int cap;
	int len;
	mk_view_nstr_t view;

	mk_assert(u64);

	fmt = &g_app.m_tmp_nstrs[g_app.m_tmps_nstr_idx++ % _countof(g_app.m_tmp_nstrs)][0];
	buf = &g_app.m_tmp_nstrs[g_app.m_tmps_nstr_idx++ % _countof(g_app.m_tmp_nstrs)][0];
	cap = _countof(g_app.m_tmp_nstrs[0]);
	mk_memcpy_c(&fmt[0], k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_fmt_u64).m_buf, k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_fmt_u64).m_len);
	fmt[k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_fmt_u64).m_len] = '\0';
	len = g_app.m_funcs_ntdll.m_pfn__snprintf(buf, cap, fmt, *((unsigned long long*)(u64)), *((unsigned long long*)(u64))); mk_assert(len >= 1); mk_assert(len < cap);
	view.m_buf = buf;
	view.m_len = len;
	return view;
}

[[nodiscard]] static inline bool blob_is_text(FWP_BYTE_BLOB const* const blob)
{
	bool is;
	UINT32 n;
	UINT32 i;

	mk_assert(blob);

	is = true;
	is = is && (blob->size % 2 == 0);
	is = is && (blob->size >= 2);
	is = is && (((UINT_PTR)(blob->data)) % 2 == 0);
	is = is && (blob->data[blob->size - 2] == 0x00);
	is = is && (blob->data[blob->size - 1] == 0x00);
	if(is)
	{
		n = (blob->size / 2) - 1;
		for(i = 0; i != n; ++i)
		{
			is = is && (blob->data[i * 2 + 0] >= 0x20 && blob->data[i * 2 + 0] < 0x7f);
			is = is && (blob->data[i * 2 + 1] == 0x00);
		}
	}
	return is;
}

[[nodiscard]] static inline mk_view_wstr_t value_to_wstr_blob(FWP_BYTE_BLOB const* const blob)
{
	LPCWSTR buf;
	SIZE_T len;
	mk_view_wstr_t wstr;

	mk_assert(blob);

	if(blob_is_text(blob))
	{
		buf = ((LPCWSTR)(blob->data));
		len = blob->size / 2 - 1;
		wstr.m_buf = buf;
		wstr.m_len = len;
	}
	else
	{
		mk_assert(("todo", false));
		wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_questions));
	}
	mk_assert(wstr.m_len >= 0);
	mk_assert(wstr.m_buf[wstr.m_len] == L'\0');
	return wstr;
}

static inline void arr16_to_arr8(UINT8 const* const arr16, USHORT* const arr8)
{
	int n;
	int i;

	mk_assert(arr16);
	mk_assert(arr8);

	n = 8;
	for(i = 0; i != n; ++i)
	{
		arr8[i] =
			(((USHORT)(arr16[i * 2 + 0])) << (1 * CHAR_BIT)) |
			(((USHORT)(arr16[i * 2 + 1])) << (0 * CHAR_BIT)) |
			0;
	}
}

[[nodiscard]] static inline mk_view_nstr_t value_to_nstr_arr16(FWP_BYTE_ARRAY16 const* const arr16)
{
	char* fmt;
	char* buf;
	int cap;
	USHORT parts[8];
	int len;
	mk_view_nstr_t view;

	mk_assert(arr16);

	fmt = &g_app.m_tmp_nstrs[g_app.m_tmps_nstr_idx++ % _countof(g_app.m_tmp_nstrs)][0];
	buf = &g_app.m_tmp_nstrs[g_app.m_tmps_nstr_idx++ % _countof(g_app.m_tmp_nstrs)][0];
	cap = _countof(g_app.m_tmp_nstrs[0]);
	mk_memcpy_c(&fmt[0], k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_fmt_arr16).m_buf, k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_fmt_arr16).m_len);
	fmt[k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_fmt_arr16).m_len] = '\0';
	arr16_to_arr8(&arr16->byteArray16[0], &parts[0]);
	len = g_app.m_funcs_ntdll.m_pfn__snprintf(buf, cap, fmt, parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], parts[6], parts[7]); mk_assert(len >= 1); mk_assert(len < cap);
	view.m_buf = buf;
	view.m_len = len;
	return view;
}

[[nodiscard]] static inline mk_view_wstr_t value_to_wstr_sd(FWP_BYTE_BLOB const* const sd)
{
	BOOL b;
	LPWSTR win_buf;
	SIZE_T len;
	LPWSTR buf;
	mk_view_wstr_t wstr;

	mk_assert(sd);

	b = g_app.m_funcs_advapi.m_pfn_ConvertSecurityDescriptorToStringSecurityDescriptorW(((PSECURITY_DESCRIPTOR)(sd->data)), SDDL_REVISION_1, OWNER_SECURITY_INFORMATION  | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION, &win_buf, NULL); mk_assert(b);
	len = mk_wcslen_c(win_buf);
	mk_assert(len < _countof(g_app.m_tmp_wstrs[0]));
	buf = &g_app.m_tmp_wstrs[g_app.m_tmps_wstr_idx++ % _countof(g_app.m_tmp_wstrs)][0];
	mk_memcpy_c(&buf[0], win_buf, (len + 1) * sizeof(buf[0]));
	g_app.m_funcs_kernel.m_pfn_LocalFree(win_buf);
	wstr.m_buf = buf;
	wstr.m_len = len;
	mk_assert(wstr.m_len >= 0);
	mk_assert(wstr.m_buf[wstr.m_len] == L'\0');
	return wstr;
}

[[nodiscard]] static inline mk_view_wstr_t value_to_wstr_sid(SID const* const sid)
{
	BOOL b;
	LPWSTR txt_sid;
	LPWSTR buf;
	SIZE_T len;
	LPWSTR ptr;
	HLOCAL hloc;
	mk_view_wstr_t wstr;

	mk_assert(sid);

	b = g_app.m_funcs_advapi.m_pfn_ConvertSidToStringSidW(((PSID)(sid)), &txt_sid); mk_assert(b);
	buf = &g_app.m_tmp_wstrs[g_app.m_tmps_wstr_idx++ % _countof(g_app.m_tmp_wstrs)][0];
	len = mk_wcslen_c(txt_sid);
	ptr = mk_memcpy(buf, txt_sid, len + 1); ((void)(ptr));
	hloc = g_app.m_funcs_kernel.m_pfn_LocalFree(txt_sid); mk_assert(!hloc);
	wstr.m_buf = buf;
	wstr.m_len = len;
	mk_assert(wstr.m_len >= 0);
	mk_assert(wstr.m_buf[wstr.m_len] == L'\0');
	return wstr;
}

[[nodiscard]] static inline mk_view_wstr_t value_to_wstr_value(FWP_VALUE0 const* const value)
{
	mk_view_wstr_t wstr;

	mk_assert(value);

	switch(value->type)
	{
		case FWP_EMPTY            : wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_empty)); break;
		case FWP_UINT8            : wstr = nstr_to_wstr(value_to_nstr_uint8(value->uint8));                 break;
		case FWP_UINT16           : wstr = nstr_to_wstr(value_to_nstr_uint16(value->uint16));               break;
		case FWP_UINT32           : wstr = nstr_to_wstr(value_to_nstr_uint32(value->uint32));               break;
		case FWP_UINT64           : wstr = nstr_to_wstr(value_to_nstr_uint64(value->uint64));               break;
		case FWP_BYTE_ARRAY16_TYPE: wstr = nstr_to_wstr(value_to_nstr_arr16(value->byteArray16));           break;
		default                   : wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_questions)); mk_assert(("todo", false)); break;
	}
	mk_assert(wstr.m_len >= 0);
	mk_assert(wstr.m_buf[wstr.m_len] == L'\0');
	return wstr;
}

[[nodiscard]] static inline mk_view_wstr_t value_to_wstr_range(FWP_RANGE0 const* const range)
{
	mk_view_wstr_t lo_wstr;
	mk_view_wstr_t hi_wstr;
	mk_view_wstr_t txt_from;
	mk_view_wstr_t txt_to;
	LPWSTR buf;
	LPWSTR ptr;
	SIZE_T len;
	mk_view_wstr_t wstr;

	mk_assert(range);

	lo_wstr = value_to_wstr_value(&range->valueLow);
	hi_wstr = value_to_wstr_value(&range->valueHigh);
	txt_from = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_range_from));
	txt_to = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_range_to));
	buf = &g_app.m_tmp_wstrs[g_app.m_tmps_wstr_idx++ % _countof(g_app.m_tmp_wstrs)][0];
	ptr = buf;
	ptr = mk_memcpy(ptr, txt_from);
	ptr = mk_memcpy(ptr, lo_wstr);
	ptr = mk_memcpy(ptr, txt_to);
	ptr = mk_memcpy(ptr, hi_wstr);
	len = ptr - buf;
	buf[len] = L'\0';
	wstr.m_buf = buf;
	wstr.m_len = len;
	mk_assert(wstr.m_len >= 0);
	mk_assert(wstr.m_buf[wstr.m_len] == L'\0');
	return wstr;
}

[[nodiscard]] static inline mk_view_wstr_t condition_value_to_text(FWP_CONDITION_VALUE0 const* const value)
{
	mk_view_wstr_t wstr;

	switch(value->type)
	{
		case FWP_UINT8                   : wstr = nstr_to_wstr(value_to_nstr_uint8(value->uint8));       break;
		case FWP_UINT16                  : wstr = nstr_to_wstr(value_to_nstr_uint16(value->uint16));     break;
		case FWP_UINT32                  : wstr = nstr_to_wstr(value_to_nstr_uint32(value->uint32));     break;
		case FWP_UINT64                  : wstr = nstr_to_wstr(value_to_nstr_uint64(value->uint64));     break;
		case FWP_BYTE_ARRAY16_TYPE       : wstr = nstr_to_wstr(value_to_nstr_arr16(value->byteArray16)); break;
		case FWP_BYTE_BLOB_TYPE          : wstr = value_to_wstr_blob(value->byteBlob);                   break;
		case FWP_SID                     : wstr = value_to_wstr_sid(value->sid);                         break;
		case FWP_SECURITY_DESCRIPTOR_TYPE: wstr = value_to_wstr_sd(value->sd);                           break;
		case FWP_RANGE_TYPE              : wstr = value_to_wstr_range(value->rangeValue);                break;
		default                          : wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_questions)); mk_assert(("todo", false)); break;
	}
	mk_assert(wstr.m_len >= 0);
	mk_assert(wstr.m_buf[wstr.m_len] == L'\0');
	return wstr;
}

[[nodiscard]] static inline mk_view_wstr_t mk_match_type_to_wstr(FWP_MATCH_TYPE const match_type)
{
	int idx;
	mk_view_wstr_t wstr;

	idx = ((int)(match_type));
	if(idx >= 0 && idx < matches_get_count_v)
	{
		wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_FWP_MATCH_EQUAL + idx));
	}
	else
	{
		wstr = nstr_to_wstr(value_to_nstr_uint8(((UINT8)(match_type))));
	}
	mk_assert(wstr.m_len >= 0);
	mk_assert(wstr.m_buf[wstr.m_len] == L'\0');
	return wstr;
}

[[nodiscard]] static inline mk_view_nstr_t action_type_to_nstr(FWP_ACTION_TYPE const action_type)
{
	int idx;
	int i;
	mk_view_nstr_t nstr;

	idx = -1;
	i = 0;
	#define x(name, value, str) \
	{ \
		if(action_type == value){ idx = i; } \
		++i; \
	}
	mk_x_action_types()
	#undef x
	if(idx != -1)
	{
		nstr = nstr_to_nstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_FWP_ACTION_BLOCK_ + idx));
	}
	else
	{
		nstr = value_to_nstr_uint32(action_type);
	}
	mk_assert(nstr.m_len >= 1);
	mk_assert(nstr.m_buf[nstr.m_len] == '\0');
	return nstr;
}

[[nodiscard]] static inline mk_view_wstr_t action_type_to_wstr(FWP_ACTION_TYPE const action_type)
{
	return nstr_to_wstr(action_type_to_nstr(action_type));
}

[[nodiscard]] static inline mk_view_wstr_t entry_to_wstr(FWPM_FILTER0 const* const entry, mk_col_id_entry_t const col_id)
{
	mk_view_wstr_t wstr;

	mk_assert(entry);
	mk_assert(col_id >= 0);
	mk_assert(col_id < mk_col_id_entry_e_dummy_end);

	switch(col_id)
	{
		case mk_col_id_entry_e_filter          : wstr = mk_guid_to_wstr_nice(&entry->filterKey)              ; break;
		case mk_col_id_entry_e_name            : wstr = wstr_to_wstr(entry->displayData.name)                ; break;
		case mk_col_id_entry_e_description     : wstr = wstr_to_wstr(entry->displayData.description)         ; break;
		case mk_col_id_entry_e_provider        : wstr = mk_guid_to_wstr_nice(entry->providerKey)             ; break;
		case mk_col_id_entry_e_layer           : wstr = mk_guid_to_wstr_nice(&entry->layerKey)               ; break;
		case mk_col_id_entry_e_sub_layer       : wstr = mk_guid_to_wstr_nice(&entry->subLayerKey)            ; break;
		case mk_col_id_entry_e_action          : wstr = action_type_to_wstr(entry->action.type)              ; break;
		case mk_col_id_entry_e_callout         : wstr = mk_guid_to_text_not_null(&entry->action.calloutKey)  ; break;
		case mk_col_id_entry_e_id              : wstr = nstr_to_wstr(value_to_nstr_uint64(&entry->filterId)) ; break;
		case mk_col_id_entry_e_weight          : wstr = value_to_wstr_value(&entry->weight)                  ; break;
		case mk_col_id_entry_e_effective_weight: wstr = value_to_wstr_value(&entry->effectiveWeight)         ; break;
		case mk_col_id_entry_e_dummy_end: mk_assert(false); break;
		default: mk_assert(false); break;
	}
	mk_assert(wstr.m_len >= 0);
	mk_assert(wstr.m_buf[wstr.m_len] == L'\0');
	return wstr;
}

[[nodiscard]] static inline mk_view_wstr_t entry_to_wstr_line(FWPM_FILTER0 const* const filter)
{
	int cap;
	LPWSTR buf;
	int len;
	int n;
	int i;
	mk_col_id_entry_t col_id;
	mk_view_wstr_t wstr;
	LPWSTR ptr;

	mk_assert(filter);

	cap = 4 * 1024;
	buf = ((LPWSTR)(g_app.m_funcs_kernel.m_pfn_HeapAlloc(g_app.m_funcs_kernel.m_pfn_GetProcessHeap(), 0, cap))); mk_assert(buf);
	len = 0;
	n = mk_col_id_entry_e_dummy_end;
	for(i = 0; i != n; ++i)
	{
		col_id = ((mk_col_id_entry_t)(i));
		wstr = entry_to_wstr(filter, col_id);
		if(len + ((int)(wstr.m_len)) + 32 > cap)
		{
			while(len + ((int)(wstr.m_len)) + 32 > cap){ cap *= 2; }
			buf = ((LPWSTR)(g_app.m_funcs_kernel.m_pfn_HeapReAlloc(g_app.m_funcs_kernel.m_pfn_GetProcessHeap(), 0, buf, cap))); mk_assert(buf);
		}
		ptr = mk_memcpy(buf + len, wstr); ((void)(ptr));
		len += ((int)(((int)(wstr.m_len))));
		wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_tab));
		mk_assert(len + ((int)(wstr.m_len)) < cap);
		ptr = mk_memcpy(buf + len, wstr); ((void)(ptr));
		len += ((int)(wstr.m_len));
	}
	buf[len] = L'\0';
	wstr.m_buf = buf;
	wstr.m_len = len;
	mk_assert(wstr.m_len >= 0);
	mk_assert(wstr.m_buf[wstr.m_len] == L'\0');
	return wstr;
}

[[nodiscard]] static inline mk_view_wstr_t condition_entry_to_wstr_filed(FWPM_FILTER0 const* const filter, FWPM_FILTER_CONDITION0 const* const condition)
{
	mk_view_wstr_t wstr;

	mk_assert(filter);
	mk_assert(condition);

	wstr = mk_guid_to_wstr_nice(&condition->fieldKey);
	mk_assert(wstr.m_len >= 0);
	mk_assert(wstr.m_buf[wstr.m_len] == L'\0');
	return wstr;
}

[[nodiscard]] static inline mk_view_wstr_t condition_entry_to_wstr_match_type(FWPM_FILTER0 const* const filter, FWPM_FILTER_CONDITION0 const* const condition)
{
	mk_view_wstr_t wstr;

	mk_assert(filter);
	mk_assert(condition);

	wstr = mk_match_type_to_wstr(condition->matchType);
	mk_assert(wstr.m_len >= 0);
	mk_assert(wstr.m_buf[wstr.m_len] == L'\0');
	return wstr;
}

[[nodiscard]] static inline mk_view_wstr_t condition_entry_to_wstr_value_type(FWPM_FILTER0 const* const filter, FWPM_FILTER_CONDITION0 const* const condition)
{
	mk_view_wstr_t wstr;

	mk_assert(filter);
	mk_assert(condition);

	wstr = type_to_text(condition->conditionValue.type);
	mk_assert(wstr.m_len >= 0);
	mk_assert(wstr.m_buf[wstr.m_len] == L'\0');
	return wstr;
}

[[nodiscard]] static inline mk_view_wstr_t condition_entry_to_wstr_value_data(FWPM_FILTER0 const* const filter, FWPM_FILTER_CONDITION0 const* const condition)
{
	mk_view_wstr_t wstr;

	mk_assert(filter);
	mk_assert(condition);

	wstr = condition_value_to_text(&condition->conditionValue);
	mk_assert(wstr.m_len >= 0);
	mk_assert(wstr.m_buf[wstr.m_len] == L'\0');
	return wstr;
}

static inline void u32_to_arr4(UINT32 const u32, unsigned char* const arr4)
{
	int n;
	int i;

	mk_assert(arr4);

	n = 4;
	for(i = 0; i != n; ++i)
	{
		arr4[(n - 1) - i] = ((unsigned char)((u32 >> (i * CHAR_BIT)) & 0xff));
	}
}

[[nodiscard]] static inline mk_view_nstr_t ip_address_v4_to_nstr(UINT32 const u32)
{
	char* fmt;
	char* buf;
	int cap;
	unsigned char parts[4];
	int len;
	mk_view_nstr_t nstr;

	fmt = &g_app.m_tmp_nstrs[g_app.m_tmps_nstr_idx++ % _countof(g_app.m_tmp_nstrs)][0];
	buf = &g_app.m_tmp_nstrs[g_app.m_tmps_nstr_idx++ % _countof(g_app.m_tmp_nstrs)][0];
	cap = _countof(g_app.m_tmp_nstrs[0]);
	mk_memcpy_c(&fmt[0], k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_fmt_ipv4).m_buf, k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_fmt_ipv4).m_len);
	fmt[k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_fmt_ipv4).m_len] = '\0';
	u32_to_arr4(u32, &parts[0]);
	len = g_app.m_funcs_ntdll.m_pfn__snprintf(buf, cap, fmt, parts[0], parts[1], parts[2], parts[3]); mk_assert(len >= 1); mk_assert(len < cap);
	nstr.m_buf = buf;
	nstr.m_len = len;
	mk_assert(nstr.m_len >= 0);
	mk_assert(nstr.m_buf[nstr.m_len] == '\0');
	return nstr;
}

[[nodiscard]] static inline mk_view_nstr_t ip_address_v6_range_to_nstr(FWP_CONDITION_VALUE0 const* const range)
{
	int same_bits;
	int n;
	int i;
	int m;
	int j;
	char* fmt;
	char* buf;
	int cap;
	USHORT parts[8];
	int len;
	mk_view_nstr_t nstr;

	mk_assert(range);

	same_bits = 0;
	n = 16;
	for(i = 0; i != n; ++i)
	{
		if(range->rangeValue->valueLow.byteArray16->byteArray16[i] == range->rangeValue->valueHigh.byteArray16->byteArray16[i])
		{
			same_bits += CHAR_BIT;
		}
		else
		{
			break;
		}
	}
	m = CHAR_BIT;
	for(j = 0; j != m; ++j)
	{
		if
		(
			(range->rangeValue->valueLow .byteArray16->byteArray16[i] & (1u << ((CHAR_BIT - 1) - j))) ==
			(range->rangeValue->valueHigh.byteArray16->byteArray16[i] & (1u << ((CHAR_BIT - 1) - j)))
		)
		{
			++same_bits;
		}
		else
		{
			break;
		}
	}
	/* todo this is incomplete */
	if(false){}
	else if(same_bits > 16 && same_bits <= 32)
	{
		fmt = &g_app.m_tmp_nstrs[g_app.m_tmps_nstr_idx++ % _countof(g_app.m_tmp_nstrs)][0];
		buf = &g_app.m_tmp_nstrs[g_app.m_tmps_nstr_idx++ % _countof(g_app.m_tmp_nstrs)][0];
		cap = _countof(g_app.m_tmp_nstrs[0]);
		mk_memcpy_c(&fmt[0], k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_fmt_ipv6_mask_32).m_buf, k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_fmt_ipv6_mask_32).m_len);
		fmt[k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_fmt_ipv6_mask_32).m_len] = '\0';
		arr16_to_arr8(&range->rangeValue->valueHigh.byteArray16->byteArray16[0], &parts[0]);
		len = g_app.m_funcs_ntdll.m_pfn__snprintf(buf, cap, fmt, parts[0], parts[1], same_bits); mk_assert(len >= 1); mk_assert(len < cap);
		nstr.m_buf = buf;
		nstr.m_len = len;
	}
	else if(same_bits > 32 && same_bits <= 48)
	{
		fmt = &g_app.m_tmp_nstrs[g_app.m_tmps_nstr_idx++ % _countof(g_app.m_tmp_nstrs)][0];
		buf = &g_app.m_tmp_nstrs[g_app.m_tmps_nstr_idx++ % _countof(g_app.m_tmp_nstrs)][0];
		cap = _countof(g_app.m_tmp_nstrs[0]);
		mk_memcpy_c(&fmt[0], k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_fmt_ipv6_mask_48).m_buf, k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_fmt_ipv6_mask_48).m_len);
		fmt[k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_fmt_ipv6_mask_48).m_len] = '\0';
		arr16_to_arr8(&range->rangeValue->valueLow.byteArray16->byteArray16[0], &parts[0]);
		parts[2] &= (((1u << (same_bits - 32)) - 1) << (16 - (same_bits - 32)));
		len = g_app.m_funcs_ntdll.m_pfn__snprintf(buf, cap, fmt, parts[0], parts[1], parts[2], same_bits); mk_assert(len >= 1); mk_assert(len < cap);
		nstr.m_buf = buf;
		nstr.m_len = len;
	}
	else if(same_bits > 112 && same_bits <= 128)
	{
		fmt = &g_app.m_tmp_nstrs[g_app.m_tmps_nstr_idx++ % _countof(g_app.m_tmp_nstrs)][0];
		buf = &g_app.m_tmp_nstrs[g_app.m_tmps_nstr_idx++ % _countof(g_app.m_tmp_nstrs)][0];
		cap = _countof(g_app.m_tmp_nstrs[0]);
		mk_memcpy_c(&fmt[0], k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_fmt_ipv6_mask_128).m_buf, k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_fmt_ipv6_mask_128).m_len);
		fmt[k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_fmt_ipv6_mask_128).m_len] = '\0';
		arr16_to_arr8(&range->rangeValue->valueLow.byteArray16->byteArray16[0], &parts[0]);
		parts[7] &= (((1u << (same_bits - 112)) - 1) << (16 - (same_bits - 112)));
		len = g_app.m_funcs_ntdll.m_pfn__snprintf(buf, cap, fmt, parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], parts[6], parts[7], same_bits); mk_assert(len >= 1); mk_assert(len < cap);
		nstr.m_buf = buf;
		nstr.m_len = len;
	}
	else
	{
		nstr = nstr_to_nstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_empty));
	}
	mk_assert(nstr.m_len >= 0);
	mk_assert(nstr.m_buf[nstr.m_len] == '\0');
	return nstr;
}

[[nodiscard]] static inline mk_view_nstr_t ip_address_v4_range_to_nstr(FWP_CONDITION_VALUE0 const* const range)
{
	int same_bits;
	int n;
	int i;
	char* buf;
	int cap;
	mk_view_nstr_t fmt;
	unsigned char parts_a[4];
	unsigned char parts_b[4];
	unsigned char parts_c[4];
	unsigned char parts_d[4];
	unsigned char mask;
	int len;
	mk_view_nstr_t nstr;

	mk_assert(range);

	same_bits = 0;
	n = 32;
	for(i = 0; i != n; ++i)
	{
		if
		(
			(range->rangeValue->valueLow .uint32 & (((UINT32)(1u)) << ((32 - 1) - i))) ==
			(range->rangeValue->valueHigh.uint32 & (((UINT32)(1u)) << ((32 - 1) - i)))
		)
		{
			++same_bits;
		}
		else
		{
			break;
		}
	}
	if(false){}
	else if(same_bits == 0)
	{
		nstr = nstr_to_nstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_every_ipv4));
		buf = &g_app.m_tmp_nstrs[g_app.m_tmps_nstr_idx++ % _countof(g_app.m_tmp_nstrs)][0];
		cap = _countof(g_app.m_tmp_nstrs[0]);
		fmt = nstr_to_nstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_fmt_ipv4_mask_08));
		u32_to_arr4(range->rangeValue->valueLow .uint32, &parts_c[0]);
		u32_to_arr4(range->rangeValue->valueHigh.uint32, &parts_d[0]);
		len = g_app.m_funcs_ntdll.m_pfn__snprintf(buf, cap, fmt.m_buf, parts_c[0], parts_c[1], parts_c[2], parts_c[3], parts_d[0], parts_d[1], parts_d[2], parts_d[3]); mk_assert(len >= 1); mk_assert(len < cap);
		nstr.m_buf = buf;
		nstr.m_len = len;
	}
	else if(same_bits > 0 && same_bits <= 8)
	{
		buf = &g_app.m_tmp_nstrs[g_app.m_tmps_nstr_idx++ % _countof(g_app.m_tmp_nstrs)][0];
		cap = _countof(g_app.m_tmp_nstrs[0]);
		fmt = nstr_to_nstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_fmt_ipv4_mask_08));
		u32_to_arr4(range->rangeValue->valueHigh.uint32, &parts_a[0]);
		u32_to_arr4(range->rangeValue->valueLow .uint32, &parts_c[0]);
		u32_to_arr4(range->rangeValue->valueHigh.uint32, &parts_d[0]);
		parts_b[0] = parts_a[0]; parts_b[1] = parts_a[1]; parts_b[2] = parts_a[2]; parts_b[3] = parts_a[3];
		mask = (((1u << (same_bits - 0)) - 1) << (CHAR_BIT - (same_bits - 0)));
		parts_a[0] &= mask;
		parts_a[1] = 0x00;
		parts_a[2] = 0x00;
		parts_a[3] = 0x00;
		parts_b[0] |=~ mask;
		parts_b[1] = 0xff;
		parts_b[2] = 0xff;
		parts_b[3] = 0xff;
		len = g_app.m_funcs_ntdll.m_pfn__snprintf(buf, cap, fmt.m_buf, parts_c[0], parts_c[1], parts_c[2], parts_c[3], parts_d[0], parts_d[1], parts_d[2], parts_d[3]); mk_assert(len >= 1); mk_assert(len < cap);
		nstr.m_buf = buf;
		nstr.m_len = len;
	}
	else if(same_bits > 8 && same_bits <= 16)
	{
		buf = &g_app.m_tmp_nstrs[g_app.m_tmps_nstr_idx++ % _countof(g_app.m_tmp_nstrs)][0];
		cap = _countof(g_app.m_tmp_nstrs[0]);
		fmt = nstr_to_nstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_fmt_ipv4_mask_16));
		u32_to_arr4(range->rangeValue->valueHigh.uint32, &parts_a[0]);
		u32_to_arr4(range->rangeValue->valueLow .uint32, &parts_c[0]);
		u32_to_arr4(range->rangeValue->valueHigh.uint32, &parts_d[0]);
		parts_b[0] = parts_a[0]; parts_b[1] = parts_a[1]; parts_b[2] = parts_a[2]; parts_b[3] = parts_a[3];
		mask = (((1u << (same_bits - 8)) - 1) << (CHAR_BIT - (same_bits - 8)));
		parts_a[1] &= mask;
		parts_a[2] = 0x00;
		parts_a[3] = 0x00;
		parts_b[1] |=~ mask;
		parts_b[2] = 0xff;
		parts_b[3] = 0xff;
		len = g_app.m_funcs_ntdll.m_pfn__snprintf(buf, cap, fmt.m_buf, parts_c[0], parts_c[1], parts_c[2], parts_c[3], parts_d[0], parts_d[1], parts_d[2], parts_d[3]); mk_assert(len >= 1); mk_assert(len < cap);
		nstr.m_buf = buf;
		nstr.m_len = len;
	}
	else if(same_bits > 16 && same_bits <= 24)
	{
		buf = &g_app.m_tmp_nstrs[g_app.m_tmps_nstr_idx++ % _countof(g_app.m_tmp_nstrs)][0];
		cap = _countof(g_app.m_tmp_nstrs[0]);
		fmt = nstr_to_nstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_fmt_ipv4_mask_24));
		u32_to_arr4(range->rangeValue->valueHigh.uint32, &parts_a[0]);
		u32_to_arr4(range->rangeValue->valueLow .uint32, &parts_c[0]);
		u32_to_arr4(range->rangeValue->valueHigh.uint32, &parts_d[0]);
		parts_b[0] = parts_a[0]; parts_b[1] = parts_a[1]; parts_b[2] = parts_a[2]; parts_b[3] = parts_a[3];
		mask = (((1u << (same_bits - 16)) - 1) << (CHAR_BIT - (same_bits - 16)));
		parts_a[2] &= mask;
		parts_a[3] = 0x00;
		parts_b[2] |=~ mask;
		parts_b[3] = 0xff;
		len = g_app.m_funcs_ntdll.m_pfn__snprintf(buf, cap, fmt.m_buf, parts_c[0], parts_c[1], parts_c[2], parts_c[3], parts_d[0], parts_d[1], parts_d[2], parts_d[3]); mk_assert(len >= 1); mk_assert(len < cap);
		nstr.m_buf = buf;
		nstr.m_len = len;
	}
	else if(same_bits > 24 && same_bits <= 32)
	{
		buf = &g_app.m_tmp_nstrs[g_app.m_tmps_nstr_idx++ % _countof(g_app.m_tmp_nstrs)][0];
		cap = _countof(g_app.m_tmp_nstrs[0]);
		fmt = nstr_to_nstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_fmt_ipv4_mask_32));
		u32_to_arr4(range->rangeValue->valueHigh.uint32, &parts_a[0]);
		u32_to_arr4(range->rangeValue->valueLow .uint32, &parts_c[0]);
		u32_to_arr4(range->rangeValue->valueHigh.uint32, &parts_d[0]);
		parts_b[0] = parts_a[0]; parts_b[1] = parts_a[1]; parts_b[2] = parts_a[2]; parts_b[3] = parts_a[3];
		mask = (((1u << (same_bits - 24)) - 1) << (CHAR_BIT - (same_bits - 24)));
		parts_a[3] &= mask;
		parts_b[3] |=~ mask;
		len = g_app.m_funcs_ntdll.m_pfn__snprintf(buf, cap, fmt.m_buf, parts_c[0], parts_c[1], parts_c[2], parts_c[3], parts_d[0], parts_d[1], parts_d[2], parts_d[3]); mk_assert(len >= 1); mk_assert(len < cap);
		nstr.m_buf = buf;
		nstr.m_len = len;
	}
	else
	{
		nstr = nstr_to_nstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_empty));
	}
	mk_assert(nstr.m_len >= 0);
	mk_assert(nstr.m_buf[nstr.m_len] == '\0');
	return nstr;
}

[[nodiscard]] static inline mk_view_wstr_t condition_entry_to_wstr_note(FWPM_FILTER0 const* const filter, FWPM_FILTER_CONDITION0 const* const condition)
{
	mk_view_wstr_t wstr;

	mk_assert(filter);
	mk_assert(condition);

	wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_empty));
	if(false){}
	else if((mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_PROTOCOL])) && (condition->conditionValue.type == FWP_UINT8) && (condition->conditionValue.uint8 ==   1)){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_protocol_icmpv4)     ); }
	else if((mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_PROTOCOL])) && (condition->conditionValue.type == FWP_UINT8) && (condition->conditionValue.uint8 ==   2)){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_protocol_igmp)       ); }
	else if((mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_PROTOCOL])) && (condition->conditionValue.type == FWP_UINT8) && (condition->conditionValue.uint8 ==   6)){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_protocol_tcp)        ); }
	else if((mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_PROTOCOL])) && (condition->conditionValue.type == FWP_UINT8) && (condition->conditionValue.uint8 ==  17)){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_protocol_udp)        ); }
	else if((mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_PROTOCOL])) && (condition->conditionValue.type == FWP_UINT8) && (condition->conditionValue.uint8 ==  41)){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_protocol_ipv6generic)); }
	else if((mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_PROTOCOL])) && (condition->conditionValue.type == FWP_UINT8) && (condition->conditionValue.uint8 ==  43)){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_protocol_ipv6route)  ); }
	else if((mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_PROTOCOL])) && (condition->conditionValue.type == FWP_UINT8) && (condition->conditionValue.uint8 ==  44)){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_protocol_ipv6frag)   ); }
	else if((mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_PROTOCOL])) && (condition->conditionValue.type == FWP_UINT8) && (condition->conditionValue.uint8 ==  47)){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_protocol_gre)        ); }
	else if((mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_PROTOCOL])) && (condition->conditionValue.type == FWP_UINT8) && (condition->conditionValue.uint8 ==  58)){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_protocol_icmpv6)     ); }
	else if((mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_PROTOCOL])) && (condition->conditionValue.type == FWP_UINT8) && (condition->conditionValue.uint8 ==  59)){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_protocol_ipv6nonxt)  ); }
	else if((mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_PROTOCOL])) && (condition->conditionValue.type == FWP_UINT8) && (condition->conditionValue.uint8 ==  60)){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_protocol_ipv6opts)   ); }
	else if((mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_PROTOCOL])) && (condition->conditionValue.type == FWP_UINT8) && (condition->conditionValue.uint8 == 112)){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_protocol_vrrp)       ); }
	else if((mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_PROTOCOL])) && (condition->conditionValue.type == FWP_UINT8) && (condition->conditionValue.uint8 == 113)){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_protocol_pgm)        ); }
	else if((mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_PROTOCOL])) && (condition->conditionValue.type == FWP_UINT8) && (condition->conditionValue.uint8 == 115)){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_protocol_l2tp)       ); }
	else if((mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_REMOTE_ADDRESS])) && (condition->conditionValue.type == FWP_UINT32)){ wstr = nstr_to_wstr(ip_address_v4_to_nstr(condition->conditionValue.uint32)); }
	else if((mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_REMOTE_ADDRESS])) && (condition->conditionValue.type == FWP_RANGE_TYPE) && (condition->conditionValue.rangeValue->valueLow.type == FWP_BYTE_ARRAY16_TYPE) && (condition->conditionValue.rangeValue->valueHigh.type == FWP_BYTE_ARRAY16_TYPE)){ wstr = nstr_to_wstr(ip_address_v6_range_to_nstr(&condition->conditionValue)); }
	else if((mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_REMOTE_ADDRESS])) && (condition->conditionValue.type == FWP_RANGE_TYPE) && (condition->conditionValue.rangeValue->valueLow.type == FWP_UINT32) && (condition->conditionValue.rangeValue->valueHigh.type == FWP_UINT32)){ wstr = nstr_to_wstr(ip_address_v4_range_to_nstr(&condition->conditionValue)); }

	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_CONNECT_V4    ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ORIGINAL_ICMP_TYPE])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v4_e_packet_too_big         )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_packet_too_big)         ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ORIGINAL_ICMP_TYPE])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v4_e_packet_too_big         )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_packet_too_big)         ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_INBOUND_ICMP_ERROR_V4  ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_LOCAL_PORT     ])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v4_e_packet_too_big         )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_packet_too_big)         ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_OUTBOUND_ICMP_ERROR_V4 ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_LOCAL_PORT     ])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v4_e_packet_too_big         )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_packet_too_big)         ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_CONNECT_V4    ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ORIGINAL_ICMP_TYPE])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v4_e_destination_unreachable)){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_destination_unreachable)); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ORIGINAL_ICMP_TYPE])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v4_e_destination_unreachable)){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_destination_unreachable)); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_INBOUND_ICMP_ERROR_V4  ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_LOCAL_PORT     ])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v4_e_destination_unreachable)){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_destination_unreachable)); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_OUTBOUND_ICMP_ERROR_V4 ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_LOCAL_PORT     ])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v4_e_destination_unreachable)){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_destination_unreachable)); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_CONNECT_V4    ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ORIGINAL_ICMP_TYPE])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v4_e_source_quench          )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_source_quench)          ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ORIGINAL_ICMP_TYPE])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v4_e_source_quench          )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_source_quench)          ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_INBOUND_ICMP_ERROR_V4  ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_LOCAL_PORT     ])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v4_e_source_quench          )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_source_quench)          ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_OUTBOUND_ICMP_ERROR_V4 ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_LOCAL_PORT     ])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v4_e_source_quench          )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_source_quench)          ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_CONNECT_V4    ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ORIGINAL_ICMP_TYPE])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v4_e_redirect               )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_redirect)               ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ORIGINAL_ICMP_TYPE])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v4_e_redirect               )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_redirect)               ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_INBOUND_ICMP_ERROR_V4  ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_LOCAL_PORT     ])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v4_e_redirect               )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_redirect)               ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_OUTBOUND_ICMP_ERROR_V4 ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_LOCAL_PORT     ])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v4_e_redirect               )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_redirect)               ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_CONNECT_V4    ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ORIGINAL_ICMP_TYPE])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v4_e_echo_request           )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_echo_request)           ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ORIGINAL_ICMP_TYPE])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v4_e_echo_request           )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_echo_request)           ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_INBOUND_ICMP_ERROR_V4  ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_LOCAL_PORT     ])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v4_e_echo_request           )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_echo_request)           ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_OUTBOUND_ICMP_ERROR_V4 ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_LOCAL_PORT     ])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v4_e_echo_request           )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_echo_request)           ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_CONNECT_V4    ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ORIGINAL_ICMP_TYPE])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v4_e_router_advertisement   )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_router_advertisement)   ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ORIGINAL_ICMP_TYPE])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v4_e_router_advertisement   )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_router_advertisement)   ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_INBOUND_ICMP_ERROR_V4  ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_LOCAL_PORT     ])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v4_e_router_advertisement   )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_router_advertisement)   ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_OUTBOUND_ICMP_ERROR_V4 ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_LOCAL_PORT     ])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v4_e_router_advertisement   )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_router_advertisement)   ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_CONNECT_V4    ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ORIGINAL_ICMP_TYPE])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v4_e_router_solicitation    )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_router_solicitation)    ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ORIGINAL_ICMP_TYPE])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v4_e_router_solicitation    )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_router_solicitation)    ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_INBOUND_ICMP_ERROR_V4  ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_LOCAL_PORT     ])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v4_e_router_solicitation    )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_router_solicitation)    ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_OUTBOUND_ICMP_ERROR_V4 ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_LOCAL_PORT     ])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v4_e_router_solicitation    )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_router_solicitation)    ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_CONNECT_V4    ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ORIGINAL_ICMP_TYPE])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v4_e_time_exceeded          )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_time_exceeded)          ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ORIGINAL_ICMP_TYPE])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v4_e_time_exceeded          )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_time_exceeded)          ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_INBOUND_ICMP_ERROR_V4  ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_LOCAL_PORT     ])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v4_e_time_exceeded          )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_time_exceeded)          ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_OUTBOUND_ICMP_ERROR_V4 ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_LOCAL_PORT     ])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v4_e_time_exceeded          )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_time_exceeded)          ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_CONNECT_V4    ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ORIGINAL_ICMP_TYPE])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v4_e_parameter_problem      )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_parameter_problem)      ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ORIGINAL_ICMP_TYPE])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v4_e_parameter_problem      )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_parameter_problem)      ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_INBOUND_ICMP_ERROR_V4  ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_LOCAL_PORT     ])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v4_e_parameter_problem      )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_parameter_problem)      ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_OUTBOUND_ICMP_ERROR_V4 ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_LOCAL_PORT     ])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v4_e_parameter_problem      )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_parameter_problem)      ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_CONNECT_V4    ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ORIGINAL_ICMP_TYPE])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v4_e_timestamp_request      )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_timestamp_request)      ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ORIGINAL_ICMP_TYPE])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v4_e_timestamp_request      )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_timestamp_request)      ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_INBOUND_ICMP_ERROR_V4  ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_LOCAL_PORT     ])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v4_e_timestamp_request      )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_timestamp_request)      ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_OUTBOUND_ICMP_ERROR_V4 ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_LOCAL_PORT     ])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v4_e_timestamp_request      )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_timestamp_request)      ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_CONNECT_V4    ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ORIGINAL_ICMP_TYPE])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v4_e_address_mask_request   )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_address_mask_request)   ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ORIGINAL_ICMP_TYPE])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v4_e_address_mask_request   )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_address_mask_request)   ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_INBOUND_ICMP_ERROR_V4  ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_LOCAL_PORT     ])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v4_e_address_mask_request   )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_address_mask_request)   ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_OUTBOUND_ICMP_ERROR_V4 ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_LOCAL_PORT     ])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v4_e_address_mask_request   )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_address_mask_request)   ); }

	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_CONNECT_V6    ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ORIGINAL_ICMP_TYPE])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_destination_unreachable         )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_destination_unreachable)         ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ORIGINAL_ICMP_TYPE])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_destination_unreachable         )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_destination_unreachable)         ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_INBOUND_ICMP_ERROR_V6  ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_LOCAL_PORT     ])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_destination_unreachable         )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_destination_unreachable)         ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_OUTBOUND_ICMP_ERROR_V6 ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_LOCAL_PORT     ])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_destination_unreachable         )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_destination_unreachable)         ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_CONNECT_V6    ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ORIGINAL_ICMP_TYPE])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_packet_too_big                  )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_packet_too_big)                  ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ORIGINAL_ICMP_TYPE])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_packet_too_big                  )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_packet_too_big)                  ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_INBOUND_ICMP_ERROR_V6  ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_LOCAL_PORT     ])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_packet_too_big                  )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_packet_too_big)                  ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_OUTBOUND_ICMP_ERROR_V6 ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_LOCAL_PORT     ])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_packet_too_big                  )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_packet_too_big)                  ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_CONNECT_V6    ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ORIGINAL_ICMP_TYPE])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_time_exceeded                   )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_time_exceeded)                   ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ORIGINAL_ICMP_TYPE])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_time_exceeded                   )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_time_exceeded)                   ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_INBOUND_ICMP_ERROR_V6  ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_LOCAL_PORT     ])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_time_exceeded                   )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_time_exceeded)                   ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_OUTBOUND_ICMP_ERROR_V6 ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_LOCAL_PORT     ])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_time_exceeded                   )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_time_exceeded)                   ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_CONNECT_V6    ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ORIGINAL_ICMP_TYPE])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_parameter_problem               )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_parameter_problem)               ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ORIGINAL_ICMP_TYPE])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_parameter_problem               )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_parameter_problem)               ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_INBOUND_ICMP_ERROR_V6  ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_LOCAL_PORT     ])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_parameter_problem               )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_parameter_problem)               ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_OUTBOUND_ICMP_ERROR_V6 ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_LOCAL_PORT     ])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_parameter_problem               )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_parameter_problem)               ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_CONNECT_V6    ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ORIGINAL_ICMP_TYPE])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_echo_request                    )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_echo_request)                    ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ORIGINAL_ICMP_TYPE])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_echo_request                    )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_echo_request)                    ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_INBOUND_ICMP_ERROR_V6  ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_LOCAL_PORT     ])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_echo_request                    )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_echo_request)                    ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_OUTBOUND_ICMP_ERROR_V6 ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_LOCAL_PORT     ])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_echo_request                    )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_echo_request)                    ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_CONNECT_V6    ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ORIGINAL_ICMP_TYPE])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_multicast_listener_query        )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_multicast_listener_query)        ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ORIGINAL_ICMP_TYPE])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_multicast_listener_query        )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_multicast_listener_query)        ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_INBOUND_ICMP_ERROR_V6  ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_LOCAL_PORT     ])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_multicast_listener_query        )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_multicast_listener_query)        ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_OUTBOUND_ICMP_ERROR_V6 ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_LOCAL_PORT     ])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_multicast_listener_query        )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_multicast_listener_query)        ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_CONNECT_V6    ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ORIGINAL_ICMP_TYPE])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_multicast_listener_report       )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_multicast_listener_report)       ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ORIGINAL_ICMP_TYPE])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_multicast_listener_report       )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_multicast_listener_report)       ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_INBOUND_ICMP_ERROR_V6  ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_LOCAL_PORT     ])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_multicast_listener_report       )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_multicast_listener_report)       ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_OUTBOUND_ICMP_ERROR_V6 ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_LOCAL_PORT     ])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_multicast_listener_report       )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_multicast_listener_report)       ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_CONNECT_V6    ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ORIGINAL_ICMP_TYPE])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_multicast_listener_done         )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_multicast_listener_done)         ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ORIGINAL_ICMP_TYPE])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_multicast_listener_done         )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_multicast_listener_done)         ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_INBOUND_ICMP_ERROR_V6  ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_LOCAL_PORT     ])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_multicast_listener_done         )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_multicast_listener_done)         ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_OUTBOUND_ICMP_ERROR_V6 ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_LOCAL_PORT     ])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_multicast_listener_done         )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_multicast_listener_done)         ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_CONNECT_V6    ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ORIGINAL_ICMP_TYPE])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_router_solicitation             )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_router_solicitation)             ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ORIGINAL_ICMP_TYPE])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_router_solicitation             )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_router_solicitation)             ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_INBOUND_ICMP_ERROR_V6  ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_LOCAL_PORT     ])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_router_solicitation             )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_router_solicitation)             ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_OUTBOUND_ICMP_ERROR_V6 ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_LOCAL_PORT     ])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_router_solicitation             )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_router_solicitation)             ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_CONNECT_V6    ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ORIGINAL_ICMP_TYPE])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_router_advertisement            )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_router_advertisement)            ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ORIGINAL_ICMP_TYPE])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_router_advertisement            )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_router_advertisement)            ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_INBOUND_ICMP_ERROR_V6  ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_LOCAL_PORT     ])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_router_advertisement            )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_router_advertisement)            ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_OUTBOUND_ICMP_ERROR_V6 ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_LOCAL_PORT     ])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_router_advertisement            )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_router_advertisement)            ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_CONNECT_V6    ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ORIGINAL_ICMP_TYPE])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_neighbor_discovery_solicitation )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_neighbor_discovery_solicitation) ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ORIGINAL_ICMP_TYPE])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_neighbor_discovery_solicitation )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_neighbor_discovery_solicitation) ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_INBOUND_ICMP_ERROR_V6  ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_LOCAL_PORT     ])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_neighbor_discovery_solicitation )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_neighbor_discovery_solicitation) ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_OUTBOUND_ICMP_ERROR_V6 ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_LOCAL_PORT     ])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_neighbor_discovery_solicitation )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_neighbor_discovery_solicitation) ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_CONNECT_V6    ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ORIGINAL_ICMP_TYPE])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_neighbor_discovery_advertisement)){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_neighbor_discovery_advertisement)); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ORIGINAL_ICMP_TYPE])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_neighbor_discovery_advertisement)){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_neighbor_discovery_advertisement)); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_INBOUND_ICMP_ERROR_V6  ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_LOCAL_PORT     ])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_neighbor_discovery_advertisement)){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_neighbor_discovery_advertisement)); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_OUTBOUND_ICMP_ERROR_V6 ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_LOCAL_PORT     ])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_neighbor_discovery_advertisement)){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_neighbor_discovery_advertisement)); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_CONNECT_V6    ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ORIGINAL_ICMP_TYPE])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_redirect                        )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_redirect)                        ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ORIGINAL_ICMP_TYPE])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_redirect                        )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_redirect)                        ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_INBOUND_ICMP_ERROR_V6  ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_LOCAL_PORT     ])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_redirect                        )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_redirect)                        ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_OUTBOUND_ICMP_ERROR_V6 ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_LOCAL_PORT     ])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_redirect                        )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_redirect)                        ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_CONNECT_V6    ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ORIGINAL_ICMP_TYPE])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_multicast_listener_report_v2    )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_multicast_listener_report_v2)    ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ORIGINAL_ICMP_TYPE])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_multicast_listener_report_v2    )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_multicast_listener_report_v2)    ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_INBOUND_ICMP_ERROR_V6  ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_LOCAL_PORT     ])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_multicast_listener_report_v2    )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_multicast_listener_report_v2)    ); }
	else if((mk_guid_eq(&filter->layerKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_OUTBOUND_ICMP_ERROR_V6 ])) && (mk_guid_eq(&condition->fieldKey, &k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_LOCAL_PORT     ])) && (condition->matchType == FWP_MATCH_EQUAL) && (condition->conditionValue.type == FWP_UINT16) && (condition->conditionValue.uint16 == mk_net_icmp_v6_e_multicast_listener_report_v2    )){ wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_icmp_multicast_listener_report_v2)    ); }

	mk_assert(wstr.m_len >= 0);
	mk_assert(wstr.m_buf[wstr.m_len] == L'\0');
	return wstr;
}

[[nodiscard]] static inline mk_view_wstr_t condition_entry_to_wstr_any(FWPM_FILTER0 const* const filter, FWPM_FILTER_CONDITION0 const* const condition, mk_col_id_condition_t const col_id)
{
	mk_view_wstr_t wstr;

	mk_assert(filter);
	mk_assert(condition);
	mk_assert(col_id >= 0);
	mk_assert(col_id < mk_col_id_condition_e_dummy_end);

	switch(col_id)
	{
		case mk_col_id_condition_e_field     : wstr = condition_entry_to_wstr_filed     (filter, condition); break;
		case mk_col_id_condition_e_match_type: wstr = condition_entry_to_wstr_match_type(filter, condition); break;
		case mk_col_id_condition_e_value_type: wstr = condition_entry_to_wstr_value_type(filter, condition); break;
		case mk_col_id_condition_e_value_data: wstr = condition_entry_to_wstr_value_data(filter, condition); break;
		case mk_col_id_condition_e_note      : wstr = condition_entry_to_wstr_note      (filter, condition); break;
		case mk_col_id_entry_e_dummy_end: mk_assert(false); break;
		default: mk_assert(false); break;
	}
	mk_assert(wstr.m_len >= 0);
	mk_assert(wstr.m_buf[wstr.m_len] == L'\0');
	return wstr;
}

[[nodiscard]] static inline mk_view_wstr_t condition_entry_to_wstr_line(FWPM_FILTER0 const* const filter, FWPM_FILTER_CONDITION0 const* const condition)
{
	int cap;
	LPWSTR buf;
	int len;
	int n;
	int i;
	mk_col_id_condition_t col_id;
	mk_view_wstr_t wstr;
	LPWSTR ptr;

	mk_assert(filter);
	mk_assert(condition);

	cap = 4 * 1024;
	buf = ((LPWSTR)(g_app.m_funcs_kernel.m_pfn_HeapAlloc(g_app.m_funcs_kernel.m_pfn_GetProcessHeap(), 0, cap))); mk_assert(buf);
	len = 0;
	n = mk_col_id_condition_e_dummy_end;
	for(i = 0; i != n; ++i)
	{
		col_id = ((mk_col_id_condition_t)(i));
		wstr = condition_entry_to_wstr_any(filter, condition, col_id);
		if(len + ((int)(wstr.m_len)) + 32 > cap)
		{
			while(len + ((int)(wstr.m_len)) + 32 > cap){ cap *= 2; }
			buf = ((LPWSTR)(g_app.m_funcs_kernel.m_pfn_HeapReAlloc(g_app.m_funcs_kernel.m_pfn_GetProcessHeap(), 0, buf, cap))); mk_assert(buf);
		}
		ptr = mk_memcpy(buf + len, wstr); ((void)(ptr));
		len += ((int)(((int)(wstr.m_len))));
		wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_tab));
		mk_assert(len + ((int)(wstr.m_len)) < cap);
		ptr = mk_memcpy(buf + len, wstr); ((void)(ptr));
		len += ((int)(wstr.m_len));
	}
	buf[len] = L'\0';
	wstr.m_buf = buf;
	wstr.m_len = len;
	mk_assert(wstr.m_len >= 0);
	mk_assert(wstr.m_buf[wstr.m_len] == L'\0');
	return wstr;
}

[[nodiscard]] static inline mk_view_wstr_t condition_entry_to_wstr_table(FWPM_FILTER0* const entry)
{
	int cap;
	LPWSTR buf;
	int len;
	UINT32 n;
	UINT32 i;
	mk_view_wstr_t wstr;
	LPWSTR ptr;
	BOOL b;

	mk_assert(entry);

	cap = 4 * 1024;
	buf = ((LPWSTR)(g_app.m_funcs_kernel.m_pfn_HeapAlloc(g_app.m_funcs_kernel.m_pfn_GetProcessHeap(), 0, cap * sizeof(WCHAR)))); mk_assert(buf);
	len = 0;
	n = entry->numFilterConditions;
	for(i = 0; i != n; ++i)
	{
		wstr = condition_entry_to_wstr_line(entry, &entry->filterCondition[i]);
		if(len + ((int)(wstr.m_len)) + 32 > cap)
		{
			while(len + ((int)(wstr.m_len)) + 32 > cap){ cap *= 2; }
			buf = ((LPWSTR)(g_app.m_funcs_kernel.m_pfn_HeapReAlloc(g_app.m_funcs_kernel.m_pfn_GetProcessHeap(), 0, buf, cap * sizeof(WCHAR)))); mk_assert(buf);
		}
		ptr = mk_memcpy(buf + len, wstr); ((void)(ptr));
		len += ((int)(wstr.m_len));
		b = g_app.m_funcs_kernel.m_pfn_HeapFree(g_app.m_funcs_kernel.m_pfn_GetProcessHeap(), 0, ((LPVOID)(wstr.m_buf))); mk_assert(b);
		wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_nl));
		mk_assert(len + ((int)(wstr.m_len)) < cap);
		ptr = mk_memcpy(buf + len, wstr); ((void)(ptr));
		len += ((int)(wstr.m_len));
	}
	buf[len] = L'\0';
	wstr.m_buf = buf;
	wstr.m_len = len;
	mk_assert(wstr.m_len >= 0);
	mk_assert(wstr.m_buf[wstr.m_len] == L'\0');
	return wstr;
}

[[nodiscard]] static inline mk_view_wstr_t filter_to_wstr_table(mk_wnd_t const* const self)
{
	int cap;
	LPWSTR buf;
	int len;
	UINT32 n;
	UINT32 i;
	mk_view_wstr_t wstr;
	LPWSTR ptr;
	BOOL b;

	mk_assert(self);

	cap = 4 * 1024;
	buf = ((LPWSTR)(g_app.m_funcs_kernel.m_pfn_HeapAlloc(g_app.m_funcs_kernel.m_pfn_GetProcessHeap(), 0, cap * sizeof(WCHAR)))); mk_assert(buf);
	len = 0;
	n = ((int)(self->m_fw->m_count));
	for(i = 0; i != n; ++i)
	{
		wstr = entry_to_wstr_line(self->m_fw->m_entries[self->m_sort_ints[i]]);
		if(len + ((int)(wstr.m_len)) + 32 > cap)
		{
			while(len + ((int)(wstr.m_len)) + 32 > cap){ cap *= 2; }
			buf = ((LPWSTR)(g_app.m_funcs_kernel.m_pfn_HeapReAlloc(g_app.m_funcs_kernel.m_pfn_GetProcessHeap(), 0, buf, cap * sizeof(WCHAR)))); mk_assert(buf);
		}
		ptr = mk_memcpy(buf + len, wstr); ((void)(ptr));
		len += ((int)(wstr.m_len));
		b = g_app.m_funcs_kernel.m_pfn_HeapFree(g_app.m_funcs_kernel.m_pfn_GetProcessHeap(), 0, ((LPVOID)(wstr.m_buf))); mk_assert(b);
		wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_nl));
		mk_assert(len + ((int)(wstr.m_len)) < cap);
		ptr = mk_memcpy(buf + len, wstr); ((void)(ptr));
		len += ((int)(wstr.m_len));
	}
	buf[len] = L'\0';
	wstr.m_buf = buf;
	wstr.m_len = len;
	mk_assert(wstr.m_len >= 0);
	mk_assert(wstr.m_buf[wstr.m_len] == L'\0');
	return wstr;
}

static inline void mk_col_id_entry_sort_collapse(mk_col_id_entry_t const col_id, bool const direction, int* const out_collapsed)
{
	int collapsed;

	mk_assert(col_id >= 0);
	mk_assert(col_id <= mk_col_id_entry_e_dummy_end);
	mk_assert(direction == false || direction == true);
	mk_assert(out_collapsed);

	collapsed = 0;
	if(col_id != mk_col_id_entry_e_dummy_end)
	{
		collapsed = ((int)(col_id)) + 1;
		collapsed *= direction ? +1 : -1;
	}
	*out_collapsed = collapsed;
}

static inline void mk_col_id_entry_sort_expand(int const collapsed, mk_col_id_entry_t* const out_col_id, bool* const out_direction)
{
	mk_col_id_entry_t col_id;
	bool direction;

	mk_assert(collapsed >= -((int)(mk_col_id_entry_e_dummy_end)));
	mk_assert(collapsed <= +((int)(mk_col_id_entry_e_dummy_end)));
	mk_assert(out_col_id);
	mk_assert(out_direction);

	col_id = mk_col_id_entry_e_dummy_end;
	direction = true;
	if(collapsed != 0)
	{
		col_id = collapsed > 0 ? ((mk_col_id_entry_t)(collapsed - 1)) : ((mk_col_id_entry_t)(-collapsed - 1));
		direction = collapsed > 0;
	}
	*out_col_id = col_id;
	*out_direction = direction;
}

[[nodiscard]] static inline int __cdecl sort_compare_entries(void const* const a, void const* const b)
{
	int aa;
	int bb;
	mk_wnd_t* win;
	mk_col_id_entry_t col_id;
	bool direction;
	FWPM_FILTER0 const* entry_a;
	FWPM_FILTER0 const* entry_b;
	mk_view_wstr_t txt_a;
	mk_view_wstr_t txt_b;
	mk_view_wstr_t* txt_aa;
	mk_view_wstr_t* txt_bb;
	int cmp;

	mk_assert(a);
	mk_assert(b);

	aa = *((int const*)(a));
	bb = *((int const*)(b));
	win = &g_app.m_fw_wnd;
	mk_col_id_entry_sort_expand(win->m_entries_sort_col, &col_id, &direction);
	if(col_id != mk_col_id_entry_e_dummy_end)
	{
		entry_a = win->m_fw->m_entries[aa];
		entry_b = win->m_fw->m_entries[bb];
		cmp = 0;
		if(cmp == 0)
		{
			txt_a = entry_to_wstr(entry_a, col_id);
			txt_b = entry_to_wstr(entry_b, col_id);
			txt_aa = direction ? &txt_a : &txt_b;
			txt_bb = direction ? &txt_b : &txt_a;
			cmp = wcsncmp_c(txt_aa->m_buf, txt_bb->m_buf, mk_min(txt_a.m_len, txt_b.m_len) + 1);
		}
		if(cmp == 0)
		{
			txt_a = entry_to_wstr(entry_a, mk_col_id_entry_e_layer);
			txt_b = entry_to_wstr(entry_b, mk_col_id_entry_e_layer);
			txt_aa = direction ? &txt_a : &txt_b;
			txt_bb = direction ? &txt_b : &txt_a;
			cmp = wcsncmp_c(txt_aa->m_buf, txt_bb->m_buf, mk_min(txt_a.m_len, txt_b.m_len) + 1);
		}
		if(cmp == 0)
		{
			txt_a = entry_to_wstr(entry_a, mk_col_id_entry_e_filter);
			txt_b = entry_to_wstr(entry_b, mk_col_id_entry_e_filter);
			txt_aa = direction ? &txt_a : &txt_b;
			txt_bb = direction ? &txt_b : &txt_a;
			cmp = wcsncmp_c(txt_aa->m_buf, txt_bb->m_buf, mk_min(txt_a.m_len, txt_b.m_len) + 1);
		}
	}
	else
	{
		cmp = aa - bb;
	}
	return cmp;
}

static inline void actual_sort(mk_wnd_t* const win)
{
	mk_assert(win);
	mk_assert(win->m_fw);
	mk_assert(win->m_sort_ints);

	g_app.m_funcs_ntdll.m_pfn_qsort(win->m_sort_ints, win->m_fw->m_count, sizeof(int), &sort_compare_entries);
}

static inline void mkfw_wnd_sort_entries(mk_wnd_t* const self, mk_col_id_entry_t const col_id, bool const direction)
{
	HWND hdr_win;
	int n;
	int i;
	HDITEMW hdr_item;
	BOOL b;

	mk_assert(self);
	mk_assert(self->m_sort_ints);
	mk_assert(col_id >= 0);
	mk_assert(col_id <= mk_col_id_entry_e_dummy_end);
	mk_assert(direction == false || direction == true);

	hdr_win = ((HWND)(g_app.m_funcs_user.m_pfn_SendMessageW(self->m_entries, LVM_GETHEADER, 0, 0))); mk_assert(hdr_win);
	n = ((int)(mk_col_id_entry_e_dummy_end));
	for(i = 0; i != n; ++i)
	{
		hdr_item.mask = HDI_FORMAT;
		b = ((BOOL)(g_app.m_funcs_user.m_pfn_SendMessageW(hdr_win, HDM_GETITEM, i, ((LPARAM)(&hdr_item))))); mk_assert(b);
		hdr_item.mask = HDI_FORMAT;
		hdr_item.fmt &=~ ((unsigned int)(HDF_SORTDOWN | HDF_SORTUP));
		b = ((BOOL)(g_app.m_funcs_user.m_pfn_SendMessageW(hdr_win, HDM_SETITEM, i, ((LPARAM)(&hdr_item))))); mk_assert(b);
	}
	mk_col_id_entry_sort_collapse(col_id, direction, &self->m_entries_sort_col);
	n = ((int)(self->m_fw->m_count));
	if(col_id != mk_col_id_entry_e_dummy_end)
	{
		hdr_item.mask = HDI_FORMAT;
		b = ((BOOL)(g_app.m_funcs_user.m_pfn_SendMessageW(hdr_win, HDM_GETITEM, col_id, ((LPARAM)(&hdr_item))))); mk_assert(b);
		hdr_item.mask = HDI_FORMAT;
		hdr_item.fmt &=~ ((unsigned int)(HDF_SORTDOWN | HDF_SORTUP));
		hdr_item.fmt |= ((unsigned int)(direction ? HDF_SORTUP : HDF_SORTDOWN));
		b = ((BOOL)(g_app.m_funcs_user.m_pfn_SendMessageW(hdr_win, HDM_SETITEM, col_id, ((LPARAM)(&hdr_item))))); mk_assert(b);
	}
	actual_sort(self);
	b = g_app.m_funcs_user.m_pfn_InvalidateRect(hdr_win, NULL, TRUE); mk_assert(b);
	b = g_app.m_funcs_user.m_pfn_InvalidateRect(self->m_entries, NULL, TRUE); mk_assert(b);
}

static inline void mkfw_wnd_sort_entries(mk_wnd_t* const self)
{
	mk_col_id_entry_t col_id;
	bool direction;

	mk_assert(self);

	mk_col_id_entry_sort_expand(self->m_entries_sort_col, &col_id, &direction);
	mkfw_wnd_sort_entries(self, col_id, direction);
}

static inline void mkfw_wnd_on_key_apps(mk_wnd_t* const self, HWND const list_view)
{
	BOOL b;
	HMENU menu;
	MENUITEMINFOW mi;
	LRESULT lr;
	RECT rect;
	int selected_idx;
	POINT pt;

	mk_assert(self);
	mk_assert(list_view);

	self->m_list_view_for_menu = list_view;
	if(self->m_menu)
	{
		b = g_app.m_funcs_user.m_pfn_DestroyMenu(self->m_menu); mk_assert(b);
	}
	menu = g_app.m_funcs_user.m_pfn_CreatePopupMenu(); mk_assert(menu);
	self->m_menu = menu;

	mi.cbSize = sizeof(mi);
	mi.fMask = MIIM_ID | MIIM_STRING | MIIM_FTYPE;
	mi.fType = MFT_STRING;
	mi.wID = menu_id_e_copy_line;
	mi.dwTypeData = ((LPWSTR)(nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_menu_copy_line)).m_buf));
	b = g_app.m_funcs_user.m_pfn_InsertMenuItemW(menu, menu_id_e_copy_line, FALSE, &mi); mk_assert(b);

	mi.cbSize = sizeof(mi);
	mi.fMask = MIIM_ID | MIIM_STRING | MIIM_FTYPE;
	mi.fType = MFT_STRING;
	mi.wID = menu_id_e_copy_table;
	mi.dwTypeData = ((LPWSTR)(nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_menu_copy_table)).m_buf));
	b = g_app.m_funcs_user.m_pfn_InsertMenuItemW(menu, menu_id_e_copy_table, FALSE, &mi); mk_assert(b);

	lr = g_app.m_funcs_user.m_pfn_SendMessageW(list_view, LVM_GETSELECTEDCOUNT, 0, 0);
	if(lr == 1)
	{
		rect.left = LVIR_LABEL;
		lr = g_app.m_funcs_user.m_pfn_SendMessageW(list_view, LVM_GETSELECTIONMARK, 0, 0); selected_idx = ((int)(lr));
		lr = g_app.m_funcs_user.m_pfn_SendMessageW(list_view, LVM_GETITEMRECT, selected_idx, ((LPARAM)(&rect))); mk_assert(lr != 0);

		pt.x = rect.left + ((rect.right - rect.left) / 2);
		pt.y = rect.top + ((rect.bottom - rect.top) / 2);
		b = g_app.m_funcs_user.m_pfn_ClientToScreen(list_view, &pt); mk_assert(b);
		b = g_app.m_funcs_user.m_pfn_TrackPopupMenu(menu, 0, pt.x, pt.y, 0, self->m_hwnd, NULL); mk_assert(b);
	}
}

static inline void mkfw_wnd_on_rclick(mk_wnd_t* const self, HWND const list_view, LPARAM const lparam)
{
	LPNMITEMACTIVATE item;
	BOOL b;
	HMENU menu;
	MENUITEMINFOW mi;
	LRESULT lr;
	int row_idx;
	LVHITTESTINFO info;
	POINT pt;

	mk_assert(self);
	mk_assert(list_view);
	mk_assert(lparam != 0);

	item = ((LPNMITEMACTIVATE)(lparam)); mk_assert(item);
	self->m_list_view_for_menu = list_view;
	if(self->m_menu)
	{
		b = g_app.m_funcs_user.m_pfn_DestroyMenu(self->m_menu); mk_assert(b);
	}
	menu = g_app.m_funcs_user.m_pfn_CreatePopupMenu(); mk_assert(menu);
	self->m_menu = menu;

	mi.cbSize = sizeof(mi);
	mi.fMask = MIIM_ID | MIIM_STRING | MIIM_FTYPE;
	mi.fType = MFT_STRING;
	mi.wID = menu_id_e_copy_cell;
	mi.dwTypeData = ((LPWSTR)(nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_menu_copy_value)).m_buf));
	b = g_app.m_funcs_user.m_pfn_InsertMenuItemW(menu, menu_id_e_copy_cell, FALSE, &mi); mk_assert(b);

	mi.cbSize = sizeof(mi);
	mi.fMask = MIIM_ID | MIIM_STRING | MIIM_FTYPE;
	mi.fType = MFT_STRING;
	mi.wID = menu_id_e_copy_line;
	mi.dwTypeData = ((LPWSTR)(nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_menu_copy_line)).m_buf));
	b = g_app.m_funcs_user.m_pfn_InsertMenuItemW(menu, menu_id_e_copy_line, FALSE, &mi); mk_assert(b);

	mi.cbSize = sizeof(mi);
	mi.fMask = MIIM_ID | MIIM_STRING | MIIM_FTYPE;
	mi.fType = MFT_STRING;
	mi.wID = menu_id_e_copy_table;
	mi.dwTypeData = ((LPWSTR)(nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_menu_copy_table)).m_buf));
	b = g_app.m_funcs_user.m_pfn_InsertMenuItemW(menu, menu_id_e_copy_table, FALSE, &mi); mk_assert(b);

	lr = g_app.m_funcs_user.m_pfn_SendMessageW(list_view, LVM_GETSELECTEDCOUNT, 0, 0);
	if(lr == 1)
	{
		lr = g_app.m_funcs_user.m_pfn_SendMessageW(list_view, LVM_GETSELECTIONMARK, 0, 0);
		mk_assert(lr >= 0);
		mk_assert(lr <= ((LRESULT)(std::numeric_limits<int>::max())));
		row_idx = ((int)(lr));
		self->m_row_idx_for_menu = row_idx;
		info.pt = item->ptAction;
		lr = g_app.m_funcs_user.m_pfn_SendMessageW(list_view, LVM_SUBITEMHITTEST, 0, ((LPARAM)(&info)));
		if(lr == row_idx)
		{
			self->m_col_idx_for_menu = info.iSubItem;
			pt = item->ptAction;
			b = g_app.m_funcs_user.m_pfn_ClientToScreen(list_view, &pt); mk_assert(b);
			b = g_app.m_funcs_user.m_pfn_TrackPopupMenu(menu, 0, pt.x, pt.y, 0, self->m_hwnd, NULL); mk_assert(b);
		}
	}
}

static inline void mkfw_wnd_refresh(mk_wnd_t* self)
{
	DWORD dw;
	HANDLE enm;
	BOOL b;
	int n;
	int i;
	LRESULT lr;

	mk_assert(self);

	g_app.m_funcs_fw.m_pfn_FwpmFreeMemory0(((void**)(&self->m_fw->m_entries)));
	dw = g_app.m_funcs_fw.m_pfn_FwpmEngineClose0(self->m_fw->m_eng); mk_assert(dw == ERROR_SUCCESS);

	dw = g_app.m_funcs_fw.m_pfn_FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &self->m_fw->m_eng); mk_assert(dw == ERROR_SUCCESS);
	dw = g_app.m_funcs_fw.m_pfn_FwpmFilterCreateEnumHandle0(self->m_fw->m_eng, NULL, &enm); mk_assert(dw == ERROR_SUCCESS);
	dw = g_app.m_funcs_fw.m_pfn_FwpmFilterEnum0(self->m_fw->m_eng, enm, k_count, &self->m_fw->m_entries, &self->m_fw->m_count); mk_assert(dw == ERROR_SUCCESS);
	dw = g_app.m_funcs_fw.m_pfn_FwpmFilterDestroyEnumHandle0(self->m_fw->m_eng, enm); mk_assert(dw == ERROR_SUCCESS);

	b = g_app.m_funcs_kernel.m_pfn_HeapFree(g_app.m_funcs_kernel.m_pfn_GetProcessHeap(), 0, self->m_sort_ints); mk_assert(b);
	self->m_sort_ints = NULL;
	if(!self->m_sort_ints)
	{
		n = ((int)(self->m_fw->m_count));
		self->m_sort_ints = ((int*)(g_app.m_funcs_kernel.m_pfn_HeapAlloc(g_app.m_funcs_kernel.m_pfn_GetProcessHeap(), 0, n * sizeof(int)))); mk_assert(self->m_sort_ints);
		for(i = 0; i != n; ++i)
		{
			self->m_sort_ints[i] = i;
		}
	}
	self->m_entry_idx_sorted = mk_min(self->m_entry_idx_sorted, n);
	lr = g_app.m_funcs_user.m_pfn_SendMessageW(self->m_entries, LVM_SETITEMCOUNT, self->m_fw->m_count, LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL); mk_assert(lr != 0);
	b = g_app.m_funcs_user.m_pfn_InvalidateRect(self->m_entries, NULL, TRUE); mk_assert(b);
	b = g_app.m_funcs_user.m_pfn_InvalidateRect(self->m_conditions, NULL, TRUE); mk_assert(b);
	mkfw_wnd_sort_entries(self);
}

static inline void mk_fw_copy_cell(mk_wnd_t* const self)
{
	NMLVDISPINFOW info;
	LRESULT lr;
	mk_view_wstr_t wstr;
	SIZE_T bytes_count;
	HGLOBAL gl;
	LPVOID ptr;
	BOOL b;
	HANDLE h;

	mk_assert(self);
	mk_assert(self->m_list_view_for_menu);

	if(false){}
	else if(self->m_list_view_for_menu == self->m_entries){}
	else if(self->m_list_view_for_menu == self->m_conditions){}
	else{ mk_assert(false); }
	
	info.hdr.hwndFrom = self->m_list_view_for_menu;
	info.hdr.code = LVN_GETDISPINFOW;
	info.item.mask = LVIF_TEXT;
	info.item.iItem = self->m_row_idx_for_menu;
	info.item.iSubItem = self->m_col_idx_for_menu;
	lr = g_app.m_funcs_user.m_pfn_SendMessageW(self->m_hwnd, WM_NOTIFY, 0, ((LPARAM)(&info))); ((void)(lr));
	wstr.m_buf = info.item.pszText;
	wstr.m_len = mk_wcslen_c(wstr.m_buf);

	bytes_count = (wstr.m_len + 1) * sizeof(*wstr.m_buf);
	gl = g_app.m_funcs_kernel.m_pfn_GlobalAlloc(GMEM_MOVEABLE, bytes_count); mk_assert(gl);
	ptr = g_app.m_funcs_kernel.m_pfn_GlobalLock(gl); mk_assert(ptr);
	mk_memcpy_c(ptr, wstr.m_buf, bytes_count);
	b = g_app.m_funcs_kernel.m_pfn_GlobalUnlock(gl); mk_assert(b == 0 && GetLastError() == NO_ERROR);

	b = g_app.m_funcs_user.m_pfn_OpenClipboard(self->m_conditions); mk_assert(b);
	b = g_app.m_funcs_user.m_pfn_EmptyClipboard(); mk_assert(b);
	h = g_app.m_funcs_user.m_pfn_SetClipboardData(CF_UNICODETEXT, gl); mk_assert(h);
	b = g_app.m_funcs_user.m_pfn_CloseClipboard(); mk_assert(b);
}

static inline void set_max_col_width(HWND const hwnd, int const col_idx, int* const max_storage)
{
	LRESULT lr;

	lr = g_app.m_funcs_user.m_pfn_SendMessageW(hwnd, LVM_SETCOLUMNWIDTH, col_idx, LVSCW_AUTOSIZE); mk_assert(lr != 0);
	lr = g_app.m_funcs_user.m_pfn_SendMessageW(hwnd, LVM_GETCOLUMNWIDTH, col_idx, 0); mk_assert(lr != 0);
	if(((int)(lr)) > *max_storage)
	{
		*max_storage = ((int)(lr));
	}
	else if(((int)(lr)) < *max_storage)
	{
		lr = g_app.m_funcs_user.m_pfn_SendMessageW(hwnd, LVM_SETCOLUMNWIDTH, col_idx, *max_storage); mk_assert(lr != 0);
	}
}

static inline void mkfw_wnd__proc__create(mk_wnd_t* const self, HWND const hwnd, UINT const msg, WPARAM const wparam, LPARAM const lparam, bool* const out_call_def, LRESULT* const out_lr)
{
	int n;
	int i;
	LRESULT lr;
	LVCOLUMNW col;

	mk_assert(self);
	self->m_hwnd = hwnd;
	self->m_entries = NULL;
	self->m_conditions = NULL;
	self->m_menu = NULL;
	self->m_list_view_for_menu = NULL;
	self->m_row_idx_for_menu = 0;
	self->m_col_idx_for_menu = 0;
	self->m_fw;
	self->m_last_sub_window_focus = mk_wnd_sub_window_id_e_entries;
	self->m_entry_idx_sorted = 0;
	self->m_entries_sort_col = 0;
	self->m_sort_ints = NULL;
	self->m_condition_row = 0;
	self->m_max_entries.m_filter = 10;
	self->m_max_entries.m_provider = 10;
	self->m_max_entries.m_layer = 10;
	self->m_max_entries.m_sub_layer = 10;
	self->m_max_entries.m_action = 10;
	self->m_max_entries.m_callout = 10;
	self->m_max_entries.m_id = 10;
	self->m_max_entries.m_weight = 10;
	self->m_max_entries.m_effective_weight = 10;
	self->m_max_conditions.m_field = 10;
	self->m_max_conditions.m_match_type = 10;
	self->m_max_conditions.m_value_type = 10;
	self->m_max_conditions.m_note = 10;

	if(!self->m_sort_ints)
	{
		n = ((int)(self->m_fw->m_count));
		self->m_sort_ints = ((int*)(g_app.m_funcs_kernel.m_pfn_HeapAlloc(g_app.m_funcs_kernel.m_pfn_GetProcessHeap(), 0, n * sizeof(int)))); mk_assert(self->m_sort_ints);
		for(i = 0; i != n; ++i)
		{
			self->m_sort_ints[i] = i;
		}
	}

	self->m_entries = g_app.m_funcs_user.m_pfn_CreateWindowExW(WS_EX_LEFT | WS_EX_LTRREADING | WS_EX_RIGHTSCROLLBAR, nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_wnd_cls_name_list_view)).m_buf, nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_empty)).m_buf, WS_VISIBLE | WS_CHILD | LVS_REPORT | LVS_OWNERDATA | LVS_SINGLESEL | LVS_SHOWSELALWAYS, 10, 10, 800, 600, self->m_hwnd, NULL, g_app.m_dlls.m_exe, NULL); mk_assert(self->m_entries);
	lr = g_app.m_funcs_user.m_pfn_SendMessageW(self->m_entries, LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_DOUBLEBUFFER | LVS_EX_FULLROWSELECT | LVS_EX_INFOTIP, LVS_EX_DOUBLEBUFFER | LVS_EX_FULLROWSELECT | LVS_EX_INFOTIP); ((void)(lr));

	col.mask = LVCF_WIDTH | LVCF_TEXT; col.pszText = ((LPWSTR)(nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_filter)).m_buf)); col.cx = 80;
	lr = g_app.m_funcs_user.m_pfn_SendMessageW(self->m_entries, LVM_INSERTCOLUMN, mk_col_id_entry_e_filter, ((LPARAM)(&col))); mk_assert(lr == mk_col_id_entry_e_filter);

	col.mask = LVCF_WIDTH | LVCF_TEXT; col.pszText = ((LPWSTR)(nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_name)).m_buf)); col.cx = 300;
	lr = g_app.m_funcs_user.m_pfn_SendMessageW(self->m_entries, LVM_INSERTCOLUMN, mk_col_id_entry_e_name, ((LPARAM)(&col))); mk_assert(lr == mk_col_id_entry_e_name);

	col.mask = LVCF_WIDTH | LVCF_TEXT; col.pszText = ((LPWSTR)(nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_description)).m_buf)); col.cx = 180;
	lr = g_app.m_funcs_user.m_pfn_SendMessageW(self->m_entries, LVM_INSERTCOLUMN, mk_col_id_entry_e_description, ((LPARAM)(&col))); mk_assert(lr == mk_col_id_entry_e_description);

	col.mask = LVCF_WIDTH | LVCF_TEXT; col.pszText = ((LPWSTR)(nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_provider)).m_buf)); col.cx = 80;
	lr = g_app.m_funcs_user.m_pfn_SendMessageW(self->m_entries, LVM_INSERTCOLUMN, mk_col_id_entry_e_provider, ((LPARAM)(&col))); mk_assert(lr == mk_col_id_entry_e_provider);

	col.mask = LVCF_WIDTH | LVCF_TEXT; col.pszText = ((LPWSTR)(nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_layer)).m_buf)); col.cx = 80;
	lr = g_app.m_funcs_user.m_pfn_SendMessageW(self->m_entries, LVM_INSERTCOLUMN, mk_col_id_entry_e_layer, ((LPARAM)(&col))); mk_assert(lr == mk_col_id_entry_e_layer);

	col.mask = LVCF_WIDTH | LVCF_TEXT; col.pszText = ((LPWSTR)(nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_sublayer)).m_buf)); col.cx = 80;
	lr = g_app.m_funcs_user.m_pfn_SendMessageW(self->m_entries, LVM_INSERTCOLUMN, mk_col_id_entry_e_sub_layer, ((LPARAM)(&col))); mk_assert(lr == mk_col_id_entry_e_sub_layer);

	col.mask = LVCF_WIDTH | LVCF_TEXT; col.pszText = ((LPWSTR)(nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_action)).m_buf)); col.cx = 80;
	lr = g_app.m_funcs_user.m_pfn_SendMessageW(self->m_entries, LVM_INSERTCOLUMN, mk_col_id_entry_e_action, ((LPARAM)(&col))); mk_assert(lr == mk_col_id_entry_e_action);

	col.mask = LVCF_WIDTH | LVCF_TEXT; col.pszText = ((LPWSTR)(nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_filter_type_callout)).m_buf)); col.cx = 80;
	lr = g_app.m_funcs_user.m_pfn_SendMessageW(self->m_entries, LVM_INSERTCOLUMN, mk_col_id_entry_e_callout, ((LPARAM)(&col))); mk_assert(lr == mk_col_id_entry_e_callout);

	col.mask = LVCF_WIDTH | LVCF_TEXT; col.pszText = ((LPWSTR)(nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_filter_id)).m_buf)); col.cx = 80;
	lr = g_app.m_funcs_user.m_pfn_SendMessageW(self->m_entries, LVM_INSERTCOLUMN, mk_col_id_entry_e_id, ((LPARAM)(&col))); mk_assert(lr == mk_col_id_entry_e_id);

	col.mask = LVCF_WIDTH | LVCF_TEXT; col.pszText = ((LPWSTR)(nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_weight)).m_buf)); col.cx = 80;
	lr = g_app.m_funcs_user.m_pfn_SendMessageW(self->m_entries, LVM_INSERTCOLUMN, mk_col_id_entry_e_weight, ((LPARAM)(&col))); mk_assert(lr == mk_col_id_entry_e_weight);

	col.mask = LVCF_WIDTH | LVCF_TEXT; col.pszText = ((LPWSTR)(nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_effective_weight)).m_buf)); col.cx = 80;
	lr = g_app.m_funcs_user.m_pfn_SendMessageW(self->m_entries, LVM_INSERTCOLUMN, mk_col_id_entry_e_effective_weight, ((LPARAM)(&col))); mk_assert(lr == mk_col_id_entry_e_effective_weight);

	lr = g_app.m_funcs_user.m_pfn_SendMessageW(self->m_entries, LVM_SETITEMCOUNT, self->m_fw->m_count, LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL); mk_assert(lr != 0);

	lr = g_app.m_funcs_user.m_pfn_SendMessageW(self->m_entries, LVM_SETCOLUMNWIDTH, mk_col_id_entry_e_filter, LVSCW_AUTOSIZE); mk_assert(lr != 0);
	lr = g_app.m_funcs_user.m_pfn_SendMessageW(self->m_entries, LVM_SETCOLUMNWIDTH, mk_col_id_entry_e_provider, LVSCW_AUTOSIZE); mk_assert(lr != 0);
	lr = g_app.m_funcs_user.m_pfn_SendMessageW(self->m_entries, LVM_SETCOLUMNWIDTH, mk_col_id_entry_e_layer, LVSCW_AUTOSIZE); mk_assert(lr != 0);
	lr = g_app.m_funcs_user.m_pfn_SendMessageW(self->m_entries, LVM_SETCOLUMNWIDTH, mk_col_id_entry_e_sub_layer, LVSCW_AUTOSIZE); mk_assert(lr != 0);

	self->m_conditions = g_app.m_funcs_user.m_pfn_CreateWindowExW(WS_EX_LEFT | WS_EX_LTRREADING | WS_EX_RIGHTSCROLLBAR, nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_wnd_cls_name_list_view)).m_buf, nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_empty)).m_buf, WS_VISIBLE | WS_CHILD | LVS_REPORT | LVS_OWNERDATA | LVS_SINGLESEL | LVS_SHOWSELALWAYS, 10, 10, 800, 600, self->m_hwnd, NULL, g_app.m_dlls.m_exe, NULL); mk_assert(self->m_entries);
	lr = g_app.m_funcs_user.m_pfn_SendMessageW(self->m_conditions, LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_DOUBLEBUFFER | LVS_EX_FULLROWSELECT | LVS_EX_INFOTIP, LVS_EX_DOUBLEBUFFER | LVS_EX_FULLROWSELECT | LVS_EX_INFOTIP); ((void)(lr));

	col.mask = LVCF_WIDTH | LVCF_TEXT; col.pszText = ((LPWSTR)(nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_field)).m_buf)); col.cx = 80;
	lr = g_app.m_funcs_user.m_pfn_SendMessageW(self->m_conditions, LVM_INSERTCOLUMN, mk_col_id_condition_e_field, ((LPARAM)(&col))); mk_assert(lr == mk_col_id_condition_e_field);

	col.mask = LVCF_WIDTH | LVCF_TEXT; col.pszText = ((LPWSTR)(nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_match_type)).m_buf)); col.cx = 80;
	lr = g_app.m_funcs_user.m_pfn_SendMessageW(self->m_conditions, LVM_INSERTCOLUMN, mk_col_id_condition_e_match_type, ((LPARAM)(&col))); mk_assert(lr == mk_col_id_condition_e_match_type);

	col.mask = LVCF_WIDTH | LVCF_TEXT; col.pszText = ((LPWSTR)(nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_type)).m_buf)); col.cx = 80;
	lr = g_app.m_funcs_user.m_pfn_SendMessageW(self->m_conditions, LVM_INSERTCOLUMN, mk_col_id_condition_e_value_type, ((LPARAM)(&col))); mk_assert(lr == mk_col_id_condition_e_value_type);

	col.mask = LVCF_WIDTH | LVCF_TEXT; col.pszText = ((LPWSTR)(nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_value)).m_buf)); col.cx = 200;
	lr = g_app.m_funcs_user.m_pfn_SendMessageW(self->m_conditions, LVM_INSERTCOLUMN, mk_col_id_condition_e_value_data, ((LPARAM)(&col))); mk_assert(lr == mk_col_id_condition_e_value_data);

	col.mask = LVCF_WIDTH | LVCF_TEXT; col.pszText = ((LPWSTR)(nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_note)).m_buf)); col.cx = 200;
	lr = g_app.m_funcs_user.m_pfn_SendMessageW(self->m_conditions, LVM_INSERTCOLUMN, mk_col_id_condition_e_note, ((LPARAM)(&col))); mk_assert(lr == mk_col_id_condition_e_note);

	mk_col_id_entry_sort_collapse(mk_col_id_entry_e_name, true, &self->m_entries_sort_col);
	mkfw_wnd_sort_entries(self);
}

static inline void mkfw_wnd__proc_create(mk_wnd_t* const self, HWND const hwnd, UINT const msg, WPARAM const wparam, LPARAM const lparam, bool* const out_call_def, LRESULT* const out_lr)
{
	LPCREATESTRUCTW crt;
	mk_wnd_t* selv;
	LONG_PTR uptr;

	crt = ((LPCREATESTRUCTW)(lparam)); mk_assert(crt);
	selv = ((mk_wnd_t*)(crt->lpCreateParams)); mk_assert(selv);
	uptr = g_app.m_funcs_user.m_pfn_SetWindowLongPtrW(hwnd, GWLP_USERDATA, ((LONG_PTR)(selv))); mk_assert(uptr == 0);
	mkfw_wnd__proc__create(selv, hwnd, msg, wparam, lparam, out_call_def, out_lr);
}

static inline void mkfw_wnd__proc_destroy(mk_wnd_t* const self, HWND const hwnd, UINT const msg, WPARAM const wparam, LPARAM const lparam, bool* const out_call_def, LRESULT* const out_lr)
{
	g_app.m_funcs_user.m_pfn_PostQuitMessage(0);
}

static inline void mkfw_wnd__proc_size(mk_wnd_t* const self, HWND const hwnd, UINT const msg, WPARAM const wparam, LPARAM const lparam, bool* const out_call_def, LRESULT* const out_lr)
{
	BOOL b;
	RECT rect;
	int height;
	int top;

	b = g_app.m_funcs_user.m_pfn_GetClientRect(self->m_hwnd, &rect); mk_assert(b); mk_assert(rect.left == 0); mk_assert(rect.top == 0);
	height = rect.bottom / 2 - 2;
	height = mk_max(height, 0);
	top = height + 2 * 2;
	b = g_app.m_funcs_user.m_pfn_MoveWindow(self->m_entries, 0, 0, rect.right, height, TRUE); mk_assert(b);
	b = g_app.m_funcs_user.m_pfn_MoveWindow(self->m_conditions, 0, top, rect.right, height, TRUE); mk_assert(b);
}

static inline void mkfw_wnd__proc_setfocus(mk_wnd_t* const self, HWND const hwnd, UINT const msg, WPARAM const wparam, LPARAM const lparam, bool* const out_call_def, LRESULT* const out_lr)
{
	HWND wnd;

	wnd = NULL;
	switch(self->m_last_sub_window_focus)
	{
		case mk_wnd_sub_window_id_e_entries   : wnd = self->m_entries   ; break;
		case mk_wnd_sub_window_id_e_conditions: wnd = self->m_conditions; break;
	}
	if(wnd)
	{
		wnd = g_app.m_funcs_user.m_pfn_SetFocus(wnd); ((void)(wnd));
	}
}

static inline void mkfw_wnd_proc__notify_entries__rclick(mk_wnd_t* const self, HWND const hwnd, UINT const msg, WPARAM const wparam, LPARAM const lparam, bool* const out_call_def, LRESULT* const out_lr)
{
	mkfw_wnd_on_rclick(self, self->m_entries, lparam);
}

static inline void mkfw_wnd_proc__notify_entries__getdispinfow_text(mk_wnd_t* const self, HWND const hwnd, UINT const msg, WPARAM const wparam, LPARAM const lparam, bool* const out_call_def, LRESULT* const out_lr)
{
	LPNMLVDISPINFOW disp_info;
	int item_idx_unsorted;
	int item_idx_sorted;
	FWPM_FILTER0* entry;
	int col_idx;
	mk_col_id_entry_t col_id;
	mk_view_wstr_t wstr;

	mk_assert(self);
	mk_assert(self->m_sort_ints);
	disp_info = ((LPNMLVDISPINFOW)(lparam));
	item_idx_unsorted = disp_info->item.iItem;
	mk_assert(item_idx_unsorted >= 0);
	mk_assert(item_idx_unsorted < ((int)(self->m_fw->m_count)));
	item_idx_sorted = self->m_sort_ints[item_idx_unsorted];
	entry = self->m_fw->m_entries[item_idx_sorted];
	col_idx = disp_info->item.iSubItem;
	mk_assert(col_idx >= 0);
	mk_assert(col_idx < mk_col_id_entry_e_dummy_end);
	col_id = ((mk_col_id_entry_t)(col_idx));
	wstr = entry_to_wstr(entry, col_id);
	disp_info->item.pszText = ((LPWSTR)(wstr.m_buf));
	mk_assert(disp_info->item.pszText);
}

static inline void mkfw_wnd_proc__notify_entries__getdispinfow_indent(mk_wnd_t* const self, HWND const hwnd, UINT const msg, WPARAM const wparam, LPARAM const lparam, bool* const out_call_def, LRESULT* const out_lr)
{
	LPNMLVDISPINFOW disp_info;

	disp_info = ((LPNMLVDISPINFOW)(lparam));
	disp_info->item.iIndent = 0;
}

static inline void mkfw_wnd_proc__notify_entries__getdispinfow_image(mk_wnd_t* const self, HWND const hwnd, UINT const msg, WPARAM const wparam, LPARAM const lparam, bool* const out_call_def, LRESULT* const out_lr)
{
	LPNMLVDISPINFOW disp_info;

	disp_info = ((LPNMLVDISPINFOW)(lparam));
	disp_info->item.iImage = 0;
}

static inline void mkfw_wnd_proc__notify_entries__getdispinfow_state(mk_wnd_t* const self, HWND const hwnd, UINT const msg, WPARAM const wparam, LPARAM const lparam, bool* const out_call_def, LRESULT* const out_lr)
{
	LPNMLVDISPINFOW disp_info;

	disp_info = ((LPNMLVDISPINFOW)(lparam));
	disp_info->item.state = 0;
}

static inline void mkfw_wnd_proc__notify_entries__getdispinfow(mk_wnd_t* const self, HWND const hwnd, UINT const msg, WPARAM const wparam, LPARAM const lparam, bool* const out_call_def, LRESULT* const out_lr)
{
	LPNMLVDISPINFOW disp_info;
	UINT mask;

	disp_info = ((LPNMLVDISPINFOW)(lparam));
	mask = disp_info->item.mask;
	if((mask & LVIF_TEXT  ) != 0){ mask &=~ LVIF_TEXT  ; mkfw_wnd_proc__notify_entries__getdispinfow_text  (self, hwnd, msg, wparam, lparam, out_call_def, out_lr); }
	if((mask & LVIF_INDENT) != 0){ mask &=~ LVIF_INDENT; mkfw_wnd_proc__notify_entries__getdispinfow_indent(self, hwnd, msg, wparam, lparam, out_call_def, out_lr); }
	if((mask & LVIF_IMAGE ) != 0){ mask &=~ LVIF_IMAGE ; mkfw_wnd_proc__notify_entries__getdispinfow_image (self, hwnd, msg, wparam, lparam, out_call_def, out_lr); }
	if((mask & LVIF_STATE ) != 0){ mask &=~ LVIF_STATE ; mkfw_wnd_proc__notify_entries__getdispinfow_state (self, hwnd, msg, wparam, lparam, out_call_def, out_lr); }
	if(mask != 0){ mk_assert(("todo", false)); }
}

static inline void mkfw_wnd_proc__notify_entries__itemchanged(mk_wnd_t* const self, HWND const hwnd, UINT const msg, WPARAM const wparam, LPARAM const lparam, bool* const out_call_def, LRESULT* const out_lr)
{
	LPNMLISTVIEW changed;
	LRESULT lr;
	BOOL b;
	int item_idx_unsorted;
	int item_idx_sorted;
	FWPM_FILTER0* entry;

	mk_assert(self);
	self->m_last_sub_window_focus = mk_wnd_sub_window_id_e_entries;
	changed = ((LPNMLISTVIEW)(lparam)); mk_assert(changed);
	if((changed->iItem != -1) && ((changed->uNewState & LVIS_SELECTED) != 0))
	{
		lr = g_app.m_funcs_user.m_pfn_SendMessageW(self->m_entries, WM_SETREDRAW, FALSE, 0); mk_assert(lr == 0);
		set_max_col_width(self->m_entries, mk_col_id_entry_e_filter, &self->m_max_entries.m_filter);
		set_max_col_width(self->m_entries, mk_col_id_entry_e_provider, &self->m_max_entries.m_provider);
		set_max_col_width(self->m_entries, mk_col_id_entry_e_layer, &self->m_max_entries.m_layer);
		set_max_col_width(self->m_entries, mk_col_id_entry_e_sub_layer, &self->m_max_entries.m_sub_layer);
		set_max_col_width(self->m_entries, mk_col_id_entry_e_action, &self->m_max_entries.m_action);
		set_max_col_width(self->m_entries, mk_col_id_entry_e_callout, &self->m_max_entries.m_callout);
		set_max_col_width(self->m_entries, mk_col_id_entry_e_id, &self->m_max_entries.m_id);
		set_max_col_width(self->m_entries, mk_col_id_entry_e_weight, &self->m_max_entries.m_weight);
		set_max_col_width(self->m_entries, mk_col_id_entry_e_effective_weight, &self->m_max_entries.m_effective_weight);
		lr = g_app.m_funcs_user.m_pfn_SendMessageW(self->m_entries, WM_SETREDRAW, TRUE, 0); mk_assert(lr == 0);
		item_idx_unsorted = changed->iItem;
		mk_assert(item_idx_unsorted >= 0);
		mk_assert(item_idx_unsorted < ((int)(self->m_fw->m_count)));
		item_idx_sorted = self->m_sort_ints[item_idx_unsorted];
		entry = self->m_fw->m_entries[item_idx_sorted];
		self->m_entry_idx_sorted = item_idx_sorted;
		lr = g_app.m_funcs_user.m_pfn_SendMessageW(self->m_conditions, WM_SETREDRAW, FALSE, 0); mk_assert(lr == 0);
		lr = g_app.m_funcs_user.m_pfn_SendMessageW(self->m_conditions, LVM_SETITEMCOUNT, entry->numFilterConditions, 0); mk_assert(lr != 0);
		set_max_col_width(self->m_conditions, mk_col_id_condition_e_field, &self->m_max_conditions.m_field);
		set_max_col_width(self->m_conditions, mk_col_id_condition_e_match_type, &self->m_max_conditions.m_match_type);
		set_max_col_width(self->m_conditions, mk_col_id_condition_e_value_type, &self->m_max_conditions.m_value_type);
		set_max_col_width(self->m_conditions, mk_col_id_condition_e_note, &self->m_max_conditions.m_note);
		lr = g_app.m_funcs_user.m_pfn_SendMessageW(self->m_conditions, WM_SETREDRAW, TRUE, 0); mk_assert(lr == 0);
		b = g_app.m_funcs_user.m_pfn_InvalidateRect(self->m_conditions, NULL, TRUE); mk_assert(b);
		b = g_app.m_funcs_user.m_pfn_UpdateWindow(self->m_conditions); mk_assert(b);
	}
}

static inline void mkfw_wnd_proc__notify_entries__columnclick(mk_wnd_t* const self, HWND const hwnd, UINT const msg, WPARAM const wparam, LPARAM const lparam, bool* const out_call_def, LRESULT* const out_lr)
{
	mk_col_id_entry_t col_id;
	bool direction;
	LPNMLISTVIEW changed;
	int col_idx;

	changed = ((LPNMLISTVIEW)(lparam)); mk_assert(changed);
	col_idx = changed->iSubItem;
	mk_assert(col_idx >= 0);
	mk_assert(col_idx < mk_col_id_entry_e_dummy_end);
	if(changed->iItem == -1)
	{
		mk_col_id_entry_sort_expand(self->m_entries_sort_col, &col_id, &direction);
		if(false){}
		else if(col_id == ((mk_col_id_entry_t)(col_idx)) && direction)
		{
			direction = false;
		}
		else if(col_id == ((mk_col_id_entry_t)(col_idx)) && !direction)
		{
			col_id = mk_col_id_entry_e_dummy_end;
		}
		else
		{
			col_id = ((mk_col_id_entry_t)(col_idx));
			direction = true;
		}
		mkfw_wnd_sort_entries(self, col_id, direction);
	}
}

static inline void mkfw_wnd_delete_selected_entry(mk_wnd_t* const self, LPDWORD const res)
{
	FWPM_FILTER0* entry;
	DWORD dw;

	mk_assert(self);
	mk_assert(res);

	entry = self->m_fw->m_entries[self->m_entry_idx_sorted];
	dw = g_app.m_funcs_fw.m_pfn_FwpmFilterDeleteByKey0(self->m_fw->m_eng, &entry->filterKey);
	*res = dw;
}

[[nodiscard]] static inline mk_view_wstr_t mkfw_wnd_get_del_question(mk_wnd_t* const self)
{
	mk_view_wstr_t name;
	mk_view_wstr_t fmt;
	LPWSTR buf;
	int cap;
	int len;
	mk_view_wstr_t wstr;

	name = entry_to_wstr(self->m_fw->m_entries[self->m_entry_idx_sorted], mk_col_id_entry_e_filter);
	fmt = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_delete_fmt));
	buf = &g_app.m_tmp_wstrs[g_app.m_tmps_wstr_idx++ % _countof(g_app.m_tmp_wstrs)][0];
	cap = _countof(g_app.m_tmp_wstrs[0]);
	len = g_app.m_funcs_ntdll.m_pfn_swprintf(buf, fmt.m_buf, name.m_buf); mk_assert(len >= 1); mk_assert(len < cap);
	wstr.m_buf = buf;
	wstr.m_len = len;
	mk_assert(wstr.m_len >= 0);
	mk_assert(wstr.m_buf[wstr.m_len] == L'\0');
	return wstr;
}

static inline void mk_to_lower(LPWSTR const buf, int const len)
{
	int n;
	int i;

	mk_assert(buf);
	mk_assert(buf[len] == L'\0');
	mk_assert(len >= 1);

	n = len;
	for(i = 0; i != n; ++i)
	{
		if(buf[i] >= L'A' && buf[i] <= L'Z')
		{
			buf[i] = L'a' + (buf[i] - L'A');
		}
	}
}

static inline void mk_last_slash(LPCWSTR const buf, int const len, LPCWSTR* const last)
{
	int t;
	int n;
	int i;

	mk_assert(buf);
	mk_assert(buf[len] == L'\0');
	mk_assert(len >= 1);
	mk_assert(last);

	t = -1;
	n = len;
	for(i = 0; i != n; ++i)
	{
		if(buf[i] == L'\\' || buf[i] == L'/')
		{
			t = i;
		}
	}
	if(t != -1 && t + 1 < len)
	{
		*last = &buf[t + 1];
	}
	else
	{
		*last = NULL;
	}
}

static inline void mkfw_block_exe(mk_fw_t* const fw, LPCWSTR const path_buf, int const path_len, bool* const gud)
{
	bool success;
	SECURITY_ATTRIBUTES sa;
	HANDLE hfile;
	LPWSTR nt_path_buf;
	int nt_path_cap;
	DWORD nt_path_len;
	LPCWSTR exe_name;
	FWPM_FILTER0 filter_ipv4;
	FWPM_FILTER0 filter_ipv6;
	FWPM_FILTER_CONDITION0 conditions_ipv4[3];
	FWPM_FILTER_CONDITION0 conditions_ipv6[2];
	FWP_BYTE_BLOB blob_v4;
	FWP_RANGE0 range_ipv4_a;
	FWP_RANGE0 range_ipv4_b;
	LPWSTR name_ipv4;
	LPWSTR desc_ipv4;
	int len;
	FWP_BYTE_BLOB blob_v6;
	FWP_BYTE_ARRAY16 ipv6_beg;
	FWP_BYTE_ARRAY16 ipv6_end;
	FWP_RANGE0 range_ipv6;
	LPWSTR name_ipv6;
	LPWSTR desc_ipv6;
	DWORD st;

	mk_assert(fw);
	mk_assert(path_buf);
	mk_assert(path_buf[path_len] == L'\0');
	mk_assert(path_len >= 1);
	mk_assert(gud);

	*gud = false;
	success = false;
	mk_make_defer([&](){ *gud = success; });
	sa.nLength = sizeof(sa);
	sa.lpSecurityDescriptor = NULL;
	sa.bInheritHandle = FALSE;
	hfile = g_app.m_funcs_kernel.m_pfn_CreateFileW(path_buf, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(hfile == INVALID_HANDLE_VALUE){ return; }
	mk_make_defer([&](){ BOOL b; b = g_app.m_funcs_kernel.m_pfn_CloseHandle(hfile); mk_assert(b); });
	nt_path_buf = &g_app.m_tmp_wstrs[g_app.m_tmps_wstr_idx++ % _countof(g_app.m_tmp_wstrs)][0];
	nt_path_cap = _countof(g_app.m_tmp_wstrs[0]);
	nt_path_len = g_app.m_funcs_kernel.m_pfn_GetFinalPathNameByHandleW(hfile, &nt_path_buf[0], nt_path_cap, FILE_NAME_NORMALIZED  | VOLUME_NAME_NT);
	if(nt_path_len == 0 || ((int)(nt_path_len)) >= nt_path_cap){ return; }
	mk_to_lower(&nt_path_buf[0], nt_path_len);
	mk_last_slash(&path_buf[0], path_len, &exe_name); if(!exe_name){ return; }

	mk_memclr_c(&filter_ipv4, sizeof(filter_ipv4));
	mk_memclr_c(&filter_ipv6, sizeof(filter_ipv6));
	mk_memclr_c(&conditions_ipv4, sizeof(conditions_ipv4));
	mk_memclr_c(&conditions_ipv6, sizeof(conditions_ipv6));

	blob_v4.size = (nt_path_len + 1) * sizeof(nt_path_buf[0]);
	blob_v4.data = ((UINT8*)(&nt_path_buf[0]));
	conditions_ipv4[0].fieldKey = *((GUID*)(&k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ALE_APP_ID]));
	conditions_ipv4[0].matchType = FWP_MATCH_EQUAL;
	conditions_ipv4[0].conditionValue.type = FWP_BYTE_BLOB_TYPE;
	conditions_ipv4[0].conditionValue.byteBlob = &blob_v4;

	/* 0.0.0.0 - 127.0.0.0 */
	range_ipv4_a.valueLow.type = FWP_UINT32;
	range_ipv4_a.valueLow.uint32 = ((UINT32)(0x00000000ul));
	range_ipv4_a.valueHigh.type = FWP_UINT32;
	range_ipv4_a.valueHigh.uint32 = ((UINT32)(0x7f000000ul));
	conditions_ipv4[1].fieldKey = *((GUID*)(&k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_REMOTE_ADDRESS]));
	conditions_ipv4[1].matchType = FWP_MATCH_RANGE;
	conditions_ipv4[1].conditionValue.type = FWP_RANGE_TYPE;
	conditions_ipv4[1].conditionValue.rangeValue = &range_ipv4_a;

	/* 127.0.0.2 - 255.255.255.255 */
	range_ipv4_b.valueLow.type = FWP_UINT32;
	range_ipv4_b.valueLow.uint32 = ((UINT32)(0x7f000002ul));
	range_ipv4_b.valueHigh.type = FWP_UINT32;
	range_ipv4_b.valueHigh.uint32 = ((UINT32)(0xfffffffful));
	conditions_ipv4[2].fieldKey = *((GUID*)(&k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_REMOTE_ADDRESS]));
	conditions_ipv4[2].matchType = FWP_MATCH_RANGE;
	conditions_ipv4[2].conditionValue.type = FWP_RANGE_TYPE;
	conditions_ipv4[2].conditionValue.rangeValue = &range_ipv4_b;

	name_ipv4 = &g_app.m_tmp_wstrs[g_app.m_tmps_wstr_idx++ % _countof(g_app.m_tmp_wstrs)][0];
	desc_ipv4 = &g_app.m_tmp_wstrs[g_app.m_tmps_wstr_idx++ % _countof(g_app.m_tmp_wstrs)][0];
	len = g_app.m_funcs_ntdll.m_pfn_swprintf(name_ipv4, nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_fmt_block_ipv4_name)).m_buf, exe_name); if(!(len >= 1 && len < nt_path_cap)){ return; }
	len = g_app.m_funcs_ntdll.m_pfn_swprintf(desc_ipv4, nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_fmt_block_ipv4_desc)).m_buf, path_buf); if(!(len >= 1 && len < nt_path_cap)){ return; }
	filter_ipv4.displayData.name = name_ipv4;
	filter_ipv4.displayData.description = desc_ipv4;
	filter_ipv4.providerKey = ((GUID*)(&k_konst.m_guids.m_guids[guid_id_e_FWPM_PROVIDER_MPSSVC_WF]));
	filter_ipv4.layerKey = *((GUID*)(&k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_CONNECT_V4]));
	filter_ipv4.subLayerKey = *((GUID*)(&k_konst.m_guids.m_guids[guid_id_e_FWPM_SUBLAYER_MPSSVC_WF]));
	filter_ipv4.action.type = FWP_ACTION_BLOCK;
	filter_ipv4.numFilterConditions = 3;
	filter_ipv4.filterCondition = &conditions_ipv4[0];
	filter_ipv4.weight.type = FWP_UINT8;
	filter_ipv4.weight.uint8 = 10;

	blob_v6.size = (nt_path_len + 1) * sizeof(nt_path_buf[0]);
	blob_v6.data = ((UINT8*)(&nt_path_buf[0]));
	conditions_ipv6[0].fieldKey = *((GUID*)(&k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_ALE_APP_ID]));
	conditions_ipv6[0].matchType = FWP_MATCH_EQUAL;
	conditions_ipv6[0].conditionValue.type = FWP_BYTE_BLOB_TYPE;
	conditions_ipv6[0].conditionValue.byteBlob = &blob_v6;

	ipv6_beg.byteArray16[ 0] = 0x00;
	ipv6_beg.byteArray16[ 1] = 0x00;
	ipv6_beg.byteArray16[ 2] = 0x00;
	ipv6_beg.byteArray16[ 3] = 0x00;
	ipv6_beg.byteArray16[ 4] = 0x00;
	ipv6_beg.byteArray16[ 5] = 0x00;
	ipv6_beg.byteArray16[ 6] = 0x00;
	ipv6_beg.byteArray16[ 7] = 0x00;
	ipv6_beg.byteArray16[ 8] = 0x00;
	ipv6_beg.byteArray16[ 9] = 0x00;
	ipv6_beg.byteArray16[10] = 0x00;
	ipv6_beg.byteArray16[11] = 0x00;
	ipv6_beg.byteArray16[12] = 0x00;
	ipv6_beg.byteArray16[13] = 0x00;
	ipv6_beg.byteArray16[14] = 0x00;
	ipv6_beg.byteArray16[15] = 0x00;
	ipv6_end.byteArray16[ 0] = 0xff;
	ipv6_end.byteArray16[ 1] = 0xff;
	ipv6_end.byteArray16[ 2] = 0xff;
	ipv6_end.byteArray16[ 3] = 0xff;
	ipv6_end.byteArray16[ 4] = 0xff;
	ipv6_end.byteArray16[ 5] = 0xff;
	ipv6_end.byteArray16[ 6] = 0xff;
	ipv6_end.byteArray16[ 7] = 0xff;
	ipv6_end.byteArray16[ 8] = 0xff;
	ipv6_end.byteArray16[ 9] = 0xff;
	ipv6_end.byteArray16[10] = 0xff;
	ipv6_end.byteArray16[11] = 0xff;
	ipv6_end.byteArray16[12] = 0xff;
	ipv6_end.byteArray16[13] = 0xff;
	ipv6_end.byteArray16[14] = 0xff;
	ipv6_end.byteArray16[15] = 0xff;
	range_ipv6.valueLow.type = FWP_BYTE_ARRAY16_TYPE;
	range_ipv6.valueLow.byteArray16 = &ipv6_beg;
	range_ipv6.valueHigh.type = FWP_BYTE_ARRAY16_TYPE;
	range_ipv6.valueHigh.byteArray16 = &ipv6_end;
	conditions_ipv6[1].fieldKey = *((GUID*)(&k_konst.m_guids.m_guids[guid_id_e_FWPM_CONDITION_IP_REMOTE_ADDRESS]));
	conditions_ipv6[1].matchType = FWP_MATCH_RANGE;
	conditions_ipv6[1].conditionValue.type = FWP_RANGE_TYPE;
	conditions_ipv6[1].conditionValue.rangeValue = &range_ipv6;

	name_ipv6 = &g_app.m_tmp_wstrs[g_app.m_tmps_wstr_idx++ % _countof(g_app.m_tmp_wstrs)][0];
	desc_ipv6 = &g_app.m_tmp_wstrs[g_app.m_tmps_wstr_idx++ % _countof(g_app.m_tmp_wstrs)][0];
	len = g_app.m_funcs_ntdll.m_pfn_swprintf(name_ipv6, nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_fmt_block_ipv6_name)).m_buf, exe_name); if(!(len >= 1 && len < nt_path_cap)){ return; }
	len = g_app.m_funcs_ntdll.m_pfn_swprintf(desc_ipv6, nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_fmt_block_ipv6_desc)).m_buf, path_buf); if(!(len >= 1 && len < nt_path_cap)){ return; }
	filter_ipv6.displayData.name = name_ipv6;
	filter_ipv6.displayData.description = desc_ipv6;
	filter_ipv6.providerKey = ((GUID*)(&k_konst.m_guids.m_guids[guid_id_e_FWPM_PROVIDER_MPSSVC_WF]));
	filter_ipv6.layerKey = *((GUID*)(&k_konst.m_guids.m_guids[guid_id_e_FWPM_LAYER_ALE_AUTH_CONNECT_V6]));
	filter_ipv6.subLayerKey = *((GUID*)(&k_konst.m_guids.m_guids[guid_id_e_FWPM_SUBLAYER_MPSSVC_WF]));
	filter_ipv6.action.type = FWP_ACTION_BLOCK;
	filter_ipv6.numFilterConditions = 2;
	filter_ipv6.filterCondition = &conditions_ipv6[0];
	filter_ipv6.weight.type = FWP_UINT8;
	filter_ipv6.weight.uint8 = 10;

	success = false;
	st = g_app.m_funcs_fw.m_pfn_FwpmTransactionBegin0(fw->m_eng, 0); if(st != ERROR_SUCCESS){ return; }
	mk_make_defer([&](){ DWORD st; if(!success){ st = g_app.m_funcs_fw.m_pfn_FwpmTransactionAbort0(fw->m_eng); ((void)(st)); } });
	st = g_app.m_funcs_fw.m_pfn_FwpmFilterAdd0(fw->m_eng, &filter_ipv4, NULL, NULL); if(st != ERROR_SUCCESS){ return; }
	st = g_app.m_funcs_fw.m_pfn_FwpmFilterAdd0(fw->m_eng, &filter_ipv6, NULL, NULL); if(st != ERROR_SUCCESS){ return; }
	st = g_app.m_funcs_fw.m_pfn_FwpmTransactionCommit0(fw->m_eng); if(st != ERROR_SUCCESS){ return; }
	success = true;
}

static inline void mkfw_wnd_insert(mk_wnd_t* const self)
{
	LPWSTR path_buf;
	int path_cap;
	OPENFILENAMEW name;
	BOOL b;
	int len;
	bool success;
	int res;

	mk_assert(self);
	mk_assert(self->m_fw);

	path_buf = &g_app.m_tmp_wstrs[g_app.m_tmps_wstr_idx++ % _countof(g_app.m_tmp_wstrs)][0];
	path_cap = _countof(g_app.m_tmp_wstrs[0]);
	path_buf[0] = L'\0';
	mk_memclr_c(&name, sizeof(name));
	name.lStructSize = sizeof(name);
	name.hwndOwner = self->m_hwnd;
	name.lpstrFilter = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_open_filter)).m_buf;
	name.lpstrFile = path_buf;
	name.nMaxFile = path_cap;
	name.lpstrTitle = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_open_title)).m_buf;
	name.Flags = OFN_HIDEREADONLY | OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_EXPLORER | OFN_ENABLESIZING;
	b = g_app.m_funcs_comdlg.m_pfn_GetOpenFileNameW(&name);
	if(b && name.lpstrFile && name.lpstrFile[0] != L'\0')
	{
		len = (int)mk_wcslen_c(name.lpstrFile);
		mkfw_block_exe(self->m_fw, name.lpstrFile, len, &success);
		mkfw_wnd_refresh(self);
		if(success)
		{
			res = g_app.m_funcs_user.m_pfn_MessageBoxW(self->m_hwnd, nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_block_added)).m_buf, nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_fire_wall)).m_buf, MB_OK | MB_ICONINFORMATION); ((void)(res));
		}
	}
}

static inline void mkfw_wnd_proc__notify_entries___keydown_tab(mk_wnd_t* const self, HWND const hwnd, UINT const msg, WPARAM const wparam, LPARAM const lparam, bool* const out_call_def, LRESULT* const out_lr)
{
	HWND prev;

	mk_assert(self);

	self->m_last_sub_window_focus = mk_wnd_sub_window_id_e_conditions;
	prev = g_app.m_funcs_user.m_pfn_SetFocus(self->m_conditions); ((void)(prev));
}

static inline void mkfw_wnd_proc__notify_entries___keydown_ins(mk_wnd_t* const self, HWND const hwnd, UINT const msg, WPARAM const wparam, LPARAM const lparam, bool* const out_call_def, LRESULT* const out_lr)
{
	mkfw_wnd_insert(self);
}

static inline void mkfw_wnd_proc__notify_entries___keydown_del(mk_wnd_t* const self, HWND const hwnd, UINT const msg, WPARAM const wparam, LPARAM const lparam, bool* const out_call_def, LRESULT* const out_lr)
{
	mk_view_wstr_t question_text;
	mk_view_wstr_t question_caption;
	int res;
	DWORD dw;
	mk_view_wstr_t ok_text;
	mk_view_wstr_t ok_caption;

	question_text = mkfw_wnd_get_del_question(self);
	question_caption = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_delete_caption));
	res = g_app.m_funcs_user.m_pfn_MessageBoxW(self->m_hwnd, question_text.m_buf, question_caption.m_buf, MB_YESNO | MB_DEFBUTTON2 | MB_ICONQUESTION);
	if(res == IDYES)
	{
		mkfw_wnd_delete_selected_entry(self, &dw);
		if(dw == ERROR_SUCCESS)
		{
			ok_text = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_delete_ok_text));
			ok_caption = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_delete_ok_caption));
			res = g_app.m_funcs_user.m_pfn_MessageBoxW(self->m_hwnd, ok_text.m_buf, ok_caption.m_buf, MB_OK | MB_ICONINFORMATION); ((void)(res));
			mkfw_wnd_refresh(self);
		}
		else
		{
			/* todo show error */
		}
	}
}

static inline void mkfw_wnd_proc__notify_entries___keydown_apps(mk_wnd_t* const self, HWND const hwnd, UINT const msg, WPARAM const wparam, LPARAM const lparam, bool* const out_call_def, LRESULT* const out_lr)
{
	mkfw_wnd_on_key_apps(self, self->m_entries);
}

static inline void mkfw_wnd_proc__notify_entries___keydown_f5(mk_wnd_t* const self, HWND const hwnd, UINT const msg, WPARAM const wparam, LPARAM const lparam, bool* const out_call_def, LRESULT* const out_lr)
{
	mkfw_wnd_refresh(self);
}

static inline void mkfw_wnd_proc__notify_entries__keydown(mk_wnd_t* const self, HWND const hwnd, UINT const msg, WPARAM const wparam, LPARAM const lparam, bool* const out_call_def, LRESULT* const out_lr)
{
	LPNMLVKEYDOWN keydown;

	keydown = ((LPNMLVKEYDOWN)(lparam));
	mk_assert(keydown);
	switch(keydown->wVKey)
	{
		case VK_TAB   : mkfw_wnd_proc__notify_entries___keydown_tab (self, hwnd, msg, wparam, lparam, out_call_def, out_lr); break;
		case VK_INSERT: mkfw_wnd_proc__notify_entries___keydown_ins (self, hwnd, msg, wparam, lparam, out_call_def, out_lr); break;
		case VK_DELETE: mkfw_wnd_proc__notify_entries___keydown_del (self, hwnd, msg, wparam, lparam, out_call_def, out_lr); break;
		case VK_APPS  : mkfw_wnd_proc__notify_entries___keydown_apps(self, hwnd, msg, wparam, lparam, out_call_def, out_lr); break;
		case VK_F5    : mkfw_wnd_proc__notify_entries___keydown_f5  (self, hwnd, msg, wparam, lparam, out_call_def, out_lr); break;
	}
}

static inline void mkfw_wnd_proc__notify_entries(mk_wnd_t* const self, HWND const hwnd, UINT const msg, WPARAM const wparam, LPARAM const lparam, bool* const out_call_def, LRESULT* const out_lr)
{
	LPNMHDR nm_hdr;

	nm_hdr = ((LPNMHDR)(lparam)); mk_assert(nm_hdr);
	if(false){}
	else if(nm_hdr->code == NM_RCLICK       ){ mkfw_wnd_proc__notify_entries__rclick      (self, hwnd, msg, wparam, lparam, out_call_def, out_lr); }
	else if(nm_hdr->code == LVN_GETDISPINFOW){ mkfw_wnd_proc__notify_entries__getdispinfow(self, hwnd, msg, wparam, lparam, out_call_def, out_lr); }
	else if(nm_hdr->code == LVN_ITEMCHANGED ){ mkfw_wnd_proc__notify_entries__itemchanged (self, hwnd, msg, wparam, lparam, out_call_def, out_lr); }
	else if(nm_hdr->code == LVN_COLUMNCLICK ){ mkfw_wnd_proc__notify_entries__columnclick (self, hwnd, msg, wparam, lparam, out_call_def, out_lr); }
	else if(nm_hdr->code == LVN_KEYDOWN     ){ mkfw_wnd_proc__notify_entries__keydown     (self, hwnd, msg, wparam, lparam, out_call_def, out_lr); }
}

static inline void mkfw_wnd_proc__notify_conditions__rclick(mk_wnd_t* const self, HWND const hwnd, UINT const msg, WPARAM const wparam, LPARAM const lparam, bool* const out_call_def, LRESULT* const out_lr)
{
	mkfw_wnd_on_rclick(self, self->m_conditions, lparam);
}

static inline void mkfw_wnd_proc__notify_conditions__getdispinfow_text(mk_wnd_t* const self, HWND const hwnd, UINT const msg, WPARAM const wparam, LPARAM const lparam, bool* const out_call_def, LRESULT* const out_lr)
{
	LPNMLVDISPINFOW disp_info;
	int item_idx;
	FWPM_FILTER0* entry;
	FWPM_FILTER_CONDITION0* condition;
	int col_idx;
	mk_col_id_condition_t col_id;
	mk_view_wstr_t wstr;

	mk_assert(self);
	mk_assert(self->m_fw);
	mk_assert(self->m_fw->m_entries);
	disp_info = ((LPNMLVDISPINFOW)(lparam)); mk_assert(disp_info);
	wstr = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_questions));
	disp_info->item.pszText = ((LPWSTR)(wstr.m_buf));
	mk_assert(disp_info->item.pszText);
	item_idx = self->m_entry_idx_sorted;
	if((item_idx >= 0) && (item_idx < ((int)(self->m_fw->m_count))))
	{
		entry = self->m_fw->m_entries[self->m_entry_idx_sorted];
		item_idx = disp_info->item.iItem;
		if((item_idx >= 0) && (item_idx < ((int)(entry->numFilterConditions))))
		{
			mk_assert(entry->filterCondition);
			condition = &entry->filterCondition[item_idx];
			col_idx = disp_info->item.iSubItem;
			if((col_idx >= 0) && (col_idx < mk_col_id_condition_e_dummy_end))
			{
				col_id = ((mk_col_id_condition_t)(col_idx));
				wstr = condition_entry_to_wstr_any(entry, condition, col_id);
				disp_info->item.pszText = ((LPWSTR)(wstr.m_buf));
				mk_assert(disp_info->item.pszText);
			}
		}
	}
}

static inline void mkfw_wnd_proc__notify_conditions__getdispinfow_indent(mk_wnd_t* const self, HWND const hwnd, UINT const msg, WPARAM const wparam, LPARAM const lparam, bool* const out_call_def, LRESULT* const out_lr)
{
	LPNMLVDISPINFOW disp_info;

	disp_info = ((LPNMLVDISPINFOW)(lparam));
	disp_info->item.iIndent = 0;
}

static inline void mkfw_wnd_proc__notify_conditions__getdispinfow_image(mk_wnd_t* const self, HWND const hwnd, UINT const msg, WPARAM const wparam, LPARAM const lparam, bool* const out_call_def, LRESULT* const out_lr)
{
	LPNMLVDISPINFOW disp_info;

	disp_info = ((LPNMLVDISPINFOW)(lparam));
	disp_info->item.iImage = 0;
}

static inline void mkfw_wnd_proc__notify_conditions__getdispinfow_state(mk_wnd_t* const self, HWND const hwnd, UINT const msg, WPARAM const wparam, LPARAM const lparam, bool* const out_call_def, LRESULT* const out_lr)
{
	LPNMLVDISPINFOW disp_info;

	disp_info = ((LPNMLVDISPINFOW)(lparam));
	disp_info->item.state = 0;
}

static inline void mkfw_wnd_proc__notify_conditions__getdispinfow(mk_wnd_t* const self, HWND const hwnd, UINT const msg, WPARAM const wparam, LPARAM const lparam, bool* const out_call_def, LRESULT* const out_lr)
{
	LPNMLVDISPINFOW disp_info;
	UINT mask;

	disp_info = ((LPNMLVDISPINFOW)(lparam));
	mask = disp_info->item.mask;
	if((mask & LVIF_TEXT  ) != 0){ mask &=~ LVIF_TEXT  ; mkfw_wnd_proc__notify_conditions__getdispinfow_text  (self, hwnd, msg, wparam, lparam, out_call_def, out_lr); }
	if((mask & LVIF_INDENT) != 0){ mask &=~ LVIF_INDENT; mkfw_wnd_proc__notify_conditions__getdispinfow_indent(self, hwnd, msg, wparam, lparam, out_call_def, out_lr); }
	if((mask & LVIF_IMAGE ) != 0){ mask &=~ LVIF_IMAGE ; mkfw_wnd_proc__notify_conditions__getdispinfow_image (self, hwnd, msg, wparam, lparam, out_call_def, out_lr); }
	if((mask & LVIF_STATE ) != 0){ mask &=~ LVIF_STATE ; mkfw_wnd_proc__notify_conditions__getdispinfow_state (self, hwnd, msg, wparam, lparam, out_call_def, out_lr); }
	if(mask != 0){ mk_assert(("todo", false)); }
}

static inline void mkfw_wnd_proc__notify_conditions__itemchanged(mk_wnd_t* const self, HWND const hwnd, UINT const msg, WPARAM const wparam, LPARAM const lparam, bool* const out_call_def, LRESULT* const out_lr)
{
	LPNMLISTVIEW changed;
	int item_idx;

	mk_assert(self);

	self->m_last_sub_window_focus = mk_wnd_sub_window_id_e_conditions;
	changed = ((LPNMLISTVIEW)(lparam)); mk_assert(changed);
	if((changed->iItem != -1) && ((changed->uNewState & LVIS_SELECTED) != 0))
	{
		item_idx = changed->iItem;
		self->m_condition_row = item_idx;
	}
}

static inline void mkfw_wnd_proc__notify_conditions___keydown_tab(mk_wnd_t* const self, HWND const hwnd, UINT const msg, WPARAM const wparam, LPARAM const lparam, bool* const out_call_def, LRESULT* const out_lr)
{
	HWND prev;

	mk_assert(self);

	self->m_last_sub_window_focus = mk_wnd_sub_window_id_e_entries;
	prev = g_app.m_funcs_user.m_pfn_SetFocus(self->m_entries); ((void)(prev));
}

static inline void mkfw_wnd_proc__notify_conditions___keydown_apps(mk_wnd_t* const self, HWND const hwnd, UINT const msg, WPARAM const wparam, LPARAM const lparam, bool* const out_call_def, LRESULT* const out_lr)
{
	mkfw_wnd_on_key_apps(self, self->m_conditions);
}

static inline void mkfw_wnd_proc__notify_conditions___keydown_f5(mk_wnd_t* const self, HWND const hwnd, UINT const msg, WPARAM const wparam, LPARAM const lparam, bool* const out_call_def, LRESULT* const out_lr)
{
	mkfw_wnd_refresh(self);
}

static inline void mkfw_wnd_proc__notify_conditions__keydown(mk_wnd_t* const self, HWND const hwnd, UINT const msg, WPARAM const wparam, LPARAM const lparam, bool* const out_call_def, LRESULT* const out_lr)
{
	LPNMLVKEYDOWN keydown;

	keydown = ((LPNMLVKEYDOWN)(lparam));
	mk_assert(keydown);
	switch(keydown->wVKey)
	{
		case VK_TAB : mkfw_wnd_proc__notify_conditions___keydown_tab (self, hwnd, msg, wparam, lparam, out_call_def, out_lr); break;
		case VK_APPS: mkfw_wnd_proc__notify_conditions___keydown_apps(self, hwnd, msg, wparam, lparam, out_call_def, out_lr); break;
		case VK_F5  : mkfw_wnd_proc__notify_conditions___keydown_f5  (self, hwnd, msg, wparam, lparam, out_call_def, out_lr); break;
	}
}

static inline void mkfw_wnd_proc__notify_conditions(mk_wnd_t* const self, HWND const hwnd, UINT const msg, WPARAM const wparam, LPARAM const lparam, bool* const out_call_def, LRESULT* const out_lr)
{
	LPNMHDR nm_hdr;

	nm_hdr = ((LPNMHDR)(lparam)); mk_assert(nm_hdr);
	if(false){}
	else if(nm_hdr->code == NM_RCLICK       ){ mkfw_wnd_proc__notify_conditions__rclick      (self, hwnd, msg, wparam, lparam, out_call_def, out_lr); }
	else if(nm_hdr->code == LVN_GETDISPINFOW){ mkfw_wnd_proc__notify_conditions__getdispinfow(self, hwnd, msg, wparam, lparam, out_call_def, out_lr); }
	else if(nm_hdr->code == LVN_ITEMCHANGED ){ mkfw_wnd_proc__notify_conditions__itemchanged (self, hwnd, msg, wparam, lparam, out_call_def, out_lr); }
	else if(nm_hdr->code == LVN_KEYDOWN     ){ mkfw_wnd_proc__notify_conditions__keydown     (self, hwnd, msg, wparam, lparam, out_call_def, out_lr); }
}

static inline void mkfw_wnd__proc_notify(mk_wnd_t* const self, HWND const hwnd, UINT const msg, WPARAM const wparam, LPARAM const lparam, bool* const out_call_def, LRESULT* const out_lr)
{
	LPNMHDR nm_hdr;

	nm_hdr = ((LPNMHDR)(lparam));
	mk_assert(nm_hdr);
	if(false){}
	else if(nm_hdr->hwndFrom == self->m_entries   ){ mkfw_wnd_proc__notify_entries   (self, hwnd, msg, wparam, lparam, out_call_def, out_lr); }
	else if(nm_hdr->hwndFrom == self->m_conditions){ mkfw_wnd_proc__notify_conditions(self, hwnd, msg, wparam, lparam, out_call_def, out_lr); }
}

static inline void mkfw_wnd__proc__command__menu_copy_cell(mk_wnd_t* const self, HWND const hwnd, UINT const msg, WPARAM const wparam, LPARAM const lparam, bool* const out_call_def, LRESULT* const out_lr)
{
	mk_fw_copy_cell(self);
}

static inline void mkfw_wnd__proc__command__menu_copy_line(mk_wnd_t* const self, HWND const hwnd, UINT const msg, WPARAM const wparam, LPARAM const lparam, bool* const out_call_def, LRESULT* const out_lr)
{
	HWND list_view;
	int entry_idx;
	FWPM_FILTER0* entry;
	int condition_idx;
	FWPM_FILTER_CONDITION0* condition;
	mk_view_wstr_t wstr;

	SIZE_T bytes_count;
	HGLOBAL gl;
	LPVOID ptr;
	BOOL b;
	HANDLE h;

	mk_assert(self);
	mk_assert(self->m_list_view_for_menu);

	list_view = self->m_list_view_for_menu;
	entry_idx = self->m_entry_idx_sorted;
	entry = self->m_fw->m_entries[entry_idx];
	condition_idx = self->m_condition_row;
	condition_idx = mk_clamp(condition_idx, 0, ((int)(entry->numFilterConditions)));
	condition = &entry->filterCondition[condition_idx];
	if(false){}
	else if(list_view == self->m_entries   ){ wstr = entry_to_wstr_line(entry); }
	else if(list_view == self->m_conditions){ wstr = condition_entry_to_wstr_line(entry, condition); }
	else{ mk_assert(false); }

	bytes_count = (wstr.m_len + 1) * sizeof(*wstr.m_buf);
	gl = g_app.m_funcs_kernel.m_pfn_GlobalAlloc(GMEM_MOVEABLE, bytes_count); mk_assert(gl);
	ptr = g_app.m_funcs_kernel.m_pfn_GlobalLock(gl); mk_assert(ptr);
	mk_memcpy_c(ptr, wstr.m_buf, bytes_count);
	b = g_app.m_funcs_kernel.m_pfn_GlobalUnlock(gl); mk_assert(b == 0 && GetLastError() == NO_ERROR);

	b = g_app.m_funcs_kernel.m_pfn_HeapFree(g_app.m_funcs_kernel.m_pfn_GetProcessHeap(), 0, ((LPVOID)(wstr.m_buf))); mk_assert(b);

	b = g_app.m_funcs_user.m_pfn_OpenClipboard(self->m_conditions); mk_assert(b);
	b = g_app.m_funcs_user.m_pfn_EmptyClipboard(); mk_assert(b);
	h = g_app.m_funcs_user.m_pfn_SetClipboardData(CF_UNICODETEXT, gl); mk_assert(h);
	b = g_app.m_funcs_user.m_pfn_CloseClipboard(); mk_assert(b);
}

static inline void mkfw_wnd__proc__command__menu_copy_table(mk_wnd_t* const self, HWND const hwnd, UINT const msg, WPARAM const wparam, LPARAM const lparam, bool* const out_call_def, LRESULT* const out_lr)
{
	HWND list_view;
	int entry_idx;
	FWPM_FILTER0* entry;
	mk_view_wstr_t wstr;

	SIZE_T bytes_count;
	HGLOBAL gl;
	LPVOID ptr;
	BOOL b;
	HANDLE h;

	list_view = self->m_list_view_for_menu;
	entry_idx = self->m_entry_idx_sorted;
	entry = self->m_fw->m_entries[entry_idx];
	if(false){}
	else if(list_view == self->m_entries   ){ wstr = filter_to_wstr_table(self); }
	else if(list_view == self->m_conditions){ wstr = condition_entry_to_wstr_table(entry); }
	else{ mk_assert(false); }

	bytes_count = (wstr.m_len + 1) * sizeof(*wstr.m_buf);
	gl = g_app.m_funcs_kernel.m_pfn_GlobalAlloc(GMEM_MOVEABLE, bytes_count); mk_assert(gl);
	ptr = g_app.m_funcs_kernel.m_pfn_GlobalLock(gl); mk_assert(ptr);
	mk_memcpy_c(ptr, wstr.m_buf, bytes_count);
	b = g_app.m_funcs_kernel.m_pfn_GlobalUnlock(gl); mk_assert(b == 0 && GetLastError() == NO_ERROR);

	b = g_app.m_funcs_kernel.m_pfn_HeapFree(g_app.m_funcs_kernel.m_pfn_GetProcessHeap(), 0, ((LPVOID)(wstr.m_buf))); mk_assert(b);

	b = g_app.m_funcs_user.m_pfn_OpenClipboard(self->m_conditions); mk_assert(b);
	b = g_app.m_funcs_user.m_pfn_EmptyClipboard(); mk_assert(b);
	h = g_app.m_funcs_user.m_pfn_SetClipboardData(CF_UNICODETEXT, gl); mk_assert(h);
	b = g_app.m_funcs_user.m_pfn_CloseClipboard(); mk_assert(b);
}

static inline void mkfw_wnd__proc__command_menu(mk_wnd_t* const self, HWND const hwnd, UINT const msg, WPARAM const wparam, LPARAM const lparam, bool* const out_call_def, LRESULT* const out_lr)
{
	int menu_idx;
	menu_id_e menu_id;

	menu_idx = LOWORD(wparam);
	mk_assert(menu_idx >= 0);
	mk_assert(menu_idx < menu_id_e_dummy_end);
	menu_id = ((menu_id_e)(menu_idx));
	switch(menu_id)
	{
		case menu_id_e_copy_cell : mkfw_wnd__proc__command__menu_copy_cell (self, hwnd, msg, wparam, lparam, out_call_def, out_lr); break;
		case menu_id_e_copy_line : mkfw_wnd__proc__command__menu_copy_line (self, hwnd, msg, wparam, lparam, out_call_def, out_lr); break;
		case menu_id_e_copy_table: mkfw_wnd__proc__command__menu_copy_table(self, hwnd, msg, wparam, lparam, out_call_def, out_lr); break;
		case menu_id_e_dummy_end: mk_assert(false); break;
		default: mk_assert(false); break;
	}
}

static inline void mkfw_wnd__proc_command(mk_wnd_t* const self, HWND const hwnd, UINT const msg, WPARAM const wparam, LPARAM const lparam, bool* const out_call_def, LRESULT* const out_lr)
{
	if(HIWORD(wparam) == 0 && lparam == 0){ mkfw_wnd__proc__command_menu(self, hwnd, msg, wparam, lparam, out_call_def, out_lr); }
}

[[nodiscard]] static inline LRESULT CALLBACK mkfw_wnd_proc(HWND const hwnd, UINT const msg, WPARAM const wparam, LPARAM const lparam)
{
	bool call_def;
	LRESULT lr;
	LONG_PTR ptr;
	mk_wnd_t* self;

	call_def = true;
	lr = 0;
	ptr = g_app.m_funcs_user.m_pfn_GetWindowLongPtrW(hwnd, GWLP_USERDATA);
	self = ((mk_wnd_t*)(ptr));
	switch(msg)
	{
		case WM_CREATE  : mkfw_wnd__proc_create  (self, hwnd, msg, wparam, lparam, &call_def, &lr); break;
		case WM_DESTROY : mkfw_wnd__proc_destroy (self, hwnd, msg, wparam, lparam, &call_def, &lr); break;
		case WM_SIZE    : mkfw_wnd__proc_size    (self, hwnd, msg, wparam, lparam, &call_def, &lr); break;
		case WM_SETFOCUS: mkfw_wnd__proc_setfocus(self, hwnd, msg, wparam, lparam, &call_def, &lr); break;
		case WM_NOTIFY  : mkfw_wnd__proc_notify  (self, hwnd, msg, wparam, lparam, &call_def, &lr); break;
		case WM_COMMAND : mkfw_wnd__proc_command (self, hwnd, msg, wparam, lparam, &call_def, &lr); break;
		break;
	}
	if(call_def)
	{
		lr = g_app.m_funcs_user.m_pfn_DefWindowProcW(hwnd, msg, wparam, lparam);
	}
	return lr;
}


extern "C" DWORD __stdcall mk_entry(PPEB const peb)
{
	WNDCLASSEXW wnd_cls_info;
	ATOM wnd_cls_atom;
	HWND hwnd;
	BOOL b;
	MSG msg;
	LRESULT lr;

	mk_assert(mk_guids_test());
	mk_assert(matches_test());
	mk_assert(types_test());

	mkfw_load_all(peb);
	fw_construct(&g_app.m_fw);
	wnd_cls_info.cbSize = sizeof(wnd_cls_info);
	wnd_cls_info.style = CS_VREDRAW | CS_HREDRAW;
	wnd_cls_info.lpfnWndProc = &mkfw_wnd_proc;
	wnd_cls_info.cbClsExtra = 0;
	wnd_cls_info.cbWndExtra = sizeof(mk_wnd_t*);
	wnd_cls_info.hInstance = g_app.m_dlls.m_exe;
	wnd_cls_info.hIcon = g_app.m_funcs_user.m_pfn_LoadIconW(NULL, IDI_APPLICATION);
	wnd_cls_info.hCursor = g_app.m_funcs_user.m_pfn_LoadCursorW(NULL, IDC_ARROW);
	wnd_cls_info.hbrBackground = ((HBRUSH)(COLOR_APPWORKSPACE + 1));
	wnd_cls_info.lpszMenuName = NULL;
	wnd_cls_info.lpszClassName = nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_mkfw)).m_buf;
	wnd_cls_info.hIconSm = g_app.m_funcs_user.m_pfn_LoadIconW(NULL, IDI_APPLICATION);
	wnd_cls_atom = g_app.m_funcs_user.m_pfn_RegisterClassExW(&wnd_cls_info); mk_assert(wnd_cls_atom);
	g_app.m_fw_wnd.m_fw = &g_app.m_fw;
	hwnd = g_app.m_funcs_user.m_pfn_CreateWindowExW(WS_EX_APPWINDOW, ((LPCWSTR)(wnd_cls_atom)), nstr_to_wstr(k_konst.m_strings.get_nstr(k_konst.m_strings.string_id::id_fire_wall)).m_buf, WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, NULL, NULL, g_app.m_dlls.m_exe, &g_app.m_fw_wnd); mk_assert(hwnd);
	b = g_app.m_funcs_user.m_pfn_ShowWindow(hwnd, SW_SHOWDEFAULT); ((void)(b));
	for(;;)
	{
		b = g_app.m_funcs_user.m_pfn_PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE);
		if(!b)
		{
			b = g_app.m_funcs_user.m_pfn_GetMessageW(&msg, NULL, 0, 0); mk_assert((b == TRUE) || (b == FALSE && msg.message == WM_QUIT));
		}
		if(msg.message == WM_QUIT)
		{
			break;
		}
		b = g_app.m_funcs_user.m_pfn_TranslateMessage(&msg); ((void)(b));
		lr = g_app.m_funcs_user.m_pfn_DispatchMessageW(&msg); ((void)(lr));
	}
	fw_destroy(&g_app.m_fw);
	g_app.m_funcs_kernel.m_pfn_ExitProcess(((UINT)(msg.wParam)));
	return 0;
}

/*
int main()
{
	mk_entry(((PPEB)(__readgsqword(0x60))));
}
*/
