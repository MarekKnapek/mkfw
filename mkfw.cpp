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
	x(wnd_cls_name_list_view, "SysListView32") \

#define mk_x_guids_n() \
	x(FWPM_PROVIDER_CONTEXT_SECURE_SOCKET_AUTHIP) \
	x(FWPM_PROVIDER_CONTEXT_SECURE_SOCKET_IPSEC) \
	x(FWPM_PROVIDER_IKEEXT) \
	x(FWPM_PROVIDER_IPSEC_DOSP_CONFIG) \
	x(FWPM_PROVIDER_MPSSVC_APP_ISOLATION) \
	x(FWPM_PROVIDER_MPSSVC_EDP) \
	x(FWPM_PROVIDER_MPSSVC_TENANT_RESTRICTIONS) \
	x(FWPM_PROVIDER_MPSSVC_WF) \
	x(FWPM_PROVIDER_MPSSVC_WSH) \
	x(FWPM_PROVIDER_TCP_CHIMNEY_OFFLOAD) \
	x(FWPM_PROVIDER_TCP_TEMPLATES) \


#define x(name) typedef decltype(&name) tfn_##name;
mk_x_all_funcs()
#undef x

constexpr static inline int mk_guids_get_count(void)
{
	GUID const* const guids[] =
	{
		#define x(name) &name,
		mk_x_guids_n()
		#undef x
	};

	int cnt;

	cnt = _countof(guids);
	return cnt;
}

constexpr static inline auto mk_guids_get_descriptions_longest(void)
{
	int mx;
	int len;

	mx = 0;
	#define x(name) len = _countof(#name) - 1; mx = len > mx ? len : mx;
	mk_x_guids_n()
	#undef x
	return mx;
}

constexpr static inline auto mk_guids_get_all_descriptions_len(void)
{
	int len;

	len = 0;
	#define x(name) len += _countof(#name) - 1;
	mk_x_guids_n()
	#undef x
	return len;
}

static GUID const* const k_guids_raw[] = 
{
	#define x(name) &name,
	mk_x_guids_n()
	#undef x
};

struct mk_guids_s
{
	GUID const* const* m_guids;
	int m_desc_lens[mk_guids_get_count()];
	int m_desc_offs[mk_guids_get_count()];
	char m_descs_str[mk_guids_get_all_descriptions_len()];
};
typedef struct mk_guids_s mk_guids_t;

constexpr static inline auto make_guids(void)
{
	int i;
	mk_guids_t guids;

	i = 0;
	guids.m_guids = &k_guids_raw[0];
	#define x(name) \
		guids.m_desc_lens[i] = _countof(#name) - 1; \
		guids.m_desc_offs[i] = ((i == 0) ? (0) : (guids.m_desc_offs[i - 1] + guids.m_desc_lens[i - 1])); \
		std::copy(&#name[0], &#name[0] + _countof(#name) - 1, &guids.m_descs_str[0] + guids.m_desc_offs[i]); \
		++i;
	mk_x_guids_n()
	#undef x
	return guids;
}

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

[[nodiscard]] constexpr static inline auto make_konst(void)
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
	WCHAR m_tmp_wstrs[8][mk_guids_get_descriptions_longest()];
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

static LPCWSTR mkfw_guid_to_text(GUID const* const guid)
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
			ggg = k_konst.m_guids.m_guids[i];
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
			lr = g_app.m_pfn_SendMessageW(self->m_list, LVM_SETITEMCOUNT, self->m_fw->m_count, LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL); mk_assert(lr != 0);
			lr = g_app.m_pfn_SendMessageW(self->m_list, LVM_SETCOLUMNWIDTH, 2, LVSCW_AUTOSIZE); mk_assert(lr != 0);
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
							disp_info->item.pszText = ((LPWSTR)(mkfw_guid_to_text(self->m_fw->m_entries[disp_info->item.iItem]->providerKey)));
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
