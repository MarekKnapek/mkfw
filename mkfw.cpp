#include <phnt_windows.h>
#include <phnt.h>

#include <CommCtrl.h>
#include <fwpmu.h>
#include <sddl.h>

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

template<typename t, size_t n>
struct mk_view_t
{
	t const* m_buf;
};

template<typename t>
struct mk_view_t<t, 0>
{
	t const* m_buf;
	size_t m_len;
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

[[nodiscard]] static inline LPWSTR mk_memcpy(LPWSTR const dst, LPCWSTR const src, SIZE_T const cnt)
{
	LPWSTR end;

	mk_assert(dst);
	mk_assert(src);
	mk_assert(cnt >= 1);
	mk_assert((dst + cnt <= src) || (dst >= src + cnt));
	mk_assert((src + cnt <= dst) || (src >= dst + cnt));

	std::memcpy(dst, src, cnt * sizeof(*dst));
	end = dst + cnt;
	return end;
}

[[nodiscard]] static inline LPWSTR mk_memcpy(LPWSTR const dst, mk_view_t<WCHAR, 0> const& src)
{
	return mk_memcpy(dst, src.m_buf, src.m_len);
}

#define mk_x_dlls_all() \
	x(ntdll)\
	x(kernel32)\
	x(advapi32)\
	x(combase)\
	x(fwpuclnt)\
	x(user32)\
	x(comctl32)\

#define mk_x_dlls_to_load() \
	x(advapi32)\
	x(combase)\
	x(fwpuclnt)\
	x(user32)\
	x(comctl32)\

#define mk_x_ntdll_funcs() \
	x(_snprintf) \
	x(memset) \
	x(wcslen) \

#define mk_x_kernel_funcs() \
	x(ExitProcess) \
	x(GetModuleHandleW) \
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
	x(InvalidateRect) \
	x(LoadCursorW) \
	x(LoadIconW) \
	x(MoveWindow) \
	x(PeekMessageW) \
	x(PostMessageW) \
	x(PostQuitMessage) \
	x(RegisterClassExW) \
	x(SendMessageW) \
	x(SetWindowLongPtrW) \
	x(ShowWindow) \
	x(TranslateMessage) \

#define mk_x_comctl_funcs() \
	x(InitCommonControls) \

#define mk_x_all_funcs() \
	mk_x_ntdll_funcs() \
	mk_x_kernel_funcs() \
	mk_x_advapi_funcs() \
	mk_x_combase_funcs() \
	mk_x_fw_funcs() \
	mk_x_user_funcs() \
	mk_x_comctl_funcs() \

#define mk_x_hash_strings() \
	x(ntdll, "ntdll.dll") \
	x(kernel32dll, "kernel32.dll") \

#define mk_x_nstrings() \
	x(description, "Description") \
	x(empty, "") \
	x(field, "Field") \
	x(fire_wall, "FireWall") \
	x(fmt_arr16, "[%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x]") \
	x(fmt_u16, "0x%04x (%d)") \
	x(fmt_u32, "0x%08x (%d)") \
	x(fmt_u64, "0x%016llx (%lld)") \
	x(fmt_u8, "0x%02x (%d)") \
	x(layer, "Layer") \
	x(match_type, "Match Type") \
	x(mkfw, "mkfw") \
	x(name, "Name") \
	x(none, "[ none ]") \
	x(provider, "Provider") \
	x(questions, "???") \
	x(range_from, "From: ") \
	x(range_to, " To: ") \
	x(sublayer, "Sub Layer") \
	x(type, "Type") \
	x(value, "Value") \
	x(wnd_cls_name_list_view, "SysListView32") \

#define mk_x_matches() \
	x(FWP_MATCH_EQUAL                 , "equal"                 ) \
	x(FWP_MATCH_GREATER               , "greater"               ) \
	x(FWP_MATCH_LESS                  , "less"                  ) \
	x(FWP_MATCH_GREATER_OR_EQUAL      , "greater or equal"      ) \
	x(FWP_MATCH_LESS_OR_EQUAL         , "less or equal"         ) \
	x(FWP_MATCH_RANGE                 , "range"                 ) \
	x(FWP_MATCH_FLAGS_ALL_SET         , "flags all set"         ) \
	x(FWP_MATCH_FLAGS_ANY_SET         , "flags any set"         ) \
	x(FWP_MATCH_FLAGS_NONE_SET        , "flags none set"        ) \
	x(FWP_MATCH_EQUAL_CASE_INSENSITIVE, "equal case insensitive") \
	x(FWP_MATCH_NOT_EQUAL             , "not equal"             ) \
	x(FWP_MATCH_PREFIX                , "prefix"                ) \
	x(FWP_MATCH_NOT_PREFIX            , "not prefix"            ) \

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

#define mk_x_guids_2() \
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
	signed short int m_desc_offs[guids_2_count() + 1];
	char m_descs_str[guids_2_strs_len()];
};
typedef struct mk_guids_s mk_guids_t;

[[nodiscard]] constexpr static inline mk_guids_t make_guids(void)
{
	int i;
	mk_guids_t guids;
	int len;

	i = 0;
	guids.m_guids = guids_2_get_all();
	guids.m_desc_offs[0] = 0;

	#define x(d1, d2, d3, dd1, dd2, dd3, dd4, dd5, dd6, dd7, dd8, name) \
		len = _countof(#name) - 1; \
		guids.m_desc_offs[i + 1] = guids.m_desc_offs[i] + len; \
		std::copy(&#name[0], &#name[0] + len, &guids.m_descs_str[0] + guids.m_desc_offs[i]); \
		++i;
	mk_x_guids_2()
	#undef x

	return guids;
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

[[nodiscard]] constexpr static inline int matches_get_texts_len(void)
{
	int total;
	int len;

	total = 0;

	#define x(enm, txt) \
		len = _countof(txt) - 1; \
		total += len;
	mk_x_matches()
	#undef x

	return total;
}

enum matches_get_count_e { matches_get_count_v = matches_get_count() };
enum matches_get_texts_len_e { matches_get_texts_len_v = matches_get_texts_len() };

struct matches_texts_s
{
	unsigned char m_offs[matches_get_count_v + 1];
	char m_txt_buf[matches_get_texts_len_v];
};
typedef struct matches_texts_s matches_texts_t;

[[nodiscard]] constexpr static inline matches_texts_t matches_get_texts(void)
{
	int i;
	matches_texts_t texts;
	int len;

	i = 0;
	texts.m_offs[0] = 0;

	#define x(enm, txt) \
		len = _countof(txt) - 1; \
		mk_assert(len >= 1); \
		mk_assert(len <= UCHAR_MAX / 4); \
		mk_assert(texts.m_offs[i] <= UCHAR_MAX - len); \
		texts.m_offs[i + 1] = texts.m_offs[i] + len; \
		std::copy(&txt[0], &txt[0] + len, &texts.m_txt_buf[0] + texts.m_offs[i]); \
		++i;
	mk_x_matches()
	#undef x

	return texts;
}

[[nodiscard]] static inline bool types_test(void)
{
	bool gud;
	int i;

	gud = true;
	i = 0;

	#define x(enm, txt) \
		++i;
	mk_x_types()
	#undef x

	return gud;
}

[[nodiscard]] constexpr static inline int types_get_count(void)
{
	int cnt;

	cnt = 0;

	#define x(enm, txt) \
		++cnt;
	mk_x_types()
	#undef x

	return cnt;
}

[[nodiscard]] constexpr static inline int types_get_texts_len(void)
{
	int total;
	int len;

	total = 0;

	#define x(enm, txt) \
		len = _countof(txt) - 1; \
		total += len;
	mk_x_types()
	#undef x

	return total;
}

enum types_get_count_e { types_get_count_v = types_get_count() };
enum types_get_texts_len_e { types_get_texts_len_v = types_get_texts_len() };

struct types_texts_s
{
	signed short int m_offs[types_get_count_v + 1];
	char m_txt_buf[types_get_texts_len_v];
};
typedef struct types_texts_s types_texts_t;

[[nodiscard]] constexpr static inline types_texts_t types_get_texts(void)
{
	int i;
	types_texts_t texts;
	int len;

	i = 0;
	texts.m_offs[0] = 0;

	#define x(enm, txt) \
		len = _countof(txt) - 1; \
		mk_assert(len >= 1); \
		mk_assert(len <= SHORT_MAX / 4); \
		mk_assert(texts.m_offs[i] <= SHORT_MAX - len); \
		texts.m_offs[i + 1] = texts.m_offs[i] + len; \
		std::copy(&txt[0], &txt[0] + len, &texts.m_txt_buf[0] + texts.m_offs[i]); \
		++i;
	mk_x_types()
	#undef x

	return texts;
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
	matches_texts_t m_matches;
	types_texts_t m_types;
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
	konst.m_matches = matches_get_texts();
	konst.m_types = types_get_texts();
	return konst;
}

struct mk_fw_s
{
	HANDLE m_eng;
	FWPM_FILTER0** m_entries;
	UINT32 m_count;
};
typedef struct mk_fw_s mk_fw_t;

enum mk_cols_entry_e
{
	//mk_cols_entry_e_filter,
	mk_cols_entry_e_name,
	mk_cols_entry_e_description,
	mk_cols_entry_e_provider,
	mk_cols_entry_e_layer,
	mk_cols_entry_e_sub_layer,
	mk_cols_entry_e_dummy_end
};
typedef enum mk_cols_entry_e mk_cols_entry_t;

enum mk_cols_condition_e
{
	mk_cols_condition_e_field,
	mk_cols_condition_e_match_type,
	mk_cols_condition_e_value_type,
	mk_cols_condition_e_value_data,
	mk_cols_condition_e_dummy_end
};
typedef enum mk_cols_condition_e mk_cols_condition_t;

struct mk_wnd_s
{
	HWND m_hwnd;
	HWND m_list;
	HWND m_conditions;
	mk_fw_t* m_fw;
	int m_entry_id;
	int m_max_width_condition;
	int m_max_width_match;
	int m_max_width_type;
};
typedef struct mk_wnd_s mk_wnd_t;

struct mk_funcs_ntdll_s
{
	#define x(name) tfn_##name m_pfn_##name;
	mk_x_ntdll_funcs()
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

struct mk_app_s
{
	PPEB m_peb;
	HMODULE m_dll_exe;
	HMODULE m_dll_ntdll;
	HMODULE m_dll_kernel;
	#define x(name) HMODULE m_dll_##name;
	mk_x_dlls_to_load()
	#undef x
	mk_funcs_ntdll_t m_funcs_ntdll;
	mk_funcs_kernel_t m_funcs_kernel;
	mk_funcs_advapi_t m_funcs_advapi;
	mk_funcs_combase_t m_funcs_combase;
	mk_funcs_fw_t m_funcs_fw;
	mk_funcs_user_t m_funcs_user;
	mk_funcs_comctl_t m_funcs_comctl;
	mk_fw_t m_fw;
	mk_wnd_t m_fw_wnd;
	UINT m_tmps_nstr_idx;
	UINT m_tmps_wstr_idx;
	CHAR m_tmp_nstrs[32][32 * 1024];
	WCHAR m_tmp_wstrs[32][32 * 1024];
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

[[nodiscard]] static inline mk_view_t<WCHAR, 0> nstr_to_wstr(mk_view_t<char, 0> const& nstr)
{
	LPWSTR buf;
	SIZE_T n;
	SIZE_T i;
	mk_view_t<WCHAR, 0> wstr;

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

[[nodiscard]] static inline mk_view_t<WCHAR, 0> nstr_to_wstr(LPCSTR const nstr, int const len)
{
	LPWSTR buf;
	int n;
	int i;
	mk_view_t<WCHAR, 0> wstr;

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
[[nodiscard]] static inline mk_view_t<WCHAR, 0> nstr_to_wstr(std::array<char, nn> const& arr)
{
	LPWSTR buf;
	int n;
	int i;
	mk_view_t<WCHAR, 0> wstr;

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

template<typename t, size_t n>
[[nodiscard]] static inline LPWSTR nstr_to_wstr(mk_view_t<t, n> const& view)
{
	return nstr_to_wstr(view.m_buf, ((int)(n)));
}

[[nodiscard]] static inline mk_view_t<WCHAR, 0> guid_to_wstr(GUID const* const guid)
{
	int cap;
	LPWSTR buf;
	mk_view_t<WCHAR, 0> wstr;
	int len;

	mk_assert(guid);

	cap = _countof(g_app.m_tmp_wstrs[0]);
	buf = &g_app.m_tmp_wstrs[g_app.m_tmps_wstr_idx++ % _countof(g_app.m_tmp_wstrs)][0];
	len = g_app.m_funcs_combase.m_pfn_StringFromGUID2(*guid, buf, cap); mk_assert(len >= 1); mk_assert(len < cap);
	wstr.m_buf = buf;
	wstr.m_len = len;
	mk_assert(wstr.m_len >= 0);
	mk_assert(wstr.m_buf[wstr.m_len] == L'\0');
	return wstr;
}

static inline void mkfw_load_all(PPEB const peb)
{
	mk_assert(peb);

	g_app.m_peb = peb;
	g_app.m_dll_ntdll = find_module(peb, k_konst.m_hash_ntdll); mk_assert(g_app.m_dll_ntdll);
	g_app.m_dll_kernel = find_module(peb, k_konst.m_hash_kernel32dll); mk_assert(g_app.m_dll_kernel);

	#define x(name) g_app.m_funcs_ntdll.m_pfn_##name = ((tfn_##name)(find_proc(peb, g_app.m_dll_ntdll, k_konst.m_hash_##name))); mk_assert(g_app.m_funcs_ntdll.m_pfn_##name);
	mk_x_ntdll_funcs()
	#undef x

	#define x(name) g_app.m_funcs_kernel.m_pfn_##name = ((tfn_##name)(find_proc(peb, g_app.m_dll_kernel, k_konst.m_hash_##name))); mk_assert(g_app.m_funcs_kernel.m_pfn_##name);
	mk_x_kernel_funcs()
	#undef x

	#define x(name) g_app.m_dll_##name = g_app.m_funcs_kernel.m_pfn_LoadLibraryExA(nstr_to_nstr(k_konst.m_nstr_##name), NULL, LOAD_LIBRARY_SEARCH_SYSTEM32); mk_assert(g_app.m_dll_##name);
	mk_x_dlls_to_load()
	#undef x

	#define x(name) g_app.m_funcs_advapi.m_pfn_##name = ((tfn_##name)(find_proc(peb, g_app.m_dll_advapi32, k_konst.m_hash_##name))); mk_assert(g_app.m_funcs_advapi.m_pfn_##name);
	mk_x_advapi_funcs()
	#undef x

	#define x(name) g_app.m_funcs_combase.m_pfn_##name = ((tfn_##name)(find_proc(peb, g_app.m_dll_combase, k_konst.m_hash_##name))); mk_assert(g_app.m_funcs_combase.m_pfn_##name);
	mk_x_combase_funcs()
	#undef x

	#define x(name) g_app.m_funcs_fw.m_pfn_##name = ((tfn_##name)(find_proc(peb, g_app.m_dll_fwpuclnt, k_konst.m_hash_##name))); mk_assert(g_app.m_funcs_fw.m_pfn_##name);
	mk_x_fw_funcs()
	#undef x

	#define x(name) g_app.m_funcs_user.m_pfn_##name = ((tfn_##name)(find_proc(peb, g_app.m_dll_user32, k_konst.m_hash_##name))); mk_assert(g_app.m_funcs_user.m_pfn_##name);
	mk_x_user_funcs()
	#undef x

	#define x(name) g_app.m_funcs_comctl.m_pfn_##name = ((tfn_##name)(find_proc(peb, g_app.m_dll_comctl32, k_konst.m_hash_##name))); mk_assert(g_app.m_funcs_comctl.m_pfn_##name);
	mk_x_comctl_funcs()
	#undef x

	g_app.m_funcs_comctl.m_pfn_InitCommonControls();
	g_app.m_dll_exe = g_app.m_funcs_kernel.m_pfn_GetModuleHandleW(NULL);

	g_app.m_funcs_ntdll.m_pfn_memset(g_app.m_tmp_nstrs, 0x00, sizeof(g_app.m_tmp_nstrs));
	g_app.m_funcs_ntdll.m_pfn_memset(g_app.m_tmp_wstrs, 0x00, sizeof(g_app.m_tmp_wstrs));
}

[[nodiscard]] static inline mk_view_t<WCHAR, 0> guid_to_text(GUID const* const guid)
{
	int n;
	int i;
	GUID const* ggg;
	mk_view_t<WCHAR, 0> wstr;

	static_assert(std::size(k_konst.m_guids.m_guids.m_guids) + 1 == std::size(k_konst.m_guids.m_desc_offs));
	
	if(guid)
	{
		n = std::size(k_konst.m_guids.m_guids.m_guids);
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
			wstr = nstr_to_wstr(&k_konst.m_guids.m_descs_str[k_konst.m_guids.m_desc_offs[i]], k_konst.m_guids.m_desc_offs[i + 1] - k_konst.m_guids.m_desc_offs[i + 0]);
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
	mk_assert(wstr.m_len >= 0);
	mk_assert(wstr.m_buf[wstr.m_len] == L'\0');
	return wstr;
}

[[nodiscard]] static inline mk_view_t<WCHAR, 0> match_type_to_text(FWP_MATCH_TYPE const match_type)
{
	int offa;
	int offb;
	int len;
	LPCSTR nstr;
	mk_view_t<WCHAR, 0> wstr;

	if(((int)(match_type)) >= 0 && ((int)(match_type)) < ((int)(matches_get_count_v)))
	{
		offa = k_konst.m_matches.m_offs[((int)(match_type)) + 0];
		offb = k_konst.m_matches.m_offs[((int)(match_type)) + 1];
		len = offb - offa;
		nstr = &k_konst.m_matches.m_txt_buf[0] + offa;
		wstr = nstr_to_wstr(nstr, len);
	}
	else
	{
		wstr = nstr_to_wstr(k_konst.m_nstr_questions);
	}
	mk_assert(wstr.m_len >= 0);
	mk_assert(wstr.m_buf[wstr.m_len] == L'\0');
	return wstr;
}

[[nodiscard]] static inline mk_view_t<WCHAR, 0> type_to_text(FWP_DATA_TYPE const type)
{
	int idx;
	int i;
	int offa;
	int offb;
	int len;
	LPCSTR nstr;
	mk_view_t<WCHAR, 0> wstr;

	idx = 0;
	i = 0;

	#define x(enm, txt) \
		if(type == enm){ idx = i; } \
		++i;
	mk_x_types()
	#undef x

	if(idx != 0)
	{
		offa = k_konst.m_types.m_offs[idx + 0];
		offb = k_konst.m_types.m_offs[idx + 1];
		len = offb - offa;
		nstr = &k_konst.m_types.m_txt_buf[0] + offa;
		wstr = nstr_to_wstr(nstr, len);
	}
	else
	{
		wstr = nstr_to_wstr(k_konst.m_nstr_questions);
	}
	mk_assert(wstr.m_len >= 0);
	mk_assert(wstr.m_buf[wstr.m_len] == L'\0');
	return wstr;
}

[[nodiscard]] static inline mk_view_t<char, 0> value_to_nstr_uint8(UINT8 const u8)
{
	char* fmt;
	char* buf;
	int cap;
	int len;
	mk_view_t<char, 0> view;

	fmt = &g_app.m_tmp_nstrs[g_app.m_tmps_nstr_idx++ % _countof(g_app.m_tmp_nstrs)][0];
	buf = &g_app.m_tmp_nstrs[g_app.m_tmps_nstr_idx++ % _countof(g_app.m_tmp_nstrs)][0];
	cap = _countof(g_app.m_tmp_nstrs[0]);
	std::memcpy(&fmt[0], k_konst.m_nstr_fmt_u8.data(), k_konst.m_nstr_fmt_u8.size());
	fmt[k_konst.m_nstr_fmt_u8.size()] = '\0';
	len = g_app.m_funcs_ntdll.m_pfn__snprintf(buf, cap, fmt, ((int)(u8)), ((int)(u8))); mk_assert(len >= 1); mk_assert(len < cap);
	view.m_buf = buf;
	view.m_len = len;
	return view;
}

[[nodiscard]] static inline mk_view_t<char, 0> value_to_nstr_uint16(UINT16 const u16)
{
	char* fmt;
	char* buf;
	int cap;
	int len;
	mk_view_t<char, 0> view;

	fmt = &g_app.m_tmp_nstrs[g_app.m_tmps_nstr_idx++ % _countof(g_app.m_tmp_nstrs)][0];
	buf = &g_app.m_tmp_nstrs[g_app.m_tmps_nstr_idx++ % _countof(g_app.m_tmp_nstrs)][0];
	cap = _countof(g_app.m_tmp_nstrs[0]);
	std::memcpy(&fmt[0], k_konst.m_nstr_fmt_u16.data(), k_konst.m_nstr_fmt_u16.size());
	fmt[k_konst.m_nstr_fmt_u16.size()] = '\0';
	len = g_app.m_funcs_ntdll.m_pfn__snprintf(buf, cap, fmt, ((int)(u16)), ((int)(u16))); mk_assert(len >= 1); mk_assert(len < cap);
	buf[len] = '\0';
	view.m_buf = buf;
	view.m_len = len;
	mk_assert(view.m_len >= 0);
	mk_assert(view.m_buf[view.m_len] == '\0');
	return view;
}

[[nodiscard]] static inline mk_view_t<char, 0> value_to_nstr_uint32(UINT32 const u32)
{
	char* fmt;
	char* buf;
	int cap;
	int len;
	mk_view_t<char, 0> view;

	fmt = &g_app.m_tmp_nstrs[g_app.m_tmps_nstr_idx++ % _countof(g_app.m_tmp_nstrs)][0];
	buf = &g_app.m_tmp_nstrs[g_app.m_tmps_nstr_idx++ % _countof(g_app.m_tmp_nstrs)][0];
	cap = _countof(g_app.m_tmp_nstrs[0]);
	std::memcpy(&fmt[0], k_konst.m_nstr_fmt_u32.data(), k_konst.m_nstr_fmt_u32.size());
	fmt[k_konst.m_nstr_fmt_u32.size()] = '\0';
	len = g_app.m_funcs_ntdll.m_pfn__snprintf(buf, cap, fmt, *((unsigned int*)(&u32)), *((unsigned int*)(&u32))); mk_assert(len >= 1); mk_assert(len < cap);
	view.m_buf = buf;
	view.m_len = len;
	return view;
}

[[nodiscard]] static inline mk_view_t<char, 0> value_to_nstr_uint64(UINT64 const* const u64)
{
	char* fmt;
	char* buf;
	int cap;
	int len;
	mk_view_t<char, 0> view;

	mk_assert(u64);

	fmt = &g_app.m_tmp_nstrs[g_app.m_tmps_nstr_idx++ % _countof(g_app.m_tmp_nstrs)][0];
	buf = &g_app.m_tmp_nstrs[g_app.m_tmps_nstr_idx++ % _countof(g_app.m_tmp_nstrs)][0];
	cap = _countof(g_app.m_tmp_nstrs[0]);
	std::memcpy(&fmt[0], k_konst.m_nstr_fmt_u64.data(), k_konst.m_nstr_fmt_u64.size());
	fmt[k_konst.m_nstr_fmt_u64.size()] = '\0';
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

[[nodiscard]] static inline mk_view_t<WCHAR, 0> value_to_wstr_blob(FWP_BYTE_BLOB const* const blob)
{
	LPCWSTR buf;
	SIZE_T len;
	mk_view_t<WCHAR, 0> wstr;

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
		wstr = nstr_to_wstr(k_konst.m_nstr_questions);
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

[[nodiscard]] static inline mk_view_t<char, 0> value_to_nstr_arr16(FWP_BYTE_ARRAY16 const* const arr16)
{
	char* fmt;
	char* buf;
	int cap;
	USHORT parts[8];
	int len;
	mk_view_t<char, 0> view;

	mk_assert(arr16);

	fmt = &g_app.m_tmp_nstrs[g_app.m_tmps_nstr_idx++ % _countof(g_app.m_tmp_nstrs)][0];
	buf = &g_app.m_tmp_nstrs[g_app.m_tmps_nstr_idx++ % _countof(g_app.m_tmp_nstrs)][0];
	cap = _countof(g_app.m_tmp_nstrs[0]);
	std::memcpy(&fmt[0], k_konst.m_nstr_fmt_arr16.data(), k_konst.m_nstr_fmt_arr16.size());
	fmt[k_konst.m_nstr_fmt_arr16.size()] = '\0';
	arr16_to_arr8(&arr16->byteArray16[0], &parts[0]);
	len = g_app.m_funcs_ntdll.m_pfn__snprintf(buf, cap, fmt, parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], parts[6], parts[7]); mk_assert(len >= 1); mk_assert(len < cap);
	view.m_buf = buf;
	view.m_len = len;
	return view;
}

[[nodiscard]] static inline mk_view_t<WCHAR, 0> value_to_wstr_sd(FWP_BYTE_BLOB const* const sd)
{
	BOOL b;
	LPWSTR win_buf;
	SIZE_T len;
	LPWSTR buf;
	mk_view_t<WCHAR, 0> wstr;

	mk_assert(sd);

	b = g_app.m_funcs_advapi.m_pfn_ConvertSecurityDescriptorToStringSecurityDescriptorW(((PSECURITY_DESCRIPTOR)(sd->data)), SDDL_REVISION_1, OWNER_SECURITY_INFORMATION  | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION, &win_buf, NULL); mk_assert(b);
	len = g_app.m_funcs_ntdll.m_pfn_wcslen(win_buf);
	mk_assert(len < _countof(g_app.m_tmp_wstrs[0]));
	buf = &g_app.m_tmp_wstrs[g_app.m_tmps_wstr_idx++ % _countof(g_app.m_tmp_wstrs)][0];
	std::memcpy(&buf[0], win_buf, (len + 1) * sizeof(buf[0]));
	g_app.m_funcs_kernel.m_pfn_LocalFree(win_buf);
	wstr.m_buf = buf;
	wstr.m_len = len;
	mk_assert(wstr.m_len >= 0);
	mk_assert(wstr.m_buf[wstr.m_len] == L'\0');
	return wstr;
}

[[nodiscard]] static inline mk_view_t<WCHAR, 0> value_to_wstr_sid(SID const* const sid)
{
	BOOL b;
	LPWSTR txt_sid;
	LPWSTR buf;
	SIZE_T len;
	LPWSTR ptr;
	HLOCAL hloc;
	mk_view_t<WCHAR, 0> wstr;

	mk_assert(sid);

	b = g_app.m_funcs_advapi.m_pfn_ConvertSidToStringSidW(((PSID)(sid)), &txt_sid); mk_assert(b);
	buf = &g_app.m_tmp_wstrs[g_app.m_tmps_wstr_idx++ % _countof(g_app.m_tmp_wstrs)][0];
	len = g_app.m_funcs_ntdll.m_pfn_wcslen(txt_sid);
	ptr = mk_memcpy(buf, txt_sid, len); ((void)(ptr));
	buf[len] = L'\0';
	hloc = g_app.m_funcs_kernel.m_pfn_LocalFree(txt_sid); mk_assert(!hloc);
	wstr.m_buf = buf;
	wstr.m_len = len;
	mk_assert(wstr.m_len >= 0);
	mk_assert(wstr.m_buf[wstr.m_len] == L'\0');
	return wstr;
}

[[nodiscard]] static inline mk_view_t<WCHAR, 0> value_to_wstr_value(FWP_VALUE0 const* const value)
{
	mk_view_t<WCHAR, 0> wstr;

	mk_assert(value);

	switch(value->type)
	{
		case FWP_UINT8:
			wstr = nstr_to_wstr(value_to_nstr_uint8(value->uint8));
		break;
		case FWP_UINT16:
			wstr = nstr_to_wstr(value_to_nstr_uint16(value->uint16));
		break;
		case FWP_UINT32:
			wstr = nstr_to_wstr(value_to_nstr_uint32(value->uint32));
		break;
		case FWP_BYTE_ARRAY16_TYPE:
			wstr = nstr_to_wstr(value_to_nstr_arr16(value->byteArray16));
		break;
		default:
			mk_assert(("todo", false));
			wstr = nstr_to_wstr(k_konst.m_nstr_questions);
		break;
	}
	mk_assert(wstr.m_len >= 0);
	mk_assert(wstr.m_buf[wstr.m_len] == L'\0');
	return wstr;
}

[[nodiscard]] static inline mk_view_t<WCHAR, 0> value_to_wstr_range(FWP_RANGE0 const* const range)
{
	mk_view_t<WCHAR, 0> lo_wstr;
	mk_view_t<WCHAR, 0> hi_wstr;
	mk_view_t<WCHAR, 0> txt_from;
	mk_view_t<WCHAR, 0> txt_to;
	LPWSTR buf;
	LPWSTR ptr;
	SIZE_T len;
	mk_view_t<WCHAR, 0> wstr;

	mk_assert(range);

	lo_wstr = value_to_wstr_value(&range->valueLow);
	hi_wstr = value_to_wstr_value(&range->valueHigh);
	txt_from = nstr_to_wstr(k_konst.m_nstr_range_from);
	txt_to = nstr_to_wstr(k_konst.m_nstr_range_to);
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

[[nodiscard]] static inline mk_view_t<WCHAR, 0> condition_value_to_text(FWP_CONDITION_VALUE0 const* const value)
{
	mk_view_t<WCHAR, 0> wstr;

	switch(value->type)
	{
		case FWP_UINT8:
			wstr = nstr_to_wstr(value_to_nstr_uint8(value->uint8));
		break;
		case FWP_UINT16:
			wstr = nstr_to_wstr(value_to_nstr_uint16(value->uint16));
		break;
		case FWP_UINT32:
			wstr = nstr_to_wstr(value_to_nstr_uint32(value->uint32));
		break;
		case FWP_UINT64:
			wstr = nstr_to_wstr(value_to_nstr_uint64(value->uint64));
		break;
		case FWP_BYTE_BLOB_TYPE:
			wstr = value_to_wstr_blob(value->byteBlob);
		break;
		case FWP_SID:
			wstr = value_to_wstr_sid(value->sid);
		break;
		case FWP_SECURITY_DESCRIPTOR_TYPE:
			wstr = value_to_wstr_sd(value->sd);
		break;
		case FWP_RANGE_TYPE:
			wstr = value_to_wstr_range(value->rangeValue);
		break;
		default:
			mk_assert(("todo", false));
			wstr = nstr_to_wstr(k_konst.m_nstr_questions);
		break;
	}
	mk_assert(wstr.m_len >= 0);
	mk_assert(wstr.m_buf[wstr.m_len] == L'\0');
	return wstr;
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

static LRESULT CALLBACK mkfw_wnd_proc(HWND const hwnd, UINT const msg, WPARAM const wparam, LPARAM const lparam)
{
	bool call_def;
	LRESULT lres;
	LONG_PTR ptr;
	mk_wnd_t* self;
	CREATESTRUCTW* crt;
	LRESULT lr;
	LVCOLUMNW col;
	BOOL b;
	RECT rect;
	int height;
	int top;
	NMHDR* nm;
	NMLVDISPINFOW* disp_info;
	UINT mask;
	NMLISTVIEW* changed;
	int item;
	FWPM_FILTER0* entry;
	FWPM_FILTER_CONDITION0* condition;

	call_def = true;
	lres = 0;
	ptr = g_app.m_funcs_user.m_pfn_GetWindowLongPtrW(hwnd, GWLP_USERDATA);
	self = ((mk_wnd_t*)(ptr));
	switch(msg)
	{
		case WM_CREATE:
			mk_assert(lparam);
			crt = ((CREATESTRUCTW*)(lparam));
			self = ((mk_wnd_t*)(crt->lpCreateParams));
			self->m_hwnd = hwnd;
			ptr = g_app.m_funcs_user.m_pfn_SetWindowLongPtrW(self->m_hwnd, GWLP_USERDATA, ((LONG_PTR)(self))); mk_assert(ptr == 0);

			self->m_entry_id = 0;
			self->m_max_width_condition = 10;
			self->m_max_width_match = 10;
			self->m_max_width_type = 10;
			self->m_list = g_app.m_funcs_user.m_pfn_CreateWindowExW(WS_EX_LEFT | WS_EX_LTRREADING | WS_EX_RIGHTSCROLLBAR, nstr_to_wstr(k_konst.m_nstr_wnd_cls_name_list_view).m_buf, nstr_to_wstr(k_konst.m_nstr_empty).m_buf, WS_VISIBLE | WS_CHILD | LVS_REPORT | LVS_OWNERDATA | LVS_SINGLESEL | LVS_SHOWSELALWAYS, 10, 10, 800, 600, self->m_hwnd, NULL, g_app.m_dll_exe, NULL); mk_assert(self->m_list);
			lr = g_app.m_funcs_user.m_pfn_SendMessageW(self->m_list, LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_DOUBLEBUFFER | LVS_EX_FULLROWSELECT, LVS_EX_DOUBLEBUFFER | LVS_EX_FULLROWSELECT); ((void)(lr));

			col.mask = LVCF_WIDTH | LVCF_TEXT; col.pszText = ((LPWSTR)(nstr_to_wstr(k_konst.m_nstr_name).m_buf)); col.cx = 80;
			lr = g_app.m_funcs_user.m_pfn_SendMessageW(self->m_list, LVM_INSERTCOLUMN, mk_cols_entry_e_name, ((LPARAM)(&col))); mk_assert(lr == mk_cols_entry_e_name);

			col.mask = LVCF_WIDTH | LVCF_TEXT; col.pszText = ((LPWSTR)(nstr_to_wstr(k_konst.m_nstr_description).m_buf)); col.cx = 180;
			lr = g_app.m_funcs_user.m_pfn_SendMessageW(self->m_list, LVM_INSERTCOLUMN, mk_cols_entry_e_description, ((LPARAM)(&col))); mk_assert(lr == mk_cols_entry_e_description);

			col.mask = LVCF_WIDTH | LVCF_TEXT; col.pszText = ((LPWSTR)(nstr_to_wstr(k_konst.m_nstr_provider).m_buf)); col.cx = 80;
			lr = g_app.m_funcs_user.m_pfn_SendMessageW(self->m_list, LVM_INSERTCOLUMN, mk_cols_entry_e_provider, ((LPARAM)(&col))); mk_assert(lr == mk_cols_entry_e_provider);

			col.mask = LVCF_WIDTH | LVCF_TEXT; col.pszText = ((LPWSTR)(nstr_to_wstr(k_konst.m_nstr_layer).m_buf)); col.cx = 80;
			lr = g_app.m_funcs_user.m_pfn_SendMessageW(self->m_list, LVM_INSERTCOLUMN, mk_cols_entry_e_layer, ((LPARAM)(&col))); mk_assert(lr == mk_cols_entry_e_layer);

			col.mask = LVCF_WIDTH | LVCF_TEXT; col.pszText = ((LPWSTR)(nstr_to_wstr(k_konst.m_nstr_sublayer).m_buf)); col.cx = 80;
			lr = g_app.m_funcs_user.m_pfn_SendMessageW(self->m_list, LVM_INSERTCOLUMN, mk_cols_entry_e_sub_layer, ((LPARAM)(&col))); mk_assert(lr == mk_cols_entry_e_sub_layer);

			lr = g_app.m_funcs_user.m_pfn_SendMessageW(self->m_list, LVM_SETITEMCOUNT, self->m_fw->m_count, LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL); mk_assert(lr != 0);

			lr = g_app.m_funcs_user.m_pfn_SendMessageW(self->m_list, LVM_SETCOLUMNWIDTH, mk_cols_entry_e_provider, LVSCW_AUTOSIZE); mk_assert(lr != 0);
			lr = g_app.m_funcs_user.m_pfn_SendMessageW(self->m_list, LVM_SETCOLUMNWIDTH, mk_cols_entry_e_layer, LVSCW_AUTOSIZE); mk_assert(lr != 0);
			lr = g_app.m_funcs_user.m_pfn_SendMessageW(self->m_list, LVM_SETCOLUMNWIDTH, mk_cols_entry_e_sub_layer, LVSCW_AUTOSIZE); mk_assert(lr != 0);

			self->m_conditions = g_app.m_funcs_user.m_pfn_CreateWindowExW(WS_EX_LEFT | WS_EX_LTRREADING | WS_EX_RIGHTSCROLLBAR, nstr_to_wstr(k_konst.m_nstr_wnd_cls_name_list_view).m_buf, nstr_to_wstr(k_konst.m_nstr_empty).m_buf, WS_VISIBLE | WS_CHILD | LVS_REPORT | LVS_OWNERDATA | LVS_SINGLESEL | LVS_SHOWSELALWAYS, 10, 10, 800, 600, self->m_hwnd, NULL, g_app.m_dll_exe, NULL); mk_assert(self->m_list);
			lr = g_app.m_funcs_user.m_pfn_SendMessageW(self->m_conditions, LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_DOUBLEBUFFER | LVS_EX_FULLROWSELECT, LVS_EX_DOUBLEBUFFER | LVS_EX_FULLROWSELECT); ((void)(lr));

			col.mask = LVCF_WIDTH | LVCF_TEXT; col.pszText = ((LPWSTR)(nstr_to_wstr(k_konst.m_nstr_field).m_buf)); col.cx = 80;
			lr = g_app.m_funcs_user.m_pfn_SendMessageW(self->m_conditions, LVM_INSERTCOLUMN, mk_cols_condition_e_field, ((LPARAM)(&col))); mk_assert(lr == mk_cols_condition_e_field);

			col.mask = LVCF_WIDTH | LVCF_TEXT; col.pszText = ((LPWSTR)(nstr_to_wstr(k_konst.m_nstr_match_type).m_buf)); col.cx = 80;
			lr = g_app.m_funcs_user.m_pfn_SendMessageW(self->m_conditions, LVM_INSERTCOLUMN, mk_cols_condition_e_match_type, ((LPARAM)(&col))); mk_assert(lr == mk_cols_condition_e_match_type);

			col.mask = LVCF_WIDTH | LVCF_TEXT; col.pszText = ((LPWSTR)(nstr_to_wstr(k_konst.m_nstr_type).m_buf)); col.cx = 80;
			lr = g_app.m_funcs_user.m_pfn_SendMessageW(self->m_conditions, LVM_INSERTCOLUMN, mk_cols_condition_e_value_type, ((LPARAM)(&col))); mk_assert(lr == mk_cols_condition_e_value_type);

			col.mask = LVCF_WIDTH | LVCF_TEXT; col.pszText = ((LPWSTR)(nstr_to_wstr(k_konst.m_nstr_value).m_buf)); col.cx = 200;
			lr = g_app.m_funcs_user.m_pfn_SendMessageW(self->m_conditions, LVM_INSERTCOLUMN, mk_cols_condition_e_value_data, ((LPARAM)(&col))); mk_assert(lr == mk_cols_condition_e_value_data);
		break;
		case WM_DESTROY:
			g_app.m_funcs_user.m_pfn_PostQuitMessage(0);
		break;
		case WM_SIZE:
			b = g_app.m_funcs_user.m_pfn_GetClientRect(self->m_hwnd, &rect); mk_assert(b); mk_assert(rect.left == 0); mk_assert(rect.top == 0);
			height = rect.bottom / 2 - 2;
			height = height < 0 ? 0 : height;
			top = height + 2 * 2;
			b = g_app.m_funcs_user.m_pfn_MoveWindow(self->m_list, 0, 0, rect.right, height, TRUE); mk_assert(b);
			b = g_app.m_funcs_user.m_pfn_MoveWindow(self->m_conditions, 0, top, rect.right, height, TRUE); mk_assert(b);
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
						mk_assert(disp_info->item.iItem >= 0);
						mk_assert(disp_info->item.iItem < ((int)(self->m_fw->m_count)));
						mask &=~ LVIF_TEXT;
						if(disp_info->item.iSubItem == mk_cols_entry_e_name)
						{
							disp_info->item.pszText = self->m_fw->m_entries[disp_info->item.iItem]->displayData.name;
						}
						else if(disp_info->item.iSubItem == mk_cols_entry_e_description)
						{
							disp_info->item.pszText = self->m_fw->m_entries[disp_info->item.iItem]->displayData.description;
						}
						else if(disp_info->item.iSubItem == mk_cols_entry_e_provider)
						{
							disp_info->item.pszText = ((LPWSTR)(guid_to_text(self->m_fw->m_entries[disp_info->item.iItem]->providerKey).m_buf));
						}
						else if(disp_info->item.iSubItem == mk_cols_entry_e_layer)
						{
							disp_info->item.pszText = ((LPWSTR)(guid_to_text(&self->m_fw->m_entries[disp_info->item.iItem]->layerKey).m_buf));
						}
						else if(disp_info->item.iSubItem == mk_cols_entry_e_sub_layer)
						{
							disp_info->item.pszText = ((LPWSTR)(guid_to_text(&self->m_fw->m_entries[disp_info->item.iItem]->subLayerKey).m_buf));
						}
						else
						{
							mk_assert(false);
						}
						if(!disp_info->item.pszText)
						{
							disp_info->item.pszText = ((LPWSTR)(nstr_to_wstr(k_konst.m_nstr_empty).m_buf));
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
				else if(nm->code == LVN_ITEMCHANGED)
				{
					changed = ((NMLISTVIEW*)(nm));
					if(changed->iItem != -1)
					{
						if((changed->uNewState & LVIS_SELECTED) != 0)
						{
							item = changed->iItem;
							self->m_entry_id = item;
							entry = self->m_fw->m_entries[item];
							lr = g_app.m_funcs_user.m_pfn_SendMessageW(self->m_conditions, WM_SETREDRAW, FALSE, 0); mk_assert(lr == 0);
							lr = g_app.m_funcs_user.m_pfn_SendMessageW(self->m_conditions, LVM_SETITEMCOUNT, entry->numFilterConditions, 0); mk_assert(lr != 0);
							set_max_col_width(self->m_conditions, 0, &self->m_max_width_condition);
							set_max_col_width(self->m_conditions, 1, &self->m_max_width_match);
							set_max_col_width(self->m_conditions, 2, &self->m_max_width_type);
							b = g_app.m_funcs_user.m_pfn_InvalidateRect(self->m_conditions, NULL, TRUE); mk_assert(b);
							lr = g_app.m_funcs_user.m_pfn_SendMessageW(self->m_conditions, WM_SETREDRAW, TRUE, 0); mk_assert(lr == 0);
						}
					}
				}
			}
			else if(nm->hwndFrom == self->m_conditions)
			{
				if(nm->code == LVN_GETDISPINFOW)
				{
					disp_info = ((NMLVDISPINFOW*)(lparam));
					item = disp_info->item.iItem;
					entry = self->m_fw->m_entries[self->m_entry_id];
					condition = &entry->filterCondition[item];
					mk_assert(item >= 0);
					mk_assert(item < ((int)(entry->numFilterConditions)));
					mask = disp_info->item.mask;
					if((mask & LVIF_TEXT) != 0)
					{
						mask &=~ LVIF_TEXT;
						if(disp_info->item.iSubItem == mk_cols_condition_e_field)
						{
							disp_info->item.pszText = ((LPWSTR)(guid_to_text(&condition->fieldKey).m_buf));
						}
						else if(disp_info->item.iSubItem == mk_cols_condition_e_match_type)
						{
							disp_info->item.pszText = ((LPWSTR)(match_type_to_text(condition->matchType).m_buf));
						}
						else if(disp_info->item.iSubItem == mk_cols_condition_e_value_type)
						{
							disp_info->item.pszText = ((LPWSTR)(type_to_text(condition->conditionValue.type).m_buf));
						}
						else if(disp_info->item.iSubItem == mk_cols_condition_e_value_data)
						{
							disp_info->item.pszText = ((LPWSTR)(condition_value_to_text(&condition->conditionValue).m_buf));
						}
						else
						{
							mk_assert(false);
						}
						if(!disp_info->item.pszText)
						{
							disp_info->item.pszText = ((LPWSTR)(nstr_to_wstr(k_konst.m_nstr_empty).m_buf));
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
		lres = g_app.m_funcs_user.m_pfn_DefWindowProcW(hwnd, msg, wparam, lparam);
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
	mk_assert(matches_test());
	mk_assert(types_test());

	mkfw_load_all(peb);
	fw_construct(&g_app.m_fw);
	wnd_cls_info.cbSize = sizeof(wnd_cls_info);
	wnd_cls_info.style = CS_VREDRAW | CS_HREDRAW;
	wnd_cls_info.lpfnWndProc = &mkfw_wnd_proc;
	wnd_cls_info.cbClsExtra = 0;
	wnd_cls_info.cbWndExtra = sizeof(mk_wnd_t*);
	wnd_cls_info.hInstance = g_app.m_dll_exe;
	wnd_cls_info.hIcon = g_app.m_funcs_user.m_pfn_LoadIconW(NULL, IDI_APPLICATION);
	wnd_cls_info.hCursor = g_app.m_funcs_user.m_pfn_LoadCursorW(NULL, IDC_ARROW);
	wnd_cls_info.hbrBackground = ((HBRUSH)(COLOR_APPWORKSPACE + 1));
	wnd_cls_info.lpszMenuName = NULL;
	wnd_cls_info.lpszClassName = nstr_to_wstr(k_konst.m_nstr_mkfw).m_buf;
	wnd_cls_info.hIconSm = g_app.m_funcs_user.m_pfn_LoadIconW(NULL, IDI_APPLICATION);
	wnd_cls_atom = g_app.m_funcs_user.m_pfn_RegisterClassExW(&wnd_cls_info); mk_assert(wnd_cls_atom);
	g_app.m_fw_wnd.m_fw = &g_app.m_fw;
	hwnd = g_app.m_funcs_user.m_pfn_CreateWindowExW(WS_EX_APPWINDOW, ((LPCWSTR)(wnd_cls_atom)), nstr_to_wstr(k_konst.m_nstr_fire_wall).m_buf, WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, NULL, NULL, g_app.m_dll_exe, &g_app.m_fw_wnd); mk_assert(hwnd);
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
