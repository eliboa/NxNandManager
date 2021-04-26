#include "virtual_fs_helper.h"
std::wstring parent_path(const std::wstring & path)
{
    auto str = path.substr(0, path.find_last_of(L"/\\"));
    return str.length() ? str : std::wstring(L"\\");
}
std::wstring base_name(const std::wstring & path)
{
    return path.substr(path.find_last_of(L"/\\") + 1);
}

bool replace_wstr(std::wstring& str, const std::wstring& from, const std::wstring& to) {
    size_t start_pos = str.find(from);
    if(start_pos == std::wstring::npos)
        return false;
    str.replace(start_pos, from.length(), to);
    return true;
}

wstring virtual_path_to_nx_path(const wchar_t* path, NxPartition* part)
{
    wstring p(path);
    replace_wstr(p, L"\\", L"/");

    if (!part)
        return p;

    wstring rp = part->fs_prefix(p.c_str());
    return rp;
}
wstring nx_path_to_virtual_path(const wchar_t* path, NxPartition* part)
{
    wstring p(path);

    if (part)
    {
        auto prefix = part->fs_prefix();
        auto pos = p.find_first_of(prefix);
        wstring p2 = p.substr(pos + prefix.size(), p.size());
        p = p2;
    }

    replace_wstr(p, L"/", L"\\");

    return p;
}


