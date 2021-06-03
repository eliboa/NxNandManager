#include "virtual_fs_helper.h"
#include <dokan/dokan.h>
#include "../res/utils.h"
#include <shellapi.h>

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
std::string dokanNtStatusToStr(NTSTATUS status)
{
    std::string str;
    switch (status) {
    case DOKAN_SUCCESS:
        break;
    case DOKAN_ERROR:
        str = "Error while launching dokan driver";
        break;
    case DOKAN_DRIVE_LETTER_ERROR:
        str = "Bad Drive letter";
        break;
    case DOKAN_DRIVER_INSTALL_ERROR:
        str = "Can't load/install dokan driver";
        break;
    case DOKAN_START_ERROR:
        str = "Driver something wrong";
        break;
    case DOKAN_MOUNT_ERROR:
        str = "Can't assign a drive letter";
        break;
    case DOKAN_MOUNT_POINT_ERROR:
        str = "Mount point error";
        break;
    case DOKAN_VERSION_ERROR:
        str = "Version error";
        break;
    default:
      str = "DokanMain failed with status" + std::to_string(status);
    }
    return str;
}
int installDokanDriver(bool silent)
{

#ifdef ARCH64
    bool x64 = true;
#else
    bool x64 = IsWow64();
#endif

    wstring dpinst = parent_path(ExePathW()).append(x64 ? L"\\res\\dokan_driver\\dpinst_x64.exe" : L"\\res\\dokan_driver\\dpinst_x86.exe");
    if (!file_exists(dpinst.c_str()))
        return ERR_DRIVER_FILE_NOT_FOUND;

    SHELLEXECUTEINFO shExInfo = { 0 };
    shExInfo.cbSize = sizeof(shExInfo);
    shExInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
    shExInfo.hwnd = nullptr;
    shExInfo.lpVerb = L"runas";
    wstring args_w = L"/path .\\ /p";
    if (silent) args_w.append(L" /q /se");
    shExInfo.lpFile = dpinst.c_str();
    shExInfo.lpParameters = args_w.c_str();
    shExInfo.lpDirectory = nullptr;
    shExInfo.nShow = SW_SHOW;
    shExInfo.hInstApp = nullptr;

    if (ShellExecuteEx(&shExInfo))
        CloseHandle(shExInfo.hProcess);

    return SUCCESS;
}

