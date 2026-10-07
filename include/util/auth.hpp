#pragma once

#include <string>
#include <curl/curl.h>

namespace inst::util {

    // RomM client API tokens start with "rmm_". When the saved remote "password"
    // is such a token it is sent as an HTTP Bearer token instead of HTTP Basic, so
    // the account password never has to be stored on the SD card.
    inline bool IsBearerToken(const std::string& secret) {
        return secret.rfind("rmm_", 0) == 0;
    }

    inline bool IsHttpsUrl(const std::string& url) {
        return url.rfind("https://", 0) == 0 || url.rfind("HTTPS://", 0) == 0;
    }

    // "https://host:443" and "https://host" are the same origin (likewise
    // "http://host:80"). Without this, a feed that links to files without the
    // explicit default port never gets credentials, and downloads fail with 401.
    inline void StripDefaultPort(std::string& origin) {
        auto endsWith = [&](const char* suffix, std::size_t len) {
            return origin.size() > len && origin.compare(origin.size() - len, len, suffix) == 0;
        };
        if (origin.rfind("https://", 0) == 0 && endsWith(":443", 4))
            origin.erase(origin.size() - 4);
        else if (origin.rfind("http://", 0) == 0 && endsWith(":80", 3))
            origin.erase(origin.size() - 3);
    }

    // Applies Basic or Bearer auth to a curl handle. Returns true when
    // credentials were applied. A bearer token is never sent over plain http.
    inline bool ApplyCurlAuth(CURL* curl, const std::string& user, const std::string& pass, const std::string& url) {
        if (IsBearerToken(pass)) {
            if (!IsHttpsUrl(url))
                return false;
            curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BEARER);
            curl_easy_setopt(curl, CURLOPT_XOAUTH2_BEARER, pass.c_str());
            return true;
        }
        if (user.empty() && pass.empty())
            return false;
        const std::string authValue = user + ":" + pass;
        curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
        curl_easy_setopt(curl, CURLOPT_USERPWD, authValue.c_str());
        return true;
    }

    // The legacy HAUTH/UAUTH headers derive a hash from the user and password.
    // Do not derive anything from a bearer token.
    inline std::string LegacyAuthUser(const std::string& user, const std::string& pass) {
        return IsBearerToken(pass) ? std::string() : user;
    }
    inline std::string LegacyAuthPass(const std::string& pass) {
        return IsBearerToken(pass) ? std::string() : pass;
    }

} // namespace inst::util
