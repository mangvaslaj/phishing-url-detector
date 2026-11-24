#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>


// ---------------------------------------------------------------------------
// URL parsing helpers
// ---------------------------------------------------------------------------

// Returns pointer to start of authority (after "scheme://"), or url if none.
static const char *authority_start(const char *url) {
    const char *p = strstr(url, "://");
    return p ? p + 3 : url;
}

// Copies the hostname (no scheme, userinfo, port, path) into out.
static void extract_host(const char *url, char *out, size_t n) {
    const char *p = authority_start(url);
    const char *end = p + strcspn(p, "/?#");     // end of authority
    const char *at = memchr(p, '@', end - p);    // skip userinfo
    if (at) p = at + 1;

    size_t len = 0;
    while (p + len < end && p[len] != ':') len++; // stop at port
    if (len >= n) len = n - 1;
    memcpy(out, p, len);
    out[len] = '\0';
}

// ---------------------------------------------------------------------------
// Individual checks
// ---------------------------------------------------------------------------

// 1. Raw IPv4 address used as host (each octet must be 0-255)
bool has_ip_address(const char *host) {
    int a, b, c, d;
    char extra;
    if (sscanf(host, "%d.%d.%d.%d%c", &a, &b, &c, &d, &extra) != 4) return false;
    return a >= 0 && a <= 255 && b >= 0 && b <= 255 &&
           c >= 0 && c <= 255 && d >= 0 && d <= 255;
}

// 2. '@' in the authority part (browsers ignore everything before it).
//    Harmless in paths/queries, so only the authority is checked.
bool has_at_symbol(const char *url) {
    const char *p = authority_start(url);
    size_t len = strcspn(p, "/?#");
    return memchr(p, '@', len) != NULL;
}

// 3. Suspicious keywords often used in phishing URLs
int count_suspicious_keywords(const char *url) {
    const char *keywords[] = {"login", "verify", "update", "secure",
                              "account", "banking", "free", "signin"};
    int count = 0;

    // Lowercase copy for case-insensitive search
    char lower_url[512];
    strncpy(lower_url, url, sizeof(lower_url) - 1);
    lower_url[sizeof(lower_url) - 1] = '\0';
    for (int i = 0; lower_url[i]; i++) {
        lower_url[i] = tolower((unsigned char)lower_url[i]);
    }

    int num_keywords = sizeof(keywords) / sizeof(keywords[0]);
    for (int i = 0; i < num_keywords; i++) {
        if (strstr(lower_url, keywords[i]) != NULL) {
            count++;
        }
    }
    return count;
}

// 4. Dots in hostname (excessive subdomains, e.g. login.secure.paypal.evil.com)
int count_dots(const char *host) {
    int dots = 0;
    for (; *host; host++) if (*host == '.') dots++;
    return dots;
}

// ---------------------------------------------------------------------------
// Main evaluation
// ---------------------------------------------------------------------------

void analyze_url(const char *url) {
    int risk_score = 0;
    char host[256];
    extract_host(url, host, sizeof host);

    printf("\nAnalyzing: %s\n", url);
    printf("Host: %s\n", host[0] ? host : "(none)");
    printf("--------------------------------------------------\n");

    if (strncasecmp(url, "https://", 8) != 0) {
        printf("[+2] Not using HTTPS\n");
        risk_score += 2;
    }
    if (strlen(url) > 75) {
        printf("[+1] Unusually long URL (%zu chars)\n", strlen(url));
        risk_score += 1;
    }
    if (has_ip_address(host)) {
        printf("[+3] Uses raw IP address instead of domain name\n");
        risk_score += 3;
    }
    if (has_at_symbol(url)) {
        printf("[+3] Contains '@' in the authority (URL redirection trick)\n");
        risk_score += 3;
    }
    if (strchr(host, '-') != NULL) {
        printf("[+1] Hyphen in hostname (often used in typosquatting)\n");
        risk_score += 1;
    }

    int dots = count_dots(host);
    if (dots > 3) {
        printf("[+2] Excessive subdomains (%d dots in host)\n", dots);
        risk_score += 2;
    }

    int kw_hits = count_suspicious_keywords(url);
    if (kw_hits > 0) {
        printf("[+%d] Contains %d suspicious keyword(s)\n", kw_hits, kw_hits);
        risk_score += kw_hits;
    }

    printf("--------------------------------------------------\n");
    printf("Total Risk Score: %d -> Verdict: ", risk_score);
    if (risk_score >= 5)      printf("HIGH RISK (Likely Phishing)\n");
    else if (risk_score >= 3) printf("SUSPICIOUS (Proceed with Caution)\n");
    else                      printf("LOW RISK (Likely Safe)\n");
}

// ---------------------------------------------------------------------------
// Menu / main
// ---------------------------------------------------------------------------

void menu_display(void) {
    printf("\n=======================\n"
           "C Phishing URL Detector\n"
           "=======================\n");
    printf("1. Check URL\n");
    printf("2. Exit\n");
    printf("=======================\n");
    printf("Enter your choice: ");
}

int main(void) {
    char url[512];
    char line[16];

    while (1) {
        menu_display();
        if (!fgets(line, sizeof line, stdin)) break;   // EOF
        int choice = atoi(line);

        if (choice == 1) {
            while (1) {
                printf("\nEnter URL (or 'exit' to return to menu): ");
                if (!fgets(url, sizeof url, stdin)) return 0;
                url[strcspn(url, "\r\n")] = '\0';

                if (strcmp(url, "exit") == 0) break;
                if (url[0] != '\0') analyze_url(url);
            }
        } else if (choice == 2) {
            printf("Thank you for using the URL checker.\n");
            break;
        } else {
            printf("Invalid choice. Please try again.\n");
        }
    }
    return 0;
}
