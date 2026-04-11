#include "em_filter.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef _WIN32
static char *strcasestr_win(const char *h, const char *n) {
    if (!*n) return (char*)h;
    for (; *h; h++) {
        if (tolower((unsigned char)*h) == tolower((unsigned char)*n)) {
            const char *p = h, *q = n;
            while (*p && *q && tolower((unsigned char)*p) == tolower((unsigned char)*q)) { p++; q++; }
            if (!*q) return (char*)h;
        }
    }
    return NULL;
}
#define strcasestr strcasestr_win
#define strncasecmp _strnicmp
#endif

/* Minimal regex-free HTML helpers using basic string scanning */

/* Append char to a growing buffer */
static void buf_append(char **buf, size_t *len, size_t *cap, char c) {
    if (*len + 1 >= *cap) {
        *cap = (*cap == 0) ? 256 : *cap * 2;
        *buf = realloc(*buf, *cap);
    }
    (*buf)[(*len)++] = c;
    (*buf)[*len] = '\0';
}

/* em_strip_scripts: remove <script...>...</script> blocks */
char *em_strip_scripts(const char *html) {
    char *out = NULL;
    size_t len = 0, cap = 0;
    const char *p = html;
    while (*p) {
        if (strncasecmp(p, "<script", 7) == 0) {
            /* skip to end of </script> */
            const char *end = strcasestr(p, "</script>");
            if (end) {
                p = end + 9;
                continue;
            }
        }
        buf_append(&out, &len, &cap, *p++);
    }
    if (!out) { out = malloc(1); out[0] = '\0'; }
    return out;
}

/* em_get_text: strip all HTML tags */
char *em_get_text(const char *html) {
    char *out = NULL;
    size_t len = 0, cap = 0;
    const char *p = html;
    while (*p) {
        if (*p == '<') {
            while (*p && *p != '>') p++;
            if (*p) p++;
        } else {
            buf_append(&out, &len, &cap, *p++);
        }
    }
    if (!out) { out = malloc(1); out[0] = '\0'; }
    return out;
}

/* em_extract_attribute: find attr="value" or attr='value' */
char *em_extract_attribute(const char *element, const char *attr) {
    char pat[256];
    snprintf(pat, sizeof(pat), "%s=", attr);
    const char *p = strcasestr(element, pat);
    if (!p) return NULL;
    p += strlen(pat);
    char quote = *p;
    if (quote != '"' && quote != '\'') return NULL;
    p++;
    const char *end = strchr(p, quote);
    if (!end) return NULL;
    size_t len = (size_t)(end - p);
    char *val = malloc(len + 1);
    memcpy(val, p, len);
    val[len] = '\0';
    return val;
}

/* em_decode_html_entities: numeric decimal, hex, and named */
static int decode_named(const char *name, size_t len, char *out_utf8) {
    struct { const char *name; const char *utf8; } table[] = {
        {"nbsp",   "\xc2\xa0"},
        {"amp",    "&"},   {"lt",     "<"},   {"gt",  ">"},
        {"quot",   "\""}, {"apos",   "'"  },
        {"eacute", "\xc3\xa9"}, {"egrave", "\xc3\xa8"},
        {"agrave", "\xc3\xa0"}, {"ccedil", "\xc3\xa7"},
        {"ocirc",  "\xc3\xb4"}, {"ecirc",  "\xc3\xaa"},
        {"icirc",  "\xc3\xae"}, {"ugrave", "\xc3\xb9"},
        {"aacute", "\xc3\xa1"},
        {NULL, NULL}
    };
    for (int i = 0; table[i].name; i++) {
        if (strlen(table[i].name) == len &&
            strncasecmp(table[i].name, name, len) == 0) {
            strcpy(out_utf8, table[i].utf8);
            return 1;
        }
    }
    return 0;
}

/* Encode a Unicode code point to UTF-8 */
static int encode_utf8(unsigned int cp, char *out) {
    if (cp <= 0x7f) { out[0]=(char)cp; return 1; }
    if (cp <= 0x7ff) {
        out[0]=(char)(0xc0|(cp>>6)); out[1]=(char)(0x80|(cp&0x3f)); return 2;
    }
    if (cp <= 0xffff) {
        out[0]=(char)(0xe0|(cp>>12)); out[1]=(char)(0x80|((cp>>6)&0x3f));
        out[2]=(char)(0x80|(cp&0x3f)); return 3;
    }
    out[0]=(char)(0xf0|(cp>>18)); out[1]=(char)(0x80|((cp>>12)&0x3f));
    out[2]=(char)(0x80|((cp>>6)&0x3f)); out[3]=(char)(0x80|(cp&0x3f));
    return 4;
}

char *em_decode_html_entities(const char *text) {
    char *out = NULL;
    size_t len = 0, cap = 0;
    const char *p = text;
    while (*p) {
        if (*p == '&') {
            const char *semi = strchr(p, ';');
            if (semi && (size_t)(semi - p) <= 10) {
                const char *inner = p + 1;
                size_t ilen = (size_t)(semi - inner);
                char tmp[8] = {0};
                if (*inner == '#') {
                    unsigned int cp;
                    if (*(inner+1) == 'x' || *(inner+1) == 'X') {
                        cp = (unsigned int)strtoul(inner+2, NULL, 16);
                    } else {
                        cp = (unsigned int)strtoul(inner+1, NULL, 10);
                    }
                    int n = encode_utf8(cp, tmp);
                    for (int i = 0; i < n; i++)
                        buf_append(&out, &len, &cap, tmp[i]);
                    p = semi + 1;
                    continue;
                } else if (decode_named(inner, ilen, tmp)) {
                    for (int i = 0; tmp[i]; i++)
                        buf_append(&out, &len, &cap, tmp[i]);
                    p = semi + 1;
                    continue;
                }
            }
        }
        buf_append(&out, &len, &cap, *p++);
    }
    if (!out) { out = malloc(1); out[0] = '\0'; }
    return out;
}

/* em_should_skip_link */
int em_should_skip_link(const char *url, const char **excluded, int excluded_len) {
    if (strncmp(url, "http", 4) != 0) return 1;
    for (int i = 0; i < excluded_len; i++) {
        if (strstr(url, excluded[i])) return 1;
    }
    return 0;
}
