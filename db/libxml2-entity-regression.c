/* Bounded offline entity-amplification regression; no external entities or I/O.
 * A focused CVE-2026-6653 backport check, not general libxml2 clearance. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

static int amplification_error;
static void capture_error(void *context, xmlErrorPtr err) {
    (void)context;
    if (err != NULL && err->code == XML_ERR_ENTITY_LOOP && err->message != NULL &&
        strstr(err->message, "Maximum entity amplification factor exceeded") != NULL)
        amplification_error = 1;
}

static int check_case(int amplification, int huge) {
    char input[4096];
    size_t n = 0;
    int levels = amplification ? 4 : 2;
    int copies = amplification ? 12 : 10;
    n += (size_t)snprintf(input + n, sizeof(input) - n, "<!DOCTYPE root [<!ENTITY e0 \"");
    memset(input + n, 'a', 1000); n += 1000;
    n += (size_t)snprintf(input + n, sizeof(input) - n, "\">");
    for (int level = 1; level <= levels; ++level) {
        n += (size_t)snprintf(input + n, sizeof(input) - n, "<!ENTITY e%d \"", level);
        for (int copy = 0; copy < copies; ++copy)
            n += (size_t)snprintf(input + n, sizeof(input) - n, "&e%d;", level - 1);
        n += (size_t)snprintf(input + n, sizeof(input) - n, "\">");
    }
    n += (size_t)snprintf(input + n, sizeof(input) - n, "]><root>&e%d;</root>", levels);
    if (n >= sizeof(input)) return 1;
    xmlParserCtxtPtr ctxt = xmlNewParserCtxt();
    if (ctxt == NULL) return 1;
    amplification_error = 0;
    xmlSetStructuredErrorFunc(NULL, capture_error);
    int flags = XML_PARSE_NONET | XML_PARSE_NOENT;
    if (huge) flags |= XML_PARSE_HUGE;
    xmlDocPtr doc = xmlCtxtReadMemory(ctxt, input, (int)n, "offline.xml", NULL, flags);
    int passed = 0;
    if (amplification) {
        passed = doc == NULL && amplification_error;
    } else if (doc != NULL) {
        xmlChar *text = xmlNodeGetContent(xmlDocGetRootElement(doc));
        passed = text != NULL && xmlStrlen(text) == 100000;
        xmlFree(text);
    }
    printf("case=%s huge=%d verdict=%s\n", amplification ? "20736000-byte-amplification" : "100000-byte-control", huge, passed ? "PASS" : "FAIL");
    xmlFreeDoc(doc); xmlFreeParserCtxt(ctxt);
    return !passed;
}
int main(void) {
    int failures = 0;
    for (int huge = 0; huge <= 1; ++huge) {
        failures += check_case(0, huge);
        failures += check_case(1, huge);
    }
    xmlCleanupParser();
    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
