/* Check ordinary local text inclusion with and without whitespace stripping. */
#include <stdio.h>
#include <string.h>
#include <libxml/parser.h>
#include <libxml/xinclude.h>

static xmlExternalEntityLoader default_loader;
static int loads, observed_flags;

static xmlParserInputPtr observe_text(const char *url, const char *id,
                                     xmlParserCtxtPtr ctxt) {
    if (!url || strcmp(url, "message.txt") || !ctxt)
        return NULL;
    ++loads;
    observed_flags = ctxt->options;
    return default_loader(url, id, ctxt);
}

static int check(int tree, int flags) {
    static const char input[] =
        "<root xmlns:xi='http://www.w3.org/2001/XInclude'>"
        "<xi:include href='message.txt' parse='text'/></root>";
    xmlDocPtr doc = xmlReadMemory(input, sizeof(input) - 1, NULL, NULL, flags);
    if (!doc)
        return 1;
    xmlNodePtr root = xmlDocGetRootElement(doc);
    loads = observed_flags = 0;
    int includes = tree ? xmlXIncludeProcessTree(root) : xmlXIncludeProcess(doc);
    xmlChar *content = xmlNodeGetContent(root);
    int passed = includes == 1 && loads == 1 &&
                 (observed_flags & XML_PARSE_NOBLANKS) == flags &&
                 xmlStrEqual(content, BAD_CAST "ordinary text");
    xmlFree(content);
    xmlFreeDoc(doc);
    printf("api=%s noblanks=%d verdict=%s\n", tree ? "tree" : "document",
           flags != 0, passed ? "PASS" : "FAIL");
    return !passed;
}

int main(void) {
    LIBXML_TEST_VERSION
    default_loader = xmlGetExternalEntityLoader();
    xmlSetExternalEntityLoader(observe_text);
    int failed = 0;
    for (int tree = 0; tree <= 1; ++tree) {
        failed |= check(tree, 0);
        failed |= check(tree, XML_PARSE_NOBLANKS);
    }
    xmlSetExternalEntityLoader(default_loader);
    xmlCleanupParser();
    return failed;
}
