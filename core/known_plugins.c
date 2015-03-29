#include "uwsgi.h"

typedef struct {
    int modifier;
    const char *usage;
    const char *plugin_name;
} map_entry_t;

#define BEGIN_KNOWN_MODIFIER_MAP(name) static map_entry_t* name[] = {
#define END_KNOWN_MODIFIER_MAP() NULL };
#define KNOWN_MODIFIER(modifier, usage, plugin_name) &(map_entry_t){modifier, usage, plugin_name},

BEGIN_KNOWN_MODIFIER_MAP(known_modifier1_map)
    KNOWN_MODIFIER(0, "Python apps", "python")
    KNOWN_MODIFIER(5, "Perl/PSGI apps", "psgi")
    KNOWN_MODIFIER(6, "Lua apps", "lua")
    KNOWN_MODIFIER(7, "Ruby/Rack apps", "rack")
    KNOWN_MODIFIER(8, "JVM apps", "jvm")
    KNOWN_MODIFIER(9, "CGI apps", "cgi")
    KNOWN_MODIFIER(11, "Go (gccgo) apps", "gccgo")
    KNOWN_MODIFIER(14, "PHP", "php")
    KNOWN_MODIFIER(15, "Mono apps", "mono")
    KNOWN_MODIFIER(17, "uWSGI Spooler", NULL)
    KNOWN_MODIFIER(18, "Symcall", "symcall")
    KNOWN_MODIFIER(19, "SSI", "ssi")
    KNOWN_MODIFIER(23, "XSLT", "xslt")
    KNOWN_MODIFIER(24, "V8 (JavaScript) apps", "v8")
    KNOWN_MODIFIER(25, "GridFS", "gridfs")
    KNOWN_MODIFIER(27, "GlusterFS", "glusterfs")
    KNOWN_MODIFIER(28, "Rados", "rados")
    KNOWN_MODIFIER(35, "WebDAV", "webdav")
    KNOWN_MODIFIER(100, "uWSGI Ping", "ping")
    KNOWN_MODIFIER(101, "Echo", "echo")
    KNOWN_MODIFIER(109, "uWSGI Legion", NULL)
    KNOWN_MODIFIER(110, "uWSGI Remote Signal", NULL)
    KNOWN_MODIFIER(111, "uWSGI Cache", NULL)
    KNOWN_MODIFIER(115, "uWSGI Emperor", NULL)
    KNOWN_MODIFIER(173, "uWSGI RPC", NULL)
    KNOWN_MODIFIER(250, "C++", "cplusplus")
END_KNOWN_MODIFIER_MAP()

/**
 * Find an entry for a given modifier in a given modifier map list.
 * @return The map entry or NULL if not found.
 */
static const map_entry_t *find_hint_for_modifier(map_entry_t** list, const int modifier) {
    while(*list) {
        if((*list)->modifier == modifier) return *list;
        list++;
    }
    return NULL;
}

/**
 * Log message about an unavailable modifier, trying to be
 * helpful by looking it up in the table of known modifiers.
 * 
 * If the modifier is well and truly unknown, revert to a less
 * helpful message.
 * 
 * @param modifier1 The modifier1 value requested.
 */
void log_modifier1_hint(int modifier1) {
    const map_entry_t *ent = find_hint_for_modifier(known_modifier1_map, modifier1);
    if(ent != NULL) {
        uwsgi_log("-- unavailable modifier requested: %d (\"%s\", try `--plugin %s`?) --\n", modifier1, ent->usage, ent->plugin_name);
    } else {
        uwsgi_log("-- unavailable modifier requested: %d (are you missing a plugin?) --\n", modifier1);
    }
}
