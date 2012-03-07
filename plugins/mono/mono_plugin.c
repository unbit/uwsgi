#include "../../uwsgi.h"

struct uwsgi_mono {

	char *assembly_name ;
	
} um;

int uwsgi_mono_init() {


	MonoDomain *domain;

	MonoAssembly *assembly;
        MonoImage *image, *corlib;

	domain = mono_jit_init("uwsgi");

	corlib = mono_get_corlib();
        if (!corlib) {
		uwsgi_log("unable to initialize MONO engine\n");
		exit(1);
        }


	image = mono_assembly_get_image(assembly);

}


struct uwsgi_plugin mono_plugin = {

	.name = "mono",
	.init = uwsgi_mono_init,
};
