NAME = 'rados'

CFLAGS = []
LDFLAGS = []
LIBS = ['-lrados']
GCC_LIST = ['rados']

import __main__
has_rados_ioctx_pool_requires_alignment2 = __main__.test_snippet("""
#include <rados/librados.h>
int main()
{
    rados_ioctx_t ctx = NULL;
    rados_ioctx_pool_requires_alignment2(ctx, NULL);
    rados_ioctx_pool_required_alignment2(ctx, NULL);
    return 0;
}
""", LIBS=['-lrados'])
has_rados_ioctx_set_namespace = __main__.test_snippet("""
#include <rados/librados.h>
int main()
{
    rados_ioctx_t ctx = NULL;
    rados_ioctx_set_namespace(ctx, NULL);
    return 0;
}
""", LIBS=['-lrados'])

if has_rados_ioctx_pool_requires_alignment2:
    CFLAGS.append('-DHAS_RADOS_IOCTX_POOL_REQUIRES_ALIGNMENT2')
if has_rados_ioctx_set_namespace:
    CFLAGS.append('-DHAS_RADOS_IOCTX_SET_NAMESPACE')
