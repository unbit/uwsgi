/*

uWSGI timers implementation

based on Linux hrtimers and nginx timeout management.

rbtree with allowed duplicate keys is used

*/

#include "uwsgi.h"

struct rb_root *uwsgi_init_rb_timer() {

	struct rb_root *u_rb_root = uwsgi_malloc(sizeof(struct rb_root));

	u_rb_root->rb_node = NULL;

	return u_rb_root;
}

struct uwsgi_rb_timer *uwsgi_min_rb_timer(struct rb_root *root) {

	struct rb_node *node = root->rb_node;

	if (node == NULL)
		return NULL;

	while (node->rb_left != NULL) {
		node = node->rb_left;
	}

	return ((struct uwsgi_rb_timer *) node);
}

struct uwsgi_rb_timer *uwsgi_add_rb_timer(struct rb_root *root, time_t key, void *data) {

	struct uwsgi_rb_timer *urbt = uwsgi_malloc(sizeof(struct uwsgi_rb_timer));
	struct rb_node **p = &root->rb_node, *parent = NULL;
	struct uwsgi_rb_timer *current_rb_timer;

	memset(urbt, 0, sizeof(struct uwsgi_rb_timer));

	urbt->key = key;
	urbt->data = data;

	while (*p) {
		parent = *p;

		current_rb_timer = (struct uwsgi_rb_timer *) parent;

		if (key <= current_rb_timer->key) {
			p = &(*p)->rb_left;
		}
		else {
			p = &(*p)->rb_right;
		}
	}

	rb_link_node((struct rb_node *) urbt, parent, p);

	rb_insert_color((struct rb_node *) urbt, root);

	return urbt;
}
