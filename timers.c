/*

uWSGI timers implementation

based on Linux hrtimers and nginx timeout management.

rbtree with allowed duplicate keys is used (code inspired by http://en.wikipedia.org/wiki/Red-black_tree)

*/

#define RBT_BLACK	0
#define RBT_RED		1

struct uwsgi_timer {
	
	time_t	key;

	struct uwsgi_timer	*left;	
	struct uwsgi_timer	*right;	
	struct uwsgi_timer	*parent;	

	uint8_t color;

	void *data;
	
};

struct uwsgi_timer *uwsgi_init_timer() {

	struct uwsgi_timer *ut = uwsgi_malloc(sizeof(struct uwsgi_timer));

	ut->key = LONG_MAX;

	ut->left = NULL;
	ut->right = NULL;
	ut->parent = NULL;

	ut->color = RB_BLACK
	ut->data = NULL;

	return ut;
}

struct uwsgi_timer *uwsgi_min_timer(struct uwsgi_timer *root) {

	struct uwsgi_timer *node = root;

	while(node->left != NULL) {
		node = node->left;
	}

	return node;
}

void uwsgi_add_timer(struct uwsgi_timer *root, time_t key, void *data) {

	struct uwsgi_timer *ut = uwsgi_malloc(sizeof(struct uwsgi_timer));
	struct uwsgi_timer *node = root;

	ut->key = key;

	// attach to parent
	for(;;) {
		
	}
	
	ut->left = NULL;
	ut->right = NULL;

	ut->color = RBT_READ;

}

void uwsgi_del_timer(struct uwsgi_timer_pool *pool, time_t key) {

	rbtree_remove(pool->rbtree, key);

}

void uwsgi_expire_timers(struct uwsgi_timer_pool *pool) {

	// nginx use a time cache, probably we can do it the same in async loop
	time_t now = time(NULL);

	for(;;) {

		node = rbtree_min(pool->rbtree);

		if (node->key <= now) {
			rbtree_remove(pool->rbtree, node->key);
			continue;
		}

		return;
	}

}
