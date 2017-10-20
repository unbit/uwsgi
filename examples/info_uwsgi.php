uWSGI version <b><?=uwsgi_version()?></b><br/>
worker id: <b><?=uwsgi_worker_id()?></b><br/>
master pid: <b><?=uwsgi_masterpid()?></b><br/>

uri: <b><?= $_SERVER['REQUEST_URI'] ?></b><br/>
docroot: <b><?= $_SERVER['DOCUMENT_ROOT'] ?></b><br/>
PATH_INFO: <b><?= $_SERVER['PATH_INFO'] ?></b><br/>

<? uwsgi_signal(17) ?>

<? uwsgi_setprocname("test test test"); ?>

rpc result:<br/>
<? echo uwsgi_rpc("", "hello", "one", "two", "three"); ?>

<?
	if ($_SERVER['REQUEST_METHOD'] == 'POST') {
		echo uwsgi_cache_update('foobar', $_POST['cache_val']);
	}

?>
cache value: <?= uwsgi_cache_get('foobar') ?><br/>
<form method="POST">
	<input type="text" name="cache_val" value="<?=uwsgi_cache_get('foobar')?>"/>
	<input type="submit" value="cache set" />
</form>
