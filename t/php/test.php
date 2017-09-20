<?php

# execute with:
# uwsgi --ini t/php/config.ini &
# curl http://localhost:8080/test.php

set_error_handler(function() {
	var_export(func_get_args());
	echo "\nFAIL\n";
	die;
});

session_start();
$_SESSION['t'] = 't';
session_commit();

session_start();
session_regenerate_id();
session_commit();

session_start();
session_destroy();
echo "PASS\n";
