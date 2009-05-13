// <?php
//
// Store the URI of the last visited page in $_SESSION['jump'] on every page hit
// except for the RPX Token authentication page.  The AuthRPX snippet checks for
// the variable in the session and, if present, redirects on successful login.
//

// ----- Configuration
$TokenAuthPage = 147;  // Set to the ID of the document the AuthRPX snippet runs on.
// ----- End Configuration

$e = & $modx->Event;

if ($e->name == 'OnWebPageInit' && $modx->documentIdentifier != $TokenAuthPage) {
	$_SESSION['jump'] = 'http://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
}
// ?>
