<?php
if (isset($_REQUEST['token'])) {
	$token = $_REQUEST['token'];
	$fields = array('apiKey' => $api_key, 'token' => $token, 'format' => 'xml');

	$fields_encoded = array();
	foreach ($fields as $name => $value)
		$fields_encoded[] = "$name=$value";

	$fields = join('&', $fields_encoded);

	// POST to RPX
	$ch = curl_init('https://rpxnow.com/api/v2/auth_info');
	curl_setopt($ch, CURLOPT_POST, true);
	curl_setopt($ch, CURLOPT_POSTFIELDS, $fields);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
	curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
	$response = curl_exec($ch);
	$info = curl_getinfo($ch);
	curl_close($ch);

	if ($response !== false && $info['http_code'] == 200) {
		$doc = new SimpleXMLElement($response);

		if ((string)$doc['stat'] == 'ok') {
			$user_id = (string)$doc->profile->primaryKey;
			if (!$user_id || !userExists($user_id)) {	// Never visited, create a user.
				$user_id = createUser($doc->profile, split(',', $groups));
				mapUser($api_key, $user_id, (string)$doc->profile->identifier) or die("couldn't map user");;
			}
			$username =
			 $modx->db->getValue($modx->db->select('username', $modx->getFullTableName('web_users'), "id = '$user_id'"));

			modxWebLogin($username);

			redirectToJump();
		}
		else {
			header("Location: /\r\n") and die();
		}
	}
	else {
		print_r($info);
		return "Error authenticating token.  Response: " . $info['http_code'];
	}

}
else if (isset($_REQUEST['logout'])) {
	modxWebLogout();
	redirectToJump();
}
else {
	return "Access denied.";
}

function redirectToJump() {
	$jump_url = (isset($_SESSION['jump']) ? $_SESSION['jump'] : '/');
	header("Location: $jump_url\r\n") and die();
}

function createUser($profile, $groups) {
	global $modx;

	$username = createUniqueUsername((string)$profile->preferredUsername);

	$user_fields = array(
		'username' => $modx->db->escape($username),
		'password' => createRandomPassword()
	);

	$user_attribute_fields = array(
		'fullname' => $modx->db->escape((string)$profile->displayName),
		'email' => $modx->db->escape((string)$profile->verifiedEmail),
		'country' => (isset($profile->address) ? $profile->address->country->text : '')
	);

	$key = $modx->db->insert($user_fields, $modx->getFullTableName('web_users'));
	$user_attribute_fields['internalKey'] = $key;
	$modx->db->insert($user_attribute_fields, $modx->getFullTableName('web_user_attributes'));

	// add user to web groups
	if(count($groups) > 0) {
		$results = $modx->db->makeArray($modx->db->select('id', $modx->getFullTableName("webgroup_names"), "name IN ('".implode("','",$groups)."')"));
		foreach ($results as $fields) {
			$modx->db->insert(array('webgroup' => $fields['id'], 'webuser' => $key), $modx->getFullTableName("web_groups"));
		}
	}

	return $key;
}

function createUniqueUsername($preferred_username) {
	global $modx;
	$username = '';
	$count = 0;
	$existing_user = false;

	do {
		$username = $preferred_username . ($count++ ? $count : '');
		$existing_user = $modx->db->getValue($modx->db->select('id', $modx->getFullTableName('web_users'), 'username = "'.$modx->db->escape($username) .'"'));
	} while ($existing_user);

	return $username;
}

function createRandomPassword() {
    $chars = "abcdefghijkmnopqrstuvwxyz023456789";
    srand((double)microtime()*1000000);
    $i = 0;
    $pass = '' ;
    while ($i <= 7) {
        $num = rand() % 33;
        $tmp = substr($chars, $num, 1);
        $pass = $pass . $tmp;
        $i++;
    }
    return $pass;
}

function mapUser($api_key, $user_id, $identifier) {
	$fields = array('apiKey' => $api_key, 'identifier' => $identifier, 'primaryKey' => $user_id, 'overwrite' => true, 'format' => 'xml');

	$fields_encoded = array();
	foreach ($fields as $name => $value)
		$fields_encoded[] = "$name=$value";

	$fields = join('&', $fields_encoded);

	$ch = curl_init('https://rpxnow.com/api/v2/map');
	curl_setopt($ch, CURLOPT_POST, true);
	curl_setopt($ch, CURLOPT_POSTFIELDS, $fields);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
	curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
	$response = curl_exec($ch);
	$info = curl_getinfo($ch);
	curl_close($ch);

	return ($response !== false && $info['http_code'] == 200);
}

function modxWebLogin($username) {
	global $modx;
	$dbase = $modx->dbConfig['dbase'];
	$table_prefix = $modx->dbConfig['table_prefix'];

	// invoke OnBeforeWebLogin event
	$modx->invokeEvent("OnBeforeWebLogin",
							array(
								"username"		=> $username,
								"userpassword"	=> $givenPassword,
								"rememberme"	=> $_POST['rememberme']
							));

	$sql = "SELECT $dbase.".$table_prefix."web_users.*, $dbase.".$table_prefix."web_user_attributes.* FROM $dbase.".$table_prefix."web_users, $dbase.".$table_prefix."web_user_attributes WHERE BINARY $dbase.".$table_prefix."web_users.username = '".$username."' and $dbase.".$table_prefix."web_user_attributes.internalKey=$dbase.".$table_prefix."web_users.id;";
	$ds = $modx->dbQuery($sql);
	$limit = $modx->db->getRecordCount($ds);

	if($limit==0 || $limit>1) {
		return;
	}	

	$row = $modx->db->getRow($ds);

	$internalKey 			= $row['internalKey'];
	$dbasePassword 			= $row['password'];
	$failedlogins 			= $row['failedlogincount'];
	$blocked 				= $row['blocked'];
	$blockeduntildate		= $row['blockeduntil'];
	$blockedafterdate		= $row['blockedafter'];
	$registeredsessionid	= $row['sessionid'];
	$role					= $row['role'];
	$lastlogin				= $row['lastlogin'];
	$nrlogins				= $row['logincount'];
	$fullname				= $row['fullname'];
	//$sessionRegistered 		= checkSession();
	$email 					= $row['email'];

	// load user settings
	if($internalKey){
		$result = $modx->dbQuery("SELECT setting_name, setting_value FROM ".$dbase.".".$table_prefix."web_user_settings WHERE webuser='$internalKey'");
		while ($row = $modx->fetchRow($result, 'both')) $modx->config[$row[0]] = $row[1];
	}		

	if($blocked=="1") { // this user has been blocked by an admin, so no way he's loggin in!
		$errortext = "You are blocked and cannot log in!";
		return $errortext;
	}

	// blockuntil
	if($blockeduntildate>time()) { // this user has a block until date
		$errortext = "You are blocked and cannot log in! Please try again later.";
		return $errortext;
	}

	// blockafter
	if($blockedafterdate>0 && $blockedafterdate<time()) { // this user has a block after date
		$errortext = "You are blocked and cannot log in! Please try again later.";
		return $errortext;
	}

	// allowed ip
	if (isset($modx->config['allowed_ip'])) {
		if (strpos($modx->config['allowed_ip'],$_SERVER['REMOTE_ADDR'])===false) {
			$errortext = "You are not allowed to login from this location.";
			return $errortext;
		}
	}

	// allowed days
	if (isset($modx->config['allowed_days'])) {
		$date = getdate();
		$day = $date['wday']+1;
		if (strpos($modx->config['allowed_days'],"$day")===false) {
			$errortext = "You are not allowed to login at this time. Please try again later.";
			return $errortext;
		}		
	}

	// invoke OnWebAuthentication event
	$rt = $modx->invokeEvent("OnWebAuthentication",
							array(
								"userid"		=> $internalKey,
								"username"		=> $username,
								"userpassword"	=> $givenPassword,
								"savedpassword"	=> $dbasePassword,
								"rememberme"	=> $_POST['rememberme']
							));


	$currentsessionid = session_id();

	if(!isset($_SESSION['webValidated'])) {
		$sql = "update $dbase.".$table_prefix."web_user_attributes SET failedlogincount=0, logincount=logincount+1, lastlogin=thislogin, thislogin=".time().", sessionid='$currentsessionid' where internalKey=$internalKey";
		$ds = $modx->dbQuery($sql);
	}

	$_SESSION['webShortname']=$username; 
	$_SESSION['webFullname']=$fullname; 
	$_SESSION['webEmail']=$email; 
	$_SESSION['webValidated']=1; 
	$_SESSION['webInternalKey']=$internalKey; 
	$_SESSION['webValid']=base64_encode($givenPassword); 
	$_SESSION['webUser']=base64_encode($username); 
	$_SESSION['webFailedlogins']=$failedlogins; 
	$_SESSION['webLastlogin']=$lastlogin; 
	$_SESSION['webnrlogins']=$nrlogins;
	$_SESSION['webUserGroupNames'] = ''; // reset user group names

	// get user's document groups
	$dg='';$i=0;
	$tblug = $dbase.".".$table_prefix."web_groups";
	$tbluga = $dbase.".".$table_prefix."webgroup_access";
	$sql = "SELECT uga.documentgroup
			FROM $tblug ug
			INNER JOIN $tbluga uga ON uga.webgroup=ug.webgroup
			WHERE ug.webuser =".$internalKey;
	$ds = $modx->db->query($sql); 
	while ($row = $modx->db->getRow($ds,'num')) $dg[$i++]=$row[0];


	$_SESSION['webDocgroups'] = $dg;

	// $log = new logHandler;
	// $log->initAndWriteLog("Logged in", $_SESSION['webInternalKey'], $_SESSION['webShortname'], "58", "-", "WebLogin");
								
	// invoke OnWebLogin event
	$modx->invokeEvent("OnWebLogin",
					array(
						"userid"		=> $internalKey,
						"username"		=> $username,
						"userpassword"	=> $givenPassword,
						"rememberme"	=> $_POST['rememberme']
					));
	
	return;

}

function userExists($user_id) {
	global $modx;
	return $modx->db->getValue($modx->db->select('id', $modx->getFullTableName('web_users'), 'id = "'.$modx->db->escape($user_id).'"')) != null;
}

function modxWebLogout() {
	global $modx;
	$dbase = $modx->dbConfig['dbase'];
	$table_prefix = $modx->dbConfig['table_prefix'];

	$internalKey = $_SESSION['webInternalKey'];
	$username = $_SESSION['webShortname'];

	// invoke OnBeforeWebLogout event
	$modx->invokeEvent("OnBeforeWebLogout",
						array(
							"userid"		=> $internalKey,
							"username"		=> $username
						));

	// if we were launched from the manager 
	// do NOT destroy session
	if(isset($_SESSION['mgrValidated'])) {
		unset($_SESSION['webShortname']);
		unset($_SESSION['webFullname']);
		unset($_SESSION['webEmail']);
		unset($_SESSION['webValidated']);
		unset($_SESSION['webInternalKey']);
		unset($_SESSION['webValid']);
		unset($_SESSION['webUser']);
		unset($_SESSION['webFailedlogins']);
		unset($_SESSION['webLastlogin']);
		unset($_SESSION['webnrlogins']);
		unset($_SESSION['webUsrConfigSet']);
		unset($_SESSION['webUserGroupNames']);
		unset($_SESSION['webDocgroups']);			
	}
	else {
		// Unset all of the session variables.
		$_SESSION = array();
		// destroy session cookie
		if (isset($_COOKIE[session_name()])) {
			setcookie(session_name(), '', time()-42000, '/');
		}
		session_destroy();
		$sessionID = md5(date('d-m-Y H:i:s'));
		session_id($sessionID);
		startCMSSession();
		session_destroy();
	}

	// invoke OnWebLogout event
	$modx->invokeEvent("OnWebLogout",
					array(
						"userid"		=> $internalKey,
						"username"		=> $username
						));

	return;

}
?>