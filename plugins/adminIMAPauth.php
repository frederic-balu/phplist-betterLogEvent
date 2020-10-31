<?php

require_once __DIR__.'/../accesscheck.php';

class adminIMAPauth extends phplistPlugin {
  public $name = 'IMAP server as authenticator';
  public $version = 0.2;
  public $authors = 'Frederic BALU';
  public $description = 'Provides authentication to phpList administrators using IMAP ';
  public $authProvider = true;

/**
 * Define settings needed by this plugin
 * !!! each array name length has to be less than or equal 36 characters
**/  
public $settings = array(
    "adminIMAPauth__imap_server_name" => array (
      'value' => "", // no default value
      'description' => 'IMAP admin authentication server nane<br/>Your IMAP server name (FQDN) or IP<br/>examples : mail.google.com, 8.8.8.8, 2001:4860:4860::8888 ...',
      'type' => "text",
      'allowempty' => 0,
      'category'=> 'security',
    ),
    "adminIMAPauth__imap_server_security" => array (
      'value' => "", // default is empty
      'description' => 'IMAP admin authentication server security<br/>Enter the string corresponding to the IMAP security protocol you have to use.<br/>Leave empty for no security. Valid : [novalidate-cert | tls | ssl | ssl/novalidate-cert]',
      'type' => "text",
      'allowempty' => 1,
      'category'=> 'security',
    ),
    "adminIMAPauth__imap_server_port" => array (
      'value' => "143", // default IMAP port
      'description' => 'IMAP admin authentication server port<br/>Enter port number value according to chosen security and provider configuration.<br/>Valid : {143-1024}',
      'type' => "integer",
      'allowempty' => 0,
      "min" => 143,
      "max" => 1024,
      'category'=> 'security',
    ),
  );
  
 /**
   * Fallback to local login if IMAP fails
   */
  public function fallback_localValidateLogin($login, $password ) {
    logEvent('calling : adminIMAPauth :fallback_localValidateLogin');
    require_once __DIR__.'/../phpListAdminAuthentication.php';
    $core_admin_auth = new phpListAdminAuthentication();
    return $core_admin_auth -> validateLogin($login, $password );
  }

  /**
   * 
   * validateLogin, verify that the login credentials are correct
   * 
   * @param string $login the login field
   * @param string $password the password
   * 
   * @return array 
   *    index 0 -> false if login failed, index of the administrator if successful
   *    index 1 -> error message when login fails
   * 
   * eg 
   *    return array(5,'OK'); // -> login successful for admin 5
   *    return array(0,'Incorrect login details'); // login failed
   * 
   */ 
  public function validateLogin($login, $password ) 
  {
    logEvent('calling : adminIMAPauth : validateLogin' );      
    // if no identifiers are given, just give up !
    if( empty($login) || ($password=="") ) {
            return array(0, s('Please enter your credentials.'));
        };
    // check if $login is in database
    $query = sprintf('select * from %s where loginname = "%s"', $GLOBALS['tables']['admin'], sql_escape($login ) );
    $req = Sql_Query($query);
    $admindata = Sql_Fetch_Assoc($req);
    if (!$admindata['id']) {
        logEvent('Connection attempt with UNKNOWN username : ' . $login );
        return array(0, 'User unknown' );
    }
    logEvent('User ' . $login . ' is known. Try to authenticate ...' );
    // Lets go on authentication !
    $imap_server_name = getConfig('adminIMAPauth__imap_server_name' );
    $imap_server_security = getConfig('adminIMAPauth__imap_server_security' );
    $imap_server_port = getConfig('adminIMAPauth__imap_server_port' );

    if (!$imap_server_name ) {
      logEvent('Admin IMAP authentication server configuration is incomplete. Please, check your configuration. Fallback to local authentication');
      return fallback_localValidateLogin($login, $password );
    }    
            $fp = @fsockopen($imap_server_name, $imap_server_port );
            if (!$fp) {
                logEvent('TCP connection to IMAP authentication server (' . $imap_server_name . ':' . $imap_server_port . ') failed. Fallback to local authentication');
                return fallback_localValidateLogin($login, $password );
            }
            else {
                logEvent('TCP connection to IMAP authentication server (' . $imap_server_name . ':' . $imap_server_port . ') is OK.');
                fclose($fp);
            }

            $imap_connection_string = '{' . $imap_server_name . ':' . $imap_server_port . '/imap/' . $imap_server_security . '}';
            logEvent('IMAP connection string = ' . $imap_connection_string );
            logEvent('IMAP login = ' . $login );
            $connection = imap_open($mailbox = $imap_connection_string, $username = $login, $password = $password, $options = OP_HALFOPEN, $n_retries = 0 );
//            $connection = imap_open($imap_connection_string, $login, $password, OP_HALFOPEN );
            if ($connection) {
                logEvent('IMAP connection succeeded for ' . $login . ' on ' . $imap_connection_string );
                imap_close($connection);
                logEvent('user ' . $login . ' with id ' . $admindata['id'] . ' has logged in through IMAP ' . $imap_connection_string );
                if ($admindata['disabled']) {
                    return array(0, s('your account has been disabled'));
                }
                else {
                    if (!empty($GLOBALS['admin_auth_module'])) {
                        Error(s('Admin authentication has changed, please update your admin module'),
                        'https://resources.phplist.com/documentation/errors/adminauthchange');
                        return;
                    }
                    else {                   
                        return array($admindata['id'], 'OK');
                    }
                }
            }
            else {        
                logEvent('IMAP authentication failed. Fallback to local authentication' );
                return fallback_localValidateLogin($login, $password );
            }
  }

  /**
   * 
   * validateAccount, verify that the logged in admin is still valid
   * 
   * this allows verification that the admin still exists and is valid
   * 
   * @param int $id the ID of the admin as provided by validateLogin
   * 
   * @return array 
   *    index 0 -> false if failed, true if successful
   *    index 1 -> error message when validation fails
   * 
   * eg 
   *    return array(1,'OK'); // -> admin valid
   *    return array(0,'No such account'); // admin failed
   * 
   */ 
  public function validateAccount($id) 
  {
        $query = sprintf('select id, disabled from %s where id = %d', $GLOBALS['tables']['admin'], $id);
        $data = Sql_Fetch_Row_Query($query);
        if (!$data[0]) {
            return array(0, s('No such account'));
        } elseif ($data[1]) {
            return array(0, s('your account has been disabled'));
        }

        //# do this separately from above, to avoid lock out when the DB hasn't been upgraded.
        //# so, ignore the error
        $query = sprintf('select privileges from %s where id = %d', $GLOBALS['tables']['admin'], $id);
        $req = Sql_Query($query);
        if ($req) {
            $data = Sql_Fetch_Row($req);
        } else {
            $data = array();
        }

        if (!empty($data[0])) {
            $_SESSION['privileges'] = unserialize($data[0]);
        }

        return array(1, 'OK');
  }


  /**
   * adminName
   * 
   * Name of the currently logged in administrator
   * Use for logging, eg "subscriber updated by XXXX"
   * and to display ownership of lists
   * 
   * @param int $id ID of the admin
   * 
   * @return string;
   */
  public function adminName($id) 
  {
        $req = Sql_Fetch_Row_Query(sprintf('select loginname from %s where id = %d', $GLOBALS['tables']['admin'], $id));
        return $req[0] ? $req[0] : s('Nobody');
  }
  
  /**
   * adminEmail
   * 
   * Email address of the currently logged in administrator
   * used to potentially pre-fill the "From" field in a campaign
   * 
   * @param int $id ID of the admin
   * 
   * @return string;
   */
  public function adminEmail($id) 
  {
        $req = Sql_Fetch_Row_Query(sprintf('select email from %s where id = %d', $GLOBALS['tables']['admin'], $id));
        return $req[0] ? $req[0] : '';
  }

  /**
   * adminIdForEmail
   * 
   * Return matching admin ID for an email address
   * used for verifying the admin email address on a Forgot Password request
   * 
   * @param string $email email address 
   * 
   * @return ID if found or false if not;
   */
  public function adminIdForEmail($email) 
  { 
        $req = Sql_Fetch_Row_Query(sprintf('select id from %s where email = "%s"', $GLOBALS['tables']['admin'],
            sql_escape($email)));

        return $req[0] ? $req[0] : '';
  } 
  
  /**
   * isSuperUser
   * 
   * Return whether this admin is a super-admin or not
   * 
   * @param int $id admin ID
   * 
   * @return true if super-admin false if not
   */
  public function isSuperUser($id) 
  {
        $req = Sql_Fetch_Row_Query(sprintf('select superuser from %s where id = %d', $GLOBALS['tables']['admin'], $id));
        return $req[0];
  }



  /**
   * listAdmins
   * 
   * Return array of admins in the system
   * Used in the list page to allow assigning ownership to lists
   * 
   * @param none
   * 
   * @return array of admins
   *    id => name
   */
function listAdmins() 
  {
logEvent('calling : adminIMAPauth : listAdmins');


require_once dirname(__FILE__).'/accesscheck.php';

if (isset($_GET['remember_find'])) {
    $remember_find = (string) $_GET['remember_find'];
} else {
    $remember_find = '';
}

logEvent('calling admins.php' );
logEvent('admins.php : $GLOBALS[admin_auth] = ' . print_r($GLOBALS['admin_auth'], true ) );

$start = isset($_GET['start']) ? sprintf('%d', $_GET['start']) : 0;
$listid = isset($_GET['id']) ? sprintf('%d', $_GET['id']) : 0;
$find = isset($_REQUEST['find']) ? $_REQUEST['find'] : '';

if (!empty($find)) {
    $remember_find = '&find='.urlencode($find);
} else {
    $remember_find = '';
}

echo '<div class="button">'.PageLink2('importadmin', s('Import list of admins')).'</div>';
echo '<div class="pull-right fright">'.PageLinkActionButton('admin', s('Add new admin'), "start=$start".$remember_find).'</div><div class="clearfix"></div>';

if (isset($_GET['delete']) && $_GET['delete']) {
    // delete the index in delete
    if ($_GET['delete'] == $_SESSION['logindetails']['id']) {
        echo s('You cannot delete yourself')."\n";
    } else {
        echo s('Deleting')." $delete ..\n";
        Sql_query(sprintf('delete from %s where id = %d', $GLOBALS['tables']['admin'], $_GET['delete']));
        Sql_query(sprintf('delete from %s where adminid = %d', $GLOBALS['tables']['admin_attribute'],
            $_GET['delete']));
        Sql_query(sprintf('delete from %s where adminid = %d', $GLOBALS['tables']['admin_task'], $_GET['delete']));
        echo '..'.s('Done')."<br /><hr><br />\n";
        Redirect("admins&start=$start");
    }
}

ob_end_flush();

if (isset($add)) {
    if (isset($new)) {
        $query = 'insert into '.$tables['admin']." (email,entered) values(\"$new\",now())";
        $result = Sql_query($query);
        $userid = Sql_insert_id();
        $query = 'insert into '.$tables['listuser']." (userid,listid,entered) values($userid,$id,now())";
        $result = Sql_query($query);
    }
    echo '<br/>'.s('Admin added').'<br/>';
}

if (!$find) {
    $result = Sql_query('SELECT count(*) FROM '.$tables['admin']);
} else {
    $result = Sql_query('SELECT count(*) FROM '.$tables['admin']." where loginname like \"%$find%\" or email like \"%$find%\"");
}
$totalres = Sql_fetch_Row($result);
$total = $totalres[0];

echo '<p class="info">'.$total.' '.s('Administrators');
echo $find ? ' '.s('found').'</p>' : '</p>';

$paging = '';
$limit = '';

if ($total > MAX_USER_PP) {
    $paging = simplePaging("admins$remember_find", $start, $total, MAX_USER_PP, s('Administrators'));
    $limit = "limit $start,".MAX_USER_PP;
}
if ($find) {
    $result = Sql_query('SELECT id,loginname,email, superuser, disabled FROM '.$tables['admin'].' where loginname like "%'.sql_escape($find).'%" or email like "%'.sql_escape($find)."%\" order by loginname $limit");
} else {
    $result = Sql_query('SELECT id,loginname,email, superuser, disabled FROM '.$tables['admin']." order by loginname $limit");
}

?>
<table>
    <tr>
        <td colspan=4><?php echo formStart('action=""') ?><input type="hidden" name="id" value="<?php echo $listid ?>">
            <?php echo s('Find an admin') ?>: <input type=text name="find"
                                                                         value="<?php echo htmlentities($find) ?>"
                                                                         size="40"><input type="submit"
                                                                                          value="<?php echo s('Go') ?>">
            </form></td>
    </tr>
</table>
<?php
$ls = new WebblerListing(s('Administrators'));
$ls->usePanel($paging);
$ls->setElementHeading('Login name');
while ($admin = Sql_fetch_array($result)) {
    $delete_url = sprintf("<a href=\"javascript:deleteRec('%s');\">".s('del').'</a>',
        PageURL2('admins', 'Delete', "start=$start&amp;delete=".$admin['id']));
    $ls->addElement(htmlentities($admin['loginname']),
        PageUrl2('admin', s('Show'), "start=$start&amp;id=".$admin['id'].$remember_find));
    $ls->addColumn($admin['loginname'], s('Id'), $admin['id']);
    $ls->addColumn($admin['loginname'], s('email'), htmlspecialchars($admin['email']));
    $ls->addColumn($admin['loginname'], s('Super Admin'), $admin['superuser'] ? s('Yes') : s('No'));
    $ls->addColumn($admin['loginname'], s('Disabled'), $admin['disabled'] ? s('Yes') : s('No'));
    if ($_SESSION['logindetails']['superuser'] && $admin['id'] != $_SESSION['logindetails']['id']) {
        $ls->addColumn($admin['loginname'], s('Del'), $delete_url);
    }
}
echo $ls->display();
echo '<br/><hr class="hidden-lg hidden-md hidden-sm hidden-xs" />';

// listAdmins
 }

} // class 
