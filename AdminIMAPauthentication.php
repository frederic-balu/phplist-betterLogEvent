<?php

class adminIMAPauthentication extends phplistPlugin {
  public $name = 'IMAP server as authenticator';
  public $version = 0.1.1;
  public $authors = 'Frederic BALU';
  public $description = 'Provides authentication to phpList administrators using IMAP ';
  public $authProvider = true;

 /**
   * Fallback to local login if IMAP fails
   */
  function localValidateLogin($login, $password ) {
    logEvent('calling : adminIMAPauthentication : localValidateLogin');
    require_once __DIR__.'/../phpListAdminAuthentication.php';
    $core_admin_auth = new phpListAdminAuthentication();
    return $core_admin_auth->validateLogin($login,$password);
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
  public function validateLogin($login,$password) 
  {
     logEvent('calling : adminIMAPauthentication : validateLogin');
        if(empty($login)||($password=="")){
            return array(0, s('Please enter your credentials.'));
        };
        $imap_host = 'mail.lacfdtaltice.fr';
        $imap_port = '993';
//        $imap_security = '/imap';
        $imap_security = '/imap/ssl';
//        $imap_security = '/imap/ssl/novalidate-cert';
//        $imap_security = '/imap/tls';
//        $imap_security = '/imap/novalidate-cert';
        
        
            $fp = @fsockopen($imap_host, $imap_port );
            if (!$fp) {
                logEvent('TCP connection to IMAP authentication server (' . $imap_host . ':' . $imap_port . ') failed. Fallback to local authentication');
                return localValidateLogin($login, $password );
//                return array(0, 'TCP connection to IMAP authentication server failed');
            }
            else {
                fclose($fp);
            }

            $imap_connection_string = '{' . $imap_host . ':{' . $imap_port . '}' . $imap_security . '}';
            logEvent('IMAP connection string = ' . $imap_connection_string );
            logEvent('IMAP login = ' . $login );
            $connection = imap_open($imap_connection_string, $login, $password, OP_HALFOPEN);
            if ($connection) {
                imap_close($connection);
                $query = sprintf('select disabled, id from %s where login = "%s"', $GLOBALS['tables']['admin'], sql_escape($login));
                $req = Sql_Query($query);
                $admindata = Sql_Fetch_Assoc($req);
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
                return localValidateLogin($login, $password );
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
     logEvent('calling : adminIMAPauthentication : validateAccount');
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
     logEvent('calling : adminIMAPauthentication : listAdmins');
        $result = array();
        $req = Sql_Query("select id,loginname,email from {$GLOBALS['tables']['admin']} order by email");
        while ($row = Sql_Fetch_Array($req)) {
            $result[$row['id']] = $row['loginname'];
        }

        return $result;
  }

} // class 
