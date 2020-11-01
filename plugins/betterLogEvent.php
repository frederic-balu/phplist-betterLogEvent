<?php

require_once __DIR__.'/../accesscheck.php';

class betterLogEvent extends phplistPlugin {
  public $name = 'Better LogEvent';
  public $version = '0.1.0';
  public $authors = 'Frederic BALU';
  public $description = 'A plugin to enhance the informations available thru eventLog function';
  public $authProvider = true;

/**
 * Define settings needed by this plugin
 * !!! each array name length has to be less than or equal 36 characters
**/  

  /**
    * Constructor.
  **/

    public $coderoot = PLUGIN_ROOTDIR . '/betterLogEvent/';

    function __construct()
    {
        parent::__construct();
     $this->settings = array(
    ),
  );
}

public function initialise()
{
    logEvent('calling : betterLogEvent : initialise' );
    parent::initialise();
}    

      /**
     * array of pages in this plugin to add to the main menu
     *
     * example format:
     *      array(
     *          'page' => array('category' => 'subscribers'),
     *      )
     *
     * valid categories are:
     *
     * subscribers
     * campaigns
     * statistics
     * system
     * config
     * develop (will only show up in "dev" mode)
     * info
     *
     */
    public $topMenuLinks = array();

      /**
     * Startup code, all other objects are constructed
     * returns success or failure, false means we cannot start
     */
    public function activate() {
      if (isset($_SESSION['logindetails']['adminname'] ) ) {
        $topMenuLinks = array(
        $_SESSION['logindetails']['adminname'] => array('category' => 'system' )
        );
      }
    }
  
  
  
  /**
   * logEvent
   * @param string msg message to log
   * @return true when dealt with or false to pass on
   */
  public function logEvent($msg = '') {
    global $tables;
    if (isset($GLOBALS['page'])) {
        $p = $GLOBALS['page'];
    } elseif (isset($_GET['page'])) {
        $p = $_GET['page'];
    } elseif (isset($_GET['p'])) {
        $p = $_GET['p'];
    } else {
        $p = '(unknown page)';
    }
    if (!Sql_Table_Exists($tables['eventlog'])) {
        return;
    }
    $uid = '?';
    if (isset($_SESSION['logindetails']['id'] ) ) {
     $uid = $_SESSION['logindetails']['id'];
    }
    $username = '?';
    if (isset($_SESSION['logindetails']['adminname'] ) ) {
     $username = $_SESSION['logindetails']['adminname'];
    }
    $from = '?'
    if (isset($remoteAddr ) ) {
     $from = $remoteAddr;
    }
    $msg = $username . '(' . $uid . ')@' . $from . ' : ' . $msg;
    Sql_Query(sprintf('insert into %s (entered,page,entry) values(now(),"%s","%s")', $tables['eventlog'],
        $p, sql_escape($msg)));
  }

} // class 
