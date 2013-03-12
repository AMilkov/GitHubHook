<?php
// error_reporting(0);
error_reporting(E_ALL);


class IP4Filter { 

    private static $_IP_TYPE_SINGLE = 'single'; 
    private static $_IP_TYPE_WILDCARD = 'wildcard'; 
    private static $_IP_TYPE_MASK = 'mask'; 
    private static $_IP_TYPE_CIDR = 'CIDR'; 
    private static $_IP_TYPE_SECTION = 'section'; 
    private $_allowed_ips = array(); 

    public function __construct($allowed_ips) { 
        $this->_allowed_ips = $allowed_ips; 
    } 

    public function check($ip, $allowed_ips = null) { 
        $allowed_ips = $allowed_ips ? $allowed_ips : $this->_allowed_ips; 

        foreach ($allowed_ips as $allowed_ip) { 
            $type = $this->_judge_ip_type($allowed_ip); 
            $sub_rst = call_user_func(array($this, '_sub_checker_' . $type), $allowed_ip, $ip);
 
            if ($sub_rst) { 
                return true; 
            } 
        } 

        return false; 
    } 

    private function _judge_ip_type($ip) { 
        if (strpos($ip, '*')) { 
            return self :: $_IP_TYPE_WILDCARD; 
        } 

        if (strpos($ip, '/')) { 
            $tmp = explode('/', $ip); 
            if (strpos($tmp[1], '.')) { 
                return self :: $_IP_TYPE_MASK; 
            } else { 
                return self :: $_IP_TYPE_CIDR; 
            } 
        } 

        if (strpos($ip, '-')) { 
            return self :: $_IP_TYPE_SECTION; 
        } 

        if (ip2long($ip)) { 
            return self :: $_IP_TYPE_SINGLE; 
        } 

        return false; 
    } 

    private function _sub_checker_single($allowed_ip, $ip) { 
        return (ip2long($allowed_ip) == ip2long($ip)); 
    } 

    private function _sub_checker_wildcard($allowed_ip, $ip) { 
        $allowed_ip_arr = explode('.', $allowed_ip); 
        $ip_arr = explode('.', $ip); 
        for ($i = 0; $i < count($allowed_ip_arr); $i++) { 
            if ($allowed_ip_arr[$i] == '*') { 
                return true; 
            } else { 
                if (false == ($allowed_ip_arr[$i] == $ip_arr[$i])) { 
                    return false; 
                } 
            } 
        } 
    } 

    private function _sub_checker_mask($allowed_ip, $ip) { 
        list($allowed_ip_ip, $allowed_ip_mask) = explode('/', $allowed_ip); 
        $begin = (ip2long($allowed_ip_ip) & ip2long($allowed_ip_mask)) + 1; 
        $end = (ip2long($allowed_ip_ip) | (~ ip2long($allowed_ip_mask))) + 1; 
        $ip = ip2long($ip); 
        return ($ip >= $begin && $ip <= $end); 
    } 

    private function _sub_checker_section($allowed_ip, $ip) { 
        list($begin, $end) = explode('-', $allowed_ip); 
        $begin = ip2long($begin); 
        $end = ip2long($end); 
        $ip = ip2long($ip); 
        return ($ip >= $begin && $ip <= $end); 
    } 

    private function _sub_checker_CIDR($CIDR, $IP) { 
        list ($net, $mask) = explode('/', $CIDR); 
        return ( ip2long($IP) & ~((1 << (32 - $mask)) - 1) ) == ip2long($net); 
    } 

} 






/**
 * GitHub Post-Receive Deployment Hook.
 *
 * @author Chin Lee <kwangchin@gmail.com>
 * @copyright Copyright (C) 2012 Chin Lee
 * @license http://www.opensource.org/licenses/mit-license.php The MIT License
 * @version 1.0
 */

class GitHubHook
{
  /**
   * @var string Remote IP of the person.
   * @since 1.0
   */
  private $_remoteIp = '';
  
  // Tony patch
  // public $log_file = '/var/log/github_hook.log';
  public $log_file = 'e:/tmp/log.log';

  /**
   * @var object Payload from GitHub.
   * @since 1.0
   */
  private $_payload = '';

  /**
   * @var boolean Log debug messages.
   * @since 1.0
   */
  private $_debug = TRUE;

  /**
   * @var array Branches.
   * @since 1.0
   */
  private $_branches = array();

  /**
   * @var array GitHub's IP addresses for hooks.
   * @since 1.1
   */
  private $_ips = array('207.97.227.253', '50.57.128.197', '108.171.174.178', '50.57.231.61', '204.232.175.64/27', '192.30.252.0/22', '127.0.0.1');

  /**
   * Constructor.
   * @since 1.0
   */
  function __construct() {
    /* Support for EC2 load balancers */
    if (
        isset($_SERVER['HTTP_X_FORWARDED_FOR']) &&
        filter_var($_SERVER['HTTP_X_FORWARDED_FOR'], FILTER_VALIDATE_IP)
      ) {
      $this->_remoteIp = $_SERVER['HTTP_X_FORWARDED_FOR'];
    } else {
      $this->_remoteIp = $_SERVER['REMOTE_ADDR'];
    }

    if (isset($_POST['payload'])) {
      $this->_payload  = json_decode($_POST['payload']);
    } else {
      $this->_notFound('Payload not available from: ' . $this->_remoteIp);
    }
  }

  /**
   * Centralize our 404.
   * @param string $reason Reason of 404 Not Found.
   * @since 1.1
   */
  private function _notFound($reason = NULL) {
    if ($reason !== NULL) {
      $this->log($reason);
    }

    header('HTTP/1.1 404 Not Found');
    echo '404 Not Found.';
	// print "<br>Reason => $reason<br>Debug: ".print_r($this->_debug)."<br>Log file => $this->log_file";
    exit;
  }

  /**
   * Enable log of debug messages.
   * @since 1.0
   */
  public function enableDebug() {
    $this->_debug = TRUE;
  }

  /**
   * Add a branch.
   * @param string $name Branch name, defaults to 'master'.
   * @param string $title Branch title, defaults to 'development'.
   * @param string $path Relative path to development directory, defaults to '/var/www/'.
   * @param array $author Contains authorized users' email addresses, defaults to everyone.
   * @since 1.0
   */
  public function addBranch($name = 'master', $title = 'development', $path = '/var/www/', $author = array()) {
    $this->_branches[] = array(
      'name'   => $name,
      'title'  => $title,
      'path'   => $path,
      'author' => $author
    );
  }

  /**
   * Log a message.
   * @param string $message Message to log.
   * @since 1.0
   */
  public function log($message) {
    if ($this->_debug) {
      file_put_contents($this->log_file, '[' . date('Y-m-d H:i:s') . '] - ' . $message . PHP_EOL, FILE_APPEND);
	  // print "<br>Result from fps is: $i<br>";
	} 
  }

  /**
   * Deploys.
   * @since 1.0
   */
  public function deploy() {
	$IPfilter = New IP4Filter($this->_ips);
    // if (in_array($this->_remoteIp, $this->_ips)) {
	if ($IPfilter->check($this->_remoteIp)) {
      foreach ($this->_branches as $branch) {
        if ($this->_payload->ref == 'refs/heads/' . $branch['name']) {

          $this->log('Deploying to ' . $branch['title'] . ' server');
          $_output = shell_exec('./deploy.sh ' . $branch['path'] . ' ' . $branch['name'] . ' 2>&1');
		  $this->log($_output);
        }
      }
    } else {
      $this->_notFound('IP address not recognized: ' . $this->_remoteIp);
    }
  }
}
