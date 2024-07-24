<?php

namespace josecarlosphp\easyservice;

require_once 'vendor/josecarlosphp/functions/src/internet.php';
require_once 'vendor/josecarlosphp/functions/src/arrays.php';
require_once 'vendor/josecarlosphp/functions/src/files.php';

require_once '_inc/classes/MySession.class.php';
include_once '_inc/classes/MyServiceResponse.class.php';

class App
{
    /**
     * Service version.
     * @var string
     */
    private $version;
    /**
     * @var boolean
     */
    private $debug;
    /**
     * @var string
     */
    private $dirSess = '_sess';
    /**
     * @var string
     */
    private $dirLog = '_log';
    /**
     * @var string
     */
    private $dirDebug = '_debug';
    /**
     * @var boolean
     */
    private $useArray = false;
    /**
     * @var MySession
     */
    private $session;
    /**
     * @var string
     */
    private $clientIp;
    /**
     * @var string
     */
    private $q;
    /**
     * @var array
     */
    private $aliases = array();

    public function __construct($debug=false, $props=array(), $version='1')
    {
        $this->version($version);
        $this->debug($debug);

        foreach($props as $key=>$val)
        {
            if(property_exists($this, $key) && !in_array($key, array('session', 'clientIp')))
            {
                $this->$key = $val;
            }
        }

        $arr = get_object_vars($this);
        foreach($arr as $key=>$val)
        {
            if(mb_substr($key, 0, 3) == 'dir')
            {
                $this->$key = ponerBarra($val);
                if(!is_dir($this->$key) && makeDir($this->$key))
                {
                    file_put_contents($this->$key.'.htaccess', 'Deny from all');
                }
            }
        }
    }

    public static function getDefaultConfig($version=1)
    {
        switch ((int)$version) {
            case 2:
                return array(
                    'autoopen' => false,
                    'tokenlifetime' => 90,
                    'tokenlength' => 64,
                );
        }

        return array(
            'autoopen' => false,
            'tokenlifetime' => 90,
            'tokenlength' => 64,
            );
    }

    public static function getConfig($q, $version=1)
    {
        $config = self::getDefaultConfig($version);

        $filename = 'q/' . LimpiarData($q) . '/config.yml';
        if (is_file($filename)) {
            $aux = self::yamlRead($filename);
            foreach ($aux as $key=>$val) {
                if ($key == 'tokenlenght') {
                    $key = 'tokenlength';
                }

                if (array_key_exists($key, $config)) {
                    $config[$key] = $val;
                }
            }
        }

        return $config;
    }

    public static function getAllHeaders()
    {
        if(!function_exists('getallheaders'))
        {
            function getallheaders()
            {
                $arh = array();
                $rx_http = '/\AHTTP_/';
                foreach($_SERVER as $key => $val)
                {
                    if(preg_match($rx_http, $key))
                    {
                        $arh_key = preg_replace($rx_http, '', $key);
                        // do some nasty string manipulations to restore the original letter case
                        // this should work in most cases
                        $rx_matches = explode('_', $arh_key);
                        if(count($rx_matches) > 0 and strlen($arh_key) > 2 )
                        {
                            foreach($rx_matches as $ak_key => $ak_val)
                            {
                                $rx_matches[$ak_key] = ucfirst(mb_strtolower($ak_val));
                            }
                            $arh_key = implode('-', $rx_matches);
                        }
                        $arh[$arh_key] = $val;
                    }
                }

                return $arh;
            }
        }

        return getallheaders();
    }

    public function getClientIp()
    {
        if(empty($this->clientIp))
        {
            $this->clientIp = GetClientIP();
        }

        return $this->clientIp;
    }

    public function run($cipher = 'aes-128-gcm')
    {
        global $app; //Para que esté disponible, por ejemplo para $app->debugging()

        if (empty($app)) {
            $app = $this; //Por si la variable se ha declarado con otro nombre
        }

        //Desencriptar
        if (array_key_exists('token', $_REQUEST) && array_key_exists('data', $_REQUEST) && array_key_exists('krip', $_REQUEST)) {
            $options = 0;

            if (in_array($cipher, openssl_get_cipher_methods())) {
                if (($ivlen = openssl_cipher_iv_length($cipher))) {
                    $iv = mb_strcut($_REQUEST['krip'], 0, $ivlen);
                    $tag = mb_strcut($_REQUEST['krip'], $ivlen);
                    if (($plaintext = openssl_decrypt($_REQUEST['data'], $cipher, $_REQUEST['token'], $options, $iv, $tag)) !== false) {
                        if (($data = json_decode($plaintext, true)) !== null) {
                            unset($_REQUEST['data'], $_REQUEST['iv'], $_REQUEST['tag']);
                            foreach ($data as $key => $val) {
                                $_REQUEST[$key] = $val;
                            }
                        } else {
                            $this->logging($msg = 'Failed json_decode(): ' . json_last_error_msg());
                            $this->doResult(\MyServiceResponse::STATUS_ERROR, $msg, 400);
                        }
                    } else {
                        $this->logging($msg = 'Failed openssl_decrypt()');
                        $this->doResult(\MyServiceResponse::STATUS_ERROR, $msg, 400);
                    }
                } else {
                    $this->logging($msg = 'Failed openssl_cipher_iv_length()');
                    $this->doResult(\MyServiceResponse::STATUS_ERROR, $msg, 400);
                }
            } else {
                $this->logging($msg = $cipher . ' not in openssl_get_cipher_methods()');
                $this->doResult(\MyServiceResponse::STATUS_ERROR, $msg, 400);
            }
        }

        $this->q = $this->alias(isset($_GET['q']) ? LimpiarData($_GET['q']) : '');

        $this->logging('$_REQUEST = '.var_export($_REQUEST, true));

        $action = isset($_GET['action']) ? mb_strtolower(LimpiarData($_GET['action'])) : '';
        $params = $_REQUEST; //$_POST

        $token = '';
        $headers = self::getAllHeaders();
        if (isset($headers['Authentication'])) {
            if (strpos($headers['Authentication'], ' ') === false) {
                $token = $headers['Authentication'];
            } else {
                $aux = explode(' ', $headers['Authentication']);
                switch (strtolower($aux[0])) {
                    case 'basic':
                        $token = trim($aux[1]);
                        break;
                    default:
                        $this->doResult(\MyServiceResponse::STATUS_ERROR, 'Unsupported auth scheme', 401);
                        break;
                }
            }
        } elseif (isset($headers['Ocp-Apim-Subscription-Key'])) {
            $token = $headers['Ocp-Apim-Subscription-Key'];
        } elseif (isset($params['token'])) {
            $token = LimpiarData($params['token']);
        }

        $aux = $this->q.'/'.ponerBarra($action);
        $this->debugging($aux.'get', $_GET);
        $this->debugging($aux.'post', $_POST);
        $this->debugging($aux.'headers', $headers);
        $this->debugging($aux.'body', file_get_contents('php://input'));
        unset($aux);

        if($this->q && $action)
        {
            if(is_dir('q/'.$this->q))
            {
                if(is_file('q/'.$this->q.'/'.$action.'.php'))
                {
                    $filename = 'q/'.$this->q.'/_inc/functions.inc.php';
                    if(is_file($filename))
                    {
                        include $filename;
                    }

                    $config = self::getConfig($this->q, $this->version);

                    \MySession::Init(ponerBarra(getcwd().'/'.$this->dirSess).$this->q.'/', $config['tokenlifetime'], $config['tokenlifetime'] == 0 ? 0 : 1, 1, $config['tokenlength']);

                    switch($action)
                    {
                        case 'open':
                            $this->session = new \MySession();
                            $token = $this->session->GetId();
                            break;
                        case 'close':
                            if(!\MySession::Destroy($token))
                            {
                                $this->doResult(\MyServiceResponse::STATUS_ERROR, MySession::Exists($token) ? 'Can not destroy session' : 'Bad token');
                            }
                            break;
                        default:
                            $this->session = new \MySession();
                            if($token == '' && $config['autoopen'])
                            {
                                $token = $this->session->GetId();
                            }
                            elseif($this->session->Load($token) === false)
                            {
                                $this->doResult(\MyServiceResponse::STATUS_ERROR, 'Bad token', 401);
                            }
                            elseif($this->session->Get('sessid') != $token)
                            {
                                $this->doResult(\MyServiceResponse::STATUS_ERROR, 'Mismatch token', 401);
                            }
                            break;
                    }

                    try {
                        include 'q/'.$this->q.'/'.$action.'.php';
                    } catch (Exception $ex) {
                        $app->doResult(MyServiceResponse::STATUS_ERROR, $ex->getMessage(), 400);
                    }

                    switch($action)
                    {
                        case 'open':
                            $this->session->Set($token, 'sessid');
                            $app->doResult(
                                \MyServiceResponse::STATUS_OK,
                                $this->version > 1 ? ['token' => $token, 'tokenlifetime' => $config['tokenlifetime']] : $token
                            );
                            break;
                        case 'close':
                            $app->doResult(\MyServiceResponse::STATUS_OK, null);
                            break;
                        default:
                            $app->doResult(\MyServiceResponse::STATUS_ERROR, 'Unexpected error');
                            break;
                    }
                }
                else
                {
                    $this->doResult(\MyServiceResponse::STATUS_ERROR, 'Unknown action: '.$action, 400);
                }
            }

            http_response_code(404);
            exit;
        }

        http_response_code(503);
        exit;
    }

    protected function doResult($status, $content, $code=200, $type='json')
    {
        if($type != 'json' && $status != \MyServiceResponse::STATUS_OK)
        {
            $type = 'json';
        }

        http_response_code($code);
        switch($type)
        {
            case 'csv':
                header('Content-Type: text/csv');

                break;
            case 'pdf':
                header('Content-Type: application/pdf');

                break;
            case 'jpg':
                header('Content-Type: image/jpg');

                break;
            case 'txt':
                header('Content-Type: text/plain');

                break;
            case 'html':
                header('Content-Type: text/html');

                break;
            case 'json':
            default:
                if($this->useArray)
                {
                    if(is_string($content))
                    {
                        $content = array($content);
                    }
                    elseif(is_null($content))
                    {
                        $content = array();
                    }
                }

                $this->logging('[Result: '.$status.'] '.var_export($content, true));

                $content = json_encode(array(
                    'status'=>$status,
                    'content'=>$content,
                ));

                header('Content-Type: application/json');

                break;
        }

        header('Content-length: '.strlen($content)); //¡OJO! no vale mb_strlen
        echo $content;

        exit; //!!!
    }

    public function version($version=null)
    {
        if(!is_null($version))
        {
            $this->version = is_int($version) ? $version : (int)str_ireplace(array('v', '.'), '', $version);
        }

        return $this->version;
    }

    public function debug($debug=null)
    {
        if(!is_null($debug))
        {
            $this->debug = $debug ? true : false;
        }

        return $this->debug;
    }

    public function debugging($k, $var)
    {
        if($this->debug)
        {
			if(makeDir(dirname($this->dirDebug.$k)))
			{
				return file_put_contents($this->dirDebug.$k, var_export($var, true)) !== false;
			}

			return false;
        }

		return true;
    }
    //TODO: Reorganizar carpetas y archivos log
    public function logging($str)
    {
        $dir = $this->dirLog.date('Y/m/');
        if(makeDir($dir))
        {
            if(($fp = fopen($dir.date('Y-m-d').'.'.$this->q.'.log', 'a')))
            {
                $r = fwrite($fp, sprintf('[%s] %s - %s%s', date('Y-m-d H:i:s'), $this->getClientIp(), $str, "\n"));
                fclose($fp);

                return $r > 0;
            }
        }

        return false;
    }

    public function SessionSet($val, $key0, $key1=null, $key2=null, $key3=null, $key4=null, $key5=null)
    {
        return $this->session->Set($val, $key0, $key1, $key2, $key3, $key4, $key5);
    }

    public function SessionGet($key0, $key1=null, $key2=null, $key3=null, $key4=null, $key5=null)
    {
        return $this->session->Get($key0, $key1, $key2, $key3, $key4, $key5);
    }

    public static function yamlRead($filename)
    {
        return \Spyc::YAMLLoad($filename);
    }

    public static function yamlWrite($filename, $data)
    {
        return file_put_contents($filename, \Spyc::YAMLDump($data, 4, 0, true));
    }
    /**
     * Alias de servicio.
     *
     * @param string $alias
     * @param string $service
     * @return string
     */
    public function alias($alias, $service=null)
    {
        if(!is_null($service))
        {
            $this->aliases[$alias] = $service;
        }

        return isset($this->aliases[$alias]) ? $this->aliases[$alias] : $alias;
    }
    /**
     * Obtiene el valor actual de la propiedad $q,
     * que indica el servicio solicitado.
     *
     * @return string
     */
    public function q()
    {
        return $this->q;
    }
}
