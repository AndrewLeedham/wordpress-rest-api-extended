<?php
/**
* Plugin Name: WordPress Rest API Extended
* Text Domain: wordPress-rest-api-extended
* Description: Extends WordPress' REST API, allowing the Content-Type header to be specified.
* Version: 1.0.0
* Author: Andrew Leedham
**/

class WP_REST_API_Extended  {

    public function __construct() {
      require_once(dirname(__FILE__) . "/include/class-wp-rest-server-extended.php");
    }
}

new WP_REST_API_Extended();