<?php
require_once(ABSPATH . '/wp-includes/rest-api/class-wp-rest-server.php');

$wp_rest_server_extended_class = function() {
  return 'WP_REST_Server_Extended';
};

add_filter('wp_rest_server_class', $wp_rest_server_extended_class);

class WP_REST_Server_Extended extends WP_REST_Server {

/**
	 * Retrieves the route map.
	 *
	 * The route map is an associative array with path regexes as the keys. The
	 * value is an indexed array with the callback function/method as the first
	 * item, and a bitmask of HTTP methods as the second item (see the class
	 * constants).
	 *
	 * Each route can be mapped to more than one callback by using an array of
	 * the indexed arrays. This allows mapping e.g. GET requests to one callback
	 * and POST requests to another.
	 *
	 * Note that the path regexes (array keys) must have @ escaped, as this is
	 * used as the delimiter with preg_match()
	 *
	 * @since 4.4.0
	 *
	 * @return array `'/path/regex' => array( $callback, $bitmask )` or
	 *               `'/path/regex' => array( array( $callback, $bitmask ), ...)`.
	 */
	public function get_routes() {
		/**
		 * Filters the array of available endpoints.
		 *
		 * @since 4.4.0
		 *
		 * @param array $endpoints The available endpoints. An array of matching regex patterns, each mapped
		 *                         to an array of callbacks for the endpoint. These take the format
		 *                         `'/path/regex' => array( $callback, $bitmask )` or
		 *                         `'/path/regex' => array( array( $callback, $bitmask ).
		 */
		$endpoints = apply_filters( 'rest_endpoints', $this->endpoints );
		// Normalise the endpoints.
		$defaults = array(
			'methods'       => '',
			'accept_json'   => false,
			'accept_raw'    => false,
			'show_in_index' => true,
      'args'          => array(),
      'content_type' => isset( $_GET['_jsonp'] ) ? 'application/javascript' : 'application/json',
      'json' => true
		);
		foreach ( $endpoints as $route => &$handlers ) {
			if ( isset( $handlers['callback'] ) ) {
				// Single endpoint, add one deeper.
				$handlers = array( $handlers );
			}
			if ( ! isset( $this->route_options[ $route ] ) ) {
				$this->route_options[ $route ] = array();
			}
			foreach ( $handlers as $key => &$handler ) {
				if ( ! is_numeric( $key ) ) {
					// Route option, move it to the options.
					$this->route_options[ $route ][ $key ] = $handler;
					unset( $handlers[ $key ] );
					continue;
        }
				$handler = wp_parse_args( $handler, $defaults );
				// Allow comma-separated HTTP methods.
				if ( is_string( $handler['methods'] ) ) {
					$methods = explode( ',', $handler['methods'] );
				} elseif ( is_array( $handler['methods'] ) ) {
					$methods = $handler['methods'];
				} else {
					$methods = array();
				}
				$handler['methods'] = array();
				foreach ( $methods as $method ) {
					$method                        = strtoupper( trim( $method ) );
					$handler['methods'][ $method ] = true;
				}
			}
		}
		return $endpoints;
  }
  
  /**
	 * Handles serving an API request.
	 *
	 * Matches the current server URI to a route and runs the first matching
	 * callback then outputs a JSON representation of the returned value.
	 *
	 * @since 4.4.0
	 *
	 * @see WP_REST_Server::dispatch()
	 *
	 * @param string $path Optional. The request route. If not set, `$_SERVER['PATH_INFO']` will be used.
	 *                     Default null.
	 * @return false|null Null if not served and a HEAD request, false otherwise.
	 */
	public function serve_request( $path = null ) {
		$content_type = isset( $_GET['_jsonp'] ) ? 'application/javascript' : 'application/json';
		$this->send_header( 'Content-Type', $content_type . '; charset=' . get_option( 'blog_charset' ) );
		$this->send_header( 'X-Robots-Tag', 'noindex' );
		$api_root = get_rest_url();
		if ( ! empty( $api_root ) ) {
			$this->send_header( 'Link', '<' . esc_url_raw( $api_root ) . '>; rel="https://api.w.org/"' );
		}
		/*
		 * Mitigate possible JSONP Flash attacks.
		 *
		 * https://miki.it/blog/2014/7/8/abusing-jsonp-with-rosetta-flash/
		 */
		$this->send_header( 'X-Content-Type-Options', 'nosniff' );
		$this->send_header( 'Access-Control-Expose-Headers', 'X-WP-Total, X-WP-TotalPages' );
		$this->send_header( 'Access-Control-Allow-Headers', 'Authorization, Content-Type' );
		/**
		 * Send nocache headers on authenticated requests.
		 *
		 * @since 4.4.0
		 *
		 * @param bool $rest_send_nocache_headers Whether to send no-cache headers.
		 */
		$send_no_cache_headers = apply_filters( 'rest_send_nocache_headers', is_user_logged_in() );
		if ( $send_no_cache_headers ) {
			foreach ( wp_get_nocache_headers() as $header => $header_value ) {
				if ( empty( $header_value ) ) {
					$this->remove_header( $header );
				} else {
					$this->send_header( $header, $header_value );
				}
			}
		}
		/**
		 * Filters whether the REST API is enabled.
		 *
		 * @since 4.4.0
		 * @deprecated 4.7.0 Use the rest_authentication_errors filter to restrict access to the API
		 *
		 * @param bool $rest_enabled Whether the REST API is enabled. Default true.
		 */
		apply_filters_deprecated(
			'rest_enabled', array( true ), '4.7.0', 'rest_authentication_errors',
			__( 'The REST API can no longer be completely disabled, the rest_authentication_errors filter can be used to restrict access to the API, instead.' )
		);
		/**
		 * Filters whether jsonp is enabled.
		 *
		 * @since 4.4.0
		 *
		 * @param bool $jsonp_enabled Whether jsonp is enabled. Default true.
		 */
		$jsonp_enabled = apply_filters( 'rest_jsonp_enabled', true );
		$jsonp_callback = null;
		if ( isset( $_GET['_jsonp'] ) ) {
			if ( ! $jsonp_enabled ) {
				echo $this->json_error( 'rest_callback_disabled', __( 'JSONP support is disabled on this site.' ), 400 );
				return false;
			}
			$jsonp_callback = $_GET['_jsonp'];
			if ( ! wp_check_jsonp_callback( $jsonp_callback ) ) {
				echo $this->json_error( 'rest_callback_invalid', __( 'Invalid JSONP callback function.' ), 400 );
				return false;
			}
		}
		if ( empty( $path ) ) {
			if ( isset( $_SERVER['PATH_INFO'] ) ) {
				$path = $_SERVER['PATH_INFO'];
			} else {
				$path = '/';
			}
		}
		$request = new WP_REST_Request( $_SERVER['REQUEST_METHOD'], $path );
		$request->set_query_params( wp_unslash( $_GET ) );
		$request->set_body_params( wp_unslash( $_POST ) );
		$request->set_file_params( $_FILES );
		$request->set_headers( $this->get_headers( wp_unslash( $_SERVER ) ) );
		$request->set_body( $this->get_raw_data() );
		/*
		 * HTTP method override for clients that can't use PUT/PATCH/DELETE. First, we check
		 * $_GET['_method']. If that is not set, we check for the HTTP_X_HTTP_METHOD_OVERRIDE
		 * header.
		 */
		if ( isset( $_GET['_method'] ) ) {
			$request->set_method( $_GET['_method'] );
		} elseif ( isset( $_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE'] ) ) {
			$request->set_method( $_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE'] );
		}
		$result = $this->check_authentication();
		if ( ! is_wp_error( $result ) ) {
			$result = $this->dispatch( $request );
		}
		// Normalize to either WP_Error or WP_REST_Response...
		$result = rest_ensure_response( $result );
		// ...then convert WP_Error across.
		if ( is_wp_error( $result ) ) {
			$result = $this->error_to_response( $result );
		}
		/**
		 * Filters the API response.
		 *
		 * Allows modification of the response before returning.
		 *
		 * @since 4.4.0
		 * @since 4.5.0 Applied to embedded responses.
		 *
		 * @param WP_HTTP_Response $result  Result to send to the client. Usually a WP_REST_Response.
		 * @param WP_REST_Server   $this    Server instance.
		 * @param WP_REST_Request  $request Request used to generate the response.
		 */
		$result = apply_filters( 'rest_post_dispatch', rest_ensure_response( $result ), $this, $request );
		// Wrap the response in an envelope if asked for.
		if ( isset( $_GET['_envelope'] ) ) {
			$result = $this->envelope_response( $result, isset( $_GET['_embed'] ) );
		}
		// Send extra data from response objects.
		$headers = $result->get_headers();
		$this->send_headers( $headers );
		$code = $result->get_status();
		$this->set_status( $code );
		/**
		 * Filters whether the request has already been served.
		 *
		 * Allow sending the request manually - by returning true, the API result
		 * will not be sent to the client.
		 *
		 * @since 4.4.0
		 *
		 * @param bool             $served  Whether the request has already been served.
		 *                                           Default false.
		 * @param WP_HTTP_Response $result  Result to send to the client. Usually a WP_REST_Response.
		 * @param WP_REST_Request  $request Request used to generate the response.
		 * @param WP_REST_Server   $this    Server instance.
		 */
		$served = apply_filters( 'rest_pre_serve_request', false, $result, $request, $this );
		if ( ! $served ) {
			if ( 'HEAD' === $request->get_method() ) {
				return null;
			}
			// Embed links inside the request.
			$result = $this->response_to_data( $result, isset( $_GET['_embed'] ) );
			/**
			 * Filters the API response.
			 *
			 * Allows modification of the response data after inserting
			 * embedded data (if any) and before echoing the response data.
			 *
			 * @since 4.8.1
			 *
			 * @param array            $result  Response data to send to the client.
			 * @param WP_REST_Server   $this    Server instance.
			 * @param WP_REST_Request  $request Request used to generate the response.
			 */
      $result = apply_filters( 'rest_pre_echo_response', $result, $this, $request );

			$json_error_message = $this->get_json_last_error();
			if ( $json_error_message ) {
				$json_error_obj = new WP_Error( 'rest_encode_error', $json_error_message, array( 'status' => 500 ) );
				$result         = $this->error_to_response( $json_error_obj );
				$result         = wp_json_encode( $result->data[0] );
			}
			if ( $jsonp_callback ) {
				// Prepend '/**/' to mitigate possible JSONP Flash attacks.
				// https://miki.it/blog/2014/7/8/abusing-jsonp-with-rosetta-flash/
				echo '/**/' . $jsonp_callback . '(' . $result . ')';
			} else {
				echo $result;
			}
		}
		return null;
	}

    /**
	 * Matches the request to a callback and call it.
	 *
	 * @since 4.4.0
	 *
	 * @param WP_REST_Request $request Request to attempt dispatching.
	 * @return WP_REST_Response Response returned by the callback.
	 */
	public function dispatch( $request ) {
		/**
		 * Filters the pre-calculated result of a REST dispatch request.
		 *
		 * Allow hijacking the request before dispatching by returning a non-empty. The returned value
		 * will be used to serve the request instead.
		 *
		 * @since 4.4.0
		 *
		 * @param mixed           $result  Response to replace the requested version with. Can be anything
		 *                                 a normal endpoint can return, or null to not hijack the request.
		 * @param WP_REST_Server  $this    Server instance.
		 * @param WP_REST_Request $request Request used to generate the response.
		 */

		$result = apply_filters( 'rest_pre_dispatch', null, $this, $request );
		if ( ! empty( $result ) ) {
			return $result;
		}
		$method = $request->get_method();
		$path   = $request->get_route();
		foreach ( $this->get_routes() as $route => $handlers ) {
			$match = preg_match( '@^' . $route . '$@i', $path, $matches );
			if ( ! $match ) {
				continue;
			}
			$args = array();
			foreach ( $matches as $param => $value ) {
				if ( ! is_int( $param ) ) {
					$args[ $param ] = $value;
				}
			}
			foreach ( $handlers as $handler ) {
        $callback = $handler['callback'];
        $content_type = $handler['content_type'];
        $json = $handler['json'];
        $response = null;
        
        $this->send_header( 'Content-Type', $content_type . '; charset=' . get_option( 'blog_charset' ) );

				// Fallback to GET method if no HEAD method is registered.
				$checked_method = $method;
				if ( 'HEAD' === $method && empty( $handler['methods']['HEAD'] ) ) {
					$checked_method = 'GET';
				}
				if ( empty( $handler['methods'][ $checked_method ] ) ) {
					continue;
				}
				if ( ! is_callable( $callback ) ) {
					$response = new WP_Error( 'rest_invalid_handler', __( 'The handler for the route is invalid' ), array( 'status' => 500 ) );
				}
				if ( ! is_wp_error( $response ) ) {
					// Remove the redundant preg_match argument.
					unset( $args[0] );
					$request->set_url_params( $args );
					$request->set_attributes( $handler );
					$defaults = array();
					foreach ( $handler['args'] as $arg => $options ) {
						if ( isset( $options['default'] ) ) {
							$defaults[ $arg ] = $options['default'];
						}
					}
					$request->set_default_params( $defaults );
					$check_required = $request->has_valid_params();
					if ( is_wp_error( $check_required ) ) {
						$response = $check_required;
					} else {
						$check_sanitized = $request->sanitize_params();
						if ( is_wp_error( $check_sanitized ) ) {
							$response = $check_sanitized;
						}
					}
				}
				/**
				 * Filters the response before executing any REST API callbacks.
				 *
				 * Allows plugins to perform additional validation after a
				 * request is initialized and matched to a registered route,
				 * but before it is executed.
				 *
				 * Note that this filter will not be called for requests that
				 * fail to authenticate or match to a registered route.
				 *
				 * @since 4.7.0
				 *
				 * @param WP_HTTP_Response $response Result to send to the client. Usually a WP_REST_Response.
				 * @param WP_REST_Server   $handler  ResponseHandler instance (usually WP_REST_Server).
				 * @param WP_REST_Request  $request  Request used to generate the response.
				 */
				$response = apply_filters( 'rest_request_before_callbacks', $response, $handler, $request );
				if ( ! is_wp_error( $response ) ) {
					// Check permission specified on the route.
					if ( ! empty( $handler['permission_callback'] ) ) {
						$permission = call_user_func( $handler['permission_callback'], $request );
						if ( is_wp_error( $permission ) ) {
							$response = $permission;
						} elseif ( false === $permission || null === $permission ) {
							$response = new WP_Error( 'rest_forbidden', __( 'Sorry, you are not allowed to do that.' ), array( 'status' => rest_authorization_required_code() ) );
						}
					}
        }
        $code = null;
				if ( ! is_wp_error( $response ) ) {
					/**
					 * Filters the REST dispatch request result.
					 *
					 * Allow plugins to override dispatching the request.
					 *
					 * @since 4.4.0
					 * @since 4.5.0 Added `$route` and `$handler` parameters.
					 *
					 * @param bool            $dispatch_result Dispatch result, will be used if not empty.
					 * @param WP_REST_Request $request         Request used to generate the response.
					 * @param string          $route           Route matched for the request.
					 * @param array           $handler         Route handler used for the request.
					 */
					$dispatch_result = apply_filters( 'rest_dispatch_request', null, $request, $route, $handler );
					// Allow plugins to halt the request via this filter.
					if ( null !== $dispatch_result ) {
						$response = $dispatch_result;
					} else {
						$response = call_user_func( $callback, $request );
          }
          
          if ($response === false) {
            $response = new WP_Error( '404', __( 'Sorry, that does not exist.' ) );
            if(!$json) {
              $response = $response->get_error_message();
              $code = 404;
            }
          }
        }

        if($json) {
          $response = wp_json_encode($response);
        }
				/**
				 * Filters the response immediately after executing any REST API
				 * callbacks.
				 *
				 * Allows plugins to perform any needed cleanup, for example,
				 * to undo changes made during the {@see 'rest_request_before_callbacks'}
				 * filter.
				 *
				 * Note that this filter will not be called for requests that
				 * fail to authenticate or match to a registered route.
				 *
				 * Note that an endpoint's `permission_callback` can still be
				 * called after this filter - see `rest_send_allow_header()`.
				 *
				 * @since 4.7.0
				 *
				 * @param WP_HTTP_Response $response Result to send to the client. Usually a WP_REST_Response.
				 * @param WP_REST_Server   $handler  ResponseHandler instance (usually WP_REST_Server).
				 * @param WP_REST_Request  $request  Request used to generate the response.
				 */
				$response = apply_filters( 'rest_request_after_callbacks', $response, $handler, $request );
				if ( is_wp_error( $response ) ) {
					$response = $this->error_to_response( $response );
				} else {
					$response = rest_ensure_response( $response );
				}
				$response->set_matched_route( $route );
        $response->set_matched_handler( $handler );
        if($code !== null) {
          $response->set_status($code);
        }

				return $response;
			}
		}
		return $this->error_to_response( new WP_Error( 'rest_no_route', __( 'No route was found matching the URL and request method' ), array( 'status' => 404 ) ) );
	}

    /**
     * Registers a route to the server.
     *
     * @since 4.4.0
     *
     * @param string $namespace  Namespace.
     * @param string $route      The REST route.
     * @param array  $route_args Route arguments.
     * @param bool   $override   Optional. Whether the route should be overridden if it already exists.
     *                           Default false.
     */
    public function register_route( $namespace, $route, $route_args, $override = false ) {
        if ( ! isset( $this->namespaces[ $namespace ] ) ) {
            $this->namespaces[ $namespace ] = array();
 
            $this->register_route( $namespace, '/' . $namespace, array(
                array(
                    'methods' => self::READABLE,
                    'callback' => array( $this, 'get_namespace_index' ),
                    'content_type' => isset( $_GET['_jsonp'] ) ? 'application/javascript' : 'application/json',
                    'json' => true,
                    'args' => array(
                        'namespace' => array(
                            'default' => $namespace,
                        ),
                        'context' => array(
                            'default' => 'view',
                        ),
                    ),
                ),
            ) );
        }

        // Associative to avoid double-registration.
        $this->namespaces[ $namespace ][ $route ] = true;
        $route_args['namespace'] = $namespace;
 
        if ( $override || empty( $this->endpoints[ $route ] ) ) {
            $this->endpoints[ $route ] = $route_args;
        } else {
            $this->endpoints[ $route ] = array_merge( $this->endpoints[ $route ], $route_args );
        }
    }
}

?>