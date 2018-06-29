# wordpress-rest-api-extended
Extends WordPress' REST API, allowing the Content-Type header to be specified, and 404 errors to be raised.

## Usage
Register a route that just returns HTML.
```php
register_rest_route( 'namespace/v1', 'route' , array(
    'methods' => 'GET',
    'callback' => function(){return '<h1>Hello World!</h1>';}, // Callback can return a string that will be passed as the response.
    'content_type' => 'text/html', // Specify any custom Content-Type.
    'json' => false // Route content is parsed as JSON by default, so must be disabled.
) );
```

register_rest_route will still work as normal with JSON:
```php
register_rest_route( 'namespace/v1', 'route' , array(
    'methods' => 'GET',
    'callback' => function(){return array('json': 'value');}
) );

// or explicitly:
register_rest_route( 'namespace/v1', 'route' , array(
    'methods' => 'GET',
    'callback' => function(){return array('json': 'value');},
    'content_type' => 'application/json',
    'json' => true
) );
```
Register a route that just returns a 404 error.
```php
register_rest_route( 'namespace/v1', 'route' , array(
    'methods' => 'GET',
    'callback' => function(){return false;}, // Callback can return a false to trigger a 404 error.
    'content_type' => 'text/html',
    'json' => false // If JSON parsing is enabled, the result will be 200 OK but the error will be returned in the JSON.
) );
```
