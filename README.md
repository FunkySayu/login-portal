Implements a login portal for an nginx based SSO auth using Discord.

## How to integrate with

Create a nginx configuration for your website using `auth_request`
module:

```nginx
server {
    # ...

    # The auth route, implemented using ngx_http_js_module.    
    location = /_auth {
        internal;
        js_content auth.validate;
    }

    # Redirect to the login page on 401 errors.
    location @error401 {
        return 302 https://login.funkysayu.fr/login?host=$host&back=$request_uri;
    }

    # General server implementation.
    location / {
        auth_request /_auth;
        error_page 401 = @error401;

        proxy_pass http://localhost:8000; # Example, to be replaced with actual website.
    }
}
```


