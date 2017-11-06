# Laravel SAML

Laravel-SAML adds SAML2 support to make a laravel application both a SAML2 identity provider (IdP) and a SAML2 service provider (SP). The package is designed to work with Laravel 5.4 or above.

The package is mostly designed to function according to following guide:
https://imbringingsyntaxback.com/implementing-a-saml-idp-with-laravel/

To get a better basic understanding for SAML in general, read https://github.com/jch/saml

Supported Features
* SP initiated login
* RelayState

## Installation and Configuration

Require the package using composer 

``` bash
   $ composer require "kingstarter/laravel-saml":"dev-master"
```
#### Laravel 5.4
Add the service provider to ```config/app.php```

```
    KingStarter\LaravelSaml\LaravelSamlServiceProvider::class,
```
#### Laravel 5.5+
This package supports Laravel's Package Auto Discovery and should be automatically loaded when required using composer. If the package is not auto discovered run

```bash
    $ php artisan package:discover
```
#### Configuration
To change the default configuration, publish the package's config file.

```bash
   $ php artisan vendor:publish --tag="saml_config"
```

This will create a `config/saml.php` file in your app's config folder.

Add the following entry to the `config/filesystem.php` file.

```php
    'disks' => [

        ...
        
        'saml' => [
            'driver' => 'local',
            'root' => storage_path().'/saml',
        ],

    ],
```

The filesystem requires the following folder `storage/saml/idp` which should be created automatically for you when publishing the config file.

You will need to place the following files with the `storage/saml/idp` folder:
- cert.pem
- key.pem
- metadata.xml - Can be generated at [https://www.samltool.com/idp_metadata.php](https://www.samltool.com/idp_metadata.php)

These filenames can be overridden within the `config/saml.php` file under `idp`

#### Configuring IdP: Adding Service Providers

Each Service Provider (SP) that you want to allow to authenticate with your Identity Service Provider (IdP) must have it's own entry within the Service Provider ('sp') array in your `config/saml.php` file. Each entry's key must equal the base_64 encoded Assertion URL of the Service Provider.   

You can generate the base_64 encoded AssertionURL by using the following artisan command.
 
```bash
   $ php artisan laravel-saml:encodeurl https://sp.webapp.com/saml/login
   --
   URL Given: https://sp.webapp.com/saml/login
   Encoded AssertionURL:aHR0cHM6Ly9zcC53ZWJhcHAuY29tL3NhbWwvbG9naW4=
```

Use the AssertionURL output by the artisan command as the key for your new SP entry. Following is the minimum configuration required for an SP.

`config/saml.php:`
```php
'sp' => [        
    
     ...

    /**
     * New entry
     * 
     * Sample URL:         https://sp.webapp.com/saml/login
     * Base64 encoded URL: aHR0cHM6Ly9zcC53ZWJhcHAuY29tL3NhbWwvY29uc3VtZQ==
     */
    'aHR0cHM6Ly9zcC53ZWJhcHAuY29tL3NhbWwvY29uc3VtZQ==' => [
        'destination' => 'https://sp.webapp.com/saml/consume',
        'issuer'      => 'https://sp.webapp.com',
    ],
],
``` 

##### Optional Configuration

There are various optional settings that can be included on a per SP basis to override the IdP's default behaviour. This section details the settings and the default behaviour.

##### Forward Roles
The global ```forward_roles``` setting can be overridden on a per SP basis by including it within SP's entry within the 'SP' array

| Setting | Description |
| ------- | ----------- |
| forward_roles | Boolean value whether to forward roles to the SP |

```php
            'forward_roles' => true,
```

##### User Identifier / NameID
The default global nameID used by the IdP is email address. This is the identifier given to the SP as the user's username or user identifier. 

This can be overridden on a per SP basis by including the following settings within SP's entry within the 'SP' array.

| Setting | Description |
| ------- | ----------- |
| name_id_format | Can be any of the NAME_ID_ constants listed in ```\LightSaml\SamlConstants::class```<br />Default: 'NAME_ID_FORMAT_EMAIL' |
| name_id_field | The name of the attribute to retrieve from the User model ('email' would result in $user->email)<br />Default: 'email'
        
```php
            'name_id_format' => 'NAME_ID_FORMAT_EMAIL',
            'name_id_field' => 'email',
```
                  
##### User Attributes
By default, the IdP will return the following User Model Attributes to the SP, ```email```, ```name```  

This can be overridden on a per SP basis by including an ```attributes``` array within SP's entry within the 'SP' array.

Provide an array where the key is a constant from ```\LightSaml\ClaimTypes::class``` and the value is the attribute to retrieve from the User model ('name' would result in $user->name)

```php
            'attributes' => [
                'EMAIL_ADDRESS' => 'email',
                'COMMON_NAME' => 'name',
            ],
```

#### IdP Setup: Authentication

To use the SAML package as an IdP, some files need to be modified. Within your login view, problably ```resources/views/auth/login.blade.php``` add a SAMLRequest field beneath the CSRF field (this is actually a good place for it):
```
    {{-- The hidden CSRF field for secure authentication --}}
    {{ csrf_field() }}
    {{-- Add a hidden SAML Request field for SAML authentication --}}
    @if(isset($_GET['SAMLRequest']))
        <input type="hidden" id="SAMLRequest" name="SAMLRequest" value="{{ $_GET['SAMLRequest'] }}">
    @endif
```

The SAMLRequest field will be filled automatically when a SAMLRequest is sent by a http request and therefore initiate a SAML authentication attempt. To initiate the SAML auth, the login and redirect functions need to be modified. Within ```app/Http/Middleware/AuthenticatesUsers.php``` add following lines to both the top and the authenticated function: 
(NOTE: you might need to copy it out from vendor/laravel/framework/src/Illuminate/Foundation/Auth/ to your Middleware directory) 

```
<?php

namespace App\Http\Middleware;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Foundation\Auth\RedirectsUsers;
use Illuminate\Foundation\Auth\ThrottlesLogins;

use KingStarter\LaravelSaml\Http\Traits\SamlAuth;

trait AuthenticatesUsers
{
    use RedirectsUsers, ThrottlesLogins, SamlAuth;
    
    ...

    protected function authenticated(Request $request, $user)
    {
        if(Auth::check() && isset($request['SAMLRequest'])) {
            $this->handleSamlLoginRequest($request);
        }
    }
    
    ...
```

To allow later direct redirection when somebody is already logged in, we need to add also some lines to ```app/Http/Middleware/RedirectIfAuthenticated.php```:
```
<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Support\Facades\Auth;

use KingStarter\LaravelSaml\Http\Traits\SamlAuth;

class RedirectIfAuthenticated
{
    use SamlAuth;
    
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @param  string|null  $guard
     * @return mixed
     */
    public function handle($request, Closure $next, $guard = null)
    {
        if(Auth::check() && isset($request['SAMLRequest'])){  
            $this->handleSamlLoginRequest($request);
        }
        if (Auth::guard($guard)->check()) {
            return redirect('/home');
        }
        return $next($request);
    }
}
```

#### Debugging
If there is an issue, you can enable debugging which will output information to your log file.

Set ```debug_saml_request``` to true within your `config/saml.php` file. Your environmental variable ```APP_LOG_LEVEL``` must also be set to `debug`.