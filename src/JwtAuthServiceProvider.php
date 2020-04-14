<?php

namespace Apantle\LaravelSimpleJwtAuth;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\ServiceProvider;

class JwtAuthServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap the application services.
     */
    public function boot()
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/config.php' => config_path('jwt-auth.php'),
            ], 'config');
        }
    }

    /**
     * Register the application services.
     */
    public function register()
    {
        // Automatically apply the package configuration
        $this->mergeConfigFrom(__DIR__.'/../config/config.php', 'jwt-auth');

        // Register the main class to use with the facade
        $this->app->singleton('jwt-auth', function ($app) {
            return new JwtAuthTokenService($app['request']);
        });

        $guardKey = config('jwt-auth.guard');
        $driverKey = config('jwt-auth.driver');
        $providerKey = config('jwt-auth.provider');
        $modelClass = config('jwt-auth.model');

        Config::set('auth.guards.' . $guardKey, [
            'driver' => $driverKey,
            'provider' => $providerKey,
        ]);

        Config::set('auth.providers.' . $providerKey, [
            'driver' => 'eloquent',
            'model' => $modelClass,
        ]);

        Auth::extend($driverKey, function ($app, $name, $config) {
            return new JwtGuard(
                Auth::createUserProvider($config['provider']),
                $app['request'],
                JwtAuth::getFacadeRoot()
            );
        });
    }
}
