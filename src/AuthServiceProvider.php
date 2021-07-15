<?php
declare(strict_types=1);

namespace zzAuth;

use Illuminate\Contracts\Support\DeferrableProvider;
use Illuminate\Support\ServiceProvider;

class AuthServiceProvider extends ServiceProvider implements DeferrableProvider
{

    /**
     * Register services.
     *
     * @return void
     */
    public function register()
    {
        $this->app->singleton('zzAuth', function () {
            return new ZzAuth();
        });
        $this->app->singleton('redirect', function () {
            return new Redirect();
        });
    }

    /**
     * Bootstrap services.
     *
     * @return void
     */
    public function boot()
    {
        $this->publishes([
            __DIR__ . '/../config/zzconfig.php' => config_path('zzconfig.php')
        ], 'config');
    }

    public function provides()
    {
        return ['zzAuth', 'redirect'];
    }

}
