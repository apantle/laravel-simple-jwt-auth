<?php

namespace Apantle\LaravelSimpleJwtAuth\Tests;

use Orchestra\Testbench\TestCase;
use Apantle\LaravelSimpleJwtAuth\JwtAuthServiceProvider;

class ExampleTest extends TestCase
{

    protected function getPackageProviders($app)
    {
        return [JwtAuthServiceProvider::class];
    }

    /** @test */
    public function true_is_true()
    {
        $this->assertTrue(true);
    }
}
