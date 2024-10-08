<?php declare(strict_types=1);
/**
 * AuthForge
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
namespace modethirteen\AuthForge\Tests;

use modethirteen\AuthForge\Tests\ServiceProvider\OAuth\AbstractOAuthTestCase;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Test;
use PHPUnit\Framework\TestListener;
use PHPUnit\Framework\TestListenerDefaultImplementation;
use Throwable;

class FailureListener implements TestListener {
    use TestListenerDefaultImplementation;

    public function addError(Test $test, Throwable $t, float $time) : void {
        if($test instanceof AbstractOAuthTestCase) {
            MockPlugEx::writeMockPlugDetailsToConsole($test, true);
        }
    }

    public function addFailure(Test $test, AssertionFailedError $e, float $time) : void {
        if($test instanceof AbstractOAuthTestCase) {
            MockPlugEx::writeMockPlugDetailsToConsole($test, true);
        }
    }
}
