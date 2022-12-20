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
namespace modethirteen\AuthForge\ServiceProvider\OAuth;

use modethirteen\Http\XUri;

interface OAuthConfigurationInterface {

    public function getAllowedClockDrift() : int;

    public function getAuthorizationCodeConsumerUri() : XUri;

    public function getDefaultReturnUri() : XUri;

    public function getRelyingPartyClientId() : string;

    public function getRelyingPartyClientSecret() : string;

    public function getIdentityProviderAuthorizationUri() : XUri;

    public function getIdentityProviderTokenClientAuthenticationMethod() : string;

    public function getIdentityProviderTokenUri() : XUri;

    /**
     * @return string[]
     */
    public function getScopes() : array;
}
