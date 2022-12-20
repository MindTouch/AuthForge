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
namespace modethirteen\AuthForge\ServiceProvider\Saml;

use modethirteen\Crypto\CryptoKeyInterface;
use modethirteen\Http\XUri;

interface SamlConfigurationInterface {

    public function getAllowedClockDrift() : int;

    /**
     * @return string[]
     */
    public function getAllowedSingleLogoutStatuses() : array;

    public function getDefaultReturnUri() : XUri;

    public function getIdentityProviderEntityId() : string;

    public function getIdentityProviderSingleLogoutUri() : ?XUri;

    public function getIdentityProviderSingleSignOnUri() : XUri;

    public function getIdentityProviderX509Certificate() : ?CryptoKeyInterface;

    /**
     * @return string[]
     */
    public function getNameIdFormats() : array;

    public function getRelayStateBaseUri() : XUri;

    /**
     * @return AssertionAttributeClaimInterface[]
     */
    public function getServiceProviderAssertionAttributeClaims() : array;

    public function getServiceProviderAssertionConsumerServiceBinding() : string;

    public function getServiceProviderAssertionConsumerServiceUri() : XUri;

    public function getServiceProviderEntityId() : string;

    public function getServiceProviderNameIdFormat() : ?string;

    public function getServiceProviderPrivateKey() : ?CryptoKeyInterface;

    public function getServiceProviderRawX509CertificateText() : ?string;

    public function getServiceProviderServiceName() : string;

    public function getServiceProviderSingleLogoutServiceBinding() : string;

    public function getServiceProviderSingleLogoutServiceUri() : XUri;

    public function getServiceProviderX509Certificate() : ?CryptoKeyInterface;

    public function isAssertionEncryptionRequired() : bool;

    public function isAssertionSignatureRequired() : bool;

    public function isAuthnRequestSignatureRequired() : bool;

    public function isLogoutRequestSignatureRequired() : bool;

    public function isLogoutResponseSignatureRequired() : bool;

    public function isMessageSignatureRequired() : bool;

    public function isMetadataSignatureRequired() : bool;

    public function isNameIdEncryptionRequired() : bool;

    public function isNameIdFormatEnforcementEnabled() : bool;

    public function isStrictValidationRequired() : bool;
}
