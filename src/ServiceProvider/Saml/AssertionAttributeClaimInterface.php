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

interface AssertionAttributeClaimInterface {

    // attribute name formats
    const NAME_FORMAT_UNSPECIFIED = 'urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified';
    const NAME_FORMAT_URI = 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri';
    const NAME_FORMAT_BASIC = 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic';

    /**
     * @return string|null
     */
    public function getFriendlyName() : ?string;

    /**
     * @return string
     */
    public function getName() : string;

    /**
     * @return string|null
     */
    public function getNameFormat() : ?string;

    /**
     * @return bool
     */
    public function isRequired() : bool;
}
