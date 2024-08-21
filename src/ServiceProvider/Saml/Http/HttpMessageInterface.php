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
namespace modethirteen\AuthForge\ServiceProvider\Saml\Http;

interface HttpMessageInterface {

    // http message parameters
    public const PARAM_SAML_RELAYSTATE = 'RelayState';
    public const PARAM_SAML_REQUEST = 'SAMLRequest';
    public const PARAM_SAML_RESPONSE = 'SAMLResponse';
    public const PARAM_SAML_SIGALG = 'SigAlg';
    public const PARAM_SAML_SIGNATURE = 'Signature';

    // auth context class
    public const AC_UNSPECIFIED = 'urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified';
    public const AC_PASSWORD = 'urn:oasis:names:tc:SAML:2.0:ac:classes:Password';
    public const AC_X509 = 'urn:oasis:names:tc:SAML:2.0:ac:classes:X509';
    public const AC_SMARTCARD = 'urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard';
    public const AC_KERBEROS = 'urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos';

    // nameid formats
    public const NAMEID_EMAIL_ADDRESS = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress';
    public const NAMEID_X509_SUBJECT_NAME = 'urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName';
    public const NAMEID_WINDOWS_DOMAIN_QUALIFIED_NAME = 'urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName';
    public const NAMEID_UNSPECIFIED = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified';
    public const NAMEID_KERBEROS = 'urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos';
    public const NAMEID_ENTITY = 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity';
    public const NAMEID_TRANSIENT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient';
    public const NAMEID_PERSISTENT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';
    public const NAMEID_ENCRYPTED = 'urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted';

    // bindings
    public const BINDING_HTTP_POST = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';
    public const BINDING_HTTP_REDIRECT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect';
    public const BINDING_HTTP_ARTIFACT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact';
    public const BINDING_SOAP = 'urn:oasis:names:tc:SAML:2.0:bindings:SOAP';
    public const BINDING_DEFLATE = 'urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE';

    // status codes
    public const STATUS_SUCCESS = 'urn:oasis:names:tc:SAML:2.0:status:Success';
    public const STATUS_REQUESTER = 'urn:oasis:names:tc:SAML:2.0:status:Requester';
    public const STATUS_RESPONDER = 'urn:oasis:names:tc:SAML:2.0:status:Responder';
    public const STATUS_VERSION_MISMATCH = 'urn:oasis:names:tc:SAML:2.0:status:VersionMismatch';
    public const STATUS_NO_PASSIVE = 'urn:oasis:names:tc:SAML:2.0:status:NoPassive';
    public const STATUS_PARTIAL_LOGOUT = 'urn:oasis:names:tc:SAML:2.0:status:PartialLogout';
    public const STATUS_PROXY_COUNT_EXCEEDED = 'urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded';

    // subject confirmation
    public const CM_BEARER = 'urn:oasis:names:tc:SAML:2.0:cm:bearer';
    public const CM_HOLDER_KEY = 'urn:oasis:names:tc:SAML:2.0:cm:holder-of-key';
    public const CM_SENDER_VOUCHES = 'urn:oasis:names:tc:SAML:2.0:cm:sender-vouches';

    /**
     * @return string
     */
    public function toString() : string;

    /**
     * @param string|null $requestId - optional request id to compare against InResponseTo value
     */
    public function validate(string $requestId = null) : void;
}
