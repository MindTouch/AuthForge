<?php
/** @noinspection PhpDeprecationInspection */
declare(strict_types=1);
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

use DateTimeInterface;
use DOMDocument;
use Exception;
use modethirteen\AuthForge\Common\Logger\ContextLoggerInterface;
use modethirteen\AuthForge\Common\Utility\DateTimeImmutableEx;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlCannotDeflateOutgoingHttpMessageException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlCannotEncryptMessageDataNameIdException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlCannotGenerateSignatureException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlCannotLoadCryptoKeyException;
use modethirteen\AuthForge\ServiceProvider\Saml\Http\HttpMessageInterface;
use modethirteen\Crypto\CryptoKeyInterface;
use modethirteen\Http\QueryParams;
use modethirteen\Http\XUri;
use modethirteen\TypeEx\StringEx;
use Ramsey\Uuid\UuidFactoryInterface;
use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityKey;

class SamlUriFactory implements SamlUriFactoryInterface {

    public function __construct(private SamlConfigurationInterface $saml, private DateTimeInterface $dateTime, private ContextLoggerInterface $logger, private UuidFactoryInterface $uuidFactory, private SessionIndexRegistryInterface $sessionIndexRegistry)
    {
    }

    /**
     * {@inheritDoc}
     * @throws SamlCannotDeflateOutgoingHttpMessageException
     * @throws SamlCannotGenerateSignatureException
     * @throws SamlCannotLoadCryptoKeyException
     */
    public function newAuthnRequestUri(XUri $returnUri, string $securityKey) : XUri {
        if(StringEx::isNullOrEmpty($securityKey)) {
            $securityKey = XMLSecurityKey::RSA_SHA1;
        }

        $id = $this->newId();
        $samlRequest = $this->newAuthnRequest($id);
        $returnHref = $returnUri->toString();
        $uri = $this->saml->getIdentityProviderSingleSignOnUri();
        $uri = $uri->withQueryParams(QueryParams::newFromArray([
            HttpMessageInterface::PARAM_SAML_REQUEST => $samlRequest,
            HttpMessageInterface::PARAM_SAML_RELAYSTATE => $returnHref
        ]));
        // Sign the request if required
        if ($this->saml->isAuthnRequestSignatureRequired()) {
            $privateKey = $this->saml->getServiceProviderPrivateKey();
            if ($privateKey === null) {
                throw new SamlCannotGenerateSignatureException();
            }

            $uri = $this->withSignature($uri, $privateKey, $securityKey);
        }

        $this->logger->debug('Sending AuthnRequest', [
            'DocumentId' => $id,
            'AuthnRequestId' => $id,
            'Url' => $uri->toString(),
            'SignatureAlgorithm' => $securityKey,
            'RelayState' => $returnHref
        ]);

        return $uri;
    }

    /**
     * {@inheritDoc}
     * @throws SamlCannotDeflateOutgoingHttpMessageException
     * @throws SamlCannotEncryptMessageDataNameIdException
     * @throws SamlCannotGenerateSignatureException
     * @throws SamlCannotLoadCryptoKeyException
     */
    public function newLogoutRequestUri(string $username, XUri $returnUri) : ?XUri {
        $uri = $this->saml->getIdentityProviderSingleLogoutUri();
        if ($uri === null) {
            return null;
        }

        $securityKey = XMLSecurityKey::RSA_SHA1;

        $id = $this->newId();
        $sessionIndex = $this->sessionIndexRegistry->getSessionIndex($username);
        $samlRequest = $this->newLogoutRequest($id, $username, $sessionIndex);
        $returnHref = $returnUri->toString();

        $uri = $uri->withQueryParams(QueryParams::newFromArray([
            HttpMessageInterface::PARAM_SAML_REQUEST => $samlRequest,
            HttpMessageInterface::PARAM_SAML_RELAYSTATE => $returnHref
        ]));

        // Sign the request if required
        if ($this->saml->isLogoutRequestSignatureRequired()) {
            $privateKey = $this->saml->getServiceProviderPrivateKey();
            if ($privateKey === null) {
                throw new SamlCannotGenerateSignatureException();
            }

            $uri = $this->withSignature($uri, $privateKey, $securityKey);
        }

        $this->logger->debug('Sending LogoutRequest', [
            'DocumentId' => $id,
            'LogoutRequestId' => $id,
            'Url' => $uri->toString(),
            'SessionIndex' => $sessionIndex,
            'SignatureAlgorithm' => $securityKey,
            'RelayState' => $returnHref
        ]);

        return $uri;
    }

    /**
     * {@inheritDoc}
     * @throws SamlCannotDeflateOutgoingHttpMessageException
     * @throws SamlCannotEncryptMessageDataNameIdException
     * @throws SamlCannotGenerateSignatureException
     * @throws SamlCannotLoadCryptoKeyException
     */
    public function newLogoutResponseUri(XUri $returnUri, string $inResponseTo) : ?XUri {
        $uri = $this->saml->getIdentityProviderSingleLogoutUri();
        if ($uri === null) {
            return null;
        }

        $securityKey = XMLSecurityKey::RSA_SHA1;
        $id = $this->newId();
        $returnHref = $returnUri->toString();
        $samlResponse = $this->newLogoutResponse($id, $inResponseTo);

        // Build base query params
        $uri = $uri->withQueryParams(QueryParams::newFromArray([
            HttpMessageInterface::PARAM_SAML_RESPONSE => $samlResponse,
            HttpMessageInterface::PARAM_SAML_RELAYSTATE => $returnHref
        ]));

        // Sign the response if required
        if ($this->saml->isLogoutResponseSignatureRequired()) {
            $privateKey = $this->saml->getServiceProviderPrivateKey();
            if ($privateKey === null) {
                throw new SamlCannotGenerateSignatureException();
            }

            $uri = $this->withSignature($uri, $privateKey, $securityKey);
        }

        $this->logger->debug('Sending LogoutResponse', [
            'DocumentId' => $id,
            'LogoutResponseId' => $id,
            'Url' => $uri->toString(),
            'SignatureAlgorithm' => $securityKey,
            'RelayState' => $returnHref
        ]);

        return $uri;
    }

    /**
     * @param CryptoKeyInterface $key - private signing key
     * @param string $algo - XMLDSIG-CORE digest algorithm (default: http://www.w3.org/2000/09/xmldsig#rsa-sha1)
     * @return static
     * @throws SamlCannotLoadCryptoKeyException
     * @throws SamlCannotGenerateSignatureException
     */
    private function withSignature(xUri $uri, CryptoKeyInterface $key, string $algo = XMLSecurityKey::RSA_SHA1) : xUri {
        if (StringEx::isNullOrEmpty($key->toString())) {
            throw new SamlCannotGenerateSignatureException();
        }

        $cert = $this->saml->getServiceProviderX509Certificate();
        if ($cert === null) {
            throw new SamlCannotGenerateSignatureException();
        }

        $msg = '';

        $request = $uri->getQueryParam(HttpMessageInterface::PARAM_SAML_REQUEST);
        if ($request !== null) {
            $msg = 'SAMLRequest=' . urlencode($request);
        }

        $response = $uri->getQueryParam(HttpMessageInterface::PARAM_SAML_RESPONSE);
        if ($response !== null) {
            $msg = 'SAMLResponse=' . urlencode($response);
        }

        if ($msg === '') {
            throw new SamlCannotGenerateSignatureException();
        }

        $relayState = $uri->getQueryParam(HttpMessageInterface::PARAM_SAML_RELAYSTATE);
        if ($relayState !== null) {
            $msg .= '&RelayState=' . urlencode($relayState);
        }

        $msg .= '&SigAlg=' . urlencode($algo);

        try {
            $signer = new XMLSecurityKey($algo, ['type' => 'private']);
            $signer->loadKey($key->toString(), false);
        } catch (Exception $e) {
            throw new SamlCannotLoadCryptoKeyException($key, $e->getMessage());
        }

        try {
            $signature = $signer->signData($msg);
        } catch (Exception $e) {
            throw new SamlCannotGenerateSignatureException();
        }
        if ($signature === null) {
            throw new SamlCannotGenerateSignatureException();
        }

        return $uri
            ->withQueryParam(HttpMessageInterface::PARAM_SAML_SIGALG, $algo)
            ->withQueryParam(HttpMessageInterface::PARAM_SAML_SIGNATURE, base64_encode($signature));
    }


    /**
     * @throws SamlCannotDeflateOutgoingHttpMessageException
     */
    private function newAuthnRequest(string $id) : string {
        $issueInstant = DateTimeImmutableEx::fromDateTime($this->dateTime)->toISO8601();

        // nameid policy
        $nameIdPolicyFormat = $this->saml->getServiceProviderNameIdFormat();
        if($this->saml->isNameIdEncryptionRequired()) {
            $nameIdPolicyFormat = HttpMessageInterface::NAMEID_ENCRYPTED;
        }

        // TODO (modethirteen 20210112): NameIDPolicy/@AllowCreate should be configurable
        $nameIdPolicyNode = !StringEx::isNullOrEmpty($nameIdPolicyFormat)
            ? "<samlp:NameIDPolicy Format=\"{$nameIdPolicyFormat}\" AllowCreate=\"true\"></samlp:NameIDPolicy>"
            : '';

        // TODO (modethirteen, 20210112): support redirect binding (acs already does)
        // do not use HEREDOC
        $request = "
<samlp:AuthnRequest
    xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"
    xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"
    ID=\"{$id}\"
    Version=\"2.0\"

    IssueInstant=\"{$issueInstant}\"
    Destination=\"{$this->saml->getIdentityProviderSingleSignOnUri()}\"
    ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"
    AssertionConsumerServiceURL=\"{$this->saml->getServiceProviderAssertionConsumerServiceUri()}\">
    <saml:Issuer>{$this->saml->getServiceProviderEntityId()}</saml:Issuer>
    {$nameIdPolicyNode}
</samlp:AuthnRequest>";
        $deflated = gzdeflate($request);
        if(is_bool($deflated)) {
            throw new SamlCannotDeflateOutgoingHttpMessageException($request);
        }
        return base64_encode($deflated);
    }

    private function newId() : string {
        return 'mindtouch_' . $this->uuidFactory->uuid4()->toString();
    }

    /**
     * @throws SamlCannotDeflateOutgoingHttpMessageException
     * @throws SamlCannotEncryptMessageDataNameIdException
     * @throws SamlCannotLoadCryptoKeyException
     */
    private function newLogoutRequest(string $id, string $nameId, ?string $sessionIndex) : string {
        $issueInstant = DateTimeImmutableEx::fromDateTime($this->dateTime)->toISO8601();

        // build nameid
        $doc = new DOMDocument();
        $nameIdElement = $doc->createElement('saml:NameID');
        $nameIdElement->setAttribute('SPNameQualifier', $this->saml->getServiceProviderEntityId());
        $nameIdFormat =  $this->saml->getServiceProviderNameIdFormat();
        if(!StringEx::isNullOrEmpty($nameIdFormat)) {
            $nameIdElement->setAttribute('Format', $nameIdFormat);
        }
        $nameIdElement->appendChild($doc->createTextNode($nameId));
        $doc->appendChild($nameIdElement);
        if($this->saml->isNameIdEncryptionRequired()) {
            $certificate = $this->saml->getIdentityProviderX509Certificate();

            // encrypt nameid
            // TODO (modethirteen, 20200113): determine if saml:NameID/@Format needs to change to urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted
            try {
                $seckey = new XMLSecurityKey(XMLSecurityKey::RSA_1_5, ['type' => 'public']);
                $seckey->loadKey($certificate->toString());
            } catch(Exception $e) {
                throw new SamlCannotLoadCryptoKeyException($certificate, $e->getMessage());
            }
            $enc = new XMLSecEnc();
            $enc->setNode($nameIdElement);
            $enc->type = XMLSecEnc::Element;
            $symmetricKey = new XMLSecurityKey(XMLSecurityKey::AES128_CBC);
            try {
                $symmetricKey->generateSessionKey();
            } catch(Exception $e) {
                throw new SamlCannotEncryptMessageDataNameIdException($certificate, $e->getMessage());
            }
            try {
                $enc->encryptKey($seckey, $symmetricKey);
                $encryptedData = $enc->encryptNode($symmetricKey);
            } catch(Exception $e) {
                throw new SamlCannotEncryptMessageDataNameIdException($certificate, $e->getMessage());
            }
            $newdoc = new DOMDocument();
            $encryptedId = $newdoc->createElement('saml:EncryptedID');
            $newdoc->appendChild($encryptedId);
            $encryptedId->appendChild($encryptedId->ownerDocument->importNode($encryptedData, true));
            $principle = $newdoc->saveXML($encryptedId);
        } else {
            $principle = $doc->saveXML($nameIdElement);
        }

        // build sessionindex
        if(!StringEx::isNullOrEmpty($sessionIndex)) {
            $principle .= "<samlp:SessionIndex>{$sessionIndex}</samlp:SessionIndex>";
        }

        // do not use HEREDOC
        $request = "
<samlp:LogoutRequest
    xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"
    xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"
    ID=\"{$id}\"
    Version=\"2.0\"
    IssueInstant=\"{$issueInstant}\"
    Destination=\"{$this->saml->getIdentityProviderSingleLogoutUri()}\">
    <saml:Issuer>{$this->saml->getServiceProviderEntityId()}</saml:Issuer>
    {$principle}
</samlp:LogoutRequest>";
        $deflated = gzdeflate($request);
        if(is_bool($deflated)) {
            throw new SamlCannotDeflateOutgoingHttpMessageException($request);
        }
        return base64_encode($deflated);
    }

    /**
     * @throws SamlCannotDeflateOutgoingHttpMessageException
     */
    private function newLogoutResponse(string $id, string $inResponseTo) : string {
        $issueInstant = DateTimeImmutableEx::fromDateTime($this->dateTime)->toISO8601();

        // do not use HEREDOC
        $response = "
<samlp:LogoutResponse xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"
      xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"
      ID=\"{$id}\"
      Version=\"2.0\"
      IssueInstant=\"{$issueInstant}\"
      Destination=\"{$this->saml->getIdentityProviderSingleLogoutUri()}\"
      InResponseTo=\"{$inResponseTo}\">
    <saml:Issuer>{$this->saml->getServiceProviderEntityId()}</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\" />
    </samlp:Status>
</samlp:LogoutResponse>";
        $deflated = gzdeflate($response);
        if(is_bool($deflated)) {
            throw new SamlCannotDeflateOutgoingHttpMessageException($response);
        }
        return base64_encode($deflated);
    }
}
