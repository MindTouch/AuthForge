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

use DateTimeInterface;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\HS256;
use modethirteen\AuthForge\Common\Http\ServerRequestEx;
use modethirteen\AuthForge\Common\Jose\JsonWebSignature;
use modethirteen\AuthForge\Common\Logger\ContextLoggerInterface;
use modethirteen\AuthForge\ServiceProvider\AuthFlowServiceInterface;
use modethirteen\AuthForge\ServiceProvider\OAuth\Event\OAuthFlowEvent;
use modethirteen\AuthForge\ServiceProvider\OAuth\Exception\OAuthFlowServiceException;
use modethirteen\AuthForge\ServiceProvider\OAuth\Middleware\OAuthMiddlewareServiceInterface;
use modethirteen\Http\Content\UrlEncodedFormDataContent;
use modethirteen\Http\Exception\PlugUriHostRequiredException;
use modethirteen\Http\Exception\ResultParserContentExceedsMaxContentLengthException;
use modethirteen\Http\Parser\JsonParser;
use modethirteen\Http\Plug;
use modethirteen\Http\XUri;
use modethirteen\TypeEx\Exception\InvalidDictionaryValueException;
use modethirteen\TypeEx\StringEx;
use modethirteen\XArray\MutableXArray;
use Psr\EventDispatcher\EventDispatcherInterface;
use Ramsey\Uuid\UuidFactoryInterface;

class OAuthFlowService implements AuthFlowServiceInterface {

    #region reserved oauth params
    public const PARAM_CLIENT_ASSERTION = 'client_assertion';
    public const PARAM_CLIENT_ASSERTION_TYPE = 'client_assertion_type';
    public const PARAM_CLIENT_ID = 'client_id';
    public const PARAM_CLIENT_SECRET = 'client_secret';
    public const PARAM_CODE = 'code';
    public const PARAM_ERROR = 'error';
    public const PARAM_ERROR_DESCRIPTION = 'error_description';
    public const PARAM_GRANT_TYPE = 'grant_type';
    public const PARAM_REDIRECT_URI = 'redirect_uri';
    public const PARAM_RESPONSE_TYPE = 'response_type';
    public const PARAM_SCOPE = 'scope';
    public const PARAM_STATE = 'state';
    #endregion

    #region session state
    public const SESSION_OAUTH_HREF = 'OAuth/href';
    public const SESSION_OAUTH_STATE = 'OAuth/state';
    #endregion

    #region token auth
    public const TOKEN_AUTH_METHOD_CLIENT_SECRET_BASIC = 'client_secret_basic';
    public const TOKEN_AUTH_METHOD_CLIENT_SECRET_POST = 'client_secret_post';
    public const TOKEN_AUTH_METHOD_CLIENT_SECRET_JWT = 'client_secret_jwt';
    #endregion

    public const PLUG_TIMEOUT = 30;

    public function __construct(private OAuthConfigurationInterface $oauth, private DateTimeInterface $dateTime, private ContextLoggerInterface $logger, private OAuthMiddlewareServiceInterface $middlewareService, private EventDispatcherInterface $eventDispatcher, private UuidFactoryInterface $uuidFactory, private MutableXArray $sessionStorage)
    {
    }

    /**
     * {@inheritDoc}
     * @throws OAuthFlowServiceException
     */
    public function getAuthenticatedUri(ServerRequestEx $request) : XUri {
        $this->logger->debug('Processing authorization code response...');

        // OAuth 2.0 authorization code flow incorporates HTTP GET requests only, therefore it is safe to assume all parameters are query parameters
        $params = $request->getQueryParams();

        // fetch return href
        $returnHref = StringEx::stringify($this->sessionStorage->getVal(self::SESSION_OAUTH_HREF));
        $this->sessionStorage->setVal(self::SESSION_OAUTH_HREF);

        // check session state
        $state = $params->get(self::PARAM_STATE);
        $sessionState = $this->sessionStorage->getVal(self::SESSION_OAUTH_STATE);
        $this->sessionStorage->setVal(self::SESSION_OAUTH_STATE);
        if($sessionState === null) {
            $this->logger->debug('Authorization code response state not found, this may be an unsolicited authorization code...');
        } else if($sessionState !== $state) {
            throw new OAuthFlowServiceException('Provided authorization code response state did not match expected value', [
                'ExpectedState' => $sessionState,
                'ProvidedState' => $state
            ]);
        }
        $this->logger->addContextHandler(function(MutableXArray $context) use ($state) : void {
            $context->setVal('State', $state ?? 'none');
        });
        $code = StringEx::stringify($params->get(self::PARAM_CODE));
        if(StringEx::isNullOrEmpty($code) && $params->get(self::PARAM_ERROR) !== null) {
            throw new OAuthFlowServiceException('The authorization endpoint returned an unsuccessful response', [
                'ErrorType' => $params->get(self::PARAM_ERROR),
                'ErrorDescription' => $params->get(self::PARAM_ERROR_DESCRIPTION)
            ]);
        }

        // request token
        $this->logger->debug('Requesting token(s)...');
        $tokenFormDataParameterValuePairs = [
            self::PARAM_CODE => $code,
            self::PARAM_GRANT_TYPE => 'authorization_code',
            self::PARAM_REDIRECT_URI => $this->oauth->getAuthorizationCodeConsumerUri()->toString()
        ];
        $tokenUri = $this->oauth->getIdentityProviderTokenUri();
        $clientId = $this->oauth->getRelyingPartyClientId();
        $clientSecret = $this->oauth->getRelyingPartyClientSecret();
        try {
            $tokenResult = match ($this->oauth->getIdentityProviderTokenClientAuthenticationMethod()) {
                self::TOKEN_AUTH_METHOD_CLIENT_SECRET_POST => $this->newPlug($tokenUri)
                    ->withResultParser(new JsonParser())
                    ->post(new UrlEncodedFormDataContent(array_merge([
                        self::PARAM_CLIENT_ID => $clientId,
                        self::PARAM_CLIENT_SECRET => $clientSecret
                    ], $tokenFormDataParameterValuePairs))),
                self::TOKEN_AUTH_METHOD_CLIENT_SECRET_JWT => $this->newPlug($tokenUri)
                    ->withResultParser(new JsonParser())
                    ->post(new UrlEncodedFormDataContent(array_merge([
                        self::PARAM_CLIENT_ASSERTION => $this->getOAuthClientAssertion($clientId, $clientSecret),
                        self::PARAM_CLIENT_ASSERTION_TYPE => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
                    ], $tokenFormDataParameterValuePairs))),
                default => $this->newPlug($tokenUri)
                    ->withCredentials($clientId, $clientSecret)
                    ->withResultParser(new JsonParser())
                    ->post(new UrlEncodedFormDataContent($tokenFormDataParameterValuePairs)),
            };
        } catch(
            InvalidDictionaryValueException |
            PlugUriHostRequiredException |
            ResultParserContentExceedsMaxContentLengthException $e
        ) {
            throw (new OAuthFlowServiceException('Could not build token endpoint request: {{Error}}', [
                'Error' => $e->getMessage()
            ]))->withInnerException($e);
        }
        if(!$tokenResult->isSuccess()) {
            throw new OAuthFlowServiceException('The token endpoint returned an unsuccessful response', [
                'Body' => $tokenResult->getBody()->toArray(),
                'Headers' => $tokenResult->getHeaders()->toFlattenedArray(),
                'StatusCode' => $tokenResult->getStatus()
            ]);
        }
        $claims = $this->middlewareService->getClaims($tokenResult);
        $username = $claims->getUsername();
        if(StringEx::isNullOrEmpty($username)) {
            $this->logger->warning('Could not find username in claims');
        } else {
            $this->logger->debug('Found username in claims', [
                'Username' => $claims->getUsername()
            ]);
        }

        // dispatch event to authenticate user in downstream system
        $this->eventDispatcher->dispatch(new OAuthFlowEvent($this->dateTime, $tokenResult, $claims, $this->middlewareService));

        // follow return uri
        $returnUri = XUri::tryParse($returnHref);
        return $returnUri ?? $this->oauth->getDefaultReturnUri();
    }

    public function getLoginUri(XUri $returnUri, XMLSecurityKey $securityKey = XMLSecurityKey::RSA_SHA1) : XUri {
        $clientId = $this->oauth->getRelyingPartyClientId();
        $state = $this->uuidFactory->uuid4()->toString();
        $uri = $this->oauth->getIdentityProviderAuthorizationUri()
            ->withoutQueryParams([
                self::PARAM_CLIENT_ID,
                self::PARAM_REDIRECT_URI,
                self::PARAM_RESPONSE_TYPE,
                self::PARAM_STATE,
                self::PARAM_SCOPE
            ])
            ->with(self::PARAM_CLIENT_ID, $clientId)
            ->with(self::PARAM_REDIRECT_URI, $this->oauth->getAuthorizationCodeConsumerUri()->toString())
            ->with(self::PARAM_RESPONSE_TYPE, 'code')
            ->with(self::PARAM_STATE, $state);

        // scope
        $scopes = array_unique(array_merge($this->middlewareService->getScopes(), $this->oauth->getScopes()));
        $uri = $uri->with(self::PARAM_SCOPE, implode(' ', $scopes));

        // store session state
        $returnHref = $returnUri->toString();
        $this->sessionStorage->setVal(self::SESSION_OAUTH_HREF, $returnHref);
        $this->sessionStorage->setVal(self::SESSION_OAUTH_STATE, $state);
        $this->logger->debug('Generating authorization code request', [
            'AuthorizeEndpointUrl' => $uri->toString(),
            'ClientId' => $clientId,
            'ReturnUrl' => $returnHref,
            'Scopes' => $scopes,
            'State' => $state
        ]);
        return $uri;
    }

    public function getLogoutUri(string $id, XUri $returnUri) : ?XUri {
        return $this->middlewareService->getLogoutUri($id, $returnUri);
    }

    /**
     * @throws InvalidDictionaryValueException
     */
    private function getOAuthClientAssertion(string $clientId, string $clientSecret) : string {
        $algo = new HS256();
        $jwk = JWKFactory::createFromSecret($clientSecret, [
            'alg' => $algo->name(),
            'use' => 'sig'
        ]);
        $now = $this->dateTime->getTimestamp();
        $claims = new JsonWebTokenClaims();
        foreach([
            'aud' => $this->oauth->getIdentityProviderTokenUri()->toString(),
            'exp' => $now + 60,
            'iat' => $now,
            'iss' => $clientId,
            'jti' => $this->uuidFactory->uuid4()->toString(),
            'sub' => $clientId
        ] as $claim => $value) {
            $claims->set($claim, $value);
        }
        return (new JsonWebSignature($claims, $jwk, $algo))->toString();
    }

    /**
     * @throws PlugUriHostRequiredException
     */
    private function newPlug(XUri $uri) : Plug {
        return (new Plug($uri))->withTimeout(self::PLUG_TIMEOUT);
    }
}
