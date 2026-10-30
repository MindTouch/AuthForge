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

use DOMElement;
use Exception;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlCannotLoadCryptoKeyException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlDocumentCannotLoadTextException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlDocumentDecryptionException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlDocumentDecryptionInvalidEncryptionAlgorithmException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlDocumentDecryptionNoEncryptedDataException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlDocumentEntityNotAllowedException;
use modethirteen\Crypto\CryptoKeyInterface;
use modethirteen\TypeEx\StringEx;
use RobRichards\XMLSecLibs\XMLSecEnc;

class DocumentFactory implements DocumentFactoryInterface {

    public function __construct(private DocumentSchemaResolverInterface $resolver)
    {
    }

    /**
     * {@inheritDoc}
     * @throws SamlCannotLoadCryptoKeyException
     * @throws SamlDocumentDecryptionInvalidEncryptionAlgorithmException
     * @throws SamlDocumentDecryptionNoEncryptedDataException
     * @throws SamlDocumentDecryptionException
     * @throws SamlDocumentCannotLoadTextException
     * @throws SamlDocumentEntityNotAllowedException
     */
    public function newDecryptedDocument(Document $doc, CryptoKeyInterface $privateKey) : Document {
        $encryptedDoc = clone $doc;
        $enc = new XMLSecEnc();
        $encryptedData = $enc->locateEncryptedData($encryptedDoc);
        if($encryptedData === null || !($encryptedData instanceof DOMElement)) {
            throw new SamlDocumentDecryptionNoEncryptedDataException();
        }
        $enc->setNode($encryptedData);
        $enc->type = $encryptedData->getAttribute('Type');
        $symmetricKey = $enc->locateKey();
        if($symmetricKey === null) {
            throw new SamlDocumentDecryptionInvalidEncryptionAlgorithmException();
        }
        $encryptionKey = null;
        $symmetricKeyInfo = $enc->locateKeyInfo($symmetricKey);
        if($symmetricKeyInfo !== null && $symmetricKeyInfo->isEncrypted) {
            $encryptedCtx = $symmetricKeyInfo->encryptedCtx;
            try {
                $symmetricKeyInfo->loadKey($privateKey->toString(), false, false);
            } catch(Exception $e) {
                throw new SamlCannotLoadCryptoKeyException($privateKey, $e->getMessage());
            }

            // XMLSecEnc::decryptKey returns string if replacement argument is not supplied
            /** @var string $encryptionKey */
            try {
                $encryptionKey = $encryptedCtx->decryptKey($symmetricKeyInfo);
            } catch(Exception $e) {
                throw new SamlDocumentDecryptionException($e->getMessage());
            }
        }
        if($symmetricKey->key === null && $encryptionKey !== null) {
            try {
                $symmetricKey->loadKey($encryptionKey);
            } catch(Exception $e) {
                throw new SamlDocumentDecryptionException($e->getMessage());
            }
        }
        try {

            // decrypt to a raw string instead of splicing in place: XMLSecEnc::decryptNode(replace=true)
            // does importNode+replaceChild, and on libxml2 >= 2.13 that reconciliation hoists the
            // xmlns:ds/xmlns:ec declarations onto the decrypted <saml:Assertion> apex. When the enveloped
            // signature's exc-c14n PrefixList includes those prefixes the hoisted declarations enter the
            // canonical bytes and the digest no longer matches, failing signature validation.
            $decryptedXml = $enc->decryptNode($symmetricKey, false);

            // unique per-call marker (random so attacker-influenced envelope content cannot collide with it)
            $marker = '__authforge_decrypted_assertion_' . bin2hex(random_bytes(16)) . '__';
        } catch(Exception $e) {
            throw new SamlDocumentDecryptionException($e->getMessage());
        }

        // swap the EncryptedData for the marker, serialize the whole envelope, then textually splice the
        // decrypted assertion in place of the marker and reparse once. Replacing an element with a text
        // node never reconciles namespaces, and matching a marker we inserted ourselves - rather than a
        // re-serialized EncryptedData fragment, whose namespace declarations can differ from their
        // in-document form - keeps the splice independent of how libxml serializes the subtree.
        $encryptedData->parentNode->replaceChild($encryptedDoc->createTextNode($marker), $encryptedData);
        $envelopeXml = $encryptedDoc->saveXML();
        $newEnvelopeXml = str_replace($marker, $decryptedXml, $envelopeXml);
        if($newEnvelopeXml === $envelopeXml) {
            throw new SamlDocumentDecryptionException('decrypted assertion could not be spliced into the response envelope');
        }
        return $this->newMessageDocument($newEnvelopeXml);
    }

    /**
     * {@inheritDoc}
     * @throws SamlDocumentCannotLoadTextException
     * @throws SamlDocumentEntityNotAllowedException
     */
    public function newMessageDocument(string $xml = null) : Document {
        return $this->newDocumentHelper($xml, 'saml-schema-protocol-2.0', [
            'samlp' => Document::NS_SAMLP,
            'saml' => Document::NS_SAML,

            // TODO (modethirteen, 20200113): determine if we should also include xmlns:dsig="http://www.w3.org/2000/09/xmldsig#"
            'ds' => Document::NS_DS,
            'xenc' => Document::NS_XENC
        ]);
    }

    /**
     * {@inheritDoc}
     * @throws SamlDocumentCannotLoadTextException
     * @throws SamlDocumentEntityNotAllowedException
     */
    public function newMetadataDocument(string $xml = null) : Document {
        return $this->newDocumentHelper($xml, 'saml-schema-metadata-2.0', [
            'md' => Document::NS_MD,
            'ds' => Document::NS_DS
        ]);
    }

    /**
     * @param array<string, string> $namespaces
     * @throws SamlDocumentCannotLoadTextException
     * @throws SamlDocumentEntityNotAllowedException
     */
    private function newDocumentHelper(?string $xml, string $schema, array $namespaces = []) : Document {
        $doc = new Document($this->resolver->resolve($schema), $namespaces);
        if(StringEx::isNullOrEmpty($xml)) {
            return $doc;
        }
        if((new StringEx($xml))->contains('<!ENTITY')) {
            throw new SamlDocumentEntityNotAllowedException();
        }
        $oldEntityLoader = libxml_disable_entity_loader(true);
        $result = $doc->loadXML($xml);
        libxml_disable_entity_loader($oldEntityLoader);
        if(!$result) {
            throw new SamlDocumentCannotLoadTextException($xml);
        }
        return $doc;
    }
}
