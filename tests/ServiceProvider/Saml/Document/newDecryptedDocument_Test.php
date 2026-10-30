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
namespace modethirteen\AuthForge\Tests\ServiceProvider\Saml\Document;

use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlCannotLoadCryptoKeyException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlDocumentCannotLoadTextException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlDocumentDecryptionException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlDocumentDecryptionInvalidEncryptionAlgorithmException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlDocumentDecryptionNoEncryptedDataException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlDocumentEntityNotAllowedException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlDocumentSignatureValidationException;
use modethirteen\AuthForge\Tests\ServiceProvider\Saml\AbstractSamlTestCase;
use modethirteen\Crypto\Exception\CryptoKeyCannotParseCryptoKeyTextException;
use modethirteen\Crypto\Exception\CryptoKeyFactoryCannotConstructCryptoKeyException;

class newDecryptedDocument_Test extends AbstractSamlTestCase {

    /**
     * Nelnet-shaped <saml:EncryptedAssertion> envelope: an aes256-gcm EncryptedData (session
     * key wrapped to the service provider via rsa-oaep-mgf1p) wrapping a <saml:Assertion> whose
     * enveloped <ds:Signature> uses exc-c14n with InclusiveNamespaces PrefixList
     * "#default saml ds xs xsi" and rsa-sha256. Generated with the KEY_IDP and KEY_SP test keys so
     * the service provider private key decrypts it and the identity provider public key verifies the
     * signature. The ds-inclusive PrefixList is what makes libxml2 >= 2.13 namespace reconciliation
     * (XMLSecEnc::decryptNode replace=true) corrupt the canonical bytes; the existing aes128-cbc /
     * rsa-1_5 / sha1 / no-PrefixList fixtures do not reproduce it.
     */
    private const MESSAGE_ENCRYPTED_SIGNED_ASSERTION = <<<TEXT
<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/><dsig:KeyInfo xmlns:dsig="http://www.w3.org/2000/09/xmldsig#"><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/><xenc:CipherData><xenc:CipherValue>sSQjHGh0WsMdV0Z/e5G2SNDLBY5Fz5qmELvRBsoGgUYuxuAmRBo3dUptqCuRMTgdLeOO4no81I2KLg4pjYAtbmmNkNoW9b7yOPf3g0wRhLZAKTWziBUtOXOUFORgY+PxVPRUxQmifcp4HJzONz18EFM9zNsetV+6XS9zXAosKxK8MsUQR9nZQ2lRFmibpo5gswlAGXboIEIUVO7Ybe/d9KldexEMYlwaJ9lAVW3GeqnjBUvPJht5qpwxgnMRAxneN7ZMT9b6RdvU7szzHNJna9v19uMGwetiXzvlrK8aPPMwcOx/v0rF3ZtJQUQw++rs090viyudwmaL69rza/ch5uIgf61xKz53o7oeLzJyKlZy6gVsu/L73LwCEq1LuJO8HGxhwl7rs+I1wlb0Np7ujDliEQsWxRfuR8CXBzMR3g1NZnkJ4//YXx2Ei6vgc+Pbi2Zui2i+gZrDqlV+01VDzt8BYzVgY+k9iO50JURNAyBY0cE0eC1RjUj5eNNuKhY2OxzwZW9HKOl6BMFtP2q/34ilruKAI1Nw9DJs8qGdHdUmrr54Fpk4VVIeua+EoXxlgCn1L0yYZqzhidSDN+hk7ILpUpuYNviEwiKblRHvVpEGf9a69oBL3n0HqYVW4EWagOV057Oq5ITYlN4UxXGp0uCJcMvBRgZ2xejccbLfBAI=</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></dsig:KeyInfo>
   <xenc:CipherData>
      <xenc:CipherValue>5Jgwr2mbLaujf0x1YT1QBZaqNLNmlgTf0/nvy3tLwBsT3N5B8ifSbLBMCPO8rMc68q4GJOeGizrgYjUCzAazjOgos6op62lNZKaP15MXd1UNE/GW2EsZn02XyPkBIW8TWmWW/VzxZhkMdHDBhBecw91270wmC4cU2vVo3cac6ZXPs25m90wOI68GaLUTq3fKIcTaKWVcHfBOobSYeOhX/9QZJ8Cd4W19q3HiEcpMx9u1fOPAS2NzI24PNohKh/fiL/5d2tQGnZUCAMn3VJeXYDJfQE3PvdfT8xL2/bhfSe8aJcFdQFDxpaiqIQnnbBsudiWMVU/Yn25hZSpHtKbxa9NAkA+uJe/s8u00qOfh4MFh5Sn0xZwWJgoLKfq7c/oO70TBolHQK3ed1U8+AtmcJirdC/Oo/FaimnjSt/N4XXp21q41M9LU+oBbS/HVyYQDgrZGV2dYdxnZYc01BR3nVLAwhXm0gVP0f+Q72owuVY96VncvmbMtArNRcAcfPdiEgiU6UjG+JcbF7M47YoPUqw/xEGJmJw34xSjYW0MiJXxGwRIYY41y/6ErPO4mfxrEu2MJzN3m9ee/UVGOEBX4WKefJdFBNcrJnnJC/d/7KkLTgs3eppZ4nILHN84gI2goBSVsD2SIxR2lLdRhJmTgHpZmgBKnZ5FrDCsk8Zgs8X/5grImqKOGvQaLOF25DcpPqTQD42oE4QR+5+vmSeWH6eJPqO3GTnLenQ95bIAqFt8qSZL4vAgKZtzmImotjrBOHdsDpmRZ8AzfyJ7yAET9IZCgTtjNTvfZbSP+PkPxYQMYwlC3eGILZXP/0aLw1oILBRE6dujWgxP28mezl1ZIzbNSWRf3b3eqWkjEz9DyF4U0QI+GhgaeZ9UkmMHKpuKFdg/PQE4okcLQJwpSjZo7I/o1PBPVamZy4bqxFyScfQXe7dVBnO1sj8sH0mwQ+ibk4wwsOavCUy9oDo74fuXPOrxGHyrNlFovCec627oSHk31g9IcH8aQHGDBxyx8BvaTJ7/2pgrLnPnQBxMQmVsJmcRi2pCiwkDmrE4oJfbQGIlr1Xev8ao2yh+xrJVAfa6WUZ0JNmvFTKwaA1oV8zMRxxhwr7bSVcA04pO3OT7p2nIMJMzLRxuetdYxrv/Onk2KwzH6Edipod9GaAe13xuuoBMIPWRTN2+YlNb7DhpsJdpup+kL1Xnl65t2+QYi3NEbe9x6CA6dgd9HVjIfOOGIiQVU6WBdZZzFIpG6GxLr+KGNpDNFZ1rlQqZztGtjbADOM/qvkC/3Erv/LGmbdJXULlik5NFeQeOfeaq8nMxkvLiEghkhic96Ged1t3RKbA+3gJcwiKkWVdCB64jRWColqmkQF1chvjDhW5EUZ/OzlDCUPTWppn+Zos4E9I5Kb5dq5Q5V2MwdivbUrXbDN2I15Fu4ehWqcr55Et2jkGT6FWFC/Uo3k/PLJ8iBeT9OhSTwS95lO9qAwX/+aM7VrtMc2Vf8OEWk+1ks8XZg2munsta3AgDsnYKISZCcZdzTQsCcmPpkI/GHEYYq1t55z3hlXPxWjkifYiOI+xW2ZeOB0dYPHIA/zvzVi1ZxknC2IdWXQiwmCTkChI7XqpvdNGZKKMFp5mlSe06qCn5CPC0KpViODsI8uhmL9GqpbJeGMKSsfGVEFin1silGFk+F156pTUXN0uRibJFnQCE1AV/EqBqZZaC89cLynCih0sVnUbg0pOqglPny0VDq4nxX6RzsCeRbq8yFmdLJ2hNSD7sYnOu0DtW5qdOBYISS/azRfnugloQxPVi7jle5UsOaGQWEHauiRLNazzl8kcs+UgU8Cdn3vkhnXu7sYm8XZliC+rPgqh4x4WUXfUNj4My1ROQyJcZgnWJqPzMtMKO7I+DVbHk934ENmetN9/mlMXFdgDOlU5hqWjtCfGI3MxP3zifD2vi/m5TiRyu8X/N2Ah5jp34loh6rzn89Uwj81ViOmdfbtitiiW2zWsr1HWioQ+ivi0UzXsIRZOsuDJV82vB50UKgoAAfBxOnlema+Wy+FUtC0LRcbVojfSUJllNhuZG1j4Wstj5fmtrn6v93NZNNnmZuuKfgslYajzN1GTzZSnfZ2EVavg4ba+UBpX9Jmxe2CdDamSgQyEaBTUN4Bh6z0QqgC2uYgq+QsZvJ/BGyttJ7Yt1IrHrDq+hoM6MgbpFhgOe4SZN7nsuqy19NsmX2zO/W2Rv3dV4M4kkb2tj1pS1u5WKFpMJDfaJIgtMNhvmUh/R7UtBPbmDDYUcrHl+amEEOocYEl6Mz7gJlCQg5qBFKRsoMPmTLAUGDzoflDRUEV7ekjGlJQ2dPoZNihyDDVPHbULRMrphA8Bu9ghtLMAXNInOx5ekAATM3maS0ramPX4/C9T/RwV4ZO/8H1+UxP+lTCzYT8phZN3cydyWBDxVQY9/VrVM1DpClWcDv5t5Pwyp0jlQOMRkMqfQZOPI9omeHMwL9rm9eU4GtzmUc6yfbJZEinzgBWTGSy2dAhoZxfURioDrb9sPuAsanCQzZa3sV5AU9KbZREHSMaWkF7o3MCwpl/T76CfZxwNKDED1KSrLmjBSNl9iT9SdY2L/z1WGC2BQTrOMYlG0uogrIRiCtYYxdnr9Cg/FNjifGRqnsfVf8f/Yd765OwIymRTWSafyQbEroy1VhFMH9Z2SWdX+PCmV2Rw4JMcffIqdLhhcFrQuIV1qqROWiMb0YYGimE8XxxXpzr6A0HNS2zdysttKhvoTgiJpJdfDIfc/+KFrG6I6tw53OPKE0VIVwZ8+9Yqt+G+hnn/UGPn2sGmcR0dWwF+G2iwLbb4AUBW6+eNKN39P+0vqxSSPcsGMn0LOXk7V6Wv8tU0ADeR9qf2ztWkFg4Jt9twYe4vPY30zRGu1R9TmI5r3XgAjtFgD9bqnMHuas12OOGJXhvbgQgh8/XM1sCjTY8cQhIC7VGqi1nX80rs0Z1dVjTuHVdqYiPeh2AzH7r6tuMa31LJLFpzwHEcTDkjfOavPg8fIrDDEFdYzfOydmjnkvsKUEAgol8cxDJdfXdXa8QVl1KgXet96geBstO5DVcmoLFStbPlUOM9u4ykC1TCdAqOFs5ljXPLwi0ke+HN2s5jWsgr3/fMZfZtJ2TEAJjksrrJ5YWc7RB6Mo3lNX9GoQASP+QRAebBKb3/0+LHPAvw5cxtSp2kgSM15/Ifi4slhNQqoTnnxIQn6Ed39PcyBouyvUk+tanHOv36w0BwHqZCxB3I5KstVtRxnsqXrPerexVbk4KeiJ0UJ8TWy7HqYk2yVxNta4V3ds+tWx+8k/HHLpTx+gv8i4PO/2XiHLCYqyB8HH02z8JiNUZmtDidOzdQYrkVkY246T3JwaV7IMu4gPxnNWaCN7tA+cfgUw1TR+oe8WD62OGtexqIpZXC+rzhRzdRQpxcG3jRMMlHIyd+3s2Qu0vAvuqkwdAvXk/E8ypu5uos/W1QOSp2eSWqnaSOPApRYUK4wh4LB862noJjjxeWMl40csYfX6Bv7njGB15e+OwMZR1sDv8i7CnfekVEcEiiFSDqz7omwT0GLy91xOJG2bLTrdQWVovGCmbgzbfDwUl5WviJWpyqHOvIO+pr/TFR4MZHMUdcWaQQng/oSv6z9KRy48s668zQCDBQb7dlYDWt9UPqarhWpR1c3pLbCDtzbXhTM4tJMyVls2kh/UdNe4JY7cN3DxhRtYBWSRc95IPQQSpISjf+41Z4HlW/HJWjjU7l1jihFM10/+E+ZdoQmmjVMACeeugVl19poD6UG9ZmvgxDsk4E+UoW2txGMUjLKl/wiHn6qorRFBbRUgDKkTyssvV6WKPNKneBmYmT/RrXaGTwdwcAP3Zl68HOnxo9YeAzObpq7dbCCzcVB+wAm02zqAkxqnKcZuTgjzZO0z3Z/U7HP1f3yQEBamNo/438kKiA7B60+WRf82ZyJUmsKPRfsRf9LsI85oaf/dgPOYtYpdskdsAwcx3uuU8Ga65wYSoc81EkKaKsG0qYez/9moi4u40glETiEsDxXAVo1WmfruNbll6T8UtiPZmpZjQ3JgQu9DxHnMJxsYob5pOz149SsfsneSgYEh+oYCi/HqigurWUvr4LU8dJ5GUFLsjt++nkbsTlQ3Gf7qnefb6VG+dgbU6b0WGIp3yv7HeEyzxiwoMEaiY5rJAul15qbG4YaG80fMRYGdrgLXemMjAq1A60FkvHD04qBGgqUB0JtZSOk4047t2uLkTPLLW2InEwTJXfcds0fEJZmIGC2wA4G/gCg7mJi162aYeTCoMkXXKdsPO8h8qPNlKluHaHRqEAqBbsL2zhwgJ8BcPafx09XSqbZYZlVWG1wwty2nZAV+nJUCpXF/boREwIQP27CaCM3tRs1uri1sy2FTZ2bHNQD0E1/PN9iydKQ+NyfxDIEMx4V4MxMnnTruqBvu7Z2Dcux4cgRUCpXvNmwRZI4QSicd41mxNSlTYyCub7T11/718MNIk8AbPQIkgtfivB2s5SNM60mcPre1ntmt2KuIVcseni3i5JloGs9gnRotliq3aekujoo+yKOgmrryHOW6k6XhIZ55lm/qPJ2svlry31pcw5op3OySCaSagbSEuo0xkSfKAwUY+UY57ggVRMtArf8BlALxFxdKcVFpqKf6wboi3LSS1CPON/ORC1OLWdscuRKsrT/j9uatyHs3lxGK7FpJfRX8z0y0Q0c7zCAQRCxILGPthct6nY8r4UrkJvX3urTqkJ/apGOj+qxC9G/4U5n1x7CrAqJfXZSEqHuX9XOKoM3bceboi2ohpfnEsHLusoQFF0O8u2C84pcdM0WSG4kdqdzcTbgLRU5dIy+jgSFJ4F9pcs+d9TlTbCBPB6WFscYXeNzPqsgq6+skU3TaaIIqDLrh3vwIxK2FLsywoSMC/8mKiT0pSMB9bXxm2rOZBgBL+fOa4rMUJtFq2BkxvEnPln7uV4gx5l4UT9YxEatFNDN7c2ARkGBGbdy87HvzgHh2IBrojcmF+wzoiH8tJw+MKZ9TrCgW9In9R6n8fs2HmAExaCyntqc30tMqO5fxEkF3sErp+iuRg8dRxUHcj2FQseAPxkdjt5piVcjA0/pWUxtC8Vpo6S2EqNSBJc5AL+B3HwaB9I5uEt76HK9h8yUIlQ7NEP3/VYYZqTYdE3xDW9DzUrSpoyHydjPtHk+7ReEVoyzPtizIGWstBt40OQVIiz17l4gY2Otx/5LdKLgMTVVHHngWAUF0zr32F/5a+/ixCaHdCpf4IFddevf1CsDD2Nf1tIA3OxS5PZPD0mGY31OkuL7+r5OO6a/NAUrH/tWtgYjRBM5Qb8Oj7hrFIzvBLPp9s+N+n/xdZTsJ3MPU8IBJZiLvqLYTk0V2gESAwQKHM0DvrlrUqteGshbnknXUSwWI5DXDIsXFXTYA3UpLQH+gfxlVWlmHLYsKd9TbssSQM2q5OQyfTSsIkg84yyXMKU5tgcrg5blSX0NsIckvSgfELK5ZNDxhEXX8z1XEtRFeusb9OIfsoFtrodI+IgDvJL/yJrKZUFSNtcymokLJnimjFxlsxLx2Pzk2MI/pK4L3Zsx2BIfA0vf1FaoFPGRq1tzpYwN8DZzNR7pC1tCVLm7AvqFIuXb9HXcEGFqChYGImn7IIX50m+yHoUgTRqUNeIa4jg7JnXK85RUwUiiQ</xenc:CipherValue>
   </xenc:CipherData>
</xenc:EncryptedData></saml:EncryptedAssertion>
TEXT;

    /**
     * An encrypted+signed assertion whose enveloped signature uses an exc-c14n ds-inclusive
     * PrefixList must still decrypt into an <saml:EncryptedAssertion>/<saml:Assertion> envelope
     * whose signature validates. On libxml2 >= 2.13 the in-place decryptNode(replace=true)
     * reconciliation hoists xmlns:ds/xmlns:ec onto the assertion apex and the signature no longer
     * validates; this test reproduces that and guards the envelope-preserving fix.
     *
     * @test
     * @throws CryptoKeyCannotParseCryptoKeyTextException
     * @throws CryptoKeyFactoryCannotConstructCryptoKeyException
     * @throws SamlCannotLoadCryptoKeyException
     * @throws SamlDocumentCannotLoadTextException
     * @throws SamlDocumentDecryptionException
     * @throws SamlDocumentDecryptionInvalidEncryptionAlgorithmException
     * @throws SamlDocumentDecryptionNoEncryptedDataException
     * @throws SamlDocumentEntityNotAllowedException
     * @throws SamlDocumentSignatureValidationException
     */
    public function Decrypts_and_validates_nelnet_encrypted_signed_assertion() : void {

        // arrange
        $spKeys = static::newServiceProviderCryptoKeyPairFactory()->newCryptoKeyPair();
        $idpKeys = static::newIdentityProviderCryptoKeyPairFactory()
            ->withDigestAlgorithm('sha256')
            ->newCryptoKeyPair();
        $factory = static::newDocumentFactory();
        $encrypted = $factory->newMessageDocument(self::MESSAGE_ENCRYPTED_SIGNED_ASSERTION);

        // act
        $decrypted = $factory->newDecryptedDocument($encrypted, $spKeys->getPrivateKey());

        // assert: envelope shape preserved AND signature still validates
        static::assertSame(1, $decrypted->query('/saml:EncryptedAssertion/saml:Assertion')->length);
        $decrypted->validateSignature($idpKeys->getPublicKey());
        static::addToAssertionCount(1);
    }
}
