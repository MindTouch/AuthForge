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
namespace modethirteen\AuthForge\Common\Jose;

use Jose\Component\Core\Algorithm;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use modethirteen\AuthForge\Common\Identity\ClaimsInterface;

class JsonWebSignature implements \Stringable {

    public function __construct(private ClaimsInterface $claims, private JWK $key, private Algorithm $algo)
    {
    }

    public function __toString() : string {
        return $this->toString();
    }

    public function toString() : string {
        $jws = (new JWSBuilder(new AlgorithmManager([$this->algo])))
            ->withPayload(JsonConverter::encode($this->claims->toArray()))
            ->addSignature($this->key, ['alg' => $this->algo->name()])
            ->build();
        return (new CompactSerializer())->serialize($jws, 0);
    }
}
