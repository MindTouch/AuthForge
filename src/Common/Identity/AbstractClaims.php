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
namespace modethirteen\AuthForge\Common\Identity;

use modethirteen\TypeEx\Dictionary;
use modethirteen\TypeEx\StringEx;

abstract class AbstractClaims extends Dictionary {

    public function getClaim(string $name) : ?string {
        $value = $this->get($name);
        return $value !== null ? StringEx::stringify($value) : null;
    }

    public function getClaims(string $name) : ?array {
        $value = $this->get($name);
        return $value !== null ? (is_array($value) ? $value : [$value]) : null;
    }
}
