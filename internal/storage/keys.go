/*
 * Copyright 2024 Galactica Network
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package storage

const (
	PrefixLength = 1
)

var (
	JobKeyPrefix              = byte(0x00)
	MerkleTreeLeafKeyPrefix   = byte(0x01)
	MerkleTreeLeafIndexPrefix = byte(0x02)

	ZKCertificateRegistryKeyPrefix     = byte(0x03)
	ZKCertificateRegistryIndexPrefix   = byte(0x04)
	ZKCertificateRegistryCounterPrefix = byte(0x05)
)
