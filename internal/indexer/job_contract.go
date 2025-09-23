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

package indexer

const (
	ContractZkCertificateRegistry       Contract = 1
	ContractZkCertificateRegistryString string   = "ZkCertificateRegistry"

	ContractZkCertificateRegistryV2       Contract = 2
	ContractZkCertificateRegistryV2String string   = "ZkCertificateRegistryV2"

	ContractTypeLength = 1
)

type (
	Contract uint8
)

func ContractFromString(s string) (Contract, error) {
	stan := Contract(0)
	err := stan.UnmarshalText([]byte(s))
	return stan, err
}

func (s Contract) String() string {
	switch s {
	case ContractZkCertificateRegistry:
		return ContractZkCertificateRegistryString
	case ContractZkCertificateRegistryV2:
		return ContractZkCertificateRegistryV2String
	default:
		return "unknown"
	}
}

func (s *Contract) UnmarshalText(text []byte) error {
	switch string(text) {
	case ContractZkCertificateRegistryString:
		*s = ContractZkCertificateRegistry
	case ContractZkCertificateRegistryV2String:
		*s = ContractZkCertificateRegistryV2
	default:
		*s = 0
	}

	return nil
}

func (s Contract) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

func (s *Contract) UnmarshalJSON(data []byte) error {
	return s.UnmarshalText(data)
}

func (s Contract) MarshalJSON() ([]byte, error) {
	return s.MarshalText()
}

func (s *Contract) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var text string
	if err := unmarshal(&text); err != nil {
		return err
	}

	return s.UnmarshalText([]byte(text))
}

func (s Contract) MarshalYAML() (interface{}, error) {
	return s.String(), nil
}
