/*
Copyright 2015 All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package proxy

import (
	"reflect"

	googleproxy "github.com/gogatekeeper/gatekeeper/pkg/google/proxy"

	configcore "github.com/gogatekeeper/gatekeeper/pkg/config/core"
	googleconfig "github.com/gogatekeeper/gatekeeper/pkg/google/config"
	keycloakconfig "github.com/gogatekeeper/gatekeeper/pkg/keycloak/config"
	keycloakproxy "github.com/gogatekeeper/gatekeeper/pkg/keycloak/proxy"
	proxycore "github.com/gogatekeeper/gatekeeper/pkg/proxy/core"
)

func ProduceProxy(cfg configcore.Configs) (proxycore.OauthProxies, error) {
	switch reflect.TypeOf(cfg) {
	case reflect.TypeOf(&(keycloakconfig.Config{})):
		c, ok := cfg.(*keycloakconfig.Config)
		if !ok {
			panic("unexpected assertion problem")
		}
		return keycloakproxy.NewProxy(c, nil, nil)
	case reflect.TypeOf(&(googleconfig.Config{})):
		c, ok := cfg.(*googleconfig.Config)
		if !ok {
			panic("unexpected assertion problem")
		}
		return googleproxy.NewProxy(c, nil, nil)
	default:
		c, ok := cfg.(*keycloakconfig.Config)
		if !ok {
			panic("unexpected assertion problem")
		}
		return keycloakproxy.NewProxy(c, nil, nil)
	}
}
