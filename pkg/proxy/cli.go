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
	"fmt"
	"os"
	"os/signal"
	"reflect"
	"syscall"
	"time"

	"github.com/gogatekeeper/gatekeeper/pkg/authorization"
	"github.com/gogatekeeper/gatekeeper/pkg/config"
	"github.com/gogatekeeper/gatekeeper/pkg/config/core"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	proxycore "github.com/gogatekeeper/gatekeeper/pkg/proxy/core"
	"github.com/gogatekeeper/gatekeeper/pkg/utils"
	"github.com/urfave/cli/v2"
)

// newOauthProxyApp creates a new cli application and runs it
func NewOauthProxyApp[T proxycore.KeycloakProvider | proxycore.GoogleProvider](provider T) *cli.App {
	cfg := config.ProduceConfig(provider)
	app := cli.NewApp()
	// we had to set this after upgrade from urvafe v1 to v2
	app.DisableSliceFlagSeparator = true
	app.Name = constant.Prog
	app.Usage = constant.Description
	app.Version = proxycore.GetVersion()
	app.Flags = getCommandLineOptions(cfg)
	app.UsageText = constant.Prog + " [options]"

	// step: the standard usage message isn't that helpful
	app.OnUsageError = func(_ *cli.Context, err error, _ bool) error {
		fmt.Fprintf(os.Stderr, "[error] invalid options, %s\n", err)
		return err
	}

	// step: set the default action
	app.Action = func(cliCx *cli.Context) error {
		configFile := cliCx.String("config")
		// step: do we have a configuration file?
		if configFile != "" {
			if err := cfg.ReadConfigFile(configFile); err != nil {
				return utils.PrintError(
					"unable to read the configuration file: %s, error: %s",
					configFile,
					err.Error(),
				)
			}
		}

		// step: parse the command line options
		if err := parseCLIOptions(cliCx, cfg); err != nil {
			return utils.PrintError(err.Error())
		}

		// step: validate the configuration
		if err := cfg.IsValid(); err != nil {
			return utils.PrintError(err.Error())
		}

		// step: create the proxy
		proxy, err := ProduceProxy(cfg)
		if err != nil {
			return utils.PrintError(err.Error())
		}

		// step: start the service
		if err := proxy.Run(); err != nil {
			return utils.PrintError(err.Error())
		}

		// step: setup the termination signals
		signalChannel := make(chan os.Signal, 1)
		signal.Notify(signalChannel, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
		<-signalChannel

		if err := proxy.Shutdown(); err != nil {
			return utils.PrintError(err.Error())
		}

		return nil
	}

	return app
}

/*
	getCommandLineOptions builds the command line options by reflecting
	the Config struct and extracting the tagged information
*/
//nolint:cyclop
func getCommandLineOptions(cfg core.Configs) []cli.Flag {
	var flags []cli.Flag
	count := reflect.TypeOf(cfg).Elem().NumField()

	for i := range count {
		field := reflect.TypeOf(cfg).Elem().Field(i)
		usage, found := field.Tag.Lookup("usage")

		if !found {
			continue
		}

		envName := field.Tag.Get("env")

		if envName != "" {
			envName = constant.EnvPrefix + envName
		}

		optName := field.Tag.Get("yaml")

		switch fType := field.Type; fType.Kind() {
		case reflect.Bool:
			dv := reflect.ValueOf(cfg).Elem().FieldByName(field.Name).Bool()
			msg := fmt.Sprintf("%s (default: %t)", usage, dv)

			flags = append(flags, &cli.BoolFlag{
				Name:    optName,
				Usage:   msg,
				EnvVars: []string{envName},
			})
		case reflect.String:
			defaultValue := reflect.ValueOf(cfg).Elem().FieldByName(field.Name).String()

			flags = append(flags, &cli.StringFlag{
				Name:    optName,
				Usage:   usage,
				EnvVars: []string{envName},
				Value:   defaultValue,
			})
		case reflect.Slice:
			fallthrough
		case reflect.Map:
			flags = append(flags, &cli.StringSliceFlag{
				Name:  optName,
				Usage: usage,
			})
		case reflect.Int:
			flags = append(flags, &cli.IntFlag{
				Name:    optName,
				Usage:   usage,
				EnvVars: []string{envName},
			})
		case reflect.Int64:
			switch fType.String() {
			case constant.DurationType:
				dv := reflect.ValueOf(cfg).Elem().FieldByName(field.Name).Int()

				flags = append(flags, &cli.DurationFlag{
					Name:    optName,
					Usage:   usage,
					Value:   time.Duration(dv),
					EnvVars: []string{envName},
				})
			default:
				panic("unknown uint64 type in the Config struct")
			}
		default:
			errMsg := fmt.Sprintf("field: %s, type: %s, kind: %s is not being handled", field.Name, fType.String(), fType.Kind())
			panic(errMsg)
		}
	}

	return flags
}

/*
	parseCLIOptions parses the command line options
	and constructs a config object
*/
//nolint:cyclop
func parseCLIOptions(cliCtx *cli.Context, config core.Configs) error {
	// step: we can ignore these options in the Config struct
	ignoredOptions := []string{"tag-data", "match-claims", "resources", "headers"}
	// step: iterate the Config and grab command line options via reflection
	count := reflect.TypeOf(config).Elem().NumField()

	for i := range count {
		field := reflect.TypeOf(config).Elem().Field(i)
		name := field.Tag.Get("yaml")

		if utils.ContainedIn(name, ignoredOptions) {
			continue
		}

		if cliCtx.IsSet(name) {
			switch field.Type.Kind() {
			case reflect.Bool:
				reflect.ValueOf(config).Elem().FieldByName(field.Name).SetBool(cliCtx.Bool(name))
			case reflect.String:
				reflect.ValueOf(config).Elem().FieldByName(field.Name).SetString(cliCtx.String(name))
			case reflect.Slice:
				reflect.ValueOf(config).Elem().FieldByName(field.Name).Set(reflect.ValueOf(cliCtx.StringSlice(name)))
			case reflect.Int:
				reflect.ValueOf(config).Elem().FieldByName(field.Name).Set(reflect.ValueOf(cliCtx.Int(name)))
			case reflect.Int64:
				switch field.Type.String() {
				case constant.DurationType:
					reflect.ValueOf(config).Elem().FieldByName(field.Name).SetInt(int64(cliCtx.Duration(name)))
				default:
					reflect.ValueOf(config).Elem().FieldByName(field.Name).SetInt(cliCtx.Int64(name))
				}
			}
		}
	}

	if cliCtx.IsSet("tag") {
		tags, err := utils.DecodeKeyPairs(cliCtx.StringSlice("tag"))
		if err != nil {
			return err
		}
		utils.MergeMaps(config.GetTags(), tags)
	}

	if cliCtx.IsSet("match-claims") {
		claims, err := utils.DecodeKeyPairs(cliCtx.StringSlice("match-claims"))
		if err != nil {
			return err
		}
		utils.MergeMaps(config.GetMatchClaims(), claims)
	}

	if cliCtx.IsSet("headers") {
		headers, err := utils.DecodeKeyPairs(cliCtx.StringSlice("headers"))
		if err != nil {
			return err
		}
		utils.MergeMaps(config.GetHeaders(), headers)
	}

	if cliCtx.IsSet("allowed-query-params") {
		headers, err := utils.DecodeKeyPairs(cliCtx.StringSlice("allowed-query-params"))
		if err != nil {
			return err
		}
		utils.MergeMaps(config.GetAllowedQueryParams(), headers)
	}

	if cliCtx.IsSet("default-allowed-query-params") {
		headers, err := utils.DecodeKeyPairs(cliCtx.StringSlice("default-allowed-query-params"))
		if err != nil {
			return err
		}
		utils.MergeMaps(config.GetDefaultAllowedQueryParams(), headers)
	}

	if cliCtx.IsSet("resources") {
		for _, x := range cliCtx.StringSlice("resources") {
			resource, err := authorization.NewResource().Parse(x)
			if err != nil {
				return fmt.Errorf("invalid resource %s, %s", x, err)
			}
			config.SetResources(append(config.GetResources(), resource))
		}
	}

	return nil
}
