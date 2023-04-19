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
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/utils"
	"github.com/urfave/cli"
)

// newOauthProxyApp creates a new cli application and runs it
func NewOauthProxyApp() *cli.App {
	defaultConfig := config.NewDefaultConfig()
	app := cli.NewApp()
	app.Name = constant.Prog
	app.Usage = constant.Description
	app.Version = GetVersion()
	app.Author = constant.Author
	app.Email = constant.Email
	app.Flags = getCommandLineOptions()
	app.UsageText = fmt.Sprintf("%s [options]", constant.Prog)

	// step: the standard usage message isn't that helpful
	app.OnUsageError = func(context *cli.Context, err error, isSubcommand bool) error {
		fmt.Fprintf(os.Stderr, "[error] invalid options, %s\n", err)
		return err
	}

	// step: set the default action
	app.Action = func(cliCx *cli.Context) error {
		configFile := cliCx.String("config")
		// step: do we have a configuration file?
		if configFile != "" {
			if err := config.ReadConfigFile(configFile, defaultConfig); err != nil {
				return utils.PrintError(
					"unable to read the configuration file: %s, error: %s",
					configFile,
					err.Error(),
				)
			}
		}

		// step: parse the command line options
		if err := parseCLIOptions(cliCx, defaultConfig); err != nil {
			return utils.PrintError(err.Error())
		}

		// step: validate the configuration
		if err := defaultConfig.IsValid(); err != nil {
			return utils.PrintError(err.Error())
		}

		// step: create the proxy
		proxy, err := NewProxy(defaultConfig)
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

		return nil
	}

	return app
}

/*
	getCommandLineOptions builds the command line options by reflecting
	the Config struct and extracting the tagged information
*/
//nolint:cyclop
func getCommandLineOptions() []cli.Flag {
	defaults := config.NewDefaultConfig()
	var flags []cli.Flag
	count := reflect.TypeOf(config.Config{}).NumField()

	for i := 0; i < count; i++ {
		field := reflect.TypeOf(config.Config{}).Field(i)
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
			dv := reflect.ValueOf(defaults).Elem().FieldByName(field.Name).Bool()
			msg := fmt.Sprintf("%s (default: %t)", usage, dv)

			flags = append(flags, cli.BoolTFlag{
				Name:   optName,
				Usage:  msg,
				EnvVar: envName,
			})
		case reflect.String:
			defaultValue := reflect.ValueOf(defaults).Elem().FieldByName(field.Name).String()

			flags = append(flags, cli.StringFlag{
				Name:   optName,
				Usage:  usage,
				EnvVar: envName,
				Value:  defaultValue,
			})
		case reflect.Slice:
			fallthrough
		case reflect.Map:
			flags = append(flags, cli.StringSliceFlag{
				Name:  optName,
				Usage: usage,
			})
		case reflect.Int:
			flags = append(flags, cli.IntFlag{
				Name:   optName,
				Usage:  usage,
				EnvVar: envName,
			})
		case reflect.Int64:
			switch fType.String() {
			case constant.DurationType:
				dv := reflect.ValueOf(defaults).Elem().FieldByName(field.Name).Int()

				flags = append(flags, cli.DurationFlag{
					Name:   optName,
					Usage:  usage,
					Value:  time.Duration(dv),
					EnvVar: envName,
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
func parseCLIOptions(cliCtx *cli.Context, config *config.Config) error {
	// step: we can ignore these options in the Config struct
	ignoredOptions := []string{"tag-data", "match-claims", "resources", "headers"}
	// step: iterate the Config and grab command line options via reflection
	count := reflect.TypeOf(config).Elem().NumField()

	for i := 0; i < count; i++ {
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
		utils.MergeMaps(config.Tags, tags)
	}

	if cliCtx.IsSet("match-claims") {
		claims, err := utils.DecodeKeyPairs(cliCtx.StringSlice("match-claims"))
		if err != nil {
			return err
		}
		utils.MergeMaps(config.MatchClaims, claims)
	}

	if cliCtx.IsSet("headers") {
		headers, err := utils.DecodeKeyPairs(cliCtx.StringSlice("headers"))
		if err != nil {
			return err
		}
		utils.MergeMaps(config.Headers, headers)
	}

	if cliCtx.IsSet("resources") {
		for _, x := range cliCtx.StringSlice("resources") {
			resource, err := authorization.NewResource().Parse(x)
			if err != nil {
				return fmt.Errorf("invalid resource %s, %s", x, err)
			}
			config.Resources = append(config.Resources, resource)
		}
	}

	return nil
}
