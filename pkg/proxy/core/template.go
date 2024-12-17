package core

import (
	"context"
	"html/template"
	"net/http"
	"path"

	"github.com/gogatekeeper/gatekeeper/pkg/utils"
	"go.uber.org/zap"
)

// AccessForbidden redirects the user to the forbidden page.
func AccessForbidden(
	logger *zap.Logger,
	httpStatus int,
	page string,
	tags map[string]string,
	tmpl *template.Template,
) func(wrt http.ResponseWriter, req *http.Request) context.Context {
	return func(wrt http.ResponseWriter, req *http.Request) context.Context {
		wrt.WriteHeader(httpStatus)
		// are we using a custom http template for 403?
		if page != "" {
			name := path.Base(page)

			if err := tmpl.ExecuteTemplate(wrt, name, tags); err != nil {
				logger.Error(
					"failed to render the template",
					zap.Error(err),
					zap.String("template", name),
				)
			}
		}

		return revokeProxy(logger, req)
	}
}

func CustomSignInPage(
	logger *zap.Logger,
	page string,
	tags map[string]string,
	tmpl *template.Template,
) func(wrt http.ResponseWriter, authURL string) {
	return func(wrt http.ResponseWriter, authURL string) {
		wrt.WriteHeader(http.StatusOK)
		name := path.Base(page)
		model := make(map[string]string)
		model["redirect"] = authURL
		mTags := utils.MergeMaps(model, tags)

		if err := tmpl.ExecuteTemplate(wrt, name, mTags); err != nil {
			logger.Error(
				"failed to render the template",
				zap.Error(err),
				zap.String("template", name),
			)
		}
	}
}
