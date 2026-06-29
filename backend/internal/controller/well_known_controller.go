package controller

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/pocket-id/pocket-id/backend/internal/common"
	"github.com/pocket-id/pocket-id/backend/internal/service"
)

const OpenIDConnectRel = "http://openid.net/specs/connect/1.0/issuer"

type WebfingerResponseLink struct {
	Rel  string `json:"rel,omitempty"`
	Href string `json:"href"`
}

type WebfingerResponse struct {
	Subject string                  `json:"subject"`
	Links   []WebfingerResponseLink `json:"links"`
}

// NewWellKnownController creates a new controller for OIDC discovery endpoints
// @Summary OIDC Discovery controller
// @Description Initializes OIDC discovery and JWKS endpoints
// @Tags Well Known
func NewWellKnownController(group *gin.RouterGroup, jwtService *service.JwtService) {
	wkc := &WellKnownController{jwtService: jwtService}

	// Pre-compute the OIDC configuration document, which is static
	var err error
	wkc.oidcConfig, err = wkc.computeOIDCConfiguration()
	if err != nil {
		slog.Error("Failed to pre-compute OpenID Connect configuration document", slog.Any("error", err))
		os.Exit(1)
		return
	}

	group.GET("/.well-known/jwks.json", wkc.jwksHandler)
	group.GET("/.well-known/openid-configuration", wkc.openIDConfigurationHandler)
	group.GET("/.well-known/webfinger", wkc.webFingerHandler)
}

type WellKnownController struct {
	jwtService *service.JwtService
	oidcConfig []byte
}

// jwksHandler godoc
// @Summary Get JSON Web Key Set (JWKS)
// @Description Returns the JSON Web Key Set used for token verification
// @Tags Well Known
// @Produce json
// @Success 200 {object} object "{ \"keys\": []interface{} }"
// @Router /.well-known/jwks.json [get]
func (wkc *WellKnownController) jwksHandler(c *gin.Context) {
	jwks, err := wkc.jwtService.GetPublicJWKSAsJSON()
	if err != nil {
		_ = c.Error(err)
		return
	}

	c.Data(http.StatusOK, "application/json; charset=utf-8", jwks)
}

// openIDConfigurationHandler godoc
// @Summary Get OpenID Connect discovery configuration
// @Description Returns the OpenID Connect discovery document with endpoints and capabilities
// @Tags Well Known
// @Success 200 {object} object "OpenID Connect configuration"
// @Router /.well-known/openid-configuration [get]
func (wkc *WellKnownController) openIDConfigurationHandler(c *gin.Context) {
	c.Data(http.StatusOK, "application/json; charset=utf-8", wkc.oidcConfig)
}

func (wkc *WellKnownController) computeOIDCConfiguration() ([]byte, error) {
	appUrl := common.EnvConfig.AppURL

	internalAppUrl := common.EnvConfig.InternalAppURL

	alg, err := wkc.jwtService.GetKeyAlg()
	if err != nil {
		return nil, fmt.Errorf("failed to get key algorithm: %w", err)
	}
	config := map[string]any{
		"issuer":                                         appUrl,
		"authorization_endpoint":                         appUrl + "/authorize",
		"token_endpoint":                                 internalAppUrl + "/api/oidc/token",
		"userinfo_endpoint":                              internalAppUrl + "/api/oidc/userinfo",
		"end_session_endpoint":                           appUrl + "/api/oidc/end-session",
		"introspection_endpoint":                         internalAppUrl + "/api/oidc/introspect",
		"device_authorization_endpoint":                  appUrl + "/api/oidc/device/authorize",
		"jwks_uri":                                       internalAppUrl + "/.well-known/jwks.json",
		"grant_types_supported":                          []string{service.GrantTypeAuthorizationCode, service.GrantTypeRefreshToken, service.GrantTypeDeviceCode, service.GrantTypeClientCredentials},
		"scopes_supported":                               []string{"openid", "profile", "email", "groups", "offline_access"},
		"claims_supported":                               []string{"sub", "given_name", "family_name", "name", "display_name", "email", "email_verified", "preferred_username", "picture", "groups", "auth_time", "amr"},
		"response_types_supported":                       []string{"code", "id_token"},
		"subject_types_supported":                        []string{"public"},
		"id_token_signing_alg_values_supported":          []string{alg.String()},
		"authorization_response_iss_parameter_supported": true,
		"code_challenge_methods_supported":               []string{"plain", "S256"},
		"prompt_values_supported":                        []string{"none", "login", "consent", "select_account"},
		"token_endpoint_auth_methods_supported":          []string{"client_secret_basic", "client_secret_post", "none"},
		"pushed_authorization_request_endpoint":          internalAppUrl + "/api/oidc/par",
		"require_pushed_authorization_requests":          false,
	}
	return json.Marshal(config)
}

// webFingerHandler godoc
// @Summary Get WebFinger resource
// @Description Returns the WebFinger resource with the associated links for the given resource
// @Tags WebFinger
// @Produce json
// @Success 200 {object} object "WebFingerResponse"
// @Router /.well-known/webfinger [get]
func (wkc *WellKnownController) webFingerHandler(c *gin.Context) {
	appUrl := common.EnvConfig.AppURL

	c.Header("Content-Type", "application/jrd+json")
	c.Header("Access-Control-Allow-Origin", "*")

	resource := c.Query("resource")

	if !wkc.validateWebFingerResource(resource) {
		c.JSON(400, gin.H{
			"status":  400,
			"message": "invalid resource",
		})
		return
	}

	res := WebfingerResponse{
		Subject: resource,
		Links:   []WebfingerResponseLink{},
	}

	rel := c.Request.URL.Query()["rel"]

	if len(rel) == 0 || slices.Contains(rel, OpenIDConnectRel) {
		res.Links = append(res.Links, WebfingerResponseLink{Rel: OpenIDConnectRel, Href: appUrl})
	}

	c.JSON(200, res)
}

func (wkc *WellKnownController) validateWebFingerResource(resource string) bool {
	prefix, suffix, found := strings.Cut(resource, ":")

	if !found {
		return false
	}

	switch prefix {
	// For users we could check if the user exists in the database but this could
	// leak information about existing users, so we just check the format of the resource
	case "acct":
		if strings.Count(suffix, "@") != 1 {
			return false
		}
		username, domain, found := strings.Cut(suffix, "@")
		if !found || username == "" || domain == "" {
			return false
		}
	case "https", "http":
		u, err := url.Parse(resource)
		if err != nil {
			return false
		}
		if u.Host == "" {
			return false
		}
	default:
		return false
	}

	return true
}
