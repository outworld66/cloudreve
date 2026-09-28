package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/user"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/pkg/auth"
	usersvc "github.com/cloudreve/Cloudreve/v4/service/user"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

const (
	statePrefix   = "oidc_state_"
	ticketPrefix  = "oidc_ticket_"
	subjectPrefix = "oidc_subject_"
	rootsPrefix   = "oidc_roots_"
)

type flowState struct {
	Verifier string `json:"verifier"`
	Nonce    string `json:"nonce"`
	Redirect string `json:"redirect"`
}

type claims struct {
	Subject string   `json:"sub"`
	Email   string   `json:"email"`
	Name    string   `json:"name"`
	Picture string   `json:"picture"`
	Groups  []string `json:"groups"`
	Nonce   string   `json:"nonce"`
}

type logoutClaims struct {
	Subject string                 `json:"sub"`
	Email   string                 `json:"email"`
	Events  map[string]interface{} `json:"events"`
}

func configured() bool {
	return os.Getenv("CR_OIDC_ISSUER") != "" &&
		os.Getenv("CR_OIDC_CLIENT_ID") != "" &&
		os.Getenv("CR_OIDC_CLIENT_SECRET") != ""
}

func randomString() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func redirectURL(c *gin.Context) string {
	base := dependency.FromContext(c).SettingProvider().SiteURL(c)
	return strings.TrimRight(base.String(), "/") + "/api/v4/session/oidc/callback"
}

func provider(c context.Context) (*oidc.Provider, *oidc.IDTokenVerifier, error) {
	if !configured() {
		return nil, nil, fmt.Errorf("OIDC is not configured")
	}
	p, err := oidc.NewProvider(c, os.Getenv("CR_OIDC_ISSUER"))
	if err != nil {
		return nil, nil, fmt.Errorf("OIDC discovery failed: %w", err)
	}
	return p, p.Verifier(&oidc.Config{ClientID: os.Getenv("CR_OIDC_CLIENT_ID")}), nil
}

func oauthConfig(p *oidc.Provider, callback string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     os.Getenv("CR_OIDC_CLIENT_ID"),
		ClientSecret: os.Getenv("CR_OIDC_CLIENT_SECRET"),
		Endpoint:     p.Endpoint(),
		RedirectURL:  callback,
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile", "groups"},
	}
}

// Login starts the authorization-code flow with PKCE.
func Login(c *gin.Context) {
	dep := dependency.FromContext(c)
	p, _, err := provider(c)
	if err != nil {
		c.String(500, err.Error())
		return
	}
	state, err := randomString()
	if err != nil {
		c.String(500, "failed to create OIDC state")
		return
	}
	nonce, err := randomString()
	if err != nil {
		c.String(500, "failed to create OIDC nonce")
		return
	}
	verifier := oauth2.GenerateVerifier()
	redirect := c.Query("redirect")
	if redirect == "" || !strings.HasPrefix(redirect, "/") || strings.HasPrefix(redirect, "//") {
		redirect = "/home"
	}
	stateData, _ := json.Marshal(flowState{Verifier: verifier, Nonce: nonce, Redirect: redirect})
	if err := dep.KV().Set(statePrefix+state, string(stateData), 600); err != nil {
		c.String(500, "failed to store OIDC state")
		return
	}
	config := oauthConfig(p, redirectURL(c))
	url := config.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("nonce", nonce))
	c.Redirect(302, url)
}

// Callback validates the identity token and creates a normal Cloudreve login session.
func Callback(c *gin.Context) {
	dep := dependency.FromContext(c)
	stateRaw, ok := dep.KV().Get(statePrefix + c.Query("state"))
	if !ok {
		c.String(400, "OIDC state is missing or expired")
		return
	}
	_ = dep.KV().Delete(statePrefix + c.Query("state"))
	var flow flowState
	if err := json.Unmarshal([]byte(stateRaw.(string)), &flow); err != nil {
		c.String(400, "invalid OIDC state")
		return
	}
	p, verifier, err := provider(c)
	if err != nil {
		c.String(500, err.Error())
		return
	}
	config := oauthConfig(p, redirectURL(c))
	token, err := config.Exchange(c, c.Query("code"), oauth2.VerifierOption(flow.Verifier))
	if err != nil {
		c.String(400, "OIDC token exchange failed")
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		c.String(400, "OIDC response does not contain an identity token")
		return
	}
	idToken, err := verifier.Verify(c, rawIDToken)
	if err != nil {
		c.String(400, "OIDC identity token is invalid")
		return
	}
	var identity claims
	if err := idToken.Claims(&identity); err != nil || identity.Nonce != flow.Nonce || identity.Email == "" {
		c.String(400, "OIDC identity claims are invalid")
		return
	}
	if !allowed(identity.Groups) {
		c.String(403, "OIDC user is not in an allowed group")
		return
	}
	u, err := upsertUser(c, identity)
	if err != nil {
		c.String(500, "failed to provision Cloudreve user")
		return
	}
	if u.Status != user.StatusActive {
		c.String(403, "Cloudreve user is not active")
		return
	}
	response, err := issueToken(c, u)
	if err != nil {
		c.String(500, "failed to issue Cloudreve token")
		return
	}
	if err := trackSession(c, identity.Subject, u.ID, response.Token.RefreshToken, response.Token.RefreshExpires); err != nil {
		c.String(500, "failed to track OIDC session")
		return
	}
	ticket, err := randomString()
	if err != nil {
		c.String(500, "failed to create login ticket")
		return
	}
	encoded, _ := json.Marshal(response)
	if err := dep.KV().Set(ticketPrefix+ticket, string(encoded), 60); err != nil {
		c.String(500, "failed to store login ticket")
		return
	}
	c.Redirect(302, "/session?oidc_ticket="+url.QueryEscape(ticket)+"&redirect="+url.QueryEscape(flow.Redirect))
}

func allowed(groups []string) bool {
	for _, value := range groups {
		if value == "media-admin" || value == "media-user" {
			return true
		}
	}
	return false
}

func upsertUser(c *gin.Context, identity claims) (*ent.User, error) {
	dep := dependency.FromContext(c)
	email := strings.ToLower(identity.Email)
	groupID := dep.SettingProvider().DefaultGroup(c)
	for _, value := range identity.Groups {
		if value == "media-admin" {
			groupID = 1
		}
	}
	ctx := context.WithValue(c, inventory.LoadUserGroup{}, true)
	u, err := dep.UserClient().GetByEmail(ctx, email)
	if err != nil {
		u, err = dep.UserClient().Create(c, &inventory.NewUserArgs{
			Email: email, Nick: identity.Name, Avatar: identity.Picture,
			Status: user.StatusActive, GroupID: groupID,
		})
		return u, err
	}
	if u.Status == user.StatusManualBanned || u.Status == user.StatusSysBanned {
		return nil, fmt.Errorf("user is banned")
	}
	updated, err := dep.DBClient().User.UpdateOne(u).SetGroupID(groupID).SetNick(identity.Name).SetAvatar(identity.Picture).Save(c)
	if err != nil {
		return nil, err
	}
	return dep.UserClient().GetByID(ctx, updated.ID)
}

func issueToken(c *gin.Context, u *ent.User) (*usersvc.BuiltinLoginResponse, error) {
	dep := dependency.FromContext(c)
	ctx := context.WithValue(c, inventory.UserCtx{}, u)
	token, err := dep.TokenAuth().Issue(ctx, &auth.IssueTokenArgs{User: u})
	if err != nil {
		return nil, err
	}
	return &usersvc.BuiltinLoginResponse{User: usersvc.BuildUser(u, dep.HashIDEncoder()), Token: *token}, nil
}

func trackSession(c *gin.Context, subject string, uid int, refreshToken string, expiresAt time.Time) error {
	dep := dependency.FromContext(c)
	claims, err := dep.TokenAuth().Claims(c, refreshToken)
	if err != nil || claims.RootTokenID == nil {
		return fmt.Errorf("invalid Cloudreve refresh token")
	}
	ttl := int(time.Until(expiresAt).Seconds())
	if ttl < 1 {
		ttl = 1
	}
	if subject != "" {
		if err := dep.KV().Set(subjectPrefix+subject, strconv.Itoa(uid), ttl); err != nil {
			return err
		}
	}
	key := rootsPrefix + strconv.Itoa(uid)
	var roots []string
	if raw, ok := dep.KV().Get(key); ok {
		_ = json.Unmarshal([]byte(raw.(string)), &roots)
	}
	roots = append(roots, claims.RootTokenID.String())
	encoded, _ := json.Marshal(roots)
	return dep.KV().Set(key, string(encoded), ttl)
}

// BackchannelLogout revokes all Cloudreve sessions created through Pocket ID.
func BackchannelLogout(c *gin.Context) {
	raw := c.PostForm("logout_token")
	if raw == "" {
		c.Status(400)
		return
	}
	_, verifier, err := provider(c)
	if err != nil {
		c.Status(500)
		return
	}
	token, err := verifier.Verify(c, raw)
	if err != nil {
		c.Status(400)
		return
	}
	var logout logoutClaims
	if err := token.Claims(&logout); err != nil || logout.Subject == "" {
		c.Status(400)
		return
	}
	dep := dependency.FromContext(c)
	uidRaw, ok := dep.KV().Get(subjectPrefix + logout.Subject)
	if !ok && logout.Email != "" {
		u, lookupErr := dep.UserClient().GetByEmail(c, strings.ToLower(logout.Email))
		if lookupErr == nil {
			uidRaw = strconv.Itoa(u.ID)
			ok = true
		}
	}
	if !ok {
		c.Status(200)
		return
	}
	uid, err := strconv.Atoi(uidRaw.(string))
	if err != nil {
		c.Status(400)
		return
	}
	key := rootsPrefix + strconv.Itoa(uid)
	if rawRoots, exists := dep.KV().Get(key); exists {
		var roots []string
		if json.Unmarshal([]byte(rawRoots.(string)), &roots) == nil {
			ttl := int(dep.SettingProvider().TokenAuth(c).RefreshTokenTTL.Seconds() + 10)
			for _, root := range roots {
				_ = dep.KV().Set(auth.RevokeTokenPrefix+root, true, ttl)
			}
		}
	}
	_ = dep.KV().Delete(key)
	c.Status(200)
}

// Exchange returns a one-time login ticket to the frontend.
func Exchange(c *gin.Context) {
	dep := dependency.FromContext(c)
	key := ticketPrefix + c.Query("ticket")
	raw, ok := dep.KV().Get(key)
	if !ok {
		c.JSON(400, gin.H{"code": 400, "msg": "OIDC login ticket is missing or expired"})
		return
	}
	_ = dep.KV().Delete(key)
	var response usersvc.BuiltinLoginResponse
	if err := json.Unmarshal([]byte(raw.(string)), &response); err != nil {
		c.JSON(500, gin.H{"code": 500, "msg": "invalid OIDC login ticket"})
		return
	}
	c.JSON(200, gin.H{"code": 0, "data": response})
}
